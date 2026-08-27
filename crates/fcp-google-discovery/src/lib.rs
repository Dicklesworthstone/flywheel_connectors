//! Shared Google Discovery snapshot substrate for FCP connectors.
//!
//! This crate provides three core capabilities:
//! - deterministic service resolution (`alias` and explicit `service:version`)
//! - Discovery document fetching with standard + alternate endpoint support
//! - normalized, stable snapshot types for generation and testing
//! - generator-consumable Google policy/capability mapping metadata
//! - generation artifacts for manifest fragments + FCP introspection + MCP tools + agent skills
//! - shared Google auth precedence/materialization rules for connectors
//! - generic Google REST execution substrate for request validation and transport

#![forbid(unsafe_code)]
// Lint groups come from [workspace.lints.clippy]; duplicating them here would
// override that table and defeat its allow entries.
#![allow(clippy::module_name_repetitions)]

use std::{collections::BTreeMap, time::Duration};

use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};

pub mod auth;
pub mod executor;
pub mod generator;
pub mod policy;
pub mod provisioning;

/// Default Google Discovery endpoint base for standard service lookups.
pub const DEFAULT_STANDARD_DISCOVERY_BASE: &str = "https://www.googleapis.com/discovery/v1/apis";
/// Default alternate endpoint template used by some Google APIs.
///
/// Supported placeholders:
/// - `{api_name}`
/// - `{api_version}`
pub const DEFAULT_ALTERNATE_DISCOVERY_TEMPLATE: &str =
    "https://{api_name}.googleapis.com/$discovery/rest?version={api_version}";

const MAX_SCHEMA_DEPTH: usize = 64;
/// Default HTTP timeout for Google Discovery transport helpers.
pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn build_http_client(timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .expect("google discovery HTTP client should build")
}

pub(crate) fn default_http_client() -> reqwest::Client {
    build_http_client(DEFAULT_HTTP_TIMEOUT)
}

/// Errors emitted by the Google Discovery substrate.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// Invalid `api_name`/`api_version` component.
    #[error("invalid {field} component `{value}`")]
    InvalidComponent {
        /// Component field name.
        field: &'static str,
        /// Rejected component value.
        value: String,
    },

    /// Invalid service selector.
    #[error("invalid service selector `{selector}` (expected alias or service:version)")]
    InvalidServiceSelector {
        /// Selector string provided by the caller.
        selector: String,
    },

    /// Unknown alias in the curated registry.
    #[error("unknown service alias `{alias}`")]
    UnknownServiceAlias {
        /// Alias that could not be resolved.
        alias: String,
    },

    /// Request transport failed.
    #[error("request failed for `{url}`: {source}")]
    RequestFailed {
        /// Requested URL.
        url: String,
        /// Upstream reqwest error.
        source: reqwest::Error,
    },

    /// Endpoint returned a non-success status.
    #[error("endpoint `{url}` returned status {status}")]
    HttpStatus {
        /// Requested URL.
        url: String,
        /// Response status.
        status: StatusCode,
    },

    /// Response body could not be parsed as JSON.
    #[error("failed to parse discovery JSON from `{url}`: {source}")]
    JsonDecode {
        /// Requested URL.
        url: String,
        /// JSON parser error.
        source: serde_json::Error,
    },

    /// Endpoint override pointed at an untrusted remote host.
    #[error("untrusted discovery endpoint `{url}`: {reason}")]
    UntrustedEndpoint {
        /// Rejected URL.
        url: String,
        /// Human-readable rejection reason.
        reason: String,
    },

    /// Both standard and alternate endpoints failed.
    #[error(
        "failed to fetch discovery for `{service}` via both endpoints (standard: {standard}; alternate: {alternate})"
    )]
    AllEndpointsFailed {
        /// Service identity.
        service: String,
        /// Standard endpoint error summary.
        standard: String,
        /// Alternate endpoint error summary.
        alternate: String,
    },

    /// Discovery document identity did not match the requested service.
    #[error("discovery document identity mismatch for `{service}`: {field} was `{actual}`")]
    SnapshotIdentityMismatch {
        /// Requested service identity.
        service: String,
        /// Mismatched Discovery identity field.
        field: &'static str,
        /// Field value from the Discovery document.
        actual: String,
    },

    /// Discovery schema tree exceeded the supported recursion depth.
    #[error("schema depth exceeds limit {max_depth}")]
    SchemaDepthExceeded {
        /// Configured max depth.
        max_depth: usize,
    },
}

/// Canonical Google API identity.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct DiscoveryServiceId {
    /// Discovery API name (for example `gmail`, `calendar`).
    pub api_name: String,
    /// Discovery API version (for example `v1`, `v3`, `v1beta`).
    pub api_version: String,
}

impl DiscoveryServiceId {
    /// Build a canonical service identity.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::InvalidComponent`] when `api_name` or `api_version`
    /// is empty or contains unsupported characters.
    pub fn new(
        api_name: impl Into<String>,
        api_version: impl Into<String>,
    ) -> Result<Self, DiscoveryError> {
        let api_name = normalize_component("api_name", &api_name.into())?;
        let api_version = normalize_component("api_version", &api_version.into())?;
        Ok(Self {
            api_name,
            api_version,
        })
    }

    /// Parse an explicit `service:version` selector.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::InvalidServiceSelector`] when the selector does
    /// not contain exactly one `:` separator.
    pub fn parse_explicit(selector: &str) -> Result<Self, DiscoveryError> {
        let selector = selector.trim();
        let (api_name, api_version) =
            selector
                .split_once(':')
                .ok_or_else(|| DiscoveryError::InvalidServiceSelector {
                    selector: selector.to_string(),
                })?;
        Self::new(api_name, api_version)
    }

    /// Canonical `api_name:api_version` identity string.
    #[must_use]
    pub fn identity(&self) -> String {
        format!("{}:{}", self.api_name, self.api_version)
    }
}

impl std::fmt::Display for DiscoveryServiceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.api_name, self.api_version)
    }
}

/// Tiny curated alias registry for high-value Google APIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAliasRegistry {
    aliases: BTreeMap<String, DiscoveryServiceId>,
}

impl ServiceAliasRegistry {
    /// Resolve a selector as either alias or explicit `service:version`.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::InvalidServiceSelector`] for malformed explicit
    /// selectors and [`DiscoveryError::UnknownServiceAlias`] for unresolved aliases.
    pub fn resolve(&self, selector: &str) -> Result<DiscoveryServiceId, DiscoveryError> {
        let selector = selector.trim();
        if selector.is_empty() {
            return Err(DiscoveryError::InvalidServiceSelector {
                selector: selector.to_string(),
            });
        }

        if selector.contains(':') {
            return DiscoveryServiceId::parse_explicit(selector);
        }

        let alias = normalize_component("alias", selector)?;
        self.aliases
            .get(&alias)
            .cloned()
            .ok_or(DiscoveryError::UnknownServiceAlias { alias })
    }

    /// Insert/replace a curated alias entry.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::InvalidComponent`] when the alias is invalid.
    pub fn insert(
        &mut self,
        alias: impl Into<String>,
        service: DiscoveryServiceId,
    ) -> Result<(), DiscoveryError> {
        let alias = normalize_component("alias", &alias.into())?;
        self.aliases.insert(alias, service);
        Ok(())
    }

    /// Read-only map view of alias entries.
    #[must_use]
    pub const fn aliases(&self) -> &BTreeMap<String, DiscoveryServiceId> {
        &self.aliases
    }
}

impl Default for ServiceAliasRegistry {
    fn default() -> Self {
        let mut aliases = BTreeMap::new();
        aliases.insert(
            "gmail".to_string(),
            DiscoveryServiceId::new("gmail", "v1").expect("static alias must be valid"),
        );
        aliases.insert(
            "calendar".to_string(),
            DiscoveryServiceId::new("calendar", "v3").expect("static alias must be valid"),
        );
        aliases.insert(
            "gcal".to_string(),
            DiscoveryServiceId::new("calendar", "v3").expect("static alias must be valid"),
        );
        aliases.insert(
            "meet".to_string(),
            DiscoveryServiceId::new("meet", "v2").expect("static alias must be valid"),
        );
        aliases.insert(
            "google-meet".to_string(),
            DiscoveryServiceId::new("meet", "v2").expect("static alias must be valid"),
        );
        aliases.insert(
            "youtube".to_string(),
            DiscoveryServiceId::new("youtube", "v3").expect("static alias must be valid"),
        );
        aliases.insert(
            "bigquery".to_string(),
            DiscoveryServiceId::new("bigquery", "v2").expect("static alias must be valid"),
        );
        aliases.insert(
            "drive".to_string(),
            DiscoveryServiceId::new("drive", "v3").expect("static alias must be valid"),
        );
        aliases.insert(
            "admin-reports".to_string(),
            DiscoveryServiceId::new("admin", "reports_v1").expect("static alias must be valid"),
        );
        aliases.insert(
            "people".to_string(),
            DiscoveryServiceId::new("people", "v1").expect("static alias must be valid"),
        );
        aliases.insert(
            "contacts".to_string(),
            DiscoveryServiceId::new("people", "v1").expect("static alias must be valid"),
        );
        aliases.insert(
            "docs".to_string(),
            DiscoveryServiceId::new("docs", "v1").expect("static alias must be valid"),
        );
        aliases.insert(
            "sheets".to_string(),
            DiscoveryServiceId::new("sheets", "v4").expect("static alias must be valid"),
        );
        aliases.insert(
            "google-ai".to_string(),
            DiscoveryServiceId::new("generativelanguage", "v1beta")
                .expect("static alias must be valid"),
        );
        aliases.insert(
            "generativelanguage".to_string(),
            DiscoveryServiceId::new("generativelanguage", "v1beta")
                .expect("static alias must be valid"),
        );
        Self { aliases }
    }
}

/// Discovery endpoint source used for a successful fetch.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryEndpointKind {
    /// Standard Google Discovery API endpoint.
    Standard,
    /// Alternate `$discovery/rest` endpoint.
    Alternate,
}

/// Snapshot fetch output (document + provenance metadata).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FetchedDiscoverySnapshot {
    /// Normalized deterministic snapshot.
    pub snapshot: DiscoverySnapshot,
    /// Endpoint that produced the snapshot.
    pub endpoint: DiscoveryEndpointKind,
    /// Source URL used for successful retrieval.
    pub source_url: String,
    /// BLAKE3 digest of the raw response bytes.
    pub source_digest: String,
}

/// Shared HTTP fetcher for Google Discovery documents.
#[derive(Debug, Clone)]
pub struct DiscoveryFetcher {
    client: reqwest::Client,
    standard_base: String,
    alternate_template: String,
}

impl Default for DiscoveryFetcher {
    fn default() -> Self {
        Self {
            client: default_http_client(),
            standard_base: DEFAULT_STANDARD_DISCOVERY_BASE.to_string(),
            alternate_template: DEFAULT_ALTERNATE_DISCOVERY_TEMPLATE.to_string(),
        }
    }
}

impl DiscoveryFetcher {
    /// Construct a fetcher with default endpoint configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the reqwest client.
    #[must_use]
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Override the standard endpoint base.
    #[must_use]
    pub fn with_standard_base(mut self, standard_base: impl Into<String>) -> Self {
        self.standard_base = standard_base.into();
        self
    }

    /// Override the alternate endpoint template.
    #[must_use]
    pub fn with_alternate_template(mut self, alternate_template: impl Into<String>) -> Self {
        self.alternate_template = alternate_template.into();
        self
    }

    /// Build the standard and alternate URL candidates for a service.
    #[must_use]
    pub fn candidate_urls(&self, service: &DiscoveryServiceId) -> [String; 2] {
        let standard = format!(
            "{}/{}/{}/rest",
            trim_trailing_slash(&self.standard_base),
            service.api_name,
            service.api_version
        );
        let alternate = self
            .alternate_template
            .replace("{api_name}", &service.api_name)
            .replace("{api_version}", &service.api_version);
        [standard, alternate]
    }

    /// Fetch and normalize a Discovery snapshot for a service identity.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError`] when both standard and alternate endpoint
    /// retrieval/parsing paths fail.
    pub async fn fetch_snapshot(
        &self,
        service: &DiscoveryServiceId,
    ) -> Result<FetchedDiscoverySnapshot, DiscoveryError> {
        let [standard_url, alternate_url] = self.candidate_urls(service);

        match self
            .try_fetch_one(service, DiscoveryEndpointKind::Standard, &standard_url)
            .await
        {
            Ok(snapshot) => Ok(snapshot),
            Err(standard_err) => {
                match self
                    .try_fetch_one(service, DiscoveryEndpointKind::Alternate, &alternate_url)
                    .await
                {
                    Ok(snapshot) => Ok(snapshot),
                    Err(alternate_err) => Err(DiscoveryError::AllEndpointsFailed {
                        service: service.identity(),
                        standard: standard_err.to_string(),
                        alternate: alternate_err.to_string(),
                    }),
                }
            }
        }
    }

    async fn try_fetch_one(
        &self,
        service: &DiscoveryServiceId,
        endpoint: DiscoveryEndpointKind,
        url: &str,
    ) -> Result<FetchedDiscoverySnapshot, DiscoveryError> {
        validate_discovery_endpoint_url(url)?;
        let resp =
            self.client
                .get(url)
                .send()
                .await
                .map_err(|source| DiscoveryError::RequestFailed {
                    url: url.to_string(),
                    source,
                })?;

        let status = resp.status();
        if !status.is_success() {
            return Err(DiscoveryError::HttpStatus {
                url: url.to_string(),
                status,
            });
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|source| DiscoveryError::RequestFailed {
                url: url.to_string(),
                source,
            })?;
        let snapshot = normalize_snapshot_bytes(service, &bytes, endpoint, url)?;

        Ok(snapshot)
    }
}

fn validate_discovery_endpoint_url(url: &str) -> Result<(), DiscoveryError> {
    let parsed = Url::parse(url).map_err(|error| DiscoveryError::UntrustedEndpoint {
        url: url.to_string(),
        reason: format!("invalid URL: {error}"),
    })?;
    let host = parsed
        .host_str()
        .ok_or_else(|| DiscoveryError::UntrustedEndpoint {
            url: url.to_string(),
            reason: "missing host".to_string(),
        })?;

    if is_local_test_host(host) {
        if parsed.fragment().is_some() {
            return Err(DiscoveryError::UntrustedEndpoint {
                url: url.to_string(),
                reason: "local test endpoints must not include fragments".to_string(),
            });
        }
        return Ok(());
    }

    if parsed.scheme() != "https" {
        return Err(DiscoveryError::UntrustedEndpoint {
            url: url.to_string(),
            reason: "remote discovery endpoints must use https".to_string(),
        });
    }
    if parsed.username() != "" || parsed.password().is_some() {
        return Err(DiscoveryError::UntrustedEndpoint {
            url: url.to_string(),
            reason: "userinfo is not allowed in discovery endpoints".to_string(),
        });
    }
    if parsed.fragment().is_some() {
        return Err(DiscoveryError::UntrustedEndpoint {
            url: url.to_string(),
            reason: "fragments are not allowed in discovery endpoints".to_string(),
        });
    }
    if host.eq_ignore_ascii_case("www.googleapis.com")
        || host.eq_ignore_ascii_case("googleapis.com")
        || host.ends_with(".googleapis.com")
    {
        return Ok(());
    }

    Err(DiscoveryError::UntrustedEndpoint {
        url: url.to_string(),
        reason: "remote discovery endpoints must target Google APIs hosts".to_string(),
    })
}

fn is_local_test_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

/// Build a deterministic snapshot storage key.
#[must_use]
pub fn snapshot_storage_key(service: &DiscoveryServiceId, source_digest: &str) -> String {
    format!(
        "google-discovery/{}/{}/{}",
        service.api_name.trim(),
        service.api_version.trim(),
        source_digest.trim()
    )
}

/// Deterministic normalized Discovery snapshot.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiscoverySnapshot {
    /// Canonical service identity.
    pub service: DiscoveryServiceId,
    /// Discovery document `name` field.
    pub name: Option<String>,
    /// Service title.
    pub title: Option<String>,
    /// Service description.
    pub description: Option<String>,
    /// Discovery revision.
    pub revision: Option<String>,
    /// Root URL for API requests.
    pub root_url: Option<String>,
    /// Service path suffix.
    pub service_path: Option<String>,
    /// Full base URL.
    pub base_url: Option<String>,
    /// Batch path if provided.
    pub batch_path: Option<String>,
    /// OAuth scopes available for the service.
    pub auth_scopes: Vec<DiscoveryScope>,
    /// Named schema map.
    pub schemas: BTreeMap<String, DiscoverySchema>,
    /// Flattened method catalog keyed by normalized method key.
    pub methods: BTreeMap<String, DiscoveryMethod>,
    /// Resource hierarchy from the source document.
    pub resources: BTreeMap<String, DiscoveryResource>,
}

/// OAuth scope entry from Discovery auth metadata.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct DiscoveryScope {
    /// Scope URI.
    pub id: String,
    /// Optional human description.
    pub description: Option<String>,
}

/// Normalized Discovery resource node.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryResource {
    /// Resource-local methods.
    pub methods: BTreeMap<String, DiscoveryMethod>,
    /// Nested resources.
    pub resources: BTreeMap<String, Self>,
}

/// Normalized method metadata.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryMethod {
    /// Method key (`users.messages.list`, etc).
    pub key: String,
    /// Discovery method ID (for example `gmail.users.messages.list`).
    pub id: String,
    /// HTTP method verb.
    pub http_method: String,
    /// Method path from Discovery (`path` field).
    pub path: String,
    /// Optional `flatPath`.
    pub flat_path: Option<String>,
    /// Chosen canonical path (`flatPath` when present, otherwise `path`).
    pub canonical_path: String,
    /// Resource path prefix for this method.
    pub resource_path: Vec<String>,
    /// Optional description.
    pub description: Option<String>,
    /// Required OAuth scopes at method level.
    pub scopes: Vec<String>,
    /// Request schema reference (`$ref`) when available.
    pub request_ref: Option<String>,
    /// Response schema reference (`$ref`) when available.
    pub response_ref: Option<String>,
    /// Method parameter metadata.
    pub parameters: BTreeMap<String, DiscoveryParameter>,
    /// Discovery flag.
    pub supports_media_download: bool,
    /// Discovery flag.
    pub supports_media_upload: bool,
    /// Upload protocol details when present.
    pub media_upload: Option<DiscoveryMediaUpload>,
}

/// Normalized method parameter metadata.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryParameter {
    /// Parameter location (`path`, `query`, ...).
    pub location: Option<String>,
    /// Whether parameter is required.
    pub required: bool,
    /// Whether parameter is repeated.
    pub repeated: bool,
    /// Discovery type name.
    pub type_name: Option<String>,
    /// Optional data format.
    pub format: Option<String>,
    /// Optional parameter description.
    pub description: Option<String>,
}

/// Media-upload protocol metadata.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryMediaUpload {
    /// Accepted content types.
    pub accept: Vec<String>,
    /// Optional max upload size.
    pub max_size: Option<String>,
    /// Simple upload path.
    pub simple_path: Option<String>,
    /// Resumable upload path.
    pub resumable_path: Option<String>,
}

/// Normalized schema node.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiscoverySchema {
    /// Discovery type (`object`, `array`, `string`, ...).
    pub type_name: Option<String>,
    /// Optional format (for example `int64`, `date-time`).
    pub format: Option<String>,
    /// Optional human description.
    pub description: Option<String>,
    /// Required property names.
    pub required: Vec<String>,
    /// Enum value set.
    pub enum_values: Vec<String>,
    /// Object property map.
    pub properties: BTreeMap<String, Self>,
    /// Array item schema.
    pub items: Option<Box<Self>>,
    /// Reference target for `$ref` nodes.
    pub ref_name: Option<String>,
    /// Additional-properties schema.
    pub additional_properties: Option<Box<Self>>,
}

/// Normalize a raw Discovery JSON document into deterministic snapshot types.
///
/// # Errors
///
/// Returns [`DiscoveryError::JsonDecode`] if JSON parsing fails and
/// [`DiscoveryError::SchemaDepthExceeded`] for deeply nested schemas.
pub fn normalize_snapshot_bytes(
    service: &DiscoveryServiceId,
    bytes: &[u8],
    endpoint: DiscoveryEndpointKind,
    source_url: &str,
) -> Result<FetchedDiscoverySnapshot, DiscoveryError> {
    let parsed: RawDiscoveryDocument =
        serde_json::from_slice(bytes).map_err(|source| DiscoveryError::JsonDecode {
            url: source_url.to_string(),
            source,
        })?;
    validate_snapshot_identity(service, &parsed)?;

    let mut methods = normalize_methods(&parsed.methods, service, &[]);
    let resources = normalize_resources(&parsed.resources, service, &[]);
    collect_resource_methods(&resources, &mut methods);

    let mut auth_scopes = normalize_scopes(parsed.auth);
    auth_scopes.sort();

    let source_digest = blake3::hash(bytes).to_hex().to_string();
    let snapshot = DiscoverySnapshot {
        service: service.clone(),
        name: normalize_optional(parsed.name),
        title: normalize_optional(parsed.title),
        description: normalize_optional(parsed.description),
        revision: normalize_optional(parsed.revision),
        root_url: normalize_optional(parsed.root_url),
        service_path: normalize_optional(parsed.service_path),
        base_url: normalize_optional(parsed.base_url),
        batch_path: normalize_optional(parsed.batch_path),
        auth_scopes,
        schemas: normalize_schema_map(parsed.schemas, 0)?,
        methods,
        resources,
    };

    Ok(FetchedDiscoverySnapshot {
        snapshot,
        endpoint,
        source_url: source_url.to_string(),
        source_digest,
    })
}

fn validate_snapshot_identity(
    service: &DiscoveryServiceId,
    document: &RawDiscoveryDocument,
) -> Result<(), DiscoveryError> {
    let service_identity = service.identity();
    if let Some(name) = normalize_optional(document.name.clone())
        && name != service.api_name
    {
        return Err(DiscoveryError::SnapshotIdentityMismatch {
            service: service_identity,
            field: "name",
            actual: name,
        });
    }
    if let Some(version) = normalize_optional(document.version.clone())
        && version != service.api_version
    {
        return Err(DiscoveryError::SnapshotIdentityMismatch {
            service: service_identity,
            field: "version",
            actual: version,
        });
    }
    Ok(())
}

fn normalize_schema_map(
    schemas: BTreeMap<String, RawSchema>,
    depth: usize,
) -> Result<BTreeMap<String, DiscoverySchema>, DiscoveryError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(DiscoveryError::SchemaDepthExceeded {
            max_depth: MAX_SCHEMA_DEPTH,
        });
    }

    let mut out = BTreeMap::new();
    for (name, schema) in schemas {
        out.insert(name, normalize_schema(schema, depth + 1)?);
    }
    Ok(out)
}

fn normalize_schema(schema: RawSchema, depth: usize) -> Result<DiscoverySchema, DiscoveryError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(DiscoveryError::SchemaDepthExceeded {
            max_depth: MAX_SCHEMA_DEPTH,
        });
    }

    let mut required: Vec<String> = schema
        .required
        .into_iter()
        .filter_map(|v| normalize_optional(Some(v)))
        .collect();
    required.sort_unstable();
    required.dedup();

    let mut enum_values: Vec<String> = schema
        .enum_values
        .into_iter()
        .filter_map(|v| normalize_optional(Some(v)))
        .collect();
    enum_values.sort_unstable();
    enum_values.dedup();

    let properties = normalize_schema_map(schema.properties, depth + 1)?;
    let items = schema
        .items
        .map(|value| normalize_schema(*value, depth + 1).map(Box::new))
        .transpose()?;
    let additional_properties = schema
        .additional_properties
        .map(|value| normalize_schema(*value, depth + 1).map(Box::new))
        .transpose()?;

    Ok(DiscoverySchema {
        type_name: normalize_optional(schema.type_name),
        format: normalize_optional(schema.format),
        description: normalize_optional(schema.description),
        required,
        enum_values,
        properties,
        items,
        ref_name: normalize_optional(schema.ref_name),
        additional_properties,
    })
}

fn normalize_resources(
    resources: &BTreeMap<String, RawResource>,
    service: &DiscoveryServiceId,
    parent: &[String],
) -> BTreeMap<String, DiscoveryResource> {
    let mut out = BTreeMap::new();
    for (resource_name, raw_resource) in resources {
        let mut next_parent = parent.to_vec();
        next_parent.push(resource_name.clone());
        let methods = normalize_methods(&raw_resource.methods, service, &next_parent);
        let nested = normalize_resources(&raw_resource.resources, service, &next_parent);
        out.insert(
            resource_name.clone(),
            DiscoveryResource {
                methods,
                resources: nested,
            },
        );
    }
    out
}

fn normalize_methods(
    methods: &BTreeMap<String, RawMethod>,
    service: &DiscoveryServiceId,
    resource_path: &[String],
) -> BTreeMap<String, DiscoveryMethod> {
    let mut out = BTreeMap::new();
    for (method_name, method) in methods {
        let key = method_key(resource_path, method_name);
        let flat_path = normalize_optional(method.flat_path.clone());
        let path = normalize_optional(method.path.clone()).unwrap_or_default();
        let canonical_path = flat_path.clone().unwrap_or_else(|| path.clone());
        let mut scopes: Vec<String> = method
            .scopes
            .clone()
            .into_iter()
            .filter_map(|v| normalize_optional(Some(v)))
            .collect();
        scopes.sort_unstable();
        scopes.dedup();

        let id = normalize_optional(method.id.clone())
            .unwrap_or_else(|| format!("{}.{}", service.api_name, key));
        let http_method = normalize_optional(method.http_method.clone())
            .unwrap_or_else(|| "GET".to_string())
            .to_ascii_uppercase();
        let request_ref = method
            .request
            .as_ref()
            .and_then(RawReference::reference_name);
        let response_ref = method
            .response
            .as_ref()
            .and_then(RawReference::reference_name);

        let mut parameters = BTreeMap::new();
        for (param_name, param) in &method.parameters {
            parameters.insert(
                param_name.clone(),
                DiscoveryParameter {
                    location: normalize_optional(param.location.clone()),
                    required: param.required,
                    repeated: param.repeated,
                    type_name: normalize_optional(param.type_name.clone()),
                    format: normalize_optional(param.format.clone()),
                    description: normalize_optional(param.description.clone()),
                },
            );
        }

        let media_upload = method
            .media_upload
            .as_ref()
            .map(|upload| normalize_media_upload(upload.clone()));
        let supports_media_upload = method.supports_media_upload || media_upload.is_some();

        out.insert(
            key.clone(),
            DiscoveryMethod {
                key,
                id,
                http_method,
                path,
                flat_path,
                canonical_path,
                resource_path: resource_path.to_vec(),
                description: normalize_optional(method.description.clone()),
                scopes,
                request_ref,
                response_ref,
                parameters,
                supports_media_download: method.supports_media_download,
                supports_media_upload,
                media_upload,
            },
        );
    }
    out
}

fn normalize_media_upload(upload: RawMediaUpload) -> DiscoveryMediaUpload {
    let mut accept: Vec<String> = upload
        .accept
        .into_iter()
        .filter_map(|v| normalize_optional(Some(v)))
        .collect();
    accept.sort_unstable();
    accept.dedup();

    let simple_path = upload
        .protocols
        .as_ref()
        .and_then(|protocols| protocols.simple.as_ref())
        .and_then(|simple| normalize_optional(simple.path.clone()));
    let resumable_path = upload
        .protocols
        .as_ref()
        .and_then(|protocols| protocols.resumable.as_ref())
        .and_then(|resumable| normalize_optional(resumable.path.clone()));

    DiscoveryMediaUpload {
        accept,
        max_size: normalize_optional(upload.max_size),
        simple_path,
        resumable_path,
    }
}

fn normalize_scopes(auth: Option<RawAuth>) -> Vec<DiscoveryScope> {
    let mut scopes = Vec::new();
    if let Some(auth) = auth {
        for (id, meta) in auth.oauth2.scopes {
            if let Some(normalized) = normalize_optional(Some(id)) {
                scopes.push(DiscoveryScope {
                    id: normalized,
                    description: normalize_optional(meta.description),
                });
            }
        }
    }
    scopes
}

fn collect_resource_methods(
    resources: &BTreeMap<String, DiscoveryResource>,
    out: &mut BTreeMap<String, DiscoveryMethod>,
) {
    for resource in resources.values() {
        for (key, method) in &resource.methods {
            out.insert(key.clone(), method.clone());
        }
        collect_resource_methods(&resource.resources, out);
    }
}

fn method_key(resource_path: &[String], method_name: &str) -> String {
    if resource_path.is_empty() {
        method_name.to_string()
    } else {
        format!("{}.{}", resource_path.join("."), method_name)
    }
}

fn normalize_component(field: &'static str, value: &str) -> Result<String, DiscoveryError> {
    let candidate = value.trim().to_ascii_lowercase();
    if candidate.is_empty() || !candidate.chars().all(is_allowed_component_char) {
        return Err(DiscoveryError::InvalidComponent {
            field,
            value: value.to_string(),
        });
    }
    Ok(candidate)
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value.and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

const fn is_allowed_component_char(ch: char) -> bool {
    ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_' | '.')
}

fn trim_trailing_slash(value: &str) -> String {
    value.trim_end_matches('/').to_string()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDiscoveryDocument {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    revision: Option<String>,
    #[serde(default)]
    root_url: Option<String>,
    #[serde(default)]
    service_path: Option<String>,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    batch_path: Option<String>,
    #[serde(default)]
    auth: Option<RawAuth>,
    #[serde(default)]
    schemas: BTreeMap<String, RawSchema>,
    #[serde(default)]
    methods: BTreeMap<String, RawMethod>,
    #[serde(default)]
    resources: BTreeMap<String, RawResource>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RawAuth {
    #[serde(default)]
    oauth2: RawOAuth2,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RawOAuth2 {
    #[serde(default)]
    scopes: BTreeMap<String, RawScopeMeta>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RawScopeMeta {
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawResource {
    #[serde(default)]
    methods: BTreeMap<String, RawMethod>,
    #[serde(default)]
    resources: BTreeMap<String, Self>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMethod {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    flat_path: Option<String>,
    #[serde(default)]
    http_method: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    request: Option<RawReference>,
    #[serde(default)]
    response: Option<RawReference>,
    #[serde(default)]
    parameters: BTreeMap<String, RawParameter>,
    #[serde(default)]
    supports_media_download: bool,
    #[serde(default)]
    supports_media_upload: bool,
    #[serde(default)]
    media_upload: Option<RawMediaUpload>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawParameter {
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    repeated: bool,
    #[serde(default, rename = "type")]
    type_name: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RawReference {
    #[serde(default, rename = "$ref")]
    ref_name: Option<String>,
}

impl RawReference {
    fn reference_name(&self) -> Option<String> {
        normalize_optional(self.ref_name.clone())
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMediaUpload {
    #[serde(default)]
    accept: Vec<String>,
    #[serde(default)]
    max_size: Option<String>,
    #[serde(default)]
    protocols: Option<RawUploadProtocols>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RawUploadProtocols {
    #[serde(default)]
    simple: Option<RawUploadProtocol>,
    #[serde(default)]
    resumable: Option<RawUploadProtocol>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RawUploadProtocol {
    #[serde(default)]
    path: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawSchema {
    #[serde(default, rename = "type")]
    type_name: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    required: Vec<String>,
    #[serde(default, rename = "enum")]
    enum_values: Vec<String>,
    #[serde(default)]
    properties: BTreeMap<String, Self>,
    #[serde(default)]
    items: Option<Box<Self>>,
    #[serde(default, rename = "$ref")]
    ref_name: Option<String>,
    #[serde(default)]
    additional_properties: Option<Box<Self>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param},
    };

    const GMAIL_FIXTURE: &str = r#"
{
  "name": "gmail",
  "version": "v1",
  "title": "Gmail API",
  "description": "Workspace mail API",
  "revision": "20260306",
  "rootUrl": "https://gmail.googleapis.com/",
  "servicePath": "gmail/v1/users/",
  "baseUrl": "https://gmail.googleapis.com/gmail/v1/users/",
  "auth": {
    "oauth2": {
      "scopes": {
        "https://www.googleapis.com/auth/gmail.modify": {"description": "Modify mailbox"},
        "https://www.googleapis.com/auth/gmail.readonly": {"description": "Read mailbox"}
      }
    }
  },
  "schemas": {
    "MessageList": {
      "type": "object",
      "properties": {
        "messages": {"type": "array", "items": {"$ref": "Message"}}
      }
    },
    "Message": {
      "type": "object",
      "required": ["id"],
      "properties": {
        "id": {"type": "string"},
        "labelIds": {"type": "array", "items": {"type": "string"}}
      }
    }
  },
  "resources": {
    "users": {
      "resources": {
        "messages": {
          "methods": {
            "list": {
              "id": "gmail.users.messages.list",
              "path": "{userId}/messages",
              "flatPath": "gmail/v1/users/{userId}/messages",
              "httpMethod": "GET",
              "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
              "parameters": {
                "q": {"type": "string", "location": "query"},
                "userId": {"type": "string", "location": "path", "required": true}
              },
              "response": {"$ref": "MessageList"}
            }
          }
        }
      }
    }
  }
}
"#;

    const YOUTUBE_FIXTURE: &str = r#"
{
  "name": "youtube",
  "version": "v3",
  "title": "YouTube Data API",
  "rootUrl": "https://youtube.googleapis.com/",
  "servicePath": "youtube/v3/",
  "methods": {
    "videosList": {
      "id": "youtube.videos.list",
      "path": "videos",
      "httpMethod": "GET",
      "scopes": ["https://www.googleapis.com/auth/youtube.readonly"],
      "parameters": {
        "part": {"type": "string", "location": "query", "required": true}
      },
      "response": {"$ref": "VideoListResponse"}
    }
  },
  "schemas": {
    "VideoListResponse": {
      "type": "object",
      "properties": {
        "items": {"type": "array", "items": {"$ref": "Video"}}
      }
    },
    "Video": {
      "type": "object",
      "properties": {
        "id": {"type": "string"}
      }
    }
  }
}
"#;

    fn mock_http_client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build test client")
    }

    #[test]
    fn default_http_timeout_matches_google_client_convention() {
        assert_eq!(DEFAULT_HTTP_TIMEOUT, Duration::from_secs(30));
    }

    #[test]
    fn build_http_client_times_out_slow_response() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_delay(Duration::from_millis(150))
                        .set_body_string("{}"),
                )
                .mount(&server)
                .await;

            let client = build_http_client(Duration::from_millis(50));
            let err = client
                .get(server.uri())
                .send()
                .await
                .expect_err("slow response should hit bounded timeout");
            assert!(err.is_timeout(), "expected timeout, got {err}");
        });
    }

    fn run_with_test_runtime<F, T>(future: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        fcp_async_core::runtime::block_on_sync(future).expect("build sync test runtime")
    }

    #[test]
    fn alias_registry_supports_tiny_curated_map() {
        let registry = ServiceAliasRegistry::default();
        let resolved = registry.resolve("gcal").expect("resolve alias");
        assert_eq!(resolved.api_name, "calendar");
        assert_eq!(resolved.api_version, "v3");
        let meet = registry.resolve("google-meet").expect("resolve meet alias");
        assert_eq!(meet.api_name, "meet");
        assert_eq!(meet.api_version, "v2");
        assert!(registry.aliases().contains_key("gmail"));
    }

    #[test]
    fn explicit_service_version_resolution_is_supported() {
        let registry = ServiceAliasRegistry::default();
        let resolved = registry
            .resolve("generativelanguage:v1beta")
            .expect("resolve explicit selector");
        assert_eq!(resolved.api_name, "generativelanguage");
        assert_eq!(resolved.api_version, "v1beta");
    }

    #[test]
    fn deterministic_snapshot_storage_key() {
        let service = DiscoveryServiceId::new("gmail", "v1").expect("valid id");
        let key_a = snapshot_storage_key(&service, "abc123");
        let key_b = snapshot_storage_key(&service, "abc123");
        assert_eq!(key_a, key_b);
        assert_eq!(key_a, "google-discovery/gmail/v1/abc123");
    }

    #[test]
    fn candidate_urls_include_standard_and_alternate_patterns() {
        let service = DiscoveryServiceId::new("gmail", "v1").expect("valid id");
        let fetcher = DiscoveryFetcher::new();
        let urls = fetcher.candidate_urls(&service);
        assert_eq!(
            urls[0],
            "https://www.googleapis.com/discovery/v1/apis/gmail/v1/rest"
        );
        assert_eq!(
            urls[1],
            "https://gmail.googleapis.com/$discovery/rest?version=v1"
        );
    }

    #[test]
    fn workspace_fixture_normalizes_with_scopes_and_resource_methods() {
        let service = DiscoveryServiceId::new("gmail", "v1").expect("valid id");
        let result = normalize_snapshot_bytes(
            &service,
            GMAIL_FIXTURE.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize gmail fixture");

        assert_eq!(result.snapshot.service.identity(), "gmail:v1");
        assert_eq!(result.snapshot.auth_scopes.len(), 2);
        assert!(result.snapshot.methods.contains_key("users.messages.list"));
        assert!(result.snapshot.schemas.contains_key("Message"));

        let method = result
            .snapshot
            .methods
            .get("users.messages.list")
            .expect("method exists");
        assert_eq!(method.id, "gmail.users.messages.list");
        assert_eq!(method.canonical_path, "gmail/v1/users/{userId}/messages");
    }

    #[test]
    fn non_workspace_fixture_normalizes_top_level_methods() {
        let service = DiscoveryServiceId::new("youtube", "v3").expect("valid id");
        let result = normalize_snapshot_bytes(
            &service,
            YOUTUBE_FIXTURE.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize youtube fixture");

        assert_eq!(result.snapshot.service.identity(), "youtube:v3");
        assert!(result.snapshot.methods.contains_key("videosList"));
        assert!(result.snapshot.schemas.contains_key("Video"));
    }

    #[test]
    fn normalization_is_deterministic_for_identical_input() {
        let service = DiscoveryServiceId::new("gmail", "v1").expect("valid id");
        let first = normalize_snapshot_bytes(
            &service,
            GMAIL_FIXTURE.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("first normalize");
        let second = normalize_snapshot_bytes(
            &service,
            GMAIL_FIXTURE.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("second normalize");
        assert_eq!(first, second);
    }

    // ── DiscoveryServiceId tests ────────────────────────────────────────

    #[test]
    fn service_id_new_valid() {
        let id = DiscoveryServiceId::new("gmail", "v1").expect("valid id");
        assert_eq!(id.api_name, "gmail");
        assert_eq!(id.api_version, "v1");
    }

    #[test]
    fn service_id_new_rejects_empty_api_name() {
        let err = DiscoveryServiceId::new("", "v1").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("api_name"),
            "expected api_name in error: {msg}"
        );
    }

    #[test]
    fn service_id_new_rejects_empty_api_version() {
        let err = DiscoveryServiceId::new("gmail", "").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("api_version"),
            "expected api_version in error: {msg}"
        );
    }

    #[test]
    fn service_id_new_rejects_special_chars() {
        let err = DiscoveryServiceId::new("gm!@#ail", "v1").unwrap_err();
        assert!(matches!(err, DiscoveryError::InvalidComponent { .. }));

        let err2 = DiscoveryServiceId::new("gmail", "v1$%^").unwrap_err();
        assert!(matches!(err2, DiscoveryError::InvalidComponent { .. }));
    }

    #[test]
    fn service_id_new_normalizes_to_lowercase() {
        let id = DiscoveryServiceId::new("Gmail", "V1").expect("valid id");
        assert_eq!(id.api_name, "gmail");
        assert_eq!(id.api_version, "v1");
    }

    #[test]
    fn service_id_parse_explicit_valid() {
        let id = DiscoveryServiceId::parse_explicit("gmail:v1").expect("valid selector");
        assert_eq!(id.api_name, "gmail");
        assert_eq!(id.api_version, "v1");
    }

    #[test]
    fn service_id_parse_explicit_no_colon() {
        let err = DiscoveryServiceId::parse_explicit("gmailv1").unwrap_err();
        assert!(matches!(err, DiscoveryError::InvalidServiceSelector { .. }));
    }

    #[test]
    fn service_id_parse_explicit_trims_whitespace() {
        let id = DiscoveryServiceId::parse_explicit("  gmail:v1  ").expect("valid selector");
        assert_eq!(id.api_name, "gmail");
        assert_eq!(id.api_version, "v1");
    }

    #[test]
    fn service_id_identity_format() {
        let id = DiscoveryServiceId::new("calendar", "v3").expect("valid id");
        assert_eq!(id.identity(), "calendar:v3");
    }

    #[test]
    fn service_id_display_format() {
        let id = DiscoveryServiceId::new("drive", "v3").expect("valid id");
        let display = format!("{id}");
        assert_eq!(display, id.identity());
        assert_eq!(display, "drive:v3");
    }

    #[test]
    fn service_id_serde_roundtrip() {
        let id = DiscoveryServiceId::new("sheets", "v4").expect("valid id");
        let json = serde_json::to_string(&id).expect("serialize");
        let deserialized: DiscoveryServiceId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deserialized);
    }

    #[test]
    fn service_id_ordering() {
        let a = DiscoveryServiceId::new("alpha", "v1").expect("valid");
        let b = DiscoveryServiceId::new("beta", "v1").expect("valid");
        let c = DiscoveryServiceId::new("alpha", "v2").expect("valid");
        assert!(a < b, "alpha < beta");
        assert!(a < c, "alpha:v1 < alpha:v2");
        assert!(c < b, "alpha:v2 < beta:v1");
    }

    #[test]
    fn service_id_hash_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let id1 = DiscoveryServiceId::new("gmail", "v1").expect("valid");
        let id2 = DiscoveryServiceId::new("gmail", "v1").expect("valid");

        let mut h1 = DefaultHasher::new();
        id1.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        id2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    // ── ServiceAliasRegistry tests ──────────────────────────────────────

    #[test]
    fn alias_registry_default_has_all_google_services() {
        let registry = ServiceAliasRegistry::default();
        let aliases = registry.aliases();
        let expected = [
            "gmail",
            "calendar",
            "gcal",
            "meet",
            "google-meet",
            "youtube",
            "bigquery",
            "drive",
            "admin-reports",
            "people",
            "contacts",
            "docs",
            "sheets",
            "google-ai",
            "generativelanguage",
        ];
        for alias in &expected {
            assert!(
                aliases.contains_key(*alias),
                "missing default alias: {alias}"
            );
        }
        assert_eq!(aliases.len(), expected.len());
    }

    #[test]
    fn alias_registry_resolve_empty_string_fails() {
        let registry = ServiceAliasRegistry::default();
        let err = registry.resolve("").unwrap_err();
        assert!(matches!(err, DiscoveryError::InvalidServiceSelector { .. }));
    }

    #[test]
    fn alias_registry_resolve_unknown_alias_fails() {
        let registry = ServiceAliasRegistry::default();
        let err = registry.resolve("nonexistent-service").unwrap_err();
        assert!(matches!(err, DiscoveryError::UnknownServiceAlias { .. }));
    }

    #[test]
    fn alias_registry_insert_and_resolve() {
        let mut registry = ServiceAliasRegistry::default();
        let service = DiscoveryServiceId::new("customapi", "v2").expect("valid");
        registry
            .insert("myalias", service.clone())
            .expect("insert alias");
        let resolved = registry.resolve("myalias").expect("resolve");
        assert_eq!(resolved, service);
    }

    #[test]
    fn alias_registry_insert_rejects_invalid_alias() {
        let mut registry = ServiceAliasRegistry::default();
        let service = DiscoveryServiceId::new("customapi", "v1").expect("valid");
        let err = registry.insert("bad!alias", service).unwrap_err();
        assert!(matches!(err, DiscoveryError::InvalidComponent { .. }));
    }

    // ── DiscoveryFetcher tests ──────────────────────────────────────────

    #[test]
    fn fetcher_with_custom_standard_base() {
        let service = DiscoveryServiceId::new("gmail", "v1").expect("valid");
        let fetcher =
            DiscoveryFetcher::new().with_standard_base("https://custom.example.com/discovery");
        let urls = fetcher.candidate_urls(&service);
        assert_eq!(
            urls[0],
            "https://custom.example.com/discovery/gmail/v1/rest"
        );
    }

    #[test]
    fn fetcher_with_custom_alternate_template() {
        let service = DiscoveryServiceId::new("gmail", "v1").expect("valid");
        let fetcher = DiscoveryFetcher::new()
            .with_alternate_template("https://alt.example.com/{api_name}?v={api_version}");
        let urls = fetcher.candidate_urls(&service);
        assert_eq!(urls[1], "https://alt.example.com/gmail?v=v1");
    }

    #[test]
    fn fetcher_candidate_urls_trim_trailing_slash() {
        let service = DiscoveryServiceId::new("gmail", "v1").expect("valid");
        let fetcher = DiscoveryFetcher::new().with_standard_base("https://example.com/api/");
        let urls = fetcher.candidate_urls(&service);
        assert!(
            !urls[0].contains("//gmail"),
            "trailing slash should be trimmed: {}",
            urls[0]
        );
        assert_eq!(urls[0], "https://example.com/api/gmail/v1/rest");
    }

    #[test]
    fn fetch_snapshot_uses_standard_endpoint_when_available() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            let service = DiscoveryServiceId::new("gmail", "v1").expect("valid");
            let standard_base = format!("{}/discovery/v1/apis", server.uri());
            let alternate_template = format!(
                "{}/$discovery/rest?api={{api_name}}&version={{api_version}}",
                server.uri()
            );

            Mock::given(method("GET"))
                .and(path("/discovery/v1/apis/gmail/v1/rest"))
                .respond_with(ResponseTemplate::new(200).set_body_string(GMAIL_FIXTURE))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/$discovery/rest"))
                .and(query_param("api", "gmail"))
                .and(query_param("version", "v1"))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;

            let fetcher = DiscoveryFetcher::new()
                .with_client(mock_http_client())
                .with_standard_base(standard_base.clone())
                .with_alternate_template(alternate_template);
            let snapshot = fetcher
                .fetch_snapshot(&service)
                .await
                .expect("fetch snapshot");

            assert_eq!(snapshot.endpoint, DiscoveryEndpointKind::Standard);
            assert_eq!(
                snapshot.source_url,
                format!("{standard_base}/gmail/v1/rest")
            );
            assert_eq!(
                snapshot.source_digest,
                blake3::hash(GMAIL_FIXTURE.as_bytes()).to_hex().to_string()
            );
            assert!(
                snapshot
                    .snapshot
                    .methods
                    .contains_key("users.messages.list")
            );
        });
    }

    #[test]
    fn fetch_snapshot_falls_back_to_alternate_endpoint() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            let service = DiscoveryServiceId::new("gmail", "v1").expect("valid");
            let standard_base = format!("{}/discovery/v1/apis", server.uri());
            let alternate_template = format!(
                "{}/$discovery/rest?api={{api_name}}&version={{api_version}}",
                server.uri()
            );
            let expected_alternate =
                format!("{}/$discovery/rest?api=gmail&version=v1", server.uri());

            Mock::given(method("GET"))
                .and(path("/discovery/v1/apis/gmail/v1/rest"))
                .respond_with(ResponseTemplate::new(404))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/$discovery/rest"))
                .and(query_param("api", "gmail"))
                .and(query_param("version", "v1"))
                .respond_with(ResponseTemplate::new(200).set_body_string(GMAIL_FIXTURE))
                .expect(1)
                .mount(&server)
                .await;

            let fetcher = DiscoveryFetcher::new()
                .with_client(mock_http_client())
                .with_standard_base(standard_base)
                .with_alternate_template(alternate_template);
            let snapshot = fetcher
                .fetch_snapshot(&service)
                .await
                .expect("fetch snapshot");

            assert_eq!(snapshot.endpoint, DiscoveryEndpointKind::Alternate);
            assert_eq!(snapshot.source_url, expected_alternate);
            assert_eq!(snapshot.snapshot.service.identity(), "gmail:v1");
        });
    }

    #[test]
    fn fetch_snapshot_returns_both_endpoint_errors_when_all_fail() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            let service = DiscoveryServiceId::new("gmail", "v1").expect("valid");
            let standard_base = format!("{}/discovery/v1/apis", server.uri());
            let alternate_template = format!(
                "{}/$discovery/rest?api={{api_name}}&version={{api_version}}",
                server.uri()
            );

            Mock::given(method("GET"))
                .and(path("/discovery/v1/apis/gmail/v1/rest"))
                .respond_with(ResponseTemplate::new(502))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/$discovery/rest"))
                .and(query_param("api", "gmail"))
                .and(query_param("version", "v1"))
                .respond_with(ResponseTemplate::new(503))
                .expect(1)
                .mount(&server)
                .await;

            let fetcher = DiscoveryFetcher::new()
                .with_client(mock_http_client())
                .with_standard_base(standard_base)
                .with_alternate_template(alternate_template);
            let err = fetcher
                .fetch_snapshot(&service)
                .await
                .expect_err("expected both endpoints to fail");

            match err {
                DiscoveryError::AllEndpointsFailed {
                    service,
                    standard,
                    alternate,
                } => {
                    assert_eq!(service, "gmail:v1");
                    assert!(
                        standard.contains("502"),
                        "expected standard endpoint status in error, got: {standard}"
                    );
                    assert!(
                        alternate.contains("503"),
                        "expected alternate endpoint status in error, got: {alternate}"
                    );
                }
                other => panic!("expected AllEndpointsFailed, got {other}"),
            }
        });
    }

    #[test]
    fn fetch_snapshot_rejects_untrusted_remote_standard_base() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            let service = DiscoveryServiceId::new("gmail", "v1").expect("valid");
            let alternate_template = format!(
                "{}/$discovery/rest?api={{api_name}}&version={{api_version}}",
                server.uri()
            );
            let fetcher = DiscoveryFetcher::new()
                .with_client(mock_http_client())
                .with_standard_base("https://evil.example.com/discovery/v1/apis")
                .with_alternate_template(alternate_template);

            let err = fetcher
                .fetch_snapshot(&service)
                .await
                .expect_err("untrusted remote base should be rejected");
            let msg = err.to_string();
            assert!(
                msg.contains("untrusted discovery endpoint"),
                "error should mention trust rejection: {msg}"
            );
            assert!(
                msg.contains("evil.example.com"),
                "error should include the rejected host: {msg}"
            );
        });
    }

    #[test]
    fn fetch_snapshot_rejects_untrusted_remote_alternate_template() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            let service = DiscoveryServiceId::new("gmail", "v1").expect("valid");
            let standard_base = format!("{}/discovery/v1/apis", server.uri());
            let fetcher = DiscoveryFetcher::new()
                .with_client(mock_http_client())
                .with_standard_base(standard_base)
                .with_alternate_template(
                    "https://evil.example.com/$discovery/rest?api={api_name}&version={api_version}",
                );

            let err = fetcher
                .fetch_snapshot(&service)
                .await
                .expect_err("untrusted alternate template should be rejected");
            let msg = err.to_string();
            assert!(
                msg.contains("untrusted discovery endpoint"),
                "error should mention trust rejection: {msg}"
            );
            assert!(
                msg.contains("evil.example.com"),
                "error should include the rejected host: {msg}"
            );
        });
    }

    // ── normalize_snapshot_bytes tests ───────────────────────────────────

    #[test]
    fn normalize_empty_document() {
        let service = DiscoveryServiceId::new("empty", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            b"{}",
            DiscoveryEndpointKind::Standard,
            "https://example.test/empty",
        )
        .expect("normalize empty doc");
        assert_eq!(result.snapshot.service.identity(), "empty:v1");
        assert!(result.snapshot.methods.is_empty());
        assert!(result.snapshot.schemas.is_empty());
        assert!(result.snapshot.auth_scopes.is_empty());
    }

    #[test]
    fn normalize_preserves_media_upload_metadata() {
        let doc = r#"{
            "resources": {
                "files": {
                    "methods": {
                        "create": {
                            "id": "drive.files.create",
                            "path": "files",
                            "httpMethod": "POST",
                            "supportsMediaUpload": true,
                            "mediaUpload": {
                                "accept": ["image/png", "application/pdf"],
                                "maxSize": "5GB",
                                "protocols": {
                                    "simple": {"path": "/upload/simple"},
                                    "resumable": {"path": "/upload/resumable"}
                                }
                            }
                        }
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("drive", "v3").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test/drive",
        )
        .expect("normalize media upload doc");

        let method = result
            .snapshot
            .methods
            .get("files.create")
            .expect("method exists");
        assert!(method.supports_media_upload);
        let upload = method.media_upload.as_ref().expect("media_upload present");
        assert_eq!(upload.accept, vec!["application/pdf", "image/png"]);
        assert_eq!(upload.max_size.as_deref(), Some("5GB"));
        assert_eq!(upload.simple_path.as_deref(), Some("/upload/simple"));
        assert_eq!(upload.resumable_path.as_deref(), Some("/upload/resumable"));
    }

    #[test]
    fn normalize_deduplicates_and_sorts_scopes() {
        let doc = r#"{
            "auth": {
                "oauth2": {
                    "scopes": {
                        "https://z-scope.example.com": {"description": "Z scope"},
                        "https://a-scope.example.com": {"description": "A scope"},
                        "https://m-scope.example.com": {"description": "M scope"}
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize scopes doc");

        let scope_ids: Vec<&str> = result
            .snapshot
            .auth_scopes
            .iter()
            .map(|s| s.id.as_str())
            .collect();
        assert_eq!(
            scope_ids,
            vec![
                "https://a-scope.example.com",
                "https://m-scope.example.com",
                "https://z-scope.example.com",
            ]
        );
    }

    #[test]
    fn normalize_handles_missing_flat_path() {
        let doc = r#"{
            "resources": {
                "items": {
                    "methods": {
                        "get": {
                            "id": "test.items.get",
                            "path": "items/{itemId}",
                            "httpMethod": "GET"
                        }
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize missing flat_path doc");

        let method = result
            .snapshot
            .methods
            .get("items.get")
            .expect("method exists");
        assert!(method.flat_path.is_none());
        assert_eq!(
            method.canonical_path, "items/{itemId}",
            "canonical_path should fall back to path"
        );
    }

    #[test]
    fn normalize_schema_depth_limit() {
        // Build a deeply nested schema that exceeds MAX_SCHEMA_DEPTH (64).
        // Use `items` nesting (arrays) which adds only 1 JSON nesting level per
        // schema level, staying under serde_json's recursion limit while
        // exceeding our own MAX_SCHEMA_DEPTH of 64.
        let mut inner = r#"{"type": "string"}"#.to_string();
        for _ in 0..66 {
            inner = format!(r#"{{"type": "array", "items": {inner}}}"#);
        }
        let doc = format!(r#"{{"schemas": {{"Deep": {inner}}}}}"#);

        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let err = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test/deep",
        )
        .unwrap_err();
        assert!(
            matches!(err, DiscoveryError::SchemaDepthExceeded { .. }),
            "expected SchemaDepthExceeded, got: {err}"
        );
    }

    // ── snapshot_storage_key tests ──────────────────────────────────────

    #[test]
    fn storage_key_trims_components() {
        let service = DiscoveryServiceId::new("gmail", "v1").expect("valid");
        let key = snapshot_storage_key(&service, "  abc123  ");
        assert_eq!(key, "google-discovery/gmail/v1/abc123");
    }

    // ── DiscoveryError tests ────────────────────────────────────────────

    #[test]
    fn discovery_error_display_all_variants() {
        let invalid_comp = DiscoveryError::InvalidComponent {
            field: "api_name",
            value: "bad!".to_string(),
        };
        assert!(invalid_comp.to_string().contains("api_name"));
        assert!(invalid_comp.to_string().contains("bad!"));

        let invalid_sel = DiscoveryError::InvalidServiceSelector {
            selector: "noseparator".to_string(),
        };
        assert!(invalid_sel.to_string().contains("noseparator"));

        let unknown_alias = DiscoveryError::UnknownServiceAlias {
            alias: "foo".to_string(),
        };
        assert!(unknown_alias.to_string().contains("foo"));

        let http_status = DiscoveryError::HttpStatus {
            url: "https://example.com".to_string(),
            status: StatusCode::NOT_FOUND,
        };
        let status_msg = http_status.to_string();
        assert!(status_msg.contains("example.com"));
        assert!(status_msg.contains("404"));

        let all_failed = DiscoveryError::AllEndpointsFailed {
            service: "gmail:v1".to_string(),
            standard: "timeout".to_string(),
            alternate: "refused".to_string(),
        };
        let all_msg = all_failed.to_string();
        assert!(all_msg.contains("gmail:v1"));
        assert!(all_msg.contains("timeout"));
        assert!(all_msg.contains("refused"));

        let depth = DiscoveryError::SchemaDepthExceeded { max_depth: 64 };
        assert!(depth.to_string().contains("64"));
    }

    // ── DiscoveryEndpointKind tests ─────────────────────────────────────

    #[test]
    fn endpoint_kind_serde_roundtrip() {
        let standard = DiscoveryEndpointKind::Standard;
        let alternate = DiscoveryEndpointKind::Alternate;

        let json_std = serde_json::to_string(&standard).expect("serialize standard");
        let json_alt = serde_json::to_string(&alternate).expect("serialize alternate");

        let deser_std: DiscoveryEndpointKind =
            serde_json::from_str(&json_std).expect("deserialize standard");
        let deser_alt: DiscoveryEndpointKind =
            serde_json::from_str(&json_alt).expect("deserialize alternate");

        assert_eq!(standard, deser_std);
        assert_eq!(alternate, deser_alt);
        assert_ne!(json_std, json_alt);
    }

    // ── DiscoverySnapshot tests ─────────────────────────────────────────

    #[test]
    fn snapshot_serde_roundtrip() {
        let service = DiscoveryServiceId::new("gmail", "v1").expect("valid id");
        let fetched = normalize_snapshot_bytes(
            &service,
            GMAIL_FIXTURE.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");

        let json = serde_json::to_string(&fetched.snapshot).expect("serialize snapshot");
        let deserialized: DiscoverySnapshot =
            serde_json::from_str(&json).expect("deserialize snapshot");
        assert_eq!(fetched.snapshot, deserialized);
        assert_eq!(deserialized.service.identity(), "gmail:v1");
        assert_eq!(deserialized.auth_scopes.len(), 2);
        assert!(deserialized.methods.contains_key("users.messages.list"));
    }

    // ── Schema normalization edge cases ─────────────────────────────────

    #[test]
    fn normalize_schema_required_dedup_and_sort() {
        let doc = r#"{
            "schemas": {
                "Foo": {
                    "type": "object",
                    "required": ["zebra", "alpha", "alpha", "middle", "zebra"],
                    "properties": {
                        "alpha": {"type": "string"},
                        "middle": {"type": "string"},
                        "zebra": {"type": "string"}
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        let schema = result.snapshot.schemas.get("Foo").expect("schema exists");
        assert_eq!(schema.required, vec!["alpha", "middle", "zebra"]);
    }

    #[test]
    fn normalize_schema_enum_values_dedup_and_sort() {
        let doc = r#"{
            "schemas": {
                "Status": {
                    "type": "string",
                    "enum": ["DONE", "ACTIVE", "DONE", "PENDING", "ACTIVE"]
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        let schema = result
            .snapshot
            .schemas
            .get("Status")
            .expect("schema exists");
        assert_eq!(schema.enum_values, vec!["ACTIVE", "DONE", "PENDING"]);
    }

    #[test]
    fn normalize_schema_additional_properties() {
        let doc = r#"{
            "schemas": {
                "Labels": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "string",
                        "description": "label value"
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        let schema = result
            .snapshot
            .schemas
            .get("Labels")
            .expect("schema exists");
        let ap = schema
            .additional_properties
            .as_ref()
            .expect("additional_properties present");
        assert_eq!(ap.type_name.as_deref(), Some("string"));
        assert_eq!(ap.description.as_deref(), Some("label value"));
    }

    #[test]
    fn normalize_schema_ref_nodes() {
        let doc = r#"{
            "schemas": {
                "Wrapper": {
                    "type": "object",
                    "properties": {
                        "child": {"$ref": "Inner"}
                    }
                },
                "Inner": {
                    "type": "object",
                    "properties": {
                        "value": {"type": "string"}
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        let wrapper = result.snapshot.schemas.get("Wrapper").expect("Wrapper");
        let child_prop = wrapper.properties.get("child").expect("child prop");
        assert_eq!(child_prop.ref_name.as_deref(), Some("Inner"));
    }

    #[test]
    fn normalize_schema_items_array() {
        let doc = r#"{
            "schemas": {
                "TagList": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "format": "byte"
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        let schema = result.snapshot.schemas.get("TagList").expect("TagList");
        assert_eq!(schema.type_name.as_deref(), Some("array"));
        let items = schema.items.as_ref().expect("items present");
        assert_eq!(items.type_name.as_deref(), Some("string"));
        assert_eq!(items.format.as_deref(), Some("byte"));
    }

    #[test]
    fn normalize_schema_nested_object_properties() {
        let doc = r#"{
            "schemas": {
                "Outer": {
                    "type": "object",
                    "properties": {
                        "nested": {
                            "type": "object",
                            "properties": {
                                "deep": {"type": "integer", "format": "int32"}
                            }
                        }
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        let outer = result.snapshot.schemas.get("Outer").expect("Outer");
        let nested = outer.properties.get("nested").expect("nested prop");
        assert_eq!(nested.type_name.as_deref(), Some("object"));
        let deep = nested.properties.get("deep").expect("deep prop");
        assert_eq!(deep.type_name.as_deref(), Some("integer"));
        assert_eq!(deep.format.as_deref(), Some("int32"));
    }

    #[test]
    fn normalize_schema_required_filters_whitespace_only() {
        let doc = r#"{
            "schemas": {
                "Foo": {
                    "type": "object",
                    "required": ["name", "  ", "", "email"],
                    "properties": {}
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        let schema = result.snapshot.schemas.get("Foo").expect("Foo");
        assert_eq!(schema.required, vec!["email", "name"]);
    }

    #[test]
    fn normalize_schema_enum_filters_whitespace_only() {
        let doc = r#"{
            "schemas": {
                "Color": {
                    "type": "string",
                    "enum": ["RED", "  ", "", "BLUE"]
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        let schema = result.snapshot.schemas.get("Color").expect("Color");
        assert_eq!(schema.enum_values, vec!["BLUE", "RED"]);
    }

    #[test]
    fn normalize_schema_depth_just_under_limit() {
        // Build nesting just under MAX_SCHEMA_DEPTH (64).
        // normalize_schema_map starts at depth 0, first schema at depth 1,
        // each items level adds 1. Properties check also adds 1 to depth,
        // so we need to stay well below the limit.
        let mut inner = r#"{"type": "string"}"#.to_string();
        for _ in 0..60 {
            inner = format!(r#"{{"type": "array", "items": {inner}}}"#);
        }
        let doc = format!(r#"{{"schemas": {{"NearLimit": {inner}}}}}"#);
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        );
        assert!(result.is_ok(), "depth under limit should succeed");
    }

    // ── Parameter extraction tests ──────────────────────────────────────

    #[test]
    fn normalize_method_parameters_path_and_query() {
        let doc = r#"{
            "resources": {
                "items": {
                    "methods": {
                        "get": {
                            "id": "test.items.get",
                            "path": "items/{itemId}",
                            "httpMethod": "GET",
                            "parameters": {
                                "itemId": {
                                    "type": "string",
                                    "location": "path",
                                    "required": true,
                                    "description": "Item identifier"
                                },
                                "fields": {
                                    "type": "string",
                                    "location": "query",
                                    "required": false,
                                    "description": "Field mask"
                                },
                                "tags": {
                                    "type": "string",
                                    "location": "query",
                                    "repeated": true
                                }
                            }
                        }
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        let method = result
            .snapshot
            .methods
            .get("items.get")
            .expect("method exists");
        assert_eq!(method.parameters.len(), 3);

        let item_id = method.parameters.get("itemId").expect("itemId param");
        assert_eq!(item_id.location.as_deref(), Some("path"));
        assert!(item_id.required);
        assert!(!item_id.repeated);
        assert_eq!(item_id.type_name.as_deref(), Some("string"));
        assert_eq!(item_id.description.as_deref(), Some("Item identifier"));

        let fields = method.parameters.get("fields").expect("fields param");
        assert_eq!(fields.location.as_deref(), Some("query"));
        assert!(!fields.required);
        assert!(!fields.repeated);

        let tags = method.parameters.get("tags").expect("tags param");
        assert!(tags.repeated);
    }

    #[test]
    fn normalize_method_request_and_response_refs() {
        let doc = r#"{
            "resources": {
                "items": {
                    "methods": {
                        "create": {
                            "id": "test.items.create",
                            "path": "items",
                            "httpMethod": "POST",
                            "request": {"$ref": "Item"},
                            "response": {"$ref": "Item"}
                        }
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        let method = result
            .snapshot
            .methods
            .get("items.create")
            .expect("method exists");
        assert_eq!(method.request_ref.as_deref(), Some("Item"));
        assert_eq!(method.response_ref.as_deref(), Some("Item"));
    }

    // ── Method scopes extraction ────────────────────────────────────────

    #[test]
    fn normalize_method_scopes_sorted_and_deduped() {
        let doc = r#"{
            "resources": {
                "items": {
                    "methods": {
                        "list": {
                            "id": "test.items.list",
                            "path": "items",
                            "httpMethod": "GET",
                            "scopes": [
                                "https://z.example.com/scope",
                                "https://a.example.com/scope",
                                "https://z.example.com/scope",
                                "https://m.example.com/scope"
                            ]
                        }
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        let method = result
            .snapshot
            .methods
            .get("items.list")
            .expect("method exists");
        assert_eq!(
            method.scopes,
            vec![
                "https://a.example.com/scope",
                "https://m.example.com/scope",
                "https://z.example.com/scope",
            ]
        );
    }

    #[test]
    fn normalize_method_defaults_http_method_to_get() {
        let doc = r#"{
            "resources": {
                "items": {
                    "methods": {
                        "list": {
                            "id": "test.items.list",
                            "path": "items"
                        }
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        let method = result
            .snapshot
            .methods
            .get("items.list")
            .expect("method exists");
        assert_eq!(method.http_method, "GET");
    }

    #[test]
    fn normalize_method_uppercases_http_method() {
        let doc = r#"{
            "resources": {
                "items": {
                    "methods": {
                        "create": {
                            "id": "test.items.create",
                            "path": "items",
                            "httpMethod": "post"
                        }
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        let method = result
            .snapshot
            .methods
            .get("items.create")
            .expect("method exists");
        assert_eq!(method.http_method, "POST");
    }

    #[test]
    fn normalize_method_generates_id_from_service_when_missing() {
        let doc = r#"{
            "resources": {
                "items": {
                    "methods": {
                        "list": {
                            "path": "items",
                            "httpMethod": "GET"
                        }
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        let method = result
            .snapshot
            .methods
            .get("items.list")
            .expect("method exists");
        assert_eq!(method.id, "test.items.list");
    }

    // ── Resource hierarchy ──────────────────────────────────────────────

    #[test]
    fn normalize_deeply_nested_resources() {
        let doc = r#"{
            "resources": {
                "projects": {
                    "resources": {
                        "datasets": {
                            "resources": {
                                "tables": {
                                    "methods": {
                                        "get": {
                                            "id": "bq.projects.datasets.tables.get",
                                            "path": "projects/{projectId}/datasets/{datasetId}/tables/{tableId}",
                                            "httpMethod": "GET"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("bq", "v2").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");

        let method = result
            .snapshot
            .methods
            .get("projects.datasets.tables.get")
            .expect("deep method");
        assert_eq!(method.resource_path, vec!["projects", "datasets", "tables"]);
        assert_eq!(method.id, "bq.projects.datasets.tables.get");

        // Verify the hierarchy in resources
        let projects = result
            .snapshot
            .resources
            .get("projects")
            .expect("projects resource");
        let datasets = projects
            .resources
            .get("datasets")
            .expect("datasets resource");
        let tables = datasets.resources.get("tables").expect("tables resource");
        assert!(tables.methods.contains_key("projects.datasets.tables.get"));
    }

    #[test]
    fn normalize_resource_with_local_and_nested_methods() {
        let doc = r#"{
            "resources": {
                "users": {
                    "methods": {
                        "getProfile": {
                            "id": "test.users.getProfile",
                            "path": "users/{userId}/profile",
                            "httpMethod": "GET"
                        }
                    },
                    "resources": {
                        "messages": {
                            "methods": {
                                "list": {
                                    "id": "test.users.messages.list",
                                    "path": "users/{userId}/messages",
                                    "httpMethod": "GET"
                                }
                            }
                        }
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        assert!(result.snapshot.methods.contains_key("users.getProfile"));
        assert!(result.snapshot.methods.contains_key("users.messages.list"));
        let profile = result
            .snapshot
            .methods
            .get("users.getProfile")
            .expect("getProfile");
        assert_eq!(profile.resource_path, vec!["users"]);
        let list = result
            .snapshot
            .methods
            .get("users.messages.list")
            .expect("list");
        assert_eq!(list.resource_path, vec!["users", "messages"]);
    }

    // ── ServiceAliasRegistry insert overwrite ───────────────────────────

    #[test]
    fn alias_registry_insert_overwrites_existing() {
        let mut registry = ServiceAliasRegistry::default();
        let gmail_before = registry.resolve("gmail").expect("resolve gmail");
        assert_eq!(gmail_before.api_name, "gmail");

        let custom = DiscoveryServiceId::new("custom-gmail", "v2").expect("valid");
        registry.insert("gmail", custom.clone()).expect("overwrite");
        let gmail_after = registry.resolve("gmail").expect("resolve gmail");
        assert_eq!(gmail_after, custom);
    }

    #[test]
    fn alias_registry_serde_roundtrip() {
        let registry = ServiceAliasRegistry::default();
        let json = serde_json::to_string(&registry).expect("serialize");
        let deserialized: ServiceAliasRegistry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.aliases().len(), registry.aliases().len());
        for (key, val) in registry.aliases() {
            let deser_val = deserialized.aliases().get(key).expect("key present");
            assert_eq!(val, deser_val);
        }
    }

    #[test]
    fn alias_registry_resolve_trims_whitespace() {
        let registry = ServiceAliasRegistry::default();
        let resolved = registry.resolve("  gmail  ").expect("resolve trimmed");
        assert_eq!(resolved.api_name, "gmail");
    }

    // ── normalize_optional edge cases ───────────────────────────────────

    #[test]
    fn normalize_optional_whitespace_only_becomes_none() {
        assert!(normalize_optional(Some("   ".to_string())).is_none());
        assert!(normalize_optional(Some(String::new())).is_none());
        assert!(normalize_optional(None).is_none());
    }

    #[test]
    fn normalize_optional_trims_whitespace() {
        assert_eq!(
            normalize_optional(Some("  hello  ".to_string())),
            Some("hello".to_string())
        );
    }

    // ── snapshot_storage_key edge cases ──────────────────────────────────

    #[test]
    fn storage_key_different_digests_produce_different_keys() {
        let service = DiscoveryServiceId::new("gmail", "v1").expect("valid");
        let key_a = snapshot_storage_key(&service, "digest_aaa");
        let key_b = snapshot_storage_key(&service, "digest_bbb");
        assert_ne!(key_a, key_b);
        assert!(key_a.ends_with("digest_aaa"));
        assert!(key_b.ends_with("digest_bbb"));
    }

    #[test]
    fn storage_key_different_services_produce_different_keys() {
        let gmail = DiscoveryServiceId::new("gmail", "v1").expect("valid");
        let drive = DiscoveryServiceId::new("drive", "v3").expect("valid");
        let key_a = snapshot_storage_key(&gmail, "same_digest");
        let key_b = snapshot_storage_key(&drive, "same_digest");
        assert_ne!(key_a, key_b);
        assert!(key_a.contains("gmail/v1"));
        assert!(key_b.contains("drive/v3"));
    }

    // ── normalize_component edge cases ──────────────────────────────────

    #[test]
    fn normalize_component_allows_dots_dashes_underscores() {
        let result = normalize_component("test", "my-api_v1.beta");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "my-api_v1.beta");
    }

    #[test]
    fn normalize_component_rejects_whitespace_only() {
        let err = normalize_component("test", "   ").unwrap_err();
        assert!(matches!(err, DiscoveryError::InvalidComponent { .. }));
    }

    #[test]
    fn normalize_component_rejects_uppercase_special_chars() {
        // Uppercase is lowered, but special chars like ! are rejected
        let err = normalize_component("test", "Hello!").unwrap_err();
        assert!(matches!(err, DiscoveryError::InvalidComponent { .. }));
    }

    #[test]
    fn normalize_component_lowercases_and_trims() {
        let result = normalize_component("test", "  MyApi  ").expect("valid");
        assert_eq!(result, "myapi");
    }

    // ── FetchedDiscoverySnapshot source_digest ──────────────────────────

    #[test]
    fn normalize_snapshot_bytes_computes_blake3_digest() {
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let input = b"{}";
        let result = normalize_snapshot_bytes(
            &service,
            input,
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        let expected_digest = blake3::hash(input).to_hex().to_string();
        assert_eq!(result.source_digest, expected_digest);
    }

    #[test]
    fn normalize_snapshot_bytes_invalid_json() {
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let err = normalize_snapshot_bytes(
            &service,
            b"not json at all {{{",
            DiscoveryEndpointKind::Standard,
            "https://example.test/bad",
        )
        .unwrap_err();
        match err {
            DiscoveryError::JsonDecode { url, .. } => {
                assert_eq!(url, "https://example.test/bad");
            }
            other => panic!("expected JsonDecode, got {other}"),
        }
    }

    // ── Media upload edge cases ─────────────────────────────────────────

    #[test]
    fn normalize_media_upload_no_protocols() {
        let doc = r#"{
            "resources": {
                "files": {
                    "methods": {
                        "create": {
                            "id": "test.files.create",
                            "path": "files",
                            "httpMethod": "POST",
                            "supportsMediaUpload": true,
                            "mediaUpload": {
                                "accept": ["*/*"],
                                "maxSize": "100MB"
                            }
                        }
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        let method = result
            .snapshot
            .methods
            .get("files.create")
            .expect("method exists");
        assert!(method.supports_media_upload);
        let upload = method.media_upload.as_ref().expect("upload present");
        assert_eq!(upload.accept, vec!["*/*"]);
        assert_eq!(upload.max_size.as_deref(), Some("100MB"));
        assert!(upload.simple_path.is_none());
        assert!(upload.resumable_path.is_none());
    }

    #[test]
    fn normalize_media_upload_accept_sorted() {
        let doc = r#"{
            "resources": {
                "files": {
                    "methods": {
                        "upload": {
                            "id": "test.files.upload",
                            "path": "files",
                            "httpMethod": "POST",
                            "mediaUpload": {
                                "accept": ["video/mp4", "application/json", "image/png"]
                            }
                        }
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        let method = result
            .snapshot
            .methods
            .get("files.upload")
            .expect("method exists");
        let upload = method.media_upload.as_ref().expect("upload present");
        assert_eq!(
            upload.accept,
            vec!["application/json", "image/png", "video/mp4"]
        );
    }

    #[test]
    fn normalize_supports_media_download_flag() {
        let doc = r#"{
            "resources": {
                "files": {
                    "methods": {
                        "get": {
                            "id": "test.files.get",
                            "path": "files/{fileId}",
                            "httpMethod": "GET",
                            "supportsMediaDownload": true
                        }
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        let method = result
            .snapshot
            .methods
            .get("files.get")
            .expect("method exists");
        assert!(method.supports_media_download);
        assert!(!method.supports_media_upload);
    }

    // ── Snapshot metadata fields ────────────────────────────────────────

    #[test]
    fn normalize_preserves_all_metadata_fields() {
        let doc = r#"{
            "name": "testapi",
            "title": "Test API",
            "description": "A test API",
            "revision": "20260307",
            "rootUrl": "https://testapi.googleapis.com/",
            "servicePath": "testapi/v1/",
            "baseUrl": "https://testapi.googleapis.com/testapi/v1/",
            "batchPath": "batch/testapi"
        }"#;
        let service = DiscoveryServiceId::new("testapi", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Alternate,
            "https://example.test",
        )
        .expect("normalize");
        let snap = &result.snapshot;
        assert_eq!(snap.name.as_deref(), Some("testapi"));
        assert_eq!(snap.title.as_deref(), Some("Test API"));
        assert_eq!(snap.description.as_deref(), Some("A test API"));
        assert_eq!(snap.revision.as_deref(), Some("20260307"));
        assert_eq!(
            snap.root_url.as_deref(),
            Some("https://testapi.googleapis.com/")
        );
        assert_eq!(snap.service_path.as_deref(), Some("testapi/v1/"));
        assert_eq!(
            snap.base_url.as_deref(),
            Some("https://testapi.googleapis.com/testapi/v1/")
        );
        assert_eq!(snap.batch_path.as_deref(), Some("batch/testapi"));
        assert_eq!(result.endpoint, DiscoveryEndpointKind::Alternate);
    }

    #[test]
    fn normalize_whitespace_only_metadata_becomes_none() {
        let doc = r#"{
            "name": "  ",
            "title": "",
            "description": "   \t  ",
            "revision": "valid"
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        let snap = &result.snapshot;
        assert!(snap.name.is_none());
        assert!(snap.title.is_none());
        assert!(snap.description.is_none());
        assert_eq!(snap.revision.as_deref(), Some("valid"));
    }

    #[test]
    fn normalize_rejects_mismatched_document_name() {
        let doc = r#"{
            "name": "drive",
            "version": "v1",
            "title": "Drive API"
        }"#;
        let service = DiscoveryServiceId::new("gmail", "v1").expect("valid");
        let err = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect_err("mismatched discovery name should fail");

        assert!(
            matches!(
                err,
                DiscoveryError::SnapshotIdentityMismatch { field: "name", .. }
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn normalize_rejects_mismatched_document_version() {
        let doc = r#"{
            "name": "gmail",
            "version": "v2",
            "title": "Gmail API"
        }"#;
        let service = DiscoveryServiceId::new("gmail", "v1").expect("valid");
        let err = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect_err("mismatched discovery version should fail");

        assert!(
            matches!(
                err,
                DiscoveryError::SnapshotIdentityMismatch {
                    field: "version",
                    ..
                }
            ),
            "unexpected error: {err}"
        );
    }

    // ── Top-level methods alongside resources ───────────────────────────

    #[test]
    fn normalize_top_level_and_resource_methods_coexist() {
        let doc = r#"{
            "methods": {
                "globalOp": {
                    "id": "test.globalOp",
                    "path": "globalOp",
                    "httpMethod": "POST"
                }
            },
            "resources": {
                "items": {
                    "methods": {
                        "list": {
                            "id": "test.items.list",
                            "path": "items",
                            "httpMethod": "GET"
                        }
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        assert!(result.snapshot.methods.contains_key("globalOp"));
        assert!(result.snapshot.methods.contains_key("items.list"));
        let global = result.snapshot.methods.get("globalOp").expect("globalOp");
        assert!(global.resource_path.is_empty());
    }

    // ── DiscoveryFetcher fetch_snapshot with malformed JSON ──────────────

    #[test]
    fn fetch_snapshot_malformed_json_response() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            let service = DiscoveryServiceId::new("test", "v1").expect("valid");
            let standard_base = format!("{}/discovery/v1/apis", server.uri());
            let alternate_template = format!(
                "{}/$discovery/rest?api={{api_name}}&version={{api_version}}",
                server.uri()
            );

            // Both return 200 but with invalid JSON
            Mock::given(method("GET"))
                .and(path("/discovery/v1/apis/test/v1/rest"))
                .respond_with(ResponseTemplate::new(200).set_body_string("not valid json"))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/$discovery/rest"))
                .respond_with(ResponseTemplate::new(200).set_body_string("{broken"))
                .mount(&server)
                .await;

            let fetcher = DiscoveryFetcher::new()
                .with_client(mock_http_client())
                .with_standard_base(standard_base)
                .with_alternate_template(alternate_template);
            let err = fetcher
                .fetch_snapshot(&service)
                .await
                .expect_err("expected failure");

            assert!(
                matches!(err, DiscoveryError::AllEndpointsFailed { .. }),
                "expected AllEndpointsFailed, got: {err}"
            );
        });
    }

    #[test]
    fn fetch_snapshot_empty_json_body() {
        run_with_test_runtime(async {
            let server = MockServer::start().await;
            let service = DiscoveryServiceId::new("test", "v1").expect("valid");
            let standard_base = format!("{}/discovery/v1/apis", server.uri());
            let alternate_template = format!(
                "{}/$discovery/rest?api={{api_name}}&version={{api_version}}",
                server.uri()
            );

            // Standard returns valid empty JSON, alternate shouldn't be called
            Mock::given(method("GET"))
                .and(path("/discovery/v1/apis/test/v1/rest"))
                .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
                .expect(1)
                .mount(&server)
                .await;

            let fetcher = DiscoveryFetcher::new()
                .with_client(mock_http_client())
                .with_standard_base(standard_base)
                .with_alternate_template(alternate_template);
            let result = fetcher
                .fetch_snapshot(&service)
                .await
                .expect("empty JSON should succeed");

            assert_eq!(result.snapshot.service.identity(), "test:v1");
            assert!(result.snapshot.methods.is_empty());
            assert!(result.snapshot.schemas.is_empty());
            assert_eq!(result.endpoint, DiscoveryEndpointKind::Standard);
        });
    }

    // ── DiscoveryServiceId edge cases ───────────────────────────────────

    #[test]
    fn service_id_with_dots_and_dashes() {
        let id = DiscoveryServiceId::new("my-api.beta", "v1.1-beta").expect("valid");
        assert_eq!(id.api_name, "my-api.beta");
        assert_eq!(id.api_version, "v1.1-beta");
        assert_eq!(id.identity(), "my-api.beta:v1.1-beta");
    }

    #[test]
    fn service_id_parse_explicit_with_multiple_colons_takes_first() {
        // split_once takes first colon, rest goes to version
        let err = DiscoveryServiceId::parse_explicit("a:b:c");
        // "b:c" contains special char ':', which should fail validation
        assert!(err.is_err());
    }

    #[test]
    fn service_id_clone_and_eq() {
        let id1 = DiscoveryServiceId::new("gmail", "v1").expect("valid");
        let id2 = id1.clone();
        assert_eq!(id1, id2);
        assert_eq!(id1.identity(), id2.identity());
    }

    // ── DiscoveryMethod flatPath vs path ────────────────────────────────

    #[test]
    fn normalize_method_flat_path_takes_precedence() {
        let doc = r#"{
            "resources": {
                "items": {
                    "methods": {
                        "get": {
                            "id": "test.items.get",
                            "path": "{+name}",
                            "flatPath": "v1/items/{itemId}",
                            "httpMethod": "GET"
                        }
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        let method = result
            .snapshot
            .methods
            .get("items.get")
            .expect("method exists");
        assert_eq!(method.path, "{+name}");
        assert_eq!(method.flat_path.as_deref(), Some("v1/items/{itemId}"));
        assert_eq!(
            method.canonical_path, "v1/items/{itemId}",
            "canonical_path should use flatPath when available"
        );
    }

    // ── Scope description preservation ──────────────────────────────────

    #[test]
    fn normalize_scope_descriptions_preserved() {
        let doc = r#"{
            "auth": {
                "oauth2": {
                    "scopes": {
                        "https://example.com/scope.read": {"description": "Read access"},
                        "https://example.com/scope.write": {}
                    }
                }
            }
        }"#;
        let service = DiscoveryServiceId::new("test", "v1").expect("valid");
        let result = normalize_snapshot_bytes(
            &service,
            doc.as_bytes(),
            DiscoveryEndpointKind::Standard,
            "https://example.test",
        )
        .expect("normalize");
        assert_eq!(result.snapshot.auth_scopes.len(), 2);
        let read_scope = result
            .snapshot
            .auth_scopes
            .iter()
            .find(|s| s.id.contains("read"))
            .expect("read scope");
        assert_eq!(read_scope.description.as_deref(), Some("Read access"));
        let write_scope = result
            .snapshot
            .auth_scopes
            .iter()
            .find(|s| s.id.contains("write"))
            .expect("write scope");
        assert!(write_scope.description.is_none());
    }

    // ── method_key helper ───────────────────────────────────────────────

    #[test]
    fn method_key_with_empty_resource_path() {
        assert_eq!(method_key(&[], "list"), "list");
    }

    #[test]
    fn method_key_with_single_resource() {
        assert_eq!(method_key(&["users".to_string()], "get"), "users.get");
    }

    #[test]
    fn method_key_with_deep_resource_path() {
        assert_eq!(
            method_key(
                &[
                    "projects".to_string(),
                    "datasets".to_string(),
                    "tables".to_string()
                ],
                "list"
            ),
            "projects.datasets.tables.list"
        );
    }

    // ── trim_trailing_slash helper ──────────────────────────────────────

    #[test]
    fn trim_trailing_slash_removes_single() {
        assert_eq!(
            trim_trailing_slash("https://example.com/"),
            "https://example.com"
        );
    }

    #[test]
    fn trim_trailing_slash_removes_multiple() {
        assert_eq!(
            trim_trailing_slash("https://example.com///"),
            "https://example.com"
        );
    }

    #[test]
    fn trim_trailing_slash_no_slash() {
        assert_eq!(
            trim_trailing_slash("https://example.com"),
            "https://example.com"
        );
    }

    // ── is_allowed_component_char ───────────────────────────────────────

    #[test]
    fn allowed_component_chars() {
        assert!(is_allowed_component_char('a'));
        assert!(is_allowed_component_char('z'));
        assert!(is_allowed_component_char('0'));
        assert!(is_allowed_component_char('9'));
        assert!(is_allowed_component_char('-'));
        assert!(is_allowed_component_char('_'));
        assert!(is_allowed_component_char('.'));
        assert!(!is_allowed_component_char('A'));
        assert!(!is_allowed_component_char('!'));
        assert!(!is_allowed_component_char(' '));
        assert!(!is_allowed_component_char(':'));
        assert!(!is_allowed_component_char('/'));
    }

    // ── DiscoverySchema serde roundtrip ─────────────────────────────────

    #[test]
    fn schema_serde_roundtrip() {
        let schema = DiscoverySchema {
            type_name: Some("object".to_string()),
            format: None,
            description: Some("A test schema".to_string()),
            required: vec!["id".to_string(), "name".to_string()],
            enum_values: vec![],
            properties: {
                let mut m = BTreeMap::new();
                m.insert(
                    "id".to_string(),
                    DiscoverySchema {
                        type_name: Some("string".to_string()),
                        format: None,
                        description: None,
                        required: vec![],
                        enum_values: vec![],
                        properties: BTreeMap::new(),
                        items: None,
                        ref_name: None,
                        additional_properties: None,
                    },
                );
                m
            },
            items: None,
            ref_name: None,
            additional_properties: Some(Box::new(DiscoverySchema {
                type_name: Some("string".to_string()),
                format: None,
                description: None,
                required: vec![],
                enum_values: vec![],
                properties: BTreeMap::new(),
                items: None,
                ref_name: None,
                additional_properties: None,
            })),
        };
        let json = serde_json::to_string(&schema).expect("serialize");
        let deser: DiscoverySchema = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(schema, deser);
    }

    // ── DiscoveryMethod serde roundtrip ─────────────────────────────────

    #[test]
    fn method_serde_roundtrip() {
        let method = DiscoveryMethod {
            key: "users.list".to_string(),
            id: "test.users.list".to_string(),
            http_method: "GET".to_string(),
            path: "users".to_string(),
            flat_path: Some("v1/users".to_string()),
            canonical_path: "v1/users".to_string(),
            resource_path: vec!["users".to_string()],
            description: Some("List users".to_string()),
            scopes: vec!["https://example.com/scope".to_string()],
            request_ref: None,
            response_ref: Some("UserList".to_string()),
            parameters: BTreeMap::new(),
            supports_media_download: false,
            supports_media_upload: false,
            media_upload: None,
        };
        let json = serde_json::to_string(&method).expect("serialize");
        let deser: DiscoveryMethod = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(method, deser);
    }

    // ── FetchedDiscoverySnapshot serde roundtrip ────────────────────────

    #[test]
    fn fetched_snapshot_serde_roundtrip() {
        let service = DiscoveryServiceId::new("gmail", "v1").expect("valid");
        let fetched = normalize_snapshot_bytes(
            &service,
            GMAIL_FIXTURE.as_bytes(),
            DiscoveryEndpointKind::Alternate,
            "https://alt.example.test",
        )
        .expect("normalize");
        let json = serde_json::to_string(&fetched).expect("serialize");
        let deser: FetchedDiscoverySnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(fetched, deser);
        assert_eq!(deser.endpoint, DiscoveryEndpointKind::Alternate);
        assert_eq!(deser.source_url, "https://alt.example.test");
    }
}
