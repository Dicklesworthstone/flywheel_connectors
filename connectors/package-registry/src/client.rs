use fcp_prelude::log_redaction::redact_url;
use std::time::Duration;

use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop, classify_http_status};
use fcp_sdk::retry::RetryDecision;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use reqwest::{Client, RequestBuilder};
use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::error::{Error, Result};
use crate::types::{
    ArtifactInfo, ArtifactsResponse, DependenciesResponse, DependencyInfo, DownloadPoint,
    DownloadsResponse, PackageMetadata, RegistryProvider, SearchResponse, SearchResult,
    VersionInfo, VersionsResponse, normalize_pypi_name,
};

const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');
const USER_AGENT: &str = concat!("fcp-package-registry/", env!("CARGO_PKG_VERSION"));

pub struct PackageRegistryClient {
    client: Client,
    provider: RegistryProvider,
    base_url: String,
    token: Option<String>,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for PackageRegistryClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PackageRegistryClient")
            .field("provider", &self.provider)
            .field("base_url", &self.base_url)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

impl PackageRegistryClient {
    pub fn new(
        provider: RegistryProvider,
        base_url: String,
        token: Option<String>,
        retry_config: HttpRetryConfig,
        request_timeout_ms: u64,
    ) -> Result<Self> {
        let client = Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_millis(request_timeout_ms))
            .build()
            .map_err(Error::Http)?;

        Ok(Self {
            client,
            provider,
            base_url,
            token,
            retry_config,
        })
    }

    #[must_use]
    pub fn is_anonymous(&self) -> bool {
        self.token.is_none()
    }

    pub async fn health_check(&self, runtime: &ConnectorRuntime) -> Result<Value> {
        match self.provider {
            RegistryProvider::Npm => self
                .get_json(
                    runtime,
                    "/-/v1/search",
                    &[("text", "react".into()), ("size", "1".into())],
                )
                .await
                .map(|_| {
                    json!({
                        "provider": "npm",
                        "probe": "search",
                        "path": "/-/v1/search",
                        "query": { "text": "react", "size": 1 },
                        "anonymous": self.is_anonymous(),
                        "base_url": self.base_url,
                    })
                }),
            RegistryProvider::Pypi => {
                self.get_json(runtime, "/pypi/pip/json", &[])
                    .await
                    .map(|_| {
                        json!({
                            "provider": "pypi",
                            "probe": "project_metadata",
                            "path": "/pypi/pip/json",
                            "anonymous": self.is_anonymous(),
                            "base_url": self.base_url,
                        })
                    })
            }
            RegistryProvider::CratesIo => self
                .get_json(
                    runtime,
                    "/api/v1/crates",
                    &[("q", "serde".into()), ("per_page", "1".into())],
                )
                .await
                .map(|_| {
                    json!({
                        "provider": "crates_io",
                        "probe": "crate_search",
                        "path": "/api/v1/crates",
                        "query": { "q": "serde", "per_page": 1 },
                        "anonymous": self.is_anonymous(),
                        "base_url": self.base_url,
                    })
                }),
        }
    }

    pub async fn search(
        &self,
        runtime: &ConnectorRuntime,
        query: &str,
        limit: u64,
        page: u64,
    ) -> Result<SearchResponse> {
        if query.trim().is_empty() {
            return Err(Error::InvalidInput("query must not be empty".into()));
        }

        match self.provider {
            RegistryProvider::Npm => {
                let from = page.saturating_sub(1) * limit;
                let payload = self
                    .get_json(
                        runtime,
                        "/-/v1/search",
                        &[
                            ("text", query.to_string()),
                            ("size", limit.to_string()),
                            ("from", from.to_string()),
                        ],
                    )
                    .await?;

                let results = payload
                    .get("objects")
                    .and_then(Value::as_array)
                    .map(|objects| {
                        objects
                            .iter()
                            .filter_map(|item| item.get("package"))
                            .map(|package| SearchResult {
                                name: str_field(package, "name").unwrap_or_default(),
                                summary: str_field(package, "description"),
                                latest_version: str_field(package, "version"),
                                homepage: nested_str_field(package, &["links", "homepage"]),
                                repository: nested_str_field(package, &["links", "repository"]),
                                downloads: None,
                                recent_downloads: None,
                                exact_match: None,
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                Ok(SearchResponse {
                    provider: self.provider,
                    query: query.to_string(),
                    total: payload.get("total").and_then(Value::as_u64),
                    page,
                    limit,
                    results,
                })
            }
            RegistryProvider::CratesIo => {
                let payload = self
                    .get_json(
                        runtime,
                        "/api/v1/crates",
                        &[
                            ("q", query.to_string()),
                            ("per_page", limit.to_string()),
                            ("page", page.to_string()),
                        ],
                    )
                    .await?;

                let results = payload
                    .get("crates")
                    .and_then(Value::as_array)
                    .map(|crates| {
                        crates
                            .iter()
                            .map(|krate| SearchResult {
                                name: str_field(krate, "name").unwrap_or_default(),
                                summary: str_field(krate, "description"),
                                latest_version: str_field(krate, "max_version"),
                                homepage: str_field(krate, "homepage"),
                                repository: str_field(krate, "repository"),
                                downloads: u64_field(krate, "downloads"),
                                recent_downloads: u64_field(krate, "recent_downloads"),
                                exact_match: krate.get("exact_match").and_then(Value::as_bool),
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                Ok(SearchResponse {
                    provider: self.provider,
                    query: query.to_string(),
                    total: nested_u64_field(&payload, &["meta", "total"]),
                    page,
                    limit,
                    results,
                })
            }
            RegistryProvider::Pypi => Err(Error::Unsupported(
                "search is unsupported for the configured provider in the first slice".into(),
            )),
        }
    }

    pub async fn get_package(
        &self,
        runtime: &ConnectorRuntime,
        name: &str,
    ) -> Result<PackageMetadata> {
        let name = validate_name(name)?;

        match self.provider {
            RegistryProvider::Npm => {
                let payload = self.npm_packument(runtime, name).await?;
                let latest = latest_npm_version(&payload);
                let latest_payload = latest
                    .as_ref()
                    .and_then(|version| npm_version_payload(&payload, version))
                    .cloned();

                let owners = payload
                    .get("maintainers")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|item| {
                                str_field(item, "name").or_else(|| str_field(item, "username"))
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                Ok(PackageMetadata {
                    provider: self.provider,
                    name: str_field(&payload, "name").unwrap_or_else(|| name.to_string()),
                    normalized_name: name.to_string(),
                    latest_version: latest,
                    description: str_field(&payload, "description").or_else(|| {
                        latest_payload
                            .as_ref()
                            .and_then(|item| str_field(item, "description"))
                    }),
                    homepage: str_field(&payload, "homepage").or_else(|| {
                        latest_payload
                            .as_ref()
                            .and_then(|item| repository_or_url(item, "homepage"))
                    }),
                    documentation: latest_payload
                        .as_ref()
                        .and_then(|item| repository_or_url(item, "documentation")),
                    repository: repository_or_url(&payload, "repository").or_else(|| {
                        latest_payload
                            .as_ref()
                            .and_then(|item| repository_or_url(item, "repository"))
                    }),
                    license: stringish_field(&payload, "license").or_else(|| {
                        latest_payload
                            .as_ref()
                            .and_then(|item| stringish_field(item, "license"))
                    }),
                    keywords: array_of_strings(payload.get("keywords")),
                    owners,
                    extra: Some(json!({
                        "dist_tags": payload.get("dist-tags").cloned().unwrap_or(Value::Null),
                    })),
                })
            }
            RegistryProvider::Pypi => {
                let payload = self.pypi_project(runtime, name).await?;
                let info = payload.get("info").cloned().unwrap_or(Value::Null);
                Ok(PackageMetadata {
                    provider: self.provider,
                    name: str_field(&info, "name").unwrap_or_else(|| normalize_pypi_name(name)),
                    normalized_name: normalize_pypi_name(name),
                    latest_version: str_field(&info, "version"),
                    description: str_field(&info, "summary"),
                    homepage: nested_str_field(&info, &["project_urls", "Homepage"])
                        .or_else(|| str_field(&info, "home_page")),
                    documentation: str_field(&info, "docs_url"),
                    repository: nested_str_field(&info, &["project_urls", "Source"])
                        .or_else(|| nested_str_field(&info, &["project_urls", "Repository"])),
                    license: str_field(&info, "license"),
                    keywords: split_keywords(str_field(&info, "keywords").as_deref()),
                    owners: Vec::new(),
                    extra: Some(json!({
                        "requires_python": info.get("requires_python").cloned().unwrap_or(Value::Null),
                        "project_urls": info.get("project_urls").cloned().unwrap_or(Value::Null),
                    })),
                })
            }
            RegistryProvider::CratesIo => {
                let payload = self.crates_details(runtime, name).await?;
                let krate = payload.get("crate").cloned().unwrap_or(Value::Null);
                let owners = self.crates_owners(runtime, name).await.unwrap_or_default();
                Ok(PackageMetadata {
                    provider: self.provider,
                    name: str_field(&krate, "name").unwrap_or_else(|| name.to_string()),
                    normalized_name: name.to_string(),
                    latest_version: str_field(&krate, "max_version"),
                    description: str_field(&krate, "description"),
                    homepage: str_field(&krate, "homepage"),
                    documentation: str_field(&krate, "documentation"),
                    repository: str_field(&krate, "repository"),
                    license: None,
                    keywords: payload
                        .get("keywords")
                        .and_then(Value::as_array)
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(|item| str_field(item, "keyword"))
                                .collect()
                        })
                        .unwrap_or_default(),
                    owners,
                    extra: Some(json!({
                        "downloads": krate.get("downloads").cloned().unwrap_or(Value::Null),
                        "recent_downloads": krate.get("recent_downloads").cloned().unwrap_or(Value::Null),
                        "trustpub_only": krate.get("trustpub_only").cloned().unwrap_or(Value::Null),
                    })),
                })
            }
        }
    }

    pub async fn list_versions(
        &self,
        runtime: &ConnectorRuntime,
        name: &str,
    ) -> Result<VersionsResponse> {
        let name = validate_name(name)?;

        match self.provider {
            RegistryProvider::Npm => {
                let payload = self.npm_packument(runtime, name).await?;
                let tag_map = npm_tags_by_version(&payload);
                let mut versions = Vec::new();
                if let Some(entries) = payload.get("versions").and_then(Value::as_object) {
                    for (version, item) in entries {
                        versions.push(VersionInfo {
                            version: version.clone(),
                            tags: tag_map.get(version).cloned().unwrap_or_default(),
                            yanked: None,
                            created_at: None,
                            downloads: None,
                            checksum: nested_str_field(item, &["dist", "shasum"]),
                            extra: Some(json!({
                                "deprecated": item.get("deprecated").cloned().unwrap_or(Value::Null),
                            })),
                        });
                    }
                }
                versions.sort_by(|left, right| right.version.cmp(&left.version));
                Ok(VersionsResponse {
                    provider: self.provider,
                    name: name.to_string(),
                    versions,
                })
            }
            RegistryProvider::Pypi => {
                let payload = self.pypi_project(runtime, name).await?;
                let mut versions = Vec::new();
                if let Some(releases) = payload.get("releases").and_then(Value::as_object) {
                    for (version, files) in releases {
                        let files = files.as_array().cloned().unwrap_or_default();
                        let created_at = files.first().and_then(|file| {
                            str_field(file, "upload_time_iso_8601")
                                .or_else(|| str_field(file, "upload_time"))
                        });
                        let yanked = if files.is_empty() {
                            None
                        } else {
                            Some(files.iter().all(|file| {
                                file.get("yanked").and_then(Value::as_bool).unwrap_or(false)
                            }))
                        };
                        versions.push(VersionInfo {
                            version: version.clone(),
                            tags: Vec::new(),
                            yanked,
                            created_at,
                            downloads: None,
                            checksum: files
                                .first()
                                .and_then(|file| nested_str_field(file, &["digests", "sha256"])),
                            extra: Some(json!({ "file_count": files.len() })),
                        });
                    }
                }
                versions.sort_by(|left, right| right.version.cmp(&left.version));
                Ok(VersionsResponse {
                    provider: self.provider,
                    name: normalize_pypi_name(name),
                    versions,
                })
            }
            RegistryProvider::CratesIo => {
                let payload = self.crates_details(runtime, name).await?;
                let versions = payload
                    .get("versions")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items.iter()
                            .map(|item| VersionInfo {
                                version: str_field(item, "num").unwrap_or_default(),
                                tags: Vec::new(),
                                yanked: item.get("yanked").and_then(Value::as_bool),
                                created_at: str_field(item, "created_at"),
                                downloads: u64_field(item, "downloads"),
                                checksum: str_field(item, "checksum"),
                                extra: Some(json!({
                                    "dl_path": item.get("dl_path").cloned().unwrap_or(Value::Null),
                                    "crate_size": item.get("crate_size").cloned().unwrap_or(Value::Null),
                                })),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                Ok(VersionsResponse {
                    provider: self.provider,
                    name: name.to_string(),
                    versions,
                })
            }
        }
    }

    pub async fn get_dependencies(
        &self,
        runtime: &ConnectorRuntime,
        name: &str,
        version: Option<&str>,
    ) -> Result<DependenciesResponse> {
        let name = validate_name(name)?;

        match self.provider {
            RegistryProvider::Npm => {
                let payload = self.npm_packument(runtime, name).await?;
                let version = resolve_npm_version(&payload, version)?;
                let version_payload = npm_version_payload(&payload, &version).ok_or_else(|| {
                    Error::NotFound(format!("npm version not found: {name}@{version}"))
                })?;
                let mut dependencies = collect_named_dependencies(
                    version_payload.get("dependencies"),
                    "dependency",
                    false,
                );
                dependencies.extend(collect_named_dependencies(
                    version_payload.get("peerDependencies"),
                    "peer_dependency",
                    false,
                ));
                dependencies.extend(collect_named_dependencies(
                    version_payload.get("optionalDependencies"),
                    "optional_dependency",
                    true,
                ));

                Ok(DependenciesResponse {
                    provider: self.provider,
                    name: name.to_string(),
                    version,
                    dependencies,
                })
            }
            RegistryProvider::Pypi => {
                let version = version.map(ToOwned::to_owned).unwrap_or_default();
                let payload = if version.is_empty() {
                    self.pypi_project(runtime, name).await?
                } else {
                    self.pypi_release(runtime, name, &version).await?
                };
                let info = payload.get("info").cloned().unwrap_or(Value::Null);
                let resolved_version = str_field(&info, "version").unwrap_or(version);
                let dependencies = info
                    .get("requires_dist")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .map(parse_pypi_requirement)
                            .collect()
                    })
                    .unwrap_or_default();
                Ok(DependenciesResponse {
                    provider: self.provider,
                    name: normalize_pypi_name(name),
                    version: resolved_version,
                    dependencies,
                })
            }
            RegistryProvider::CratesIo => {
                let version = match version {
                    Some(version) => version.to_string(),
                    None => self
                        .crates_details(runtime, name)
                        .await?
                        .get("crate")
                        .and_then(|krate| str_field(krate, "max_version"))
                        .ok_or_else(|| Error::NotFound(format!("crate not found: {name}")))?,
                };

                let path = format!(
                    "/api/v1/crates/{}/{}{}",
                    encode_segment(name)?,
                    encode_segment(&version)?,
                    "/dependencies"
                );
                let payload = self.get_json(runtime, &path, &[]).await?;
                let dependencies = payload
                    .get("dependencies")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .map(|item| DependencyInfo {
                                name: str_field(item, "crate_id").unwrap_or_default(),
                                requirement: str_field(item, "req"),
                                kind: str_field(item, "kind"),
                                optional: item.get("optional").and_then(Value::as_bool),
                                target: str_field(item, "target"),
                                features: item
                                    .get("features")
                                    .and_then(Value::as_array)
                                    .map(|features| {
                                        features
                                            .iter()
                                            .filter_map(Value::as_str)
                                            .map(ToOwned::to_owned)
                                            .collect()
                                    })
                                    .unwrap_or_default(),
                                raw: None,
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                Ok(DependenciesResponse {
                    provider: self.provider,
                    name: name.to_string(),
                    version,
                    dependencies,
                })
            }
        }
    }

    pub async fn list_artifacts(
        &self,
        runtime: &ConnectorRuntime,
        name: &str,
        version: Option<&str>,
    ) -> Result<ArtifactsResponse> {
        let name = validate_name(name)?;

        match self.provider {
            RegistryProvider::Npm => {
                let payload = self.npm_packument(runtime, name).await?;
                let version = resolve_npm_version(&payload, version)?;
                let version_payload = npm_version_payload(&payload, &version).ok_or_else(|| {
                    Error::NotFound(format!("npm version not found: {name}@{version}"))
                })?;
                let dist = version_payload.get("dist").cloned().unwrap_or(Value::Null);
                let artifact = ArtifactInfo {
                    filename: Some(format!("{name}-{version}.tgz")),
                    url: str_field(&dist, "tarball").unwrap_or_default(),
                    checksum: str_field(&dist, "shasum"),
                    integrity: str_field(&dist, "integrity"),
                    size: u64_field(&dist, "unpackedSize"),
                    packagetype: Some("tgz".into()),
                    yanked: None,
                };
                Ok(ArtifactsResponse {
                    provider: self.provider,
                    name: name.to_string(),
                    version,
                    artifacts: vec![artifact],
                })
            }
            RegistryProvider::Pypi => {
                let version = version.map(ToOwned::to_owned).unwrap_or_default();
                let payload = if version.is_empty() {
                    self.pypi_project(runtime, name).await?
                } else {
                    self.pypi_release(runtime, name, &version).await?
                };
                let info = payload.get("info").cloned().unwrap_or(Value::Null);
                let resolved_version = str_field(&info, "version").unwrap_or(version);
                let artifacts = payload
                    .get("urls")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .map(|item| ArtifactInfo {
                                filename: str_field(item, "filename"),
                                url: str_field(item, "url").unwrap_or_default(),
                                checksum: nested_str_field(item, &["digests", "sha256"]),
                                integrity: None,
                                size: u64_field(item, "size"),
                                packagetype: str_field(item, "packagetype"),
                                yanked: item.get("yanked").and_then(Value::as_bool),
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                Ok(ArtifactsResponse {
                    provider: self.provider,
                    name: normalize_pypi_name(name),
                    version: resolved_version,
                    artifacts,
                })
            }
            RegistryProvider::CratesIo => {
                let payload = self.crates_details(runtime, name).await?;
                let versions = payload
                    .get("versions")
                    .and_then(Value::as_array)
                    .ok_or_else(|| Error::NotFound(format!("crate versions not found: {name}")))?;
                let selected_version = version
                    .map(ToOwned::to_owned)
                    .or_else(|| {
                        payload
                            .get("crate")
                            .and_then(|krate| str_field(krate, "max_version"))
                    })
                    .ok_or_else(|| Error::NotFound(format!("crate not found: {name}")))?;
                let version_payload = versions
                    .iter()
                    .find(|item| {
                        str_field(item, "num").as_deref() == Some(selected_version.as_str())
                    })
                    .ok_or_else(|| {
                        Error::NotFound(format!(
                            "crate version not found: {name}@{selected_version}"
                        ))
                    })?;
                let dl_path = str_field(version_payload, "dl_path").ok_or_else(|| {
                    Error::NotFound(format!("download path missing: {name}@{selected_version}"))
                })?;
                let artifact = ArtifactInfo {
                    filename: Some(format!("{name}-{selected_version}.crate")),
                    url: format!("{}{}", self.base_url, dl_path),
                    checksum: str_field(version_payload, "checksum"),
                    integrity: None,
                    size: u64_field(version_payload, "crate_size"),
                    packagetype: Some("crate".into()),
                    yanked: version_payload.get("yanked").and_then(Value::as_bool),
                };
                Ok(ArtifactsResponse {
                    provider: self.provider,
                    name: name.to_string(),
                    version: selected_version,
                    artifacts: vec![artifact],
                })
            }
        }
    }

    pub async fn get_downloads(
        &self,
        runtime: &ConnectorRuntime,
        name: &str,
    ) -> Result<DownloadsResponse> {
        let name = validate_name(name)?;

        match self.provider {
            RegistryProvider::CratesIo => {
                let details = self.crates_details(runtime, name).await?;
                let path = format!("/api/v1/crates/{}/downloads", encode_segment(name)?);
                let payload = self.get_json(runtime, &path, &[]).await?;
                let points = payload
                    .get("version_downloads")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items.iter()
                            .map(|item| DownloadPoint {
                                version: str_field(item, "version"),
                                date: str_field(item, "date"),
                                downloads: u64_field(item, "downloads").unwrap_or(0),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let krate = details.get("crate").cloned().unwrap_or(Value::Null);
                Ok(DownloadsResponse {
                    provider: self.provider,
                    name: name.to_string(),
                    total: u64_field(&krate, "downloads"),
                    recent_downloads: u64_field(&krate, "recent_downloads"),
                    points,
                })
            }
            _ => Err(Error::Unsupported(
                "download statistics are unsupported for the configured provider in the first slice"
                    .into(),
            )),
        }
    }

    async fn npm_packument(&self, runtime: &ConnectorRuntime, name: &str) -> Result<Value> {
        let path = format!("/{}", encode_segment(name)?);
        self.get_json(runtime, &path, &[]).await
    }

    async fn pypi_project(&self, runtime: &ConnectorRuntime, name: &str) -> Result<Value> {
        let normalized = normalize_pypi_name(name);
        let path = format!("/pypi/{}/json", encode_segment(&normalized)?);
        self.get_json(runtime, &path, &[]).await
    }

    async fn pypi_release(
        &self,
        runtime: &ConnectorRuntime,
        name: &str,
        version: &str,
    ) -> Result<Value> {
        let normalized = normalize_pypi_name(name);
        let path = format!(
            "/pypi/{}/{}/json",
            encode_segment(&normalized)?,
            encode_segment(version)?
        );
        self.get_json(runtime, &path, &[]).await
    }

    async fn crates_details(&self, runtime: &ConnectorRuntime, name: &str) -> Result<Value> {
        let path = format!("/api/v1/crates/{}", encode_segment(name)?);
        self.get_json(runtime, &path, &[]).await
    }

    async fn crates_owners(&self, runtime: &ConnectorRuntime, name: &str) -> Result<Vec<String>> {
        let path = format!("/api/v1/crates/{}/owners", encode_segment(name)?);
        let payload = self.get_json(runtime, &path, &[]).await?;
        Ok(payload
            .get("users")
            .and_then(Value::as_array)
            .map(|users| {
                users
                    .iter()
                    .filter_map(|user| str_field(user, "login"))
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn get_json(
        &self,
        runtime: &ConnectorRuntime,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let client = self.client.clone();
        let token = self.token.clone();
        let provider = self.provider;
        let query = query
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.clone()))
            .collect::<Vec<_>>();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = client.clone();
            let token = token.clone();
            let query = query.clone();

            async move {
                debug!(attempt, provider = provider.as_str(), url = %redact_url(&url), "package registry GET");

                let mut request =
                    client
                        .get(&url)
                        .header(reqwest::header::USER_AGENT, "fcp-package-registry/0.1");
                request = with_auth(request, token.as_deref());
                if !query.is_empty() {
                    request = request.query(&query);
                }

                let response = match request.send().await {
                    Ok(response) => response,
                    Err(error) => {
                        let wrapped = Error::Http(error);
                        return if wrapped.is_retryable() {
                            AttemptOutcome::Retryable {
                                error: wrapped,
                                retry_after: None,
                            }
                        } else {
                            AttemptOutcome::Terminal(wrapped)
                        };
                    }
                };

                let status = response.status().as_u16();
                if response.status().is_success() {
                    return match response.json::<Value>().await {
                        Ok(value) => AttemptOutcome::Success(value),
                        Err(error) => AttemptOutcome::Terminal(Error::Http(error)),
                    };
                }

                let retry_after = response
                    .headers()
                    .get("retry-after")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                    .map(Duration::from_secs);

                if status == 429 {
                    return AttemptOutcome::Retryable {
                        error: Error::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(30))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                if matches!(status, 401 | 403) {
                    return AttemptOutcome::Terminal(Error::Unauthorized(format!(
                        "{} request rejected with HTTP {}",
                        provider, status
                    )));
                }

                if status == 404 {
                    return AttemptOutcome::Terminal(Error::NotFound(format!(
                        "{} resource not found at {}",
                        provider, url
                    )));
                }

                let body = response.text().await.unwrap_or_default();
                let message = if body.trim().is_empty() {
                    format!("HTTP {status}")
                } else {
                    serde_json::from_str::<Value>(&body)
                        .ok()
                        .and_then(extract_error_message)
                        .unwrap_or(body)
                };

                warn!(provider = provider.as_str(), url = %redact_url(&url), status, "package registry request failed");
                let error = Error::Api { status, message };
                if matches!(classify_http_status(status, retry_after), RetryDecision::Terminal) {
                    AttemptOutcome::Terminal(error)
                } else {
                    AttemptOutcome::Retryable { error, retry_after }
                }
            }
        })
        .await
    }
}

fn with_auth(request: RequestBuilder, token: Option<&str>) -> RequestBuilder {
    match token {
        Some(token) => request.bearer_auth(token),
        None => request,
    }
}

fn validate_name(name: &str) -> Result<&str> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidInput("name must not be empty".into()));
    }
    // A bare `.`/`..` package name would normalize to a sibling endpoint
    // (`/{name}` → `/..` → registry root). Package names never legitimately
    // contain consecutive dots.
    if trimmed == "." || trimmed.contains("..") {
        return Err(Error::InvalidInput(
            "name must not contain path-traversal segments".into(),
        ));
    }
    Ok(trimmed)
}

/// Percent-encode a value as a single URL path segment.
///
/// `PATH_SEGMENT` encodes slashes and other separators but not `.`, so a bare
/// `.`/`..` segment (a package name or version) would survive to the server and
/// normalize to a sibling endpoint (e.g. `/api/v1/crates/{name}/../dependencies`
/// → `/api/v1/crates/dependencies`, dropping the name). Names and versions never
/// legitimately contain consecutive dots, so such values are rejected.
fn encode_segment(input: &str) -> Result<String> {
    if input.is_empty() {
        return Err(Error::InvalidInput("path segment must not be empty".into()));
    }
    if input == "." || input.contains("..") {
        return Err(Error::InvalidInput(
            "path segment must not contain traversal sequences".into(),
        ));
    }
    Ok(utf8_percent_encode(input, PATH_SEGMENT).to_string())
}

fn latest_npm_version(payload: &Value) -> Option<String> {
    nested_str_field(payload, &["dist-tags", "latest"])
}

fn resolve_npm_version(payload: &Value, requested: Option<&str>) -> Result<String> {
    match requested {
        Some(version) if !version.trim().is_empty() => Ok(version.trim().to_string()),
        _ => latest_npm_version(payload)
            .ok_or_else(|| Error::NotFound("npm latest dist-tag missing".into())),
    }
}

fn npm_version_payload<'a>(payload: &'a Value, version: &str) -> Option<&'a Value> {
    payload
        .get("versions")
        .and_then(Value::as_object)
        .and_then(|versions| versions.get(version))
}

fn npm_tags_by_version(payload: &Value) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut tags = std::collections::BTreeMap::<String, Vec<String>>::new();
    if let Some(dist_tags) = payload.get("dist-tags").and_then(Value::as_object) {
        for (tag, version) in dist_tags {
            if let Some(version) = version.as_str() {
                tags.entry(version.to_string())
                    .or_default()
                    .push(tag.clone());
            }
        }
    }
    tags
}

fn collect_named_dependencies(
    value: Option<&Value>,
    kind: &str,
    optional: bool,
) -> Vec<DependencyInfo> {
    value
        .and_then(Value::as_object)
        .map(|deps| {
            deps.iter()
                .map(|(name, requirement)| DependencyInfo {
                    name: name.clone(),
                    requirement: requirement.as_str().map(ToOwned::to_owned),
                    kind: Some(kind.to_string()),
                    optional: Some(optional),
                    target: None,
                    features: Vec::new(),
                    raw: None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_pypi_requirement(raw: &str) -> DependencyInfo {
    let trimmed = raw.trim();
    let name = trimmed
        .split([';', ' ', '('])
        .next()
        .unwrap_or(trimmed)
        .trim()
        .to_string();
    DependencyInfo {
        name,
        requirement: None,
        kind: Some("requires_dist".into()),
        optional: None,
        target: None,
        features: Vec::new(),
        raw: Some(trimmed.to_string()),
    }
}

fn extract_error_message(value: Value) -> Option<String> {
    if let Some(message) = value.get("message").and_then(Value::as_str) {
        return Some(message.to_string());
    }
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        return Some(error.to_string());
    }
    if let Some(errors) = value.get("errors").and_then(Value::as_array) {
        let joined = errors
            .iter()
            .filter_map(|item| {
                item.get("detail")
                    .and_then(Value::as_str)
                    .or_else(|| item.get("message").and_then(Value::as_str))
            })
            .collect::<Vec<_>>()
            .join("; ");
        if !joined.is_empty() {
            return Some(joined);
        }
    }
    value.as_str().map(ToOwned::to_owned)
}

fn str_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn nested_str_field(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for part in path {
        current = current.get(*part)?;
    }
    current.as_str().map(ToOwned::to_owned)
}

fn nested_u64_field(value: &Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for part in path {
        current = current.get(*part)?;
    }
    current.as_u64()
}

fn u64_field(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn stringish_field(value: &Value, key: &str) -> Option<String> {
    let field = value.get(key)?;
    if let Some(text) = field.as_str() {
        return Some(text.to_string());
    }
    if let Some(object) = field.as_object() {
        return object
            .get("type")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
    }
    None
}

fn repository_or_url(value: &Value, key: &str) -> Option<String> {
    let field = value.get(key)?;
    if let Some(text) = field.as_str() {
        return Some(text.to_string());
    }
    if let Some(object) = field.as_object() {
        return object
            .get("url")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
    }
    None
}

fn array_of_strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn split_keywords(value: Option<&str>) -> Vec<String> {
    value
        .map(|keywords| {
            keywords
                .split(|ch: char| ch == ',' || ch.is_ascii_whitespace())
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn encode_segment_escapes_scoped_npm_name() {
        assert_eq!(encode_segment("@scope/name").unwrap(), "@scope%2Fname");
    }

    #[test]
    fn encode_segment_rejects_traversal() {
        // A bare `.`/`..` name or version would normalize to a sibling endpoint.
        for evil in ["..", ".", "../..", "a..b", ""] {
            assert!(
                matches!(encode_segment(evil), Err(Error::InvalidInput(_))),
                "path segment {evil:?} must be rejected"
            );
        }
    }

    #[test]
    fn parse_pypi_requirement_preserves_raw_text() {
        let requirement = parse_pypi_requirement("coverage; extra == \"test\"");
        assert_eq!(requirement.name, "coverage");
        assert_eq!(
            requirement.raw.as_deref(),
            Some("coverage; extra == \"test\"")
        );
    }

    #[test]
    fn npm_tags_by_version_reverses_dist_tags() {
        let payload = json!({
            "dist-tags": {
                "latest": "1.2.3",
                "next": "2.0.0-beta.1"
            }
        });
        let tags = npm_tags_by_version(&payload);
        assert_eq!(tags.get("1.2.3").unwrap(), &vec!["latest".to_string()]);
        assert_eq!(tags.get("2.0.0-beta.1").unwrap(), &vec!["next".to_string()]);
    }

    #[test]
    fn collect_named_dependencies_sets_kind_and_optional() {
        let deps = collect_named_dependencies(Some(&json!({"serde": "^1"})), "dependency", false);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].kind.as_deref(), Some("dependency"));
        assert_eq!(deps[0].optional, Some(false));
    }
}
