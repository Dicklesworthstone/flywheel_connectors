use std::fmt;

use fcp_sdk::migration::HttpRetryConfig;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegistryProvider {
    Npm,
    Pypi,
    CratesIo,
}

impl RegistryProvider {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::CratesIo => "crates_io",
        }
    }

    #[must_use]
    pub const fn default_base_url(self) -> &'static str {
        match self {
            Self::Npm => "https://registry.npmjs.org",
            Self::Pypi => "https://pypi.org",
            Self::CratesIo => "https://crates.io",
        }
    }

    #[must_use]
    pub const fn supports_search(self) -> bool {
        matches!(self, Self::Npm | Self::CratesIo)
    }

    #[must_use]
    pub const fn supports_downloads(self) -> bool {
        matches!(self, Self::CratesIo)
    }
}

impl fmt::Display for RegistryProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[must_use]
pub const fn default_request_timeout_ms() -> u64 {
    30_000
}

#[derive(Clone, Deserialize)]
pub struct PackageRegistryConfig {
    pub provider: RegistryProvider,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
}

impl fmt::Debug for PackageRegistryConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PackageRegistryConfig")
            .field("provider", &self.provider)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("base_url", &self.base_url)
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

impl PackageRegistryConfig {
    /// Build a config from its JSON representation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the JSON does not match the config schema.
    pub fn from_value(value: Value) -> Result<Self> {
        let mut config: Self = serde_json::from_value(value)
            .map_err(|error| Error::Config(format!("invalid package-registry config: {error}")))?;
        config.normalize();
        config.validate()?;
        Ok(config)
    }

    fn normalize(&mut self) {
        self.token = self.token.take().and_then(|token| {
            let trimmed = token.trim().to_owned();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });

        self.base_url = self.base_url.take().and_then(|base_url| {
            let trimmed = base_url.trim().trim_end_matches('/').to_owned();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });
    }

    /// Validate the normalized config.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when a field holds an invalid value.
    pub fn validate(&self) -> Result<()> {
        if self.request_timeout_ms == 0 {
            return Err(Error::Config(
                "request_timeout_ms must be greater than 0".into(),
            ));
        }

        let base_url = self.resolved_base_url();
        let allowed = base_url.starts_with("https://")
            || base_url.starts_with("http://localhost")
            || base_url.starts_with("http://127.0.0.1");
        if !allowed {
            return Err(Error::Config(format!(
                "base_url must use https unless it targets localhost for verification: {base_url}"
            )));
        }
        if base_url.contains('@') {
            return Err(Error::Config(
                "base_url must not include embedded credentials".into(),
            ));
        }
        if base_url.contains('?') || base_url.contains('#') {
            return Err(Error::Config(
                "base_url must not include a query string or fragment".into(),
            ));
        }

        Ok(())
    }

    #[must_use]
    pub fn resolved_base_url(&self) -> String {
        self.base_url
            .clone()
            .unwrap_or_else(|| self.provider.default_base_url().to_string())
    }

    #[must_use]
    pub fn auth_label(&self) -> &'static str {
        if self.token.is_some() {
            "token"
        } else {
            "anonymous"
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchResponse {
    pub provider: RegistryProvider,
    pub query: String,
    pub total: Option<u64>,
    pub page: u64,
    pub limit: u64,
    pub results: Vec<SearchResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchResult {
    pub name: String,
    pub summary: Option<String>,
    pub latest_version: Option<String>,
    pub homepage: Option<String>,
    pub repository: Option<String>,
    pub downloads: Option<u64>,
    pub recent_downloads: Option<u64>,
    pub exact_match: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackageMetadata {
    pub provider: RegistryProvider,
    pub name: String,
    pub normalized_name: String,
    pub latest_version: Option<String>,
    pub description: Option<String>,
    pub homepage: Option<String>,
    pub documentation: Option<String>,
    pub repository: Option<String>,
    pub license: Option<String>,
    pub keywords: Vec<String>,
    pub owners: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VersionsResponse {
    pub provider: RegistryProvider,
    pub name: String,
    pub versions: Vec<VersionInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    pub version: String,
    pub tags: Vec<String>,
    pub yanked: Option<bool>,
    pub created_at: Option<String>,
    pub downloads: Option<u64>,
    pub checksum: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DependenciesResponse {
    pub provider: RegistryProvider,
    pub name: String,
    pub version: String,
    pub dependencies: Vec<DependencyInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DependencyInfo {
    pub name: String,
    pub requirement: Option<String>,
    pub kind: Option<String>,
    pub optional: Option<bool>,
    pub target: Option<String>,
    pub features: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactsResponse {
    pub provider: RegistryProvider,
    pub name: String,
    pub version: String,
    pub artifacts: Vec<ArtifactInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactInfo {
    pub filename: Option<String>,
    pub url: String,
    pub checksum: Option<String>,
    pub integrity: Option<String>,
    pub size: Option<u64>,
    pub packagetype: Option<String>,
    pub yanked: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DownloadsResponse {
    pub provider: RegistryProvider,
    pub name: String,
    pub total: Option<u64>,
    pub recent_downloads: Option<u64>,
    pub points: Vec<DownloadPoint>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DownloadPoint {
    pub version: Option<String>,
    pub date: Option<String>,
    pub downloads: u64,
}

#[must_use]
pub fn normalize_pypi_name(name: &str) -> String {
    let mut output = String::with_capacity(name.len());
    let mut previous_dash = false;

    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            output.push(ch.to_ascii_lowercase());
            previous_dash = false;
        } else if matches!(ch, '-' | '_' | '.') && !previous_dash {
            output.push('-');
            previous_dash = true;
        }
    }

    output.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn normalize_pypi_name_collapses_separator_runs() {
        assert_eq!(normalize_pypi_name("Foo__Bar.Baz"), "foo-bar-baz");
    }

    #[test]
    fn config_uses_provider_default_base_url() {
        let config = PackageRegistryConfig::from_value(json!({
            "provider": "npm"
        }))
        .unwrap();
        assert_eq!(config.resolved_base_url(), "https://registry.npmjs.org");
        assert_eq!(config.auth_label(), "anonymous");
    }

    #[test]
    fn config_rejects_zero_timeout() {
        let error = PackageRegistryConfig::from_value(json!({
            "provider": "crates_io",
            "request_timeout_ms": 0
        }))
        .unwrap_err();
        assert!(error.to_string().contains("request_timeout_ms"));
    }
}
