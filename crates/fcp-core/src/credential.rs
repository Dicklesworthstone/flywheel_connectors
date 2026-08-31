//! Credential types for FCP secretless egress (NORMATIVE).
//!
//! This module implements `CredentialObject` and `CredentialId` for "secretless"
//! credential injection as described in `FCP_Specification_V3.md` §5.6
//! (Network Guard and Secret Use).
//!
//! **Core principle:** Connectors SHOULD NOT receive raw credential bytes. They
//! reference a `CredentialId` in egress requests, and the `MeshNode` egress proxy
//! injects credential material at the network boundary.
//!
//! **Security guarantees:**
//! - Credentials are zone-bound and capability-gated.
//! - Credential injection is audited via `AuditEvent`.
//! - Host binding provides defense-in-depth against credential misuse.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{LeaseToken, ObjectHeader, SecretId, ZoneId};

/// Canonical credential identifier (NORMATIVE).
///
/// A `CredentialId` uniquely identifies a credential within a zone. It is used
/// to reference credentials in egress requests without exposing secret material.
///
/// **IMPORTANT**: Credential IDs MUST NOT be encoded inside capability IDs.
/// Operations that need credentials must require a capability whose constraints
/// include the needed `CredentialId` in `credential_allow`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialId(Uuid);

impl CredentialId {
    /// Create a new random `CredentialId`.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a `CredentialId` from a UUID.
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Parse a `CredentialId` from a string.
    ///
    /// # Errors
    /// Returns an error if the string is not a valid UUID.
    pub fn parse(s: &str) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(s)?))
    }

    /// Create a test `CredentialId` from bytes (for testing only).
    #[cfg(test)]
    #[must_use]
    pub const fn test_id(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }
}

impl Default for CredentialId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CredentialId")
            .field(&self.0.to_string())
            .finish()
    }
}

impl fmt::Display for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// How to apply a credential to outbound traffic (NORMATIVE).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CredentialApplication {
    /// HTTP Authorization header (e.g., `Bearer <token>`).
    HttpAuthorizationBearer,

    /// HTTP Authorization header with Basic auth.
    HttpAuthorizationBasic,

    /// Custom HTTP header.
    HttpHeader {
        /// Header name (e.g., "X-API-Key").
        name: String,
        /// Optional prefix before the secret value.
        #[serde(skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
    },

    /// Query parameter.
    QueryParameter {
        /// Parameter name.
        name: String,
    },

    /// TLS client certificate.
    TlsClientCertificate,

    /// SSH key authentication.
    SshKey,

    /// Database connection string credential.
    DatabaseConnection,

    /// WebSocket subprotocol with auth token.
    WebSocketAuth,

    /// Generic credential (application-specific handling).
    Generic {
        /// Application-specific configuration.
        config: String,
    },
}

/// Mesh-stored credential object (NORMATIVE).
///
/// A `CredentialObject` is a zone-bound, auditable handle describing *how to apply*
/// a secret to outbound traffic. It maps `CredentialId` to `SecretId` and defines
/// the application method.
///
/// **Key properties:**
/// - Zone-bound: Only usable within the owning zone.
/// - Auditable: Every use is logged via `AuditEvent`.
/// - Host-bound (optional): Can restrict which hosts the credential may be sent to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialObject {
    /// Standard object header.
    pub header: ObjectHeader,

    /// Unique identifier for this credential.
    pub credential_id: CredentialId,

    /// Human-readable label (MUST NOT contain secret material).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Reference to the underlying secret.
    pub secret_id: SecretId,

    /// How to apply this credential to outbound traffic.
    pub application: CredentialApplication,

    /// Allowed hosts for defense-in-depth (optional).
    ///
    /// If present, the egress proxy MUST verify the destination host matches
    /// one of these patterns before injecting the credential.
    ///
    /// Patterns support:
    /// - Exact match: `"api.example.com"`
    /// - Wildcard prefix: `"*.example.com"` (matches subdomains)
    /// - Port specification: `"api.example.com:443"`
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_allow: Vec<String>,

    /// When this credential expires (Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,

    /// Optional description of the credential's purpose.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Tags for categorization and filtering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

impl CredentialObject {
    /// Get the zone ID from the header.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.header.zone_id
    }

    /// Check if this credential has expired.
    #[must_use]
    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.expires_at.is_some_and(|exp| now_unix >= exp)
    }

    /// Check if a host is allowed by this credential's `host_allow` list.
    ///
    /// If `host_allow` is empty, all hosts are allowed.
    /// Otherwise, the host must match at least one pattern.
    #[must_use]
    pub fn is_host_allowed(&self, host: &str) -> bool {
        if self.host_allow.is_empty() {
            return true;
        }

        let host_lower = host.to_lowercase();
        self.host_allow.iter().any(|pattern| {
            let pattern_lower = pattern.to_lowercase();
            pattern_lower.strip_prefix("*.").map_or_else(
                // Exact match when no wildcard
                || host_lower == pattern_lower,
                |_| {
                    // Wildcard match: *.example.com matches foo.example.com (not base domain)
                    let suffix = &pattern_lower[1..]; // ".example.com"
                    host_lower.ends_with(suffix) && host_lower.len() > suffix.len()
                },
            )
        })
    }

    /// Check if this credential is currently usable for a given host.
    #[must_use]
    pub fn is_usable(&self, now_unix: u64, host: &str) -> bool {
        !self.is_expired(now_unix) && self.is_host_allowed(host)
    }

    /// Check if the given host string is an IP literal (IPv4 or IPv6).
    ///
    /// Handles port suffixes (e.g., `192.168.1.1:8080`, `[::1]:8080`).
    #[must_use]
    pub fn is_ip_literal(host: &str) -> bool {
        // Strip port if present
        let host_part = if host.starts_with('[') {
            // IPv6 with brackets: [::1]:8080 or [::1]
            host.find(']').map_or(host, |i| &host[1..i])
        } else if let Some(colon_pos) = host.rfind(':') {
            // Could be IPv4:port or IPv6 without brackets
            let before_colon = &host[..colon_pos];
            // If there's another colon before this one, it's IPv6
            if before_colon.contains(':') {
                host // Return full string, it's IPv6
            } else {
                before_colon // IPv4 with port
            }
        } else {
            host
        };

        // Try parsing as IP address
        host_part.parse::<std::net::IpAddr>().is_ok()
    }

    /// Check if the `host_allow` list contains any IP literals.
    ///
    /// This is useful for policies that require canonical hostnames only.
    #[must_use]
    pub fn has_ip_literal_in_host_allow(&self) -> bool {
        self.host_allow.iter().any(|h| {
            // Skip wildcard prefix for IP check
            let host = h.strip_prefix("*.").unwrap_or(h);
            Self::is_ip_literal(host)
        })
    }

    /// Validate that the credential configuration is policy-compliant.
    ///
    /// When `reject_ip_literals` is true, returns an error if any entry in
    /// `host_allow` is an IP literal rather than a hostname.
    ///
    /// # Errors
    ///
    /// Returns `CredentialValidationError::HostNotAllowed` if an IP literal
    /// is found when they are not allowed.
    pub fn validate_host_policy(
        &self,
        reject_ip_literals: bool,
    ) -> Result<(), CredentialValidationError> {
        if reject_ip_literals && self.has_ip_literal_in_host_allow() {
            // Find the first offending IP literal for the error message
            let ip_literal = self
                .host_allow
                .iter()
                .find(|h| {
                    let host = h.strip_prefix("*.").unwrap_or(h);
                    Self::is_ip_literal(host)
                })
                .cloned()
                .unwrap_or_default();

            return Err(CredentialValidationError::HostNotAllowed {
                credential_id: self.credential_id,
                host: ip_literal,
            });
        }
        Ok(())
    }
}

/// Error when credential validation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialValidationError {
    /// Credential has expired.
    Expired { credential_id: CredentialId },
    /// Host is not in the allowed list.
    HostNotAllowed {
        credential_id: CredentialId,
        host: String,
    },
    /// Credential ID not in capability's `credential_allow`.
    NotInCredentialAllow { credential_id: CredentialId },
    /// Referenced secret not found.
    SecretNotFound { secret_id: SecretId },
    /// Referenced secret has been revoked.
    SecretRevoked { secret_id: SecretId },
}

impl fmt::Display for CredentialValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired { credential_id } => {
                write!(f, "credential {credential_id} has expired")
            }
            Self::HostNotAllowed {
                credential_id,
                host,
            } => {
                write!(
                    f,
                    "host '{host}' not in allowed list for credential {credential_id}"
                )
            }
            Self::NotInCredentialAllow { credential_id } => {
                write!(
                    f,
                    "credential {credential_id} not in capability's credential_allow"
                )
            }
            Self::SecretNotFound { secret_id } => {
                write!(f, "secret {secret_id} not found")
            }
            Self::SecretRevoked { secret_id } => {
                write!(f, "secret {secret_id} has been revoked")
            }
        }
    }
}

impl std::error::Error for CredentialValidationError {}

/// Connector request for a host-selected credential lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialLeaseRequest {
    /// Existing connector credential reference.
    pub credential_id: CredentialId,
    /// Optional provider hint, such as `openai` or `anthropic`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Optional operation name for pool strategy/audit context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
}

impl CredentialLeaseRequest {
    /// Build a lease request for an existing credential reference.
    #[must_use]
    pub const fn new(credential_id: CredentialId) -> Self {
        Self {
            credential_id,
            provider: None,
            operation: None,
        }
    }

    /// Attach a provider hint.
    #[must_use]
    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = Some(provider.into());
        self
    }

    /// Attach an operation hint.
    #[must_use]
    pub fn with_operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = Some(operation.into());
        self
    }
}

/// Secretless credential lease granted by the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialLease {
    /// Concrete credential selected for this lease.
    pub credential_id: CredentialId,
    /// Opaque, display-safe lease authority token.
    pub lease_token: LeaseToken,
    /// Provider that issued the lease, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

impl CredentialLease {
    /// Build a secretless credential lease handle.
    #[must_use]
    pub const fn new(credential_id: CredentialId, lease_token: LeaseToken) -> Self {
        Self {
            credential_id,
            lease_token,
            provider: None,
        }
    }

    /// Attach the provider that selected this lease.
    #[must_use]
    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = Some(provider.into());
        self
    }

    /// Build the release request for this lease.
    #[must_use]
    pub fn release_request(&self) -> CredentialLeaseRelease {
        CredentialLeaseRelease::new(self.credential_id, self.lease_token.clone())
    }
}

/// Request to release a previously granted credential lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialLeaseRelease {
    /// Credential that was leased.
    pub credential_id: CredentialId,
    /// Opaque lease token returned by the host.
    pub lease_token: LeaseToken,
}

impl CredentialLeaseRelease {
    /// Build a lease release request.
    #[must_use]
    pub const fn new(credential_id: CredentialId, lease_token: LeaseToken) -> Self {
        Self {
            credential_id,
            lease_token,
        }
    }
}

/// Credential-scoped error class reported against a lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialErrorKind {
    /// Provider returned a rate-limit response.
    RateLimited,
    /// Provider reported exhausted quota.
    QuotaExhausted,
    /// Provider rejected authentication.
    AuthFailed,
    /// Provider returned another retryable credential-scoped failure.
    RetryableProviderError,
}

/// Connector report for a credential-scoped failure.
///
/// Reports carry only typed error classification and a sanitized retry hint.
/// Provider response bodies are deliberately excluded because they may contain
/// credential fragments or account-specific data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialErrorReport {
    /// Credential that produced the error.
    pub credential_id: CredentialId,
    /// Opaque lease token returned by the host.
    pub lease_token: LeaseToken,
    /// Credential-scoped failure class.
    pub kind: CredentialErrorKind,
    /// Sanitized provider retry hint in whole seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
}

impl CredentialErrorReport {
    /// Build an error report for a leased credential.
    #[must_use]
    pub const fn new(
        credential_id: CredentialId,
        lease_token: LeaseToken,
        kind: CredentialErrorKind,
    ) -> Self {
        Self {
            credential_id,
            lease_token,
            kind,
            retry_after_seconds: None,
        }
    }

    /// Attach a sanitized retry-after duration in seconds.
    #[must_use]
    pub const fn with_retry_after_seconds(mut self, retry_after_seconds: u64) -> Self {
        self.retry_after_seconds = Some(retry_after_seconds);
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Credential backend trait (mesh-native contract)
// ─────────────────────────────────────────────────────────────────────────────

/// Error from a credential backend operation.
#[derive(Debug)]
pub enum CredentialBackendError {
    /// Credential not found.
    NotFound { credential_id: CredentialId },
    /// Backend storage error.
    StorageError { message: String },
    /// Credential validation failed.
    Validation(CredentialValidationError),
}

impl fmt::Display for CredentialBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { credential_id } => {
                write!(f, "credential {credential_id} not found in backend")
            }
            Self::StorageError { message } => {
                write!(f, "credential backend storage error: {message}")
            }
            Self::Validation(inner) => write!(f, "credential validation: {inner}"),
        }
    }
}

impl std::error::Error for CredentialBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Validation(inner) => Some(inner),
            _ => None,
        }
    }
}

impl From<CredentialValidationError> for CredentialBackendError {
    fn from(err: CredentialValidationError) -> Self {
        Self::Validation(err)
    }
}

/// Mesh-native credential storage trait (NORMATIVE).
///
/// Any runtime (host, SDK, agent) that manages credentials MUST implement
/// this trait. The trait abstracts over the actual storage mechanism (in-memory,
/// database, vault, mesh-replicated store).
///
/// **Security contract:**
/// - Implementations MUST be zone-scoped: operations only see credentials
///   within the caller's zone.
/// - Implementations MUST NOT log or expose secret material.
/// - Implementations SHOULD audit all access via `AuditEvent`.
#[async_trait::async_trait]
pub trait CredentialBackend: Send + Sync {
    /// Retrieve a credential by ID within a zone.
    async fn get(
        &self,
        zone_id: &ZoneId,
        credential_id: &CredentialId,
    ) -> Result<CredentialObject, CredentialBackendError>;

    /// List all credentials within a zone.
    async fn list(&self, zone_id: &ZoneId)
    -> Result<Vec<CredentialObject>, CredentialBackendError>;

    /// Store or update a credential.
    async fn put(&self, credential: &CredentialObject) -> Result<(), CredentialBackendError>;

    /// Delete a credential by ID within a zone.
    async fn delete(
        &self,
        zone_id: &ZoneId,
        credential_id: &CredentialId,
    ) -> Result<(), CredentialBackendError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Provenance;
    use fcp_cbor::SchemaId;
    use semver::Version;

    fn test_header() -> ObjectHeader {
        ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.core", "CredentialObject", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_credential() -> CredentialObject {
        CredentialObject {
            header: test_header(),
            credential_id: CredentialId::new(),
            label: Some("api-key-prod".into()),
            secret_id: SecretId::new(),
            application: CredentialApplication::HttpAuthorizationBearer,
            host_allow: vec![],
            expires_at: None,
            description: Some("Production API key".into()),
            tags: vec!["prod".into(), "api".into()],
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialId Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_id_new_is_unique() {
        let id1 = CredentialId::new();
        let id2 = CredentialId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn credential_id_parse_roundtrip() {
        let id = CredentialId::new();
        let s = id.to_string();
        let parsed = CredentialId::parse(&s).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn credential_id_display_is_uuid() {
        let uuid = Uuid::from_bytes([0xCD; 16]);
        let id = CredentialId::from_uuid(uuid);
        assert_eq!(id.to_string(), uuid.to_string());
    }

    #[test]
    fn credential_id_serialization_roundtrip() {
        let id = CredentialId::new();
        let json = serde_json::to_string(&id).unwrap();
        let deserialized: CredentialId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, deserialized);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialApplication Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_application_serializes_tagged() {
        let bearer = CredentialApplication::HttpAuthorizationBearer;
        let json = serde_json::to_string(&bearer).unwrap();
        assert!(json.contains("\"type\":\"http_authorization_bearer\""));

        let header = CredentialApplication::HttpHeader {
            name: "X-API-Key".into(),
            prefix: Some("Key ".into()),
        };
        let json = serde_json::to_string(&header).unwrap();
        assert!(json.contains("\"type\":\"http_header\""));
        assert!(json.contains("\"name\":\"X-API-Key\""));
        assert!(json.contains("\"prefix\":\"Key \""));
    }

    #[test]
    fn credential_application_roundtrip() {
        let apps = vec![
            CredentialApplication::HttpAuthorizationBearer,
            CredentialApplication::HttpAuthorizationBasic,
            CredentialApplication::HttpHeader {
                name: "Authorization".into(),
                prefix: None,
            },
            CredentialApplication::QueryParameter {
                name: "api_key".into(),
            },
            CredentialApplication::TlsClientCertificate,
            CredentialApplication::SshKey,
            CredentialApplication::DatabaseConnection,
            CredentialApplication::WebSocketAuth,
            CredentialApplication::Generic {
                config: r#"{"custom": true}"#.into(),
            },
        ];

        for app in apps {
            let json = serde_json::to_string(&app).unwrap();
            let decoded: CredentialApplication = serde_json::from_str(&json).unwrap();
            assert_eq!(app, decoded);
        }
    }

    #[test]
    fn credential_lease_request_omits_empty_hints() {
        let credential_id = CredentialId::test_id([0x31; 16]);
        let request = CredentialLeaseRequest::new(credential_id);

        let json = serde_json::to_string(&request).unwrap();

        assert!(json.contains("credential_id"));
        assert!(!json.contains("provider"));
        assert!(!json.contains("operation"));
        let decoded: CredentialLeaseRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn credential_lease_request_preserves_hints() {
        let request = CredentialLeaseRequest::new(CredentialId::test_id([0x32; 16]))
            .with_provider("openai")
            .with_operation("chat.completions");

        let json = serde_json::to_string(&request).unwrap();
        let decoded: CredentialLeaseRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.provider.as_deref(), Some("openai"));
        assert_eq!(decoded.operation.as_deref(), Some("chat.completions"));
    }

    #[test]
    fn credential_lease_is_secretless_debug_and_serde() {
        let credential_id = CredentialId::test_id([0x33; 16]);
        let lease_handle = LeaseToken::new("lease:credential:test").unwrap();
        let lease = CredentialLease::new(credential_id, lease_handle.clone()).with_provider("groq");

        let debug = format!("{lease:?}");
        assert!(debug.contains("CredentialLease"));
        assert!(debug.contains("credential_id"));
        assert!(!debug.contains("api_key"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("sk-"));

        let release = lease.release_request();
        assert_eq!(release.credential_id, credential_id);
        assert_eq!(release.lease_token, lease_handle);

        let json = serde_json::to_string(&lease).unwrap();
        let decoded: CredentialLease = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, lease);
    }

    #[test]
    fn credential_error_report_roundtrips_retry_hint() {
        let report = CredentialErrorReport::new(
            CredentialId::test_id([0x34; 16]),
            LeaseToken::new("lease:credential:rate-limited").unwrap(),
            CredentialErrorKind::RateLimited,
        )
        .with_retry_after_seconds(30);

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"kind\":\"rate_limited\""));
        assert!(json.contains("\"retry_after_seconds\":30"));
        assert!(!json.contains("provider said"));
        assert!(!json.contains("sk-"));

        let decoded: CredentialErrorReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, report);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialObject Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_object_is_expired() {
        let mut cred = test_credential();
        cred.expires_at = Some(1_700_000_100);

        assert!(!cred.is_expired(1_700_000_000));
        assert!(!cred.is_expired(1_700_000_099));
        assert!(cred.is_expired(1_700_000_100));
        assert!(cred.is_expired(1_700_000_200));
    }

    #[test]
    fn credential_object_no_expiry_never_expires() {
        let cred = test_credential();
        assert!(!cred.is_expired(u64::MAX));
    }

    #[test]
    fn credential_object_host_allow_empty_allows_all() {
        let cred = test_credential();
        assert!(cred.is_host_allowed("api.example.com"));
        assert!(cred.is_host_allowed("anything.anywhere.net"));
        assert!(cred.is_host_allowed("localhost"));
    }

    #[test]
    fn credential_object_host_allow_exact_match() {
        let mut cred = test_credential();
        cred.host_allow = vec!["api.example.com".into(), "api.other.net".into()];

        assert!(cred.is_host_allowed("api.example.com"));
        assert!(cred.is_host_allowed("API.EXAMPLE.COM")); // case insensitive
        assert!(cred.is_host_allowed("api.other.net"));
        assert!(!cred.is_host_allowed("evil.com"));
        assert!(!cred.is_host_allowed("foo.api.example.com")); // no wildcard
    }

    #[test]
    fn credential_object_host_allow_wildcard() {
        let mut cred = test_credential();
        cred.host_allow = vec!["*.example.com".into()];

        assert!(cred.is_host_allowed("api.example.com"));
        assert!(cred.is_host_allowed("foo.example.com"));
        assert!(!cred.is_host_allowed("example.com")); // wildcard does not match base domain
        assert!(!cred.is_host_allowed("example.net"));
        assert!(!cred.is_host_allowed("notexample.com"));
    }

    #[test]
    fn credential_object_host_allow_with_port() {
        let mut cred = test_credential();
        cred.host_allow = vec!["api.example.com:443".into()];

        assert!(cred.is_host_allowed("api.example.com:443"));
        assert!(!cred.is_host_allowed("api.example.com:80"));
        assert!(!cred.is_host_allowed("api.example.com")); // port required
    }

    #[test]
    fn credential_object_is_usable() {
        let mut cred = test_credential();
        cred.expires_at = Some(1_700_000_100);
        cred.host_allow = vec!["api.example.com".into()];

        assert!(cred.is_usable(1_700_000_000, "api.example.com"));
        assert!(!cred.is_usable(1_700_000_000, "evil.com")); // host not allowed
        assert!(!cred.is_usable(1_700_000_200, "api.example.com")); // expired
    }

    #[test]
    fn credential_object_serialization_roundtrip() {
        let cred = CredentialObject {
            header: test_header(),
            credential_id: CredentialId::new(),
            label: Some("github-token".into()),
            secret_id: SecretId::new(),
            application: CredentialApplication::HttpHeader {
                name: "Authorization".into(),
                prefix: Some("token ".into()),
            },
            host_allow: vec!["api.github.com".into(), "*.githubusercontent.com".into()],
            expires_at: Some(1_800_000_000),
            description: Some("GitHub personal access token".into()),
            tags: vec!["github".into(), "vcs".into()],
        };

        let json = serde_json::to_string(&cred).unwrap();
        let decoded: CredentialObject = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.credential_id, cred.credential_id);
        assert_eq!(decoded.label.as_deref(), Some("github-token"));
        assert_eq!(decoded.host_allow.len(), 2);
        assert_eq!(decoded.tags.len(), 2);
    }

    #[test]
    fn credential_object_optional_fields_omitted() {
        let cred = CredentialObject {
            header: test_header(),
            credential_id: CredentialId::new(),
            label: None,
            secret_id: SecretId::new(),
            application: CredentialApplication::HttpAuthorizationBearer,
            host_allow: vec![],
            expires_at: None,
            description: None,
            tags: vec![],
        };

        let json = serde_json::to_string(&cred).unwrap();
        assert!(!json.contains("label"));
        assert!(!json.contains("host_allow"));
        assert!(!json.contains("expires_at"));
        assert!(!json.contains("description"));
        assert!(!json.contains("tags"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialValidationError Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_validation_error_display() {
        let cred_id = CredentialId::test_id([0x11; 16]);
        let secret_id = SecretId::test_id([0x22; 16]);

        let err = CredentialValidationError::Expired {
            credential_id: cred_id,
        };
        assert!(err.to_string().contains("expired"));

        let err = CredentialValidationError::HostNotAllowed {
            credential_id: cred_id,
            host: "evil.com".into(),
        };
        assert!(err.to_string().contains("evil.com"));
        assert!(err.to_string().contains("not in allowed list"));

        let err = CredentialValidationError::NotInCredentialAllow {
            credential_id: cred_id,
        };
        assert!(err.to_string().contains("credential_allow"));

        let err = CredentialValidationError::SecretNotFound { secret_id };
        assert!(err.to_string().contains("not found"));

        let err = CredentialValidationError::SecretRevoked { secret_id };
        assert!(err.to_string().contains("revoked"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IP Literal Detection Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn is_ip_literal_ipv4() {
        assert!(CredentialObject::is_ip_literal("192.168.1.1"));
        assert!(CredentialObject::is_ip_literal("10.0.0.1"));
        assert!(CredentialObject::is_ip_literal("127.0.0.1"));
        assert!(CredentialObject::is_ip_literal("0.0.0.0"));
        assert!(CredentialObject::is_ip_literal("255.255.255.255"));
    }

    #[test]
    fn is_ip_literal_ipv4_with_port() {
        assert!(CredentialObject::is_ip_literal("192.168.1.1:8080"));
        assert!(CredentialObject::is_ip_literal("10.0.0.1:443"));
        assert!(CredentialObject::is_ip_literal("127.0.0.1:80"));
    }

    #[test]
    fn is_ip_literal_ipv6() {
        assert!(CredentialObject::is_ip_literal("::1"));
        assert!(CredentialObject::is_ip_literal("::"));
        assert!(CredentialObject::is_ip_literal("fe80::1"));
        assert!(CredentialObject::is_ip_literal("2001:db8::1"));
        assert!(CredentialObject::is_ip_literal("::ffff:192.168.1.1"));
    }

    #[test]
    fn is_ip_literal_ipv6_with_brackets() {
        assert!(CredentialObject::is_ip_literal("[::1]"));
        assert!(CredentialObject::is_ip_literal("[::1]:8080"));
        assert!(CredentialObject::is_ip_literal("[2001:db8::1]:443"));
        // IPv6 zone IDs like [fe80::1%eth0] don't parse as valid IPs
        assert!(!CredentialObject::is_ip_literal("[fe80::1%eth0]"));
    }

    #[test]
    fn is_ip_literal_not_ip() {
        assert!(!CredentialObject::is_ip_literal("api.example.com"));
        assert!(!CredentialObject::is_ip_literal("localhost"));
        assert!(!CredentialObject::is_ip_literal("api.example.com:443"));
        assert!(!CredentialObject::is_ip_literal("*.example.com"));
        assert!(!CredentialObject::is_ip_literal("sub.domain.example.com"));
    }

    #[test]
    fn is_ip_literal_edge_cases() {
        // Invalid but not hostnames
        assert!(!CredentialObject::is_ip_literal("999.999.999.999")); // Invalid IPv4 - doesn't parse
        assert!(!CredentialObject::is_ip_literal(""));
        assert!(!CredentialObject::is_ip_literal(":"));
        assert!(!CredentialObject::is_ip_literal("[]"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Host Policy Validation Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn has_ip_literal_in_host_allow_detects_ipv4() {
        let mut cred = test_credential();
        cred.host_allow = vec!["192.168.1.1".into()];
        assert!(cred.has_ip_literal_in_host_allow());

        cred.host_allow = vec!["api.example.com".into(), "10.0.0.1:8080".into()];
        assert!(cred.has_ip_literal_in_host_allow());
    }

    #[test]
    fn has_ip_literal_in_host_allow_detects_ipv6() {
        let mut cred = test_credential();
        cred.host_allow = vec!["[::1]:8080".into()];
        assert!(cred.has_ip_literal_in_host_allow());

        cred.host_allow = vec!["::1".into()];
        assert!(cred.has_ip_literal_in_host_allow());
    }

    #[test]
    fn has_ip_literal_in_host_allow_no_ip() {
        let mut cred = test_credential();
        cred.host_allow = vec!["api.example.com".into(), "*.other.net".into()];
        assert!(!cred.has_ip_literal_in_host_allow());
    }

    #[test]
    fn has_ip_literal_in_host_allow_empty() {
        let cred = test_credential();
        assert!(!cred.has_ip_literal_in_host_allow());
    }

    #[test]
    fn validate_host_policy_allows_hostnames() {
        let mut cred = test_credential();
        cred.host_allow = vec!["api.example.com".into(), "*.other.net".into()];

        assert!(cred.validate_host_policy(true).is_ok());
        assert!(cred.validate_host_policy(false).is_ok());
    }

    #[test]
    fn validate_host_policy_rejects_ip_when_required() {
        let mut cred = test_credential();
        cred.host_allow = vec!["192.168.1.1".into()];

        // Should reject when reject_ip_literals is true
        let result = cred.validate_host_policy(true);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                &err,
                CredentialValidationError::HostNotAllowed { host, .. } if host == "192.168.1.1"
            ),
            "Expected HostNotAllowed error, got {err:?}"
        );

        // Should allow when reject_ip_literals is false
        assert!(cred.validate_host_policy(false).is_ok());
    }

    #[test]
    fn validate_host_policy_rejects_ipv6_when_required() {
        let mut cred = test_credential();
        cred.host_allow = vec!["api.example.com".into(), "[::1]:8080".into()];

        let result = cred.validate_host_policy(true);
        assert!(result.is_err());
    }

    #[test]
    fn validate_host_policy_empty_list_passes() {
        let cred = test_credential();
        assert!(cred.validate_host_policy(true).is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialId Canonicity Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_id_is_canonical_uuid() {
        let id = CredentialId::new();
        let s = id.to_string();

        // UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
        assert_eq!(s.len(), 36);
        assert_eq!(s.chars().filter(|c| *c == '-').count(), 4);

        // Verify it's lowercase (canonical)
        assert_eq!(s, s.to_lowercase());
    }

    #[test]
    fn credential_id_stable_display() {
        let bytes = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ];
        let id = CredentialId::test_id(bytes);

        // Display should be deterministic
        let s1 = id.to_string();
        let s2 = id.to_string();
        assert_eq!(s1, s2);

        // Display should be the canonical lowercase UUID
        assert_eq!(s1, "11223344-5566-7788-99aa-bbccddeeff00");
    }

    #[test]
    fn credential_id_parse_rejects_invalid() {
        assert!(CredentialId::parse("not-a-uuid").is_err());
        assert!(CredentialId::parse("").is_err());
        assert!(CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff0").is_err()); // too short
        assert!(CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff000").is_err()); // too long
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialId – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_id_copy() {
        let a = CredentialId::test_id([0x42; 16]);
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn credential_id_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        let id = CredentialId::test_id([0xAA; 16]);
        set.insert(id);
        set.insert(id);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn credential_id_ord() {
        let a = CredentialId::test_id([0x00; 16]);
        let b = CredentialId::test_id([0xFF; 16]);
        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn credential_id_default_is_unique() {
        let a = CredentialId::default();
        let b = CredentialId::default();
        assert_ne!(a, b);
    }

    #[test]
    fn credential_id_from_uuid_as_uuid_roundtrip() {
        let uuid = Uuid::from_bytes([0x12; 16]);
        let id = CredentialId::from_uuid(uuid);
        assert_eq!(*id.as_uuid(), uuid);
    }

    #[test]
    fn credential_id_debug_contains_uuid() {
        let id = CredentialId::test_id([0xAB; 16]);
        let dbg = format!("{id:?}");
        assert!(dbg.contains("CredentialId"));
        assert!(dbg.contains("abababab"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialApplication – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_application_clone() {
        let app = CredentialApplication::HttpHeader {
            name: "X-Token".into(),
            prefix: Some("Bearer ".into()),
        };
        let cloned = app.clone();
        assert_eq!(app, cloned);
    }

    #[test]
    fn credential_application_inequality() {
        assert_ne!(
            CredentialApplication::HttpAuthorizationBearer,
            CredentialApplication::HttpAuthorizationBasic,
        );
    }

    #[test]
    fn credential_application_http_header_no_prefix_serde() {
        let app = CredentialApplication::HttpHeader {
            name: "X-Key".into(),
            prefix: None,
        };
        let json = serde_json::to_string(&app).unwrap();
        assert!(!json.contains("prefix")); // skip_serializing_if = None
        let decoded: CredentialApplication = serde_json::from_str(&json).unwrap();
        assert_eq!(app, decoded);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialObject – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_object_clone() {
        let cred = test_credential();
        let cloned = cred.clone();
        assert_eq!(cloned.credential_id, cred.credential_id);
        assert_eq!(cloned.label, cred.label);
        assert_eq!(cloned.tags, cred.tags);
    }

    #[test]
    fn credential_object_zone_id() {
        let cred = test_credential();
        assert_eq!(*cred.zone_id(), ZoneId::work());
    }

    #[test]
    fn credential_object_wildcard_case_insensitive() {
        let mut cred = test_credential();
        cred.host_allow = vec!["*.EXAMPLE.COM".into()];
        assert!(cred.is_host_allowed("api.example.com"));
        assert!(cred.is_host_allowed("API.EXAMPLE.COM"));
    }

    #[test]
    fn credential_object_is_usable_no_expiry_no_host() {
        let cred = test_credential();
        // No expiry, no host restrictions → always usable
        assert!(cred.is_usable(u64::MAX, "any.host"));
    }

    #[test]
    fn credential_object_serde_all_fields_present() {
        let cred = CredentialObject {
            header: test_header(),
            credential_id: CredentialId::test_id([0x11; 16]),
            label: Some("labeled".into()),
            secret_id: SecretId::test_id([0x22; 16]),
            application: CredentialApplication::SshKey,
            host_allow: vec!["host.example.com".into()],
            expires_at: Some(1_800_000_000),
            description: Some("desc".into()),
            tags: vec!["tag1".into()],
        };
        let json = serde_json::to_string(&cred).unwrap();
        assert!(json.contains("label"));
        assert!(json.contains("host_allow"));
        assert!(json.contains("expires_at"));
        assert!(json.contains("description"));
        assert!(json.contains("tags"));
        let decoded: CredentialObject = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.credential_id, cred.credential_id);
        assert_eq!(decoded.tags, cred.tags);
    }

    #[test]
    fn credential_object_is_expired_at_exact_boundary() {
        let mut cred = test_credential();
        cred.expires_at = Some(1000);
        assert!(!cred.is_expired(999));
        assert!(cred.is_expired(1000));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialValidationError – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_validation_error_clone() {
        let err = CredentialValidationError::Expired {
            credential_id: CredentialId::test_id([0x11; 16]),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn credential_validation_error_equality() {
        let a = CredentialValidationError::NotInCredentialAllow {
            credential_id: CredentialId::test_id([0x11; 16]),
        };
        let b = CredentialValidationError::NotInCredentialAllow {
            credential_id: CredentialId::test_id([0x11; 16]),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn credential_validation_error_inequality() {
        let a = CredentialValidationError::Expired {
            credential_id: CredentialId::test_id([0x11; 16]),
        };
        let b = CredentialValidationError::NotInCredentialAllow {
            credential_id: CredentialId::test_id([0x11; 16]),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn credential_validation_error_is_error_trait() {
        let err: &dyn std::error::Error = &CredentialValidationError::Expired {
            credential_id: CredentialId::test_id([0x11; 16]),
        };
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn credential_id_parse_accepts_uppercase() {
        // UUID parsing should be case-insensitive
        let upper = CredentialId::parse("11223344-5566-7788-99AA-BBCCDDEEFF00");
        let lower = CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00");

        assert!(upper.is_ok());
        assert!(lower.is_ok());
        assert_eq!(upper.unwrap(), lower.unwrap());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialId – serde transparency & JSON shape
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_id_serde_transparent_is_bare_string() {
        let id = CredentialId::test_id([0x11; 16]);
        let json = serde_json::to_string(&id).unwrap();
        // Should be a bare quoted UUID string, not {"uuid": "..."}
        assert!(json.starts_with('"'));
        assert!(json.ends_with('"'));
        assert!(!json.contains('{'));
    }

    #[test]
    fn credential_id_deserialize_from_bare_string() {
        let json = r#""11111111-1111-1111-1111-111111111111""#;
        let id: CredentialId = serde_json::from_str(json).unwrap();
        assert_eq!(id.to_string(), "11111111-1111-1111-1111-111111111111");
    }

    #[test]
    fn credential_id_parse_rejects_whitespace() {
        assert!(CredentialId::parse(" 11223344-5566-7788-99aa-bbccddeeff00").is_err());
        assert!(CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00 ").is_err());
    }

    #[test]
    fn credential_id_parse_accepts_braces() {
        // UUID's parse_str accepts brace-wrapped format
        let result = CredentialId::parse("{11223344-5566-7788-99aa-bbccddeeff00}");
        assert!(result.is_ok());
        let expected = CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00").unwrap();
        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn credential_id_ord_total_order() {
        let a = CredentialId::test_id([0x00; 16]);
        let b = CredentialId::test_id([0x80; 16]);
        let c = CredentialId::test_id([0xFF; 16]);
        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
        // Reflexive: equal elements are not strictly ordered
        assert_eq!(a.cmp(&a), std::cmp::Ordering::Equal);
    }

    #[test]
    fn credential_id_hash_different_ids() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        let a = CredentialId::test_id([0x01; 16]);
        let b = CredentialId::test_id([0x02; 16]);
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialApplication – per-variant serde & debug coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_application_tls_serde_tag() {
        let app = CredentialApplication::TlsClientCertificate;
        let json = serde_json::to_string(&app).unwrap();
        assert!(json.contains("\"type\":\"tls_client_certificate\""));
        let decoded: CredentialApplication = serde_json::from_str(&json).unwrap();
        assert_eq!(app, decoded);
    }

    #[test]
    fn credential_application_ssh_key_serde_tag() {
        let app = CredentialApplication::SshKey;
        let json = serde_json::to_string(&app).unwrap();
        assert!(json.contains("\"type\":\"ssh_key\""));
    }

    #[test]
    fn credential_application_database_connection_serde_tag() {
        let app = CredentialApplication::DatabaseConnection;
        let json = serde_json::to_string(&app).unwrap();
        assert!(json.contains("\"type\":\"database_connection\""));
    }

    #[test]
    fn credential_application_websocket_auth_serde_tag() {
        let app = CredentialApplication::WebSocketAuth;
        let json = serde_json::to_string(&app).unwrap();
        assert!(json.contains("\"type\":\"web_socket_auth\""));
    }

    #[test]
    fn credential_application_query_parameter_serde_tag() {
        let app = CredentialApplication::QueryParameter {
            name: "token".into(),
        };
        let json = serde_json::to_string(&app).unwrap();
        assert!(json.contains("\"type\":\"query_parameter\""));
        assert!(json.contains("\"name\":\"token\""));
    }

    #[test]
    fn credential_application_generic_config_preserved() {
        let config_str = r#"{"method":"oauth2","scope":"read"}"#;
        let app = CredentialApplication::Generic {
            config: config_str.into(),
        };
        let json = serde_json::to_string(&app).unwrap();
        let decoded: CredentialApplication = serde_json::from_str(&json).unwrap();
        if let CredentialApplication::Generic { config } = decoded {
            assert_eq!(config, config_str);
        } else {
            panic!("Expected Generic variant");
        }
    }

    #[test]
    fn credential_application_debug_format() {
        let app = CredentialApplication::HttpAuthorizationBearer;
        let dbg = format!("{app:?}");
        assert!(dbg.contains("HttpAuthorizationBearer"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Host matching – edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn host_allow_wildcard_deep_subdomain() {
        let mut cred = test_credential();
        cred.host_allow = vec!["*.example.com".into()];
        // Multi-level subdomains should match *.example.com
        assert!(cred.is_host_allowed("a.b.example.com"));
        assert!(cred.is_host_allowed("deep.nested.sub.example.com"));
    }

    #[test]
    fn host_allow_wildcard_does_not_match_partial_suffix() {
        let mut cred = test_credential();
        cred.host_allow = vec!["*.example.com".into()];
        // "badexample.com" ends with "example.com" but not ".example.com"
        assert!(!cred.is_host_allowed("badexample.com"));
    }

    #[test]
    fn host_allow_multiple_patterns_any_match() {
        let mut cred = test_credential();
        cred.host_allow = vec![
            "api.example.com".into(),
            "*.internal.net".into(),
            "special.host:9090".into(),
        ];
        assert!(cred.is_host_allowed("api.example.com"));
        assert!(cred.is_host_allowed("svc.internal.net"));
        assert!(cred.is_host_allowed("special.host:9090"));
        assert!(!cred.is_host_allowed("other.com"));
    }

    #[test]
    fn host_allow_empty_host_string() {
        let mut cred = test_credential();
        cred.host_allow = vec!["api.example.com".into()];
        assert!(!cred.is_host_allowed(""));
    }

    #[test]
    fn host_allow_case_insensitive_exact_mixed() {
        let mut cred = test_credential();
        cred.host_allow = vec!["Api.Example.COM".into()];
        assert!(cred.is_host_allowed("api.example.com"));
        assert!(cred.is_host_allowed("API.EXAMPLE.COM"));
        assert!(cred.is_host_allowed("Api.Example.COM"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IP literal – additional edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn is_ip_literal_ipv6_full_form() {
        assert!(CredentialObject::is_ip_literal(
            "2001:0db8:0000:0000:0000:0000:0000:0001"
        ));
    }

    #[test]
    fn is_ip_literal_mapped_ipv4_in_brackets() {
        assert!(CredentialObject::is_ip_literal("[::ffff:192.168.1.1]"));
        assert!(CredentialObject::is_ip_literal("[::ffff:192.168.1.1]:443"));
    }

    #[test]
    fn is_ip_literal_rejects_hostname_with_numbers() {
        // Hostnames with numbers should not be detected as IP literals
        assert!(!CredentialObject::is_ip_literal("host123.example.com"));
        assert!(!CredentialObject::is_ip_literal("192.168.1.1.example.com"));
    }

    #[test]
    fn is_ip_literal_single_bracket_malformed() {
        // Malformed bracket syntax
        assert!(!CredentialObject::is_ip_literal("["));
        assert!(!CredentialObject::is_ip_literal("[not-ip]"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // has_ip_literal_in_host_allow – wildcard prefix stripping
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn has_ip_literal_detects_wildcard_prefixed_ip() {
        let mut cred = test_credential();
        // *.192.168.1.1 — wildcard prefix stripped, then IP detected
        cred.host_allow = vec!["*.192.168.1.1".into()];
        assert!(cred.has_ip_literal_in_host_allow());
    }

    #[test]
    fn has_ip_literal_ignores_wildcard_prefixed_hostname() {
        let mut cred = test_credential();
        cred.host_allow = vec!["*.sub.example.com".into()];
        assert!(!cred.has_ip_literal_in_host_allow());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // validate_host_policy – more coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn validate_host_policy_wildcard_ip_rejected() {
        let mut cred = test_credential();
        cred.host_allow = vec!["*.10.0.0.1".into()];
        let result = cred.validate_host_policy(true);
        assert!(result.is_err());
        if let Err(CredentialValidationError::HostNotAllowed { host, .. }) = result {
            assert_eq!(host, "*.10.0.0.1");
        } else {
            panic!("Expected HostNotAllowed");
        }
    }

    #[test]
    fn validate_host_policy_mixed_host_ip_rejects_on_first_ip() {
        let mut cred = test_credential();
        cred.host_allow = vec![
            "safe.example.com".into(),
            "172.16.0.1".into(),
            "also-safe.example.com".into(),
        ];
        let result = cred.validate_host_policy(true);
        assert!(result.is_err());
        if let Err(CredentialValidationError::HostNotAllowed { host, .. }) = result {
            assert_eq!(host, "172.16.0.1");
        } else {
            panic!("Expected HostNotAllowed");
        }
    }

    #[test]
    fn validate_host_policy_error_contains_credential_id() {
        let mut cred = test_credential();
        let cred_id = CredentialId::test_id([0xAA; 16]);
        cred.credential_id = cred_id;
        cred.host_allow = vec!["127.0.0.1".into()];

        let result = cred.validate_host_policy(true);
        if let Err(CredentialValidationError::HostNotAllowed { credential_id, .. }) = result {
            assert_eq!(credential_id, cred_id);
        } else {
            panic!("Expected HostNotAllowed");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // is_usable – combined conditions
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn is_usable_expired_and_host_disallowed() {
        let mut cred = test_credential();
        cred.expires_at = Some(1000);
        cred.host_allow = vec!["allowed.example.com".into()];

        // Both conditions fail: expired AND wrong host
        assert!(!cred.is_usable(2000, "evil.com"));
    }

    #[test]
    fn is_usable_not_expired_host_allowed() {
        let mut cred = test_credential();
        cred.expires_at = Some(5000);
        cred.host_allow = vec!["*.example.com".into()];

        assert!(cred.is_usable(1000, "api.example.com"));
    }

    #[test]
    fn is_usable_at_exact_expiry_boundary() {
        let mut cred = test_credential();
        cred.expires_at = Some(1000);
        cred.host_allow = vec!["api.example.com".into()];

        assert!(cred.is_usable(999, "api.example.com"));
        assert!(!cred.is_usable(1000, "api.example.com"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialObject deserialization – missing optional fields
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_object_deserialize_minimal_json() {
        // Serialize with all optional fields absent, then verify defaults
        let cred = CredentialObject {
            header: test_header(),
            credential_id: CredentialId::test_id([0x33; 16]),
            label: None,
            secret_id: SecretId::test_id([0x44; 16]),
            application: CredentialApplication::HttpAuthorizationBearer,
            host_allow: vec![],
            expires_at: None,
            description: None,
            tags: vec![],
        };
        let json = serde_json::to_string(&cred).unwrap();
        let decoded: CredentialObject = serde_json::from_str(&json).unwrap();
        assert!(decoded.label.is_none());
        assert!(decoded.host_allow.is_empty());
        assert!(decoded.expires_at.is_none());
        assert!(decoded.description.is_none());
        assert!(decoded.tags.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialValidationError – Display format precision
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_validation_error_expired_display_has_credential_id() {
        let cred_id = CredentialId::test_id([0x55; 16]);
        let err = CredentialValidationError::Expired {
            credential_id: cred_id,
        };
        let msg = err.to_string();
        assert!(msg.contains(&cred_id.to_string()));
        assert!(msg.contains("expired"));
    }

    #[test]
    fn credential_validation_error_not_in_allow_display_has_id() {
        let cred_id = CredentialId::test_id([0x66; 16]);
        let err = CredentialValidationError::NotInCredentialAllow {
            credential_id: cred_id,
        };
        let msg = err.to_string();
        assert!(msg.contains(&cred_id.to_string()));
    }

    #[test]
    fn credential_validation_error_secret_not_found_display_has_id() {
        let sid = SecretId::test_id([0x77; 16]);
        let err = CredentialValidationError::SecretNotFound { secret_id: sid };
        let msg = err.to_string();
        assert!(msg.contains(&sid.to_string()));
    }

    #[test]
    fn credential_validation_error_secret_revoked_display_has_id() {
        let sid = SecretId::test_id([0x88; 16]);
        let err = CredentialValidationError::SecretRevoked { secret_id: sid };
        let msg = err.to_string();
        assert!(msg.contains(&sid.to_string()));
    }

    #[test]
    fn credential_validation_error_host_not_allowed_display_has_both() {
        let cred_id = CredentialId::test_id([0x99; 16]);
        let err = CredentialValidationError::HostNotAllowed {
            credential_id: cred_id,
            host: "bad.host.com".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains(&cred_id.to_string()));
        assert!(msg.contains("bad.host.com"));
    }

    #[test]
    fn credential_validation_error_debug_format() {
        let err = CredentialValidationError::Expired {
            credential_id: CredentialId::test_id([0x11; 16]),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Expired"));
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn credential_validation_error_source_is_none() {
        let err = CredentialValidationError::Expired {
            credential_id: CredentialId::test_id([0x11; 16]),
        };
        // std::error::Error::source() should be None (no inner error)
        assert!(std::error::Error::source(&err).is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialId – structural & boundary tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_id_test_id_deterministic() {
        let a = CredentialId::test_id([0x01; 16]);
        let b = CredentialId::test_id([0x01; 16]);
        assert_eq!(a, b);
    }

    #[test]
    fn credential_id_test_id_different_bytes_differ() {
        let a = CredentialId::test_id([0x01; 16]);
        let b = CredentialId::test_id([0x02; 16]);
        assert_ne!(a, b);
    }

    #[test]
    fn credential_id_nil_uuid() {
        let nil = CredentialId::from_uuid(Uuid::nil());
        assert_eq!(nil.to_string(), "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn credential_id_max_uuid() {
        let max = CredentialId::from_uuid(Uuid::max());
        assert_eq!(max.to_string(), "ffffffff-ffff-ffff-ffff-ffffffffffff");
    }

    #[test]
    fn credential_id_size_is_uuid_size() {
        assert_eq!(
            std::mem::size_of::<CredentialId>(),
            std::mem::size_of::<Uuid>()
        );
    }

    #[test]
    fn credential_id_parse_nil_uuid() {
        let id = CredentialId::parse("00000000-0000-0000-0000-000000000000").unwrap();
        assert_eq!(*id.as_uuid(), Uuid::nil());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialObject – is_expired edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_object_is_expired_at_zero() {
        let mut cred = test_credential();
        cred.expires_at = Some(0);
        // Expired at time 0 means expired at any time >= 0
        assert!(cred.is_expired(0));
        assert!(cred.is_expired(1));
    }

    #[test]
    fn credential_object_is_expired_at_u64_max() {
        let mut cred = test_credential();
        cred.expires_at = Some(u64::MAX);
        assert!(!cred.is_expired(u64::MAX - 1));
        assert!(cred.is_expired(u64::MAX));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialObject – host matching refinements
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn host_allow_wildcard_single_char_subdomain() {
        let mut cred = test_credential();
        cred.host_allow = vec!["*.example.com".into()];
        assert!(cred.is_host_allowed("x.example.com"));
    }

    #[test]
    fn host_allow_exact_match_with_trailing_dot_no_match() {
        let mut cred = test_credential();
        cred.host_allow = vec!["api.example.com".into()];
        // Trailing dot is a different string
        assert!(!cred.is_host_allowed("api.example.com."));
    }

    #[test]
    fn host_allow_wildcard_hyphenated_subdomain() {
        let mut cred = test_credential();
        cred.host_allow = vec!["*.example.com".into()];
        assert!(cred.is_host_allowed("my-service.example.com"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialValidationError – clone & equality coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_validation_error_host_not_allowed_clone() {
        let err = CredentialValidationError::HostNotAllowed {
            credential_id: CredentialId::test_id([0xCC; 16]),
            host: "blocked.host".into(),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn credential_validation_error_secret_not_found_clone() {
        let err = CredentialValidationError::SecretNotFound {
            secret_id: SecretId::test_id([0xDD; 16]),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn credential_validation_error_secret_revoked_clone() {
        let err = CredentialValidationError::SecretRevoked {
            secret_id: SecretId::test_id([0xEE; 16]),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn credential_validation_error_all_sources_none() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(CredentialValidationError::Expired {
                credential_id: CredentialId::test_id([0x01; 16]),
            }),
            Box::new(CredentialValidationError::HostNotAllowed {
                credential_id: CredentialId::test_id([0x02; 16]),
                host: "h".into(),
            }),
            Box::new(CredentialValidationError::NotInCredentialAllow {
                credential_id: CredentialId::test_id([0x03; 16]),
            }),
            Box::new(CredentialValidationError::SecretNotFound {
                secret_id: SecretId::test_id([0x04; 16]),
            }),
            Box::new(CredentialValidationError::SecretRevoked {
                secret_id: SecretId::test_id([0x05; 16]),
            }),
        ];
        for err in &variants {
            assert!(err.source().is_none(), "source should be None for {err}");
        }
    }

    #[test]
    fn credential_validation_error_different_cred_ids_not_equal() {
        let a = CredentialValidationError::Expired {
            credential_id: CredentialId::test_id([0x11; 16]),
        };
        let b = CredentialValidationError::Expired {
            credential_id: CredentialId::test_id([0x22; 16]),
        };
        assert_ne!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CredentialBackendError tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_backend_error_not_found_display() {
        let err = CredentialBackendError::NotFound {
            credential_id: CredentialId::test_id([0x11; 16]),
        };
        let msg = err.to_string();
        assert!(msg.contains("not found"));
        assert!(msg.contains("backend"));
    }

    #[test]
    fn credential_backend_error_storage_display() {
        let err = CredentialBackendError::StorageError {
            message: "disk full".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("disk full"));
        assert!(msg.contains("storage error"));
    }

    #[test]
    fn credential_backend_error_validation_display() {
        let inner = CredentialValidationError::Expired {
            credential_id: CredentialId::test_id([0x22; 16]),
        };
        let err = CredentialBackendError::Validation(inner);
        let msg = err.to_string();
        assert!(msg.contains("validation"));
        assert!(msg.contains("expired"));
    }

    #[test]
    fn credential_backend_error_from_validation() {
        let inner = CredentialValidationError::Expired {
            credential_id: CredentialId::test_id([0x33; 16]),
        };
        let err: CredentialBackendError = inner.into();
        assert!(matches!(err, CredentialBackendError::Validation(_)));
    }

    #[test]
    fn credential_backend_error_source_not_found() {
        let err = CredentialBackendError::NotFound {
            credential_id: CredentialId::test_id([0x44; 16]),
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn credential_backend_error_source_storage() {
        let err = CredentialBackendError::StorageError {
            message: "io error".into(),
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn credential_backend_error_source_validation() {
        let inner = CredentialValidationError::Expired {
            credential_id: CredentialId::test_id([0x55; 16]),
        };
        let err = CredentialBackendError::Validation(inner);
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn credential_backend_error_debug_format() {
        let err = CredentialBackendError::NotFound {
            credential_id: CredentialId::test_id([0x66; 16]),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NotFound"));
    }
}
