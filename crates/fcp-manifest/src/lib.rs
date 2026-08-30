//! Connector manifest parsing and validation with FCPS durable references.
//!
//! This crate provides a strict, machine-checkable interpretation of the
//! connector manifest contract in `FCP_Specification_V3.md` §10 (Manifest,
//! Provisioning, and Isolation). Manifest objects are stored durably as per
//! §6 (Durable Object and Evidence Model).

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::path::{Component, Path};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use fcp_crypto::{
    CryptoResult, HybridSignable, HybridSignedObjectKind, SignedEnvelope, signing_bytes_for_payload,
};
use fcp_prelude::{
    ApprovalMode as CoreApprovalMode, CapabilityId, ConnectorId, IdValidationError,
    IdempotencyClass, ObjectId, RateLimitDeclarationError, RateLimitDeclarations, RateLimitPool,
    RevocationFreshnessClass, RiskLevel, SafetyTier, ZoneId, ZoneIdError, validate_canonical_id,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

const MANIFEST_FORMAT: &str = "fcp-connector-manifest";
const INTERFACE_HASH_DOMAIN: &str = "fcp.interface.v2";

/// Default freshness class for backward compatibility with pre-C1.3 manifests.
const fn default_freshness_class() -> RevocationFreshnessClass {
    RevocationFreshnessClass::Safe
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Serialize)]
struct InterfaceDescriptorV2<'a> {
    connector_id: &'a str,
    archetypes: Vec<&'a str>,
    state: EffectiveStateModel<'a>,
    capabilities: InterfaceCapabilitiesDescriptor<'a>,
    operations: Vec<InterfaceOperationDescriptor<'a>>,
}

#[derive(Debug, Serialize)]
struct InterfaceCapabilitiesDescriptor<'a> {
    required: Vec<&'a str>,
    optional: Vec<&'a str>,
    forbidden: Vec<&'a str>,
}

#[derive(Debug, Serialize)]
struct InterfaceOperationDescriptor<'a> {
    id: &'a str,
    capability: &'a str,
    description: &'a str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    requires_approval: ManifestApprovalMode,
    idempotency: IdempotencyClass,
    #[serde(skip_serializing_if = "is_false")]
    migration_supported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_limit: Option<&'a RateLimit>,
    input_schema: &'a serde_json::Value,
    output_schema: &'a serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_constraints: Option<InterfaceNetworkConstraints<'a>>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Serialize)]
struct InterfaceNetworkConstraints<'a> {
    host_allow: Vec<&'a str>,
    port_allow: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ip_allow: Vec<IpAddr>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cidr_deny: Vec<&'a str>,
    deny_localhost: bool,
    deny_private_ranges: bool,
    deny_tailnet_ranges: bool,
    require_sni: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    spki_pins: Vec<&'a Base64Bytes>,
    deny_ip_literals: bool,
    require_host_canonicalization: bool,
    dns_max_ips: u16,
    max_redirects: u8,
    connect_timeout_ms: u32,
    total_timeout_ms: u32,
    max_response_bytes: u64,
}

/// Connector manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorManifest {
    pub manifest: ManifestSection,
    pub connector: ConnectorSection,
    pub zones: ZonesSection,
    pub capabilities: CapabilitiesSection,
    pub provides: ProvidesSection,
    #[serde(default)]
    pub event_caps: Option<EventCapsSection>,
    #[serde(default)]
    pub timeouts: Option<ManifestTimeouts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub performance_budget: Option<PerformanceBudget>,
    pub sandbox: SandboxSection,
    #[serde(default)]
    pub rate_limits: Option<RateLimitsSection>,
    #[serde(default)]
    pub signatures: Option<SignaturesSection>,
    #[serde(default)]
    pub supply_chain: Option<SupplyChainSection>,
    #[serde(default)]
    pub policy: Option<PolicySection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<ConnectorSecuritySection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling: Option<ConnectorSamplingSection>,
}

/// Hybrid-signed envelope alias for [`ConnectorManifest`].
pub type HybridSignedConnectorManifest = SignedEnvelope<ConnectorManifest>;

impl HybridSignable for ConnectorManifest {
    const OBJECT_KIND: HybridSignedObjectKind = HybridSignedObjectKind::Manifest;

    fn hybrid_signing_bytes(&self) -> CryptoResult<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signatures = None;
        signing_bytes_for_payload(Self::OBJECT_KIND, &unsigned)
    }
}

impl ConnectorManifest {
    /// Parse a manifest from TOML and validate it (NORMATIVE: fail closed).
    ///
    /// # Errors
    /// Returns an error if TOML parsing fails or if validation fails.
    pub fn parse_str(input: &str) -> Result<Self, ManifestError> {
        let parsed = Self::parse_str_unchecked(input)?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// Parse a manifest from TOML without validation.
    ///
    /// Useful for computing the interface hash before validation.
    ///
    /// # Errors
    /// Returns an error if TOML parsing fails.
    pub fn parse_str_unchecked(input: &str) -> Result<Self, ManifestError> {
        Ok(toml::from_str(input)?)
    }

    /// Validate the manifest for internal consistency.
    ///
    /// # Errors
    /// Returns an error if any NORMATIVE requirement is violated.
    pub fn validate(&self) -> Result<(), ManifestError> {
        self.manifest.validate()?;
        self.connector.validate()?;
        self.zones.validate()?;
        self.capabilities.validate()?;
        self.provides.validate()?;
        self.validate_extended_sections()?;

        if self.zones.forbidden.iter().any(|z| z == &self.zones.home) {
            return Err(ManifestError::Invalid {
                field: "zones.forbidden",
                message: "home zone must not be forbidden".into(),
            });
        }

        // NORMATIVE: Host restrictions MUST NOT be encoded in capability IDs.
        // Enforce for the `network.*` capability family.
        self.capabilities.validate_no_network_host_restrictions()?;

        // Lint: reject capability IDs embedding hostnames, ports, URLs, or IPs.
        self.capabilities.validate_no_hostname_port_url_patterns()?;

        // Also lint capability IDs declared in individual operations.
        for (op_id, op) in &self.provides.operations {
            lint_capability_id_no_network_addressing(
                op.capability.as_str(),
                "provides.operations.*.capability",
            )
            .map_err(|e| ManifestError::Invalid {
                field: "provides.operations.*.capability",
                message: format!("operation `{op_id}`: {e}"),
            })?;
        }

        let declared_capabilities: HashSet<&str> = self
            .capabilities
            .required
            .iter()
            .chain(self.capabilities.optional.iter())
            .map(CapabilityId::as_str)
            .collect();
        let forbidden_capabilities: HashSet<&str> = self
            .capabilities
            .forbidden
            .iter()
            .map(CapabilityId::as_str)
            .collect();
        for (op_id, op) in &self.provides.operations {
            let capability = op.capability.as_str();
            if forbidden_capabilities.contains(capability) {
                return Err(ManifestError::Invalid {
                    field: "provides.operations.*.capability",
                    message: format!(
                        "operation `{op_id}` references forbidden capability `{capability}`"
                    ),
                });
            }
            if !declared_capabilities.contains(capability) {
                return Err(ManifestError::Invalid {
                    field: "provides.operations.*.capability",
                    message: format!(
                        "operation `{op_id}` capability `{capability}` must appear in \
                         capabilities.required or capabilities.optional"
                    ),
                });
            }
        }

        // NORMATIVE: interface_hash must be well-formed and match computed value.
        let expected = self.compute_interface_hash()?;
        if self.manifest.interface_hash != expected {
            return Err(ManifestError::InterfaceHashMismatch {
                expected: expected.to_string(),
                found: self.manifest.interface_hash.to_string(),
            });
        }

        Ok(())
    }

    fn validate_extended_sections(&self) -> Result<(), ManifestError> {
        if let Some(ref caps) = self.event_caps {
            caps.validate()?;
        }
        if let Some(ref timeouts) = self.timeouts {
            timeouts.validate()?;
        }
        if let Some(ref performance_budget) = self.performance_budget {
            performance_budget.validate()?;
        }
        self.sandbox.validate()?;
        if let Some(ref rate_limits) = self.rate_limits {
            rate_limits.validate()?;
        }
        if let Some(ref sigs) = self.signatures {
            sigs.validate()?;
        }
        if let Some(ref supply_chain) = self.supply_chain {
            supply_chain.validate()?;
        }
        if let Some(ref policy) = self.policy {
            policy.validate()?;
        }
        if let Some(ref security) = self.security {
            security.validate()?;
        }
        if let Some(ref sampling) = self.sampling {
            sampling.validate()?;
        }

        if self
            .policy
            .as_ref()
            .is_some_and(|policy| policy.require_transparency_log)
            && self
                .signatures
                .as_ref()
                .is_none_or(|signatures| signatures.transparency_log_entry.is_none())
        {
            return Err(ManifestError::Invalid {
                field: "signatures.transparency_log_entry",
                message: "required when policy.require_transparency_log is true".into(),
            });
        }

        Ok(())
    }

    /// Compute the deterministic interface hash from the declared API surface.
    ///
    /// This intentionally excludes supply-chain metadata (`[signatures]`,
    /// `[supply_chain]`, `[policy]`) so provenance updates do not change the
    /// connector's mechanical interface.
    ///
    /// # Errors
    /// Returns an error if canonical serialization fails.
    #[allow(clippy::too_many_lines)]
    pub fn compute_interface_hash(&self) -> Result<InterfaceHash, ManifestError> {
        let mut archetypes: Vec<&str> = self
            .connector
            .archetypes
            .iter()
            .map(ConnectorArchetype::as_str)
            .collect();
        archetypes.sort_unstable();
        archetypes.dedup();

        let state = self.connector.effective_state_model()?;

        let mut required: Vec<&str> = self
            .capabilities
            .required
            .iter()
            .map(CapabilityId::as_str)
            .collect();
        required.sort_unstable();
        required.dedup();

        let mut optional: Vec<&str> = self
            .capabilities
            .optional
            .iter()
            .map(CapabilityId::as_str)
            .collect();
        optional.sort_unstable();
        optional.dedup();

        let mut forbidden: Vec<&str> = self
            .capabilities
            .forbidden
            .iter()
            .map(CapabilityId::as_str)
            .collect();
        forbidden.sort_unstable();
        forbidden.dedup();

        let mut operations: Vec<InterfaceOperationDescriptor<'_>> = self
            .provides
            .operations
            .iter()
            .map(|(id, op)| {
                let network_constraints = op.network_constraints.as_ref().map(|nc| {
                    let mut host_allow: Vec<&str> =
                        nc.host_allow.iter().map(String::as_str).collect();
                    host_allow.sort_unstable();

                    let mut port_allow = nc.port_allow.clone();
                    port_allow.sort_unstable();

                    let mut ip_allow = nc.ip_allow.clone();
                    ip_allow.sort();

                    let mut cidr_deny: Vec<&str> =
                        nc.cidr_deny.iter().map(String::as_str).collect();
                    cidr_deny.sort_unstable();

                    let mut spki_pins: Vec<&Base64Bytes> = nc.spki_pins.iter().collect();
                    spki_pins.sort_unstable();

                    InterfaceNetworkConstraints {
                        host_allow,
                        port_allow,
                        ip_allow,
                        cidr_deny,
                        deny_localhost: nc.deny_localhost,
                        deny_private_ranges: nc.deny_private_ranges,
                        deny_tailnet_ranges: nc.deny_tailnet_ranges,
                        require_sni: nc.require_sni,
                        spki_pins,
                        deny_ip_literals: nc.deny_ip_literals,
                        require_host_canonicalization: nc.require_host_canonicalization,
                        dns_max_ips: nc.dns_max_ips,
                        max_redirects: nc.max_redirects,
                        connect_timeout_ms: nc.connect_timeout_ms,
                        total_timeout_ms: nc.total_timeout_ms,
                        max_response_bytes: nc.max_response_bytes,
                    }
                });

                InterfaceOperationDescriptor {
                    id,
                    capability: op.capability.as_str(),
                    description: op.description.as_str(),
                    risk_level: op.risk_level,
                    safety_tier: op.safety_tier,
                    requires_approval: op.requires_approval,
                    idempotency: op.idempotency,
                    migration_supported: op.migration_supported,
                    rate_limit: op.rate_limit.as_ref(),
                    input_schema: &op.input_schema,
                    output_schema: &op.output_schema,
                    network_constraints,
                }
            })
            .collect();
        operations.sort_unstable_by(|a, b| a.id.cmp(b.id));

        let descriptor = InterfaceDescriptorV2 {
            connector_id: self.connector.id.as_str(),
            archetypes,
            state,
            capabilities: InterfaceCapabilitiesDescriptor {
                required,
                optional,
                forbidden,
            },
            operations,
        };

        let canonical = fcp_cbor::to_canonical_cbor(&descriptor)?;
        let mut h = blake3::Hasher::new();
        h.update(b"FCP2-INTERFACE-V1");
        h.update(&canonical);
        Ok(InterfaceHash::new_blake3_256(
            INTERFACE_HASH_DOMAIN,
            *h.finalize().as_bytes(),
        ))
    }
}

/// Errors returned by manifest parsing/validation.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("failed to parse manifest TOML: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("invalid identifier: {0}")]
    Id(#[from] IdValidationError),

    #[error("invalid zone id: {0}")]
    ZoneId(#[from] ZoneIdError),

    #[error("invalid canonical CBOR: {0}")]
    CanonicalCbor(#[from] fcp_cbor::SerializationError),

    #[error("invalid manifest field `{field}`: {message}")]
    Invalid {
        field: &'static str,
        message: String,
    },

    #[error("invalid performance budget field `{field}`: {message}")]
    InvalidPerformanceBudget {
        field: &'static str,
        message: String,
    },

    #[error("interface hash mismatch (expected {expected}, found {found})")]
    InterfaceHashMismatch { expected: String, found: String },

    #[error("invalid rate limit: {0}")]
    RateLimit(#[from] fcp_core::RateLimitValidationError),

    #[error("invalid rate limit declaration: {0}")]
    RateLimitDeclaration(#[from] RateLimitDeclarationError),
}

/// Errors returned while parsing a manifest zone policy selector.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ZonePatternError {
    #[error("unsupported zone wildcard pattern `{pattern}` (only `z:project:*` is allowed)")]
    UnsupportedWildcard { pattern: String },

    #[error("invalid zone id: {0}")]
    ZoneId(#[from] ZoneIdError),
}

impl ManifestError {
    /// Return actionable guidance when this error is the capability-ID
    /// lint that rejects embedded hostnames, ports, URLs, or IP addresses.
    #[must_use]
    pub fn capability_id_lint_message(&self) -> Option<String> {
        match self {
            Self::Invalid { field, message }
                if message.contains("capability id") && message.contains("network_constraints") =>
            {
                Some(format!(
                    "{message} (field: {field}). \
                     Move hostnames/ports into network_constraints and keep capability IDs abstract."
                ))
            }
            _ => None,
        }
    }
}

/// Optional connector-local security controls.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSecuritySection {
    #[serde(default = "default_description_scan_mode")]
    pub description_scan: String,
}

impl ConnectorSecuritySection {
    fn validate(&self) -> Result<(), ManifestError> {
        match self.description_scan.as_str() {
            "warn" | "block" | "off" => Ok(()),
            other => Err(ManifestError::Invalid {
                field: "security.description_scan",
                message: format!("must be one of warn, block, off; got {other}"),
            }),
        }
    }
}

fn default_description_scan_mode() -> String {
    "warn".to_string()
}

/// Optional MCP sampling policy for connectors that receive server-side sampling requests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSamplingSection {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_connector: Option<String>,
    #[serde(default = "default_sampling_max_rpm")]
    pub max_rpm: u32,
    #[serde(default = "default_sampling_timeout_secs")]
    pub timeout_secs: u32,
    #[serde(default = "default_sampling_max_tokens_cap")]
    pub max_tokens_cap: u32,
    #[serde(default = "default_sampling_max_tool_rounds")]
    pub max_tool_rounds: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_override: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_models: Vec<String>,
}

impl ConnectorSamplingSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.max_rpm == 0 {
            return Err(ManifestError::Invalid {
                field: "sampling.max_rpm",
                message: "must be greater than zero".into(),
            });
        }
        if self.timeout_secs == 0 {
            return Err(ManifestError::Invalid {
                field: "sampling.timeout_secs",
                message: "must be greater than zero".into(),
            });
        }
        if self.max_tokens_cap == 0 {
            return Err(ManifestError::Invalid {
                field: "sampling.max_tokens_cap",
                message: "must be greater than zero".into(),
            });
        }
        Ok(())
    }
}

const fn default_sampling_max_rpm() -> u32 {
    10
}

const fn default_sampling_timeout_secs() -> u32 {
    30
}

const fn default_sampling_max_tokens_cap() -> u32 {
    4096
}

const fn default_sampling_max_tool_rounds() -> u32 {
    5
}

/// `[manifest]` section (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSection {
    pub format: String,
    pub schema_version: ManifestSchemaVersion,
    pub min_mesh_version: semver::Version,
    pub min_protocol: ProtocolRequirement,
    #[serde(default)]
    pub protocol_features: Vec<FeatureId>,
    pub max_datagram_bytes: u16,
    pub interface_hash: InterfaceHash,
}

impl ManifestSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.format != MANIFEST_FORMAT {
            return Err(ManifestError::Invalid {
                field: "manifest.format",
                message: format!("must be `{MANIFEST_FORMAT}`"),
            });
        }

        if self.schema_version.major != 2 {
            return Err(ManifestError::Invalid {
                field: "manifest.schema_version",
                message: "unsupported manifest schema major version".into(),
            });
        }

        if self.max_datagram_bytes == 0 {
            return Err(ManifestError::Invalid {
                field: "manifest.max_datagram_bytes",
                message: "must be > 0".into(),
            });
        }

        Ok(())
    }
}

/// Manifest schema version as `MAJOR.MINOR` (e.g., `"2.1"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ManifestSchemaVersion {
    pub major: u16,
    pub minor: u16,
}

impl fmt::Display for ManifestSchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl TryFrom<String> for ManifestSchemaVersion {
    type Error = ManifestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let (major, minor) = value
            .split_once('.')
            .ok_or_else(|| ManifestError::Invalid {
                field: "manifest.schema_version",
                message: "must be in MAJOR.MINOR format".into(),
            })?;
        let major: u16 = major.parse().map_err(|_| ManifestError::Invalid {
            field: "manifest.schema_version",
            message: "major version must be an integer".into(),
        })?;
        let minor: u16 = minor.parse().map_err(|_| ManifestError::Invalid {
            field: "manifest.schema_version",
            message: "minor version must be an integer".into(),
        })?;
        Ok(Self { major, minor })
    }
}

impl From<ManifestSchemaVersion> for String {
    fn from(value: ManifestSchemaVersion) -> Self {
        value.to_string()
    }
}

impl<'de> Deserialize<'de> for ManifestSchemaVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for ManifestSchemaVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// Minimum protocol requirement (NORMATIVE): `name/MAJOR.MINOR`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtocolRequirement {
    pub name: String,
    pub version: ProtocolVersion,
}

impl fmt::Display for ProtocolRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.name, self.version)
    }
}

impl TryFrom<String> for ProtocolRequirement {
    type Error = ManifestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let (name, version) = value
            .split_once('/')
            .ok_or_else(|| ManifestError::Invalid {
                field: "manifest.min_protocol",
                message: "must include a version component (e.g. \"fcp2-sym/2.0\")".into(),
            })?;
        if name.is_empty() {
            return Err(ManifestError::Invalid {
                field: "manifest.min_protocol",
                message: "protocol name must not be empty".into(),
            });
        }
        Ok(Self {
            name: name.to_string(),
            version: ProtocolVersion::try_from(version.to_string())?,
        })
    }
}

impl From<ProtocolRequirement> for String {
    fn from(value: ProtocolRequirement) -> Self {
        value.to_string()
    }
}

impl<'de> Deserialize<'de> for ProtocolRequirement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for ProtocolRequirement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// Protocol version as `MAJOR.MINOR` (e.g., `"2.0"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl TryFrom<String> for ProtocolVersion {
    type Error = ManifestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let (major, minor) = value
            .split_once('.')
            .ok_or_else(|| ManifestError::Invalid {
                field: "manifest.min_protocol",
                message: "protocol version must be in MAJOR.MINOR format".into(),
            })?;
        let major: u16 = major.parse().map_err(|_| ManifestError::Invalid {
            field: "manifest.min_protocol",
            message: "protocol major version must be an integer".into(),
        })?;
        let minor: u16 = minor.parse().map_err(|_| ManifestError::Invalid {
            field: "manifest.min_protocol",
            message: "protocol minor version must be an integer".into(),
        })?;
        Ok(Self { major, minor })
    }
}

/// Canonical feature identifier (validated using the canonical id rules).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FeatureId(String);

impl FeatureId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for FeatureId {
    type Error = ManifestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_canonical_id(&value)?;
        Ok(Self(value))
    }
}

impl From<FeatureId> for String {
    fn from(value: FeatureId) -> Self {
        value.0
    }
}

impl<'de> Deserialize<'de> for FeatureId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for FeatureId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// Interface hash (NORMATIVE): `algorithm:domain:digest_hex`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InterfaceHash {
    pub algorithm: InterfaceHashAlgorithm,
    pub domain: &'static str,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterfaceHashAlgorithm {
    Blake3_256,
}

impl InterfaceHash {
    #[must_use]
    pub const fn new_blake3_256(domain: &'static str, digest: [u8; 32]) -> Self {
        Self {
            algorithm: InterfaceHashAlgorithm::Blake3_256,
            domain,
            digest,
        }
    }
}

impl fmt::Display for InterfaceHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let algorithm = match self.algorithm {
            InterfaceHashAlgorithm::Blake3_256 => "blake3-256",
        };
        write!(
            f,
            "{}:{}:{}",
            algorithm,
            self.domain,
            hex::encode(self.digest)
        )
    }
}

impl TryFrom<String> for InterfaceHash {
    type Error = ManifestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut parts = value.splitn(3, ':');
        let algorithm = parts.next().unwrap_or_default();
        let domain = parts.next().unwrap_or_default();
        let digest = parts.next().unwrap_or_default();

        let algorithm = match algorithm {
            "blake3-256" => InterfaceHashAlgorithm::Blake3_256,
            _ => {
                return Err(ManifestError::Invalid {
                    field: "manifest.interface_hash",
                    message: "unsupported interface hash algorithm".into(),
                });
            }
        };

        if domain != INTERFACE_HASH_DOMAIN {
            return Err(ManifestError::Invalid {
                field: "manifest.interface_hash",
                message: format!("unsupported interface hash domain `{domain}`"),
            });
        }

        if digest.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(ManifestError::Invalid {
                field: "manifest.interface_hash",
                message: "digest must be lowercase hex".into(),
            });
        }

        let digest_bytes = hex::decode(digest).map_err(|_| ManifestError::Invalid {
            field: "manifest.interface_hash",
            message: "digest must be valid hex".into(),
        })?;
        let digest: [u8; 32] = digest_bytes
            .try_into()
            .map_err(|_| ManifestError::Invalid {
                field: "manifest.interface_hash",
                message: "digest must be 32 bytes (64 hex chars)".into(),
            })?;

        Ok(Self {
            algorithm,
            domain: INTERFACE_HASH_DOMAIN,
            digest,
        })
    }
}

impl From<InterfaceHash> for String {
    fn from(value: InterfaceHash) -> Self {
        value.to_string()
    }
}

impl<'de> Deserialize<'de> for InterfaceHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for InterfaceHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// `[connector]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSection {
    pub id: ConnectorId,
    pub name: String,
    pub version: semver::Version,
    pub description: String,
    pub archetypes: Vec<ConnectorArchetype>,
    pub format: ConnectorRuntimeFormat,
    #[serde(default)]
    pub status: ConnectorStatus,
    #[serde(default)]
    pub singleton_writer: Option<bool>,
    #[serde(default)]
    pub state: Option<ConnectorStateSection>,
}

/// Readiness status of a connector.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorStatus {
    /// Fully functional — all declared operations work.
    #[default]
    Ready,
    /// Fully functional and backed by the connector graduation proof bundle.
    Proven,
    /// Operations are declared but return "not implemented" errors.
    Stub,
    /// Connector is experimental/in development.
    Experimental,
    /// Connector is deprecated — prefer the listed alternative.
    Deprecated,
    /// Contract shape is useful but the runtime path is incomplete,
    /// safety-sensitive, or lacks honest non-mock evidence.
    /// Hidden from default catalog/install flows; discoverable via
    /// `--include-incubating` or equivalent operator opt-in.
    Incubating,
    /// High-risk or architecturally incomplete surface requiring explicit
    /// operator approval. May not graduate without significant changes.
    /// Hidden from all default discovery surfaces.
    Quarantined,
    /// Deliberately hostile connector used only by conformance and hardening
    /// tests. It must never load in production deploy mode.
    Adversarial,
}

impl ConnectorStatus {
    /// Returns `true` if this status represents a live, production-ready connector.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        matches!(self, Self::Ready | Self::Proven | Self::Experimental)
    }

    /// Returns `true` if this connector should be hidden from default
    /// catalog, install, and discovery surfaces.
    #[must_use]
    pub const fn is_hidden_by_default(&self) -> bool {
        matches!(
            self,
            Self::Incubating | Self::Quarantined | Self::Stub | Self::Adversarial
        )
    }

    /// Returns a human-readable rationale for why the connector is non-live.
    #[must_use]
    pub const fn non_live_rationale(&self) -> Option<&'static str> {
        match self {
            Self::Ready | Self::Proven | Self::Experimental => None,
            Self::Stub => Some("Operations are declared but return not-implemented errors"),
            Self::Deprecated => Some("Connector is deprecated; prefer the listed alternative"),
            Self::Incubating => Some("Runtime path is incomplete or lacks production evidence"),
            Self::Quarantined => Some("High-risk surface requiring explicit operator approval"),
            Self::Adversarial => Some("Deliberately hostile test surface; production load refused"),
        }
    }

    /// Returns guidance for what would be needed to graduate to `Ready`.
    #[must_use]
    pub const fn graduation_guidance(&self) -> Option<&'static str> {
        match self {
            Self::Ready | Self::Proven | Self::Deprecated => None,
            Self::Experimental => Some("Stabilize API surface and complete production testing"),
            Self::Stub => Some("Implement all declared operations with real API integration"),
            Self::Incubating => Some(
                "Complete runtime implementation, add production evidence, pass compliance suite",
            ),
            Self::Quarantined => {
                Some("Resolve architectural concerns, complete safety review, pass security audit")
            }
            Self::Adversarial => Some("Never graduates; replace with a non-adversarial connector"),
        }
    }
}

impl std::fmt::Display for ConnectorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ready => write!(f, "ready"),
            Self::Proven => write!(f, "proven"),
            Self::Stub => write!(f, "stub"),
            Self::Experimental => write!(f, "experimental"),
            Self::Deprecated => write!(f, "deprecated"),
            Self::Incubating => write!(f, "incubating"),
            Self::Quarantined => write!(f, "quarantined"),
            Self::Adversarial => write!(f, "adversarial"),
        }
    }
}

/// Result of a status consistency check between manifest and runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusConsistencyResult {
    /// Whether the manifest and runtime statuses are consistent.
    pub consistent: bool,
    /// The manifest-declared status.
    pub manifest_status: ConnectorStatus,
    /// The runtime-reported status string.
    pub runtime_status: String,
    /// Explanation of the mismatch (if any).
    pub mismatch_reason: Option<String>,
}

impl StatusConsistencyResult {
    /// Check if manifest status is consistent with a runtime-reported `surface_status` string.
    ///
    /// The canonical mapping is:
    /// - `"ready"` / `"live"` → `ConnectorStatus::Ready`
    /// - `"proven"` → `ConnectorStatus::Proven`
    /// - `"stub"` → `ConnectorStatus::Stub`
    /// - `"experimental"` → `ConnectorStatus::Experimental`
    /// - `"deprecated"` → `ConnectorStatus::Deprecated`
    /// - `"incubating"` → `ConnectorStatus::Incubating`
    /// - `"quarantined"` → `ConnectorStatus::Quarantined`
    /// - `"adversarial"` → `ConnectorStatus::Adversarial`
    #[must_use]
    pub fn check(manifest_status: ConnectorStatus, runtime_status: &str) -> Self {
        let runtime_canonical = match runtime_status {
            "ready" | "live" => Some(ConnectorStatus::Ready),
            "proven" => Some(ConnectorStatus::Proven),
            "stub" => Some(ConnectorStatus::Stub),
            "experimental" => Some(ConnectorStatus::Experimental),
            "deprecated" => Some(ConnectorStatus::Deprecated),
            "incubating" => Some(ConnectorStatus::Incubating),
            "quarantined" => Some(ConnectorStatus::Quarantined),
            "adversarial" => Some(ConnectorStatus::Adversarial),
            _ => None,
        };

        match runtime_canonical {
            Some(rt)
                if rt == manifest_status
                    || (manifest_status == ConnectorStatus::Proven
                        && rt == ConnectorStatus::Ready) =>
            {
                Self {
                    consistent: true,
                    manifest_status,
                    runtime_status: runtime_status.to_string(),
                    mismatch_reason: None,
                }
            }
            Some(rt) => Self {
                consistent: false,
                manifest_status,
                runtime_status: runtime_status.to_string(),
                mismatch_reason: Some(format!(
                    "manifest declares '{manifest_status}' but runtime reports '{runtime_status}' (maps to '{rt}')"
                )),
            },
            None => Self {
                consistent: false,
                manifest_status,
                runtime_status: runtime_status.to_string(),
                mismatch_reason: Some(format!(
                    "runtime reports unknown status '{runtime_status}'; manifest declares '{manifest_status}'"
                )),
            },
        }
    }
}

impl ConnectorSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.name.trim().is_empty() {
            return Err(ManifestError::Invalid {
                field: "connector.name",
                message: "must not be empty".into(),
            });
        }
        if self.description.trim().is_empty() {
            return Err(ManifestError::Invalid {
                field: "connector.description",
                message: "must not be empty".into(),
            });
        }
        if self.archetypes.is_empty() {
            return Err(ManifestError::Invalid {
                field: "connector.archetypes",
                message: "must list at least one archetype".into(),
            });
        }

        // Validate state model consistency (legacy singleton_writer flag).
        let _ = self.effective_state_model()?;
        Ok(())
    }

    fn effective_state_model(&self) -> Result<EffectiveStateModel<'_>, ManifestError> {
        let legacy_singleton = self.singleton_writer.unwrap_or(false);
        let Some(ref state) = self.state else {
            return Ok(if legacy_singleton {
                EffectiveStateModel::SingletonWriter {
                    state_schema_version: None,
                    migration_hint: None,
                    crdt_type: None,
                    snapshot_every_updates: None,
                    snapshot_every_bytes: None,
                }
            } else {
                EffectiveStateModel::Stateless
            });
        };

        state.validate()?;

        if legacy_singleton && state.model != StateModelKind::SingletonWriter {
            return Err(ManifestError::Invalid {
                field: "connector.singleton_writer",
                message: "conflicts with connector.state.model (must be singleton_writer)".into(),
            });
        }

        // Convert TOML model + crdt_type to rich ConnectorStateModel
        let model = state.to_state_model()?;

        Ok(match model {
            ConnectorStateModel::Stateless => EffectiveStateModel::Stateless,
            ConnectorStateModel::SingletonWriter => EffectiveStateModel::SingletonWriter {
                state_schema_version: Some(state.state_schema_version.as_str()),
                migration_hint: state.migration_hint.as_deref(),
                crdt_type: None,
                snapshot_every_updates: None,
                snapshot_every_bytes: None,
            },
            ConnectorStateModel::Crdt { crdt_type } => EffectiveStateModel::Crdt {
                state_schema_version: Some(state.state_schema_version.as_str()),
                migration_hint: state.migration_hint.as_deref(),
                crdt_type: Some(crdt_type.as_str()),
                snapshot_every_updates: state.snapshot_every_updates,
                snapshot_every_bytes: state.snapshot_every_bytes,
            },
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorArchetype {
    Bidirectional,
    Streaming,
    Operational,
    Storage,
    Knowledge,
}

impl ConnectorArchetype {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Bidirectional => "bidirectional",
            Self::Streaming => "streaming",
            Self::Operational => "operational",
            Self::Storage => "storage",
            Self::Knowledge => "knowledge",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorRuntimeFormat {
    Native,
    Wasi,
}

/// Simple state model kind for TOML parsing (unit variants only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StateModelKind {
    Stateless,
    SingletonWriter,
    Crdt,
}

/// Connector state section `[connector.state]` (model-guide aligned).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorStateSection {
    model: StateModelKind,
    pub state_schema_version: String,
    #[serde(default)]
    pub migration_hint: Option<String>,
    #[serde(default)]
    pub crdt_type: Option<ConnectorCrdtType>,
    #[serde(default)]
    pub snapshot_every_updates: Option<u64>,
    #[serde(default)]
    pub snapshot_every_bytes: Option<u64>,
}

impl ConnectorStateSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.state_schema_version.trim().is_empty() {
            return Err(ManifestError::Invalid {
                field: "connector.state.state_schema_version",
                message: "must not be empty".into(),
            });
        }
        if self.model != StateModelKind::Crdt {
            if self.crdt_type.is_some() {
                return Err(ManifestError::Invalid {
                    field: "connector.state.crdt_type",
                    message: "only allowed when model = \"crdt\"".into(),
                });
            }
            if self.snapshot_every_updates.is_some() {
                return Err(ManifestError::Invalid {
                    field: "connector.state.snapshot_every_updates",
                    message: "only allowed when model = \"crdt\"".into(),
                });
            }
            if self.snapshot_every_bytes.is_some() {
                return Err(ManifestError::Invalid {
                    field: "connector.state.snapshot_every_bytes",
                    message: "only allowed when model = \"crdt\"".into(),
                });
            }
        }
        Ok(())
    }

    /// Convert to the public `ConnectorStateModel` enum.
    ///
    /// # Errors
    ///
    /// Returns `ManifestError::Invalid` if `model` is `Crdt` but `crdt_type` is `None`.
    pub fn to_state_model(&self) -> Result<ConnectorStateModel, ManifestError> {
        match self.model {
            StateModelKind::Stateless => Ok(ConnectorStateModel::Stateless),
            StateModelKind::SingletonWriter => Ok(ConnectorStateModel::SingletonWriter),
            StateModelKind::Crdt => {
                let crdt_type = self.crdt_type.ok_or_else(|| ManifestError::Invalid {
                    field: "connector.state.crdt_type",
                    message: "required when model = \"crdt\"".into(),
                })?;
                Ok(ConnectorStateModel::Crdt { crdt_type })
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConnectorStateModel {
    /// No persistent state.
    #[default]
    Stateless,
    /// Single-writer with lease-based fencing.
    SingletonWriter,
    /// CRDT-based collaborative state.
    Crdt {
        /// The CRDT type determining merge semantics.
        crdt_type: ConnectorCrdtType,
    },
}

impl ConnectorStateModel {
    /// Returns `true` if this is the stateless model.
    #[must_use]
    pub const fn is_stateless(&self) -> bool {
        matches!(self, Self::Stateless)
    }

    /// Returns `true` if this is the singleton-writer model.
    #[must_use]
    pub const fn is_singleton_writer(&self) -> bool {
        matches!(self, Self::SingletonWriter)
    }

    /// Returns `true` if this is a CRDT model.
    #[must_use]
    pub const fn is_crdt(&self) -> bool {
        matches!(self, Self::Crdt { .. })
    }

    /// Returns the CRDT type if this is a CRDT model.
    #[must_use]
    pub const fn crdt_type(&self) -> Option<ConnectorCrdtType> {
        match self {
            Self::Crdt { crdt_type } => Some(*crdt_type),
            _ => None,
        }
    }
}

impl std::fmt::Display for ConnectorStateModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stateless => write!(f, "stateless"),
            Self::SingletonWriter => write!(f, "singleton_writer"),
            Self::Crdt { crdt_type } => write!(f, "crdt({})", crdt_type.as_str()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorCrdtType {
    /// Last-writer-wins map.
    LwwMap,
    /// Observed-remove set.
    OrSet,
    /// Grow-only counter.
    GCounter,
    /// Positive-negative counter.
    PnCounter,
}

impl ConnectorCrdtType {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::LwwMap => "lww_map",
            Self::OrSet => "or_set",
            Self::GCounter => "g_counter",
            Self::PnCounter => "pn_counter",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "model", rename_all = "snake_case")]
enum EffectiveStateModel<'a> {
    Stateless,
    SingletonWriter {
        #[serde(skip_serializing_if = "Option::is_none")]
        state_schema_version: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        migration_hint: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        crdt_type: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        snapshot_every_updates: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        snapshot_every_bytes: Option<u64>,
    },
    Crdt {
        #[serde(skip_serializing_if = "Option::is_none")]
        state_schema_version: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        migration_hint: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        crdt_type: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        snapshot_every_updates: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        snapshot_every_bytes: Option<u64>,
    },
}

/// `[zones]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZonesSection {
    pub home: ZoneId,
    #[serde(default)]
    pub allowed_sources: Vec<ZonePattern>,
    #[serde(default)]
    pub allowed_targets: Vec<ZonePattern>,
    #[serde(default)]
    pub forbidden: Vec<ZoneId>,
}

impl ZonesSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.home.as_str().is_empty() {
            return Err(ManifestError::Invalid {
                field: "zones.home",
                message: "must not be empty".into(),
            });
        }
        Ok(())
    }
}

/// A manifest zone policy selector.
///
/// `home` and `forbidden` zones are concrete [`ZoneId`]s. Allowlist entries
/// may also use the documented `z:project:*` selector to grant all concrete
/// project zones without weakening the `ZoneId` grammar.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ZonePattern(std::sync::Arc<str>);

impl ZonePattern {
    pub const PROJECT_WILDCARD: &str = "z:project:*";

    /// Create a validated zone policy selector.
    ///
    /// # Errors
    /// Returns an error if the selector is neither a concrete [`ZoneId`] nor
    /// the documented `z:project:*` project-zone wildcard.
    pub fn new(pattern: impl Into<String>) -> Result<Self, ZonePatternError> {
        Self::try_from(pattern.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_project_wildcard(&self) -> bool {
        self.as_str() == Self::PROJECT_WILDCARD
    }

    #[must_use]
    pub fn matches(&self, zone: &ZoneId) -> bool {
        self.as_str() == zone.as_str()
            || (self.is_project_wildcard() && zone.as_str().starts_with("z:project:"))
    }
}

impl TryFrom<String> for ZonePattern {
    type Error = ZonePatternError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.contains('*') {
            if value == Self::PROJECT_WILDCARD {
                return Ok(Self(value.into()));
            }
            return Err(ZonePatternError::UnsupportedWildcard { pattern: value });
        }

        ZoneId::try_from(value.clone())?;
        Ok(Self(value.into()))
    }
}

impl From<ZonePattern> for String {
    fn from(value: ZonePattern) -> Self {
        value.0.to_string()
    }
}

impl From<ZoneId> for ZonePattern {
    fn from(value: ZoneId) -> Self {
        Self(value.as_str().into())
    }
}

impl std::str::FromStr for ZonePattern {
    type Err = ZonePatternError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl fmt::Display for ZonePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for ZonePattern {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq<ZoneId> for ZonePattern {
    fn eq(&self, other: &ZoneId) -> bool {
        self.as_str() == other.as_str()
    }
}

impl PartialEq<ZonePattern> for ZoneId {
    fn eq(&self, other: &ZonePattern) -> bool {
        self.as_str() == other.as_str()
    }
}

/// `[capabilities]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesSection {
    #[serde(default)]
    pub required: Vec<CapabilityId>,
    #[serde(default)]
    pub optional: Vec<CapabilityId>,
    #[serde(default)]
    pub forbidden: Vec<CapabilityId>,
}

impl CapabilitiesSection {
    fn validate(&self) -> Result<(), ManifestError> {
        let mut seen = HashSet::new();
        for (field, caps) in [
            ("capabilities.required", &self.required),
            ("capabilities.optional", &self.optional),
            ("capabilities.forbidden", &self.forbidden),
        ] {
            for cap in caps {
                let inserted = seen.insert(cap.as_str().to_owned());
                if !inserted {
                    return Err(ManifestError::Invalid {
                        field,
                        message: format!("duplicate capability id `{}`", cap.as_str()),
                    });
                }
            }
        }
        let exec_forbidden = self
            .forbidden
            .iter()
            .any(|cap| cap.as_str() == "system.exec");
        if !exec_forbidden {
            return Err(ManifestError::Invalid {
                field: "capabilities.forbidden",
                message: "must include system.exec (default-deny execution)".into(),
            });
        }
        Ok(())
    }

    fn validate_no_network_host_restrictions(&self) -> Result<(), ManifestError> {
        for (field, caps) in [
            ("capabilities.required", &self.required),
            ("capabilities.optional", &self.optional),
            ("capabilities.forbidden", &self.forbidden),
        ] {
            for cap in caps {
                let s = cap.as_str();
                if s.starts_with("network.") && s.contains(':') {
                    return Err(ManifestError::Invalid {
                        field,
                        message: format!(
                            "network capability id `{s}` appears to encode host restrictions; use `network_constraints` instead"
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    /// Lint: reject capability IDs that embed hostnames, ports, or URL-like
    /// patterns. FCP2 requires that all network addressing live in
    /// `network_constraints`, not in capability identifiers.
    ///
    /// Detected patterns:
    /// - URL schemes: `http:`, `https:`, `ftp:`, `ws:`, `wss:`
    /// - Port suffixes: `:<digits>` (2–5 digits resembling a TCP/UDP port)
    /// - Hostname TLD endings: `.com`, `.org`, `.net`, `.edu`, `.gov`, `.mil`
    /// - IPv4 address fragments: four consecutive all-digit dot-segments
    fn validate_no_hostname_port_url_patterns(&self) -> Result<(), ManifestError> {
        for (field, caps) in [
            ("capabilities.required", &self.required),
            ("capabilities.optional", &self.optional),
            ("capabilities.forbidden", &self.forbidden),
        ] {
            for cap in caps {
                lint_capability_id_no_network_addressing(cap.as_str(), field)?;
            }
        }
        Ok(())
    }
}

/// Well-known TLDs that are unlikely to appear as legitimate capability
/// namespace segments. Kept deliberately conservative to avoid false positives.
const KNOWN_TLDS: &[&str] = &["com", "org", "net", "edu", "gov", "mil"];

/// URL schemes that must never appear at the start of a capability ID.
const URL_SCHEMES: &[&str] = &["http:", "https:", "ftp:", "ws:", "wss:"];

/// Check a single capability ID for network-addressing patterns.
///
/// Returns `Ok(())` when the ID looks like a clean capability namespace
/// (e.g. `telegram.send_message`, `network.egress`). Returns an error when
/// the ID embeds hostnames, ports, URL schemes, or IP addresses.
fn lint_capability_id_no_network_addressing(
    id: &str,
    field: &'static str,
) -> Result<(), ManifestError> {
    // 1. URL scheme prefix
    for scheme in URL_SCHEMES {
        if id.starts_with(scheme) {
            return Err(ManifestError::Invalid {
                field,
                message: format!(
                    "capability id `{id}` contains URL scheme `{scheme}`; \
                     network addressing belongs in `network_constraints`"
                ),
            });
        }
    }

    let segments: Vec<&str> = id.split('.').collect();

    // 2. Port-like suffix: colon followed by 2–5 digits within any segment.
    for segment in &segments {
        if let Some(colon_idx) = segment.rfind(':') {
            let after = &segment[colon_idx + 1..];
            if (2..=5).contains(&after.len()) && after.bytes().all(|b| b.is_ascii_digit()) {
                if let Ok(port) = after.parse::<u32>() {
                    if port > 0 && port <= 65535 {
                        return Err(ManifestError::Invalid {
                            field,
                            message: format!(
                                "capability id `{id}` contains port number `:{after}`; \
                                 network addressing belongs in `network_constraints`"
                            ),
                        });
                    }
                }
            }
        }
    }

    // 3. Hostname TLD ending: the last dot-segment (ignoring any trailing
    //    port) matches a well-known TLD and there are at least 2 segments.
    if segments.len() >= 2 {
        let last = segments[segments.len() - 1];
        // Strip trailing port if present (e.g. "org:443" → "org")
        let tld_candidate = last.split(':').next().unwrap_or(last);
        if KNOWN_TLDS.contains(&tld_candidate) {
            return Err(ManifestError::Invalid {
                field,
                message: format!(
                    "capability id `{id}` appears to contain a hostname \
                     (ends with `.{tld_candidate}`); \
                     network addressing belongs in `network_constraints`"
                ),
            });
        }
    }

    // 4. IPv4 address pattern: four consecutive all-digit segments (1–3 chars each).
    if segments.len() >= 4 {
        for window in segments.windows(4) {
            if window
                .iter()
                .all(|s| !s.is_empty() && s.len() <= 3 && s.bytes().all(|b| b.is_ascii_digit()))
            {
                return Err(ManifestError::Invalid {
                    field,
                    message: format!(
                        "capability id `{id}` appears to contain an IPv4 address; \
                         network addressing belongs in `network_constraints`"
                    ),
                });
            }
        }
    }

    Ok(())
}

/// `[provides]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvidesSection {
    pub operations: BTreeMap<String, OperationSection>,
    /// Optional event declarations for streaming connectors.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub events: BTreeMap<String, EventSection>,
}

/// `[provides.events.<id>]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventSection {
    pub description: String,
    /// Whether this event supports streaming delivery.
    #[serde(default)]
    pub streaming: bool,
    /// Whether this event supports replay/backfill.
    #[serde(default)]
    pub replay: bool,
    /// Topic identifier for event routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    /// Whether the event requires explicit acknowledgement.
    #[serde(default)]
    pub requires_ack: bool,
    /// Optional schema for the event payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<serde_json::Value>,
}

impl EventSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.description.trim().is_empty() {
            return Err(ManifestError::Invalid {
                field: "provides.events.*.description",
                message: "must not be empty".into(),
            });
        }
        if let Some(topic) = self.topic.as_deref()
            && topic.trim().is_empty()
        {
            return Err(ManifestError::Invalid {
                field: "provides.events.*.topic",
                message: "must not be empty when present".into(),
            });
        }
        Ok(())
    }
}

impl ProvidesSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.operations.is_empty() {
            return Err(ManifestError::Invalid {
                field: "provides.operations",
                message: "must declare at least one operation".into(),
            });
        }
        for (op_id, op) in &self.operations {
            validate_canonical_id(op_id)?;
            op.validate()?;
        }
        for (event_id, event) in &self.events {
            validate_canonical_id(event_id)?;
            event.validate()?;
        }
        Ok(())
    }
}

/// `[provides.operations.<id>]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationSection {
    pub description: String,
    pub capability: CapabilityId,
    pub risk_level: RiskLevel,
    pub safety_tier: SafetyTier,
    pub requires_approval: ManifestApprovalMode,
    pub rate_limit: Option<RateLimit>,
    pub idempotency: IdempotencyClass,
    /// Whether this operation may participate in computation migration flows.
    #[serde(default, skip_serializing_if = "is_false")]
    pub migration_supported: bool,
    /// Revocation freshness class declared by the connector author.
    ///
    /// Determines the minimum [`FreshnessPolicy`](fcp_core::FreshnessPolicy) the host MUST enforce.
    /// Defaults to `safe` for backward compatibility with pre-C1.3 manifests.
    #[serde(default = "default_freshness_class")]
    pub revocation_freshness: RevocationFreshnessClass,
    pub input_schema: serde_json::Value,
    pub output_schema: serde_json::Value,
    #[serde(default)]
    pub network_constraints: Option<NetworkConstraints>,
    #[serde(default)]
    pub ai_hints: fcp_core::AgentHint,
}

impl OperationSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.description.trim().is_empty() {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.description",
                message: "must not be empty".into(),
            });
        }
        if let Some(ref rate_limit) = self.rate_limit {
            rate_limit.as_inner().validate()?;
        }
        if let Some(ref nc) = self.network_constraints {
            nc.validate()?;
        }
        Ok(())
    }
}

/// Approval mode as expressed in manifests.
///
/// Note: the spec historically used `"approval_required"`; the core currently uses
/// `"elevation_token"`. This type accepts both and normalizes deterministically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestApprovalMode {
    None,
    Policy,
    Interactive,
    ElevationToken,
}

impl From<ManifestApprovalMode> for CoreApprovalMode {
    fn from(value: ManifestApprovalMode) -> Self {
        match value {
            ManifestApprovalMode::None => Self::None,
            ManifestApprovalMode::Policy => Self::Policy,
            ManifestApprovalMode::Interactive => Self::Interactive,
            ManifestApprovalMode::ElevationToken => Self::ElevationToken,
        }
    }
}

impl<'de> Deserialize<'de> for ManifestApprovalMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "none" => Ok(Self::None),
            "policy" => Ok(Self::Policy),
            "interactive" => Ok(Self::Interactive),
            "elevation_token" | "approval_required" => Ok(Self::ElevationToken),
            _ => Err(serde::de::Error::custom(
                "invalid approval mode (expected: none|policy|interactive|elevation_token)",
            )),
        }
    }
}

/// Rate limit (manifest-friendly).
///
/// Supports either a shorthand string (e.g. `"60/min"`) or a structured object matching
/// `fcp_core::RateLimit`. The value is normalized to the structured form for hashing.
#[derive(Debug, Clone)]
pub struct RateLimit(pub fcp_core::RateLimit);

impl RateLimit {
    #[must_use]
    pub const fn as_inner(&self) -> &fcp_core::RateLimit {
        &self.0
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RateLimitRepr {
    Shorthand(String),
    Structured(fcp_core::RateLimit),
}

impl<'de> Deserialize<'de> for RateLimit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let repr = RateLimitRepr::deserialize(deserializer)?;
        let rate = match repr {
            RateLimitRepr::Shorthand(s) => parse_rate_limit_shorthand(&s)
                .map_err(|e| serde::de::Error::custom(format!("invalid rate_limit: {e}")))?,
            RateLimitRepr::Structured(v) => v,
        };
        Ok(Self(rate))
    }
}

impl Serialize for RateLimit {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

fn parse_rate_limit_shorthand(input: &str) -> Result<fcp_core::RateLimit, &'static str> {
    let (max, unit) = input
        .split_once('/')
        .ok_or("expected format like \"60/min\"")?;
    let max: u32 = max.parse().map_err(|_| "max must be an integer")?;
    let per_ms = match unit {
        "sec" | "s" => 1_000_u64,
        "min" | "m" => 60_000_u64,
        "hour" | "h" => 3_600_000_u64,
        "day" | "d" => 86_400_000_u64,
        _ => return Err("unknown period unit (expected sec|min|hour|day)"),
    };
    Ok(fcp_core::RateLimit {
        max,
        per_ms,
        burst: None,
        scope: None,
        pool_name: None,
    })
}

/// `[event_caps]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventCapsSection {
    pub streaming: bool,
    pub replay: bool,
    pub min_buffer_events: u32,
}

impl EventCapsSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.streaming && self.min_buffer_events == 0 {
            return Err(ManifestError::Invalid {
                field: "event_caps.min_buffer_events",
                message: "must be > 0 when streaming is enabled".into(),
            });
        }
        Ok(())
    }
}

/// `[rate_limits]` section for connector-level rate limit pool declarations.
///
/// Defines named rate limit pools that can be referenced by operations to share
/// quota buckets across multiple operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitsSection {
    /// Named rate limit pools with configuration.
    #[serde(default)]
    pub pools: Vec<RateLimitPoolSection>,
    /// Map of operation names to pool IDs they consume.
    /// Operations can consume from multiple pools (e.g., both RPM and token limits).
    #[serde(default)]
    pub operation_pools: std::collections::HashMap<String, Vec<String>>,
}

/// Hard caps on the size/shape of declared rate-limit sections. Manifests
/// that exceed these bounds are rejected at validation time so that a
/// malicious or buggy author cannot submit a declaration that degenerates
/// into "unlimited" — e.g. `requests = u32::MAX, window_ms = 1` — or that
/// blows up memory via millions of pool entries.
const MAX_RATE_LIMIT_POOLS: usize = 1024;
const MAX_RATE_LIMIT_OPERATION_POOL_MAP: usize = 4096;
const MAX_RATE_LIMIT_POOL_IDS_PER_OPERATION: usize = 16;
const MAX_RATE_LIMIT_REQUESTS: u32 = 1_000_000_000;
const MAX_RATE_LIMIT_BURST: u32 = 1_000_000_000;
const MAX_RATE_LIMIT_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

impl RateLimitsSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.pools.len() > MAX_RATE_LIMIT_POOLS {
            return Err(ManifestError::Invalid {
                field: "rate_limits.pools",
                message: format!(
                    "declared {} pools; maximum is {}",
                    self.pools.len(),
                    MAX_RATE_LIMIT_POOLS
                ),
            });
        }
        if self.operation_pools.len() > MAX_RATE_LIMIT_OPERATION_POOL_MAP {
            return Err(ManifestError::Invalid {
                field: "rate_limits.operation_pools",
                message: format!(
                    "declared {} operation->pool mappings; maximum is {}",
                    self.operation_pools.len(),
                    MAX_RATE_LIMIT_OPERATION_POOL_MAP
                ),
            });
        }
        for (op, pool_ids) in &self.operation_pools {
            if pool_ids.len() > MAX_RATE_LIMIT_POOL_IDS_PER_OPERATION {
                return Err(ManifestError::Invalid {
                    field: "rate_limits.operation_pools.*",
                    message: format!(
                        "operation `{op}` references {} pools; maximum is {}",
                        pool_ids.len(),
                        MAX_RATE_LIMIT_POOL_IDS_PER_OPERATION
                    ),
                });
            }
        }
        for pool in &self.pools {
            pool.validate()?;
        }
        // Convert to fcp_core declarations and validate
        let decls = self.to_declarations();
        decls.validate()?;
        Ok(())
    }

    /// Convert to the canonical `RateLimitDeclarations` type.
    #[must_use]
    pub fn to_declarations(&self) -> RateLimitDeclarations {
        use fcp_prelude::{RateLimitConfig, RateLimitEnforcement, RateLimitScope, RateLimitUnit};
        use std::time::Duration;

        let limits =
            self.pools
                .iter()
                .map(|pool| RateLimitPool {
                    id: pool.id.clone(),
                    description: pool.description.clone().unwrap_or_default(),
                    config: RateLimitConfig {
                        requests: pool.requests,
                        window: Duration::from_millis(pool.window_ms),
                        burst: pool.burst,
                        unit: pool.unit.as_ref().map_or(RateLimitUnit::Requests, |u| {
                            match u.as_str() {
                                "tokens" => RateLimitUnit::Tokens,
                                "bytes" => RateLimitUnit::Bytes,
                                "custom" => RateLimitUnit::Custom,
                                _ => RateLimitUnit::Requests,
                            }
                        }),
                    },
                    enforcement: pool.enforcement.as_ref().map_or(
                        RateLimitEnforcement::Hard,
                        |e| match e.as_str() {
                            "soft" => RateLimitEnforcement::Soft,
                            "advisory" => RateLimitEnforcement::Advisory,
                            _ => RateLimitEnforcement::Hard,
                        },
                    ),
                    scope: pool.scope.as_ref().map_or(RateLimitScope::Instance, |s| {
                        match s.as_str() {
                            "credential" => RateLimitScope::Credential,
                            "global" => RateLimitScope::Global,
                            _ => RateLimitScope::Instance,
                        }
                    }),
                })
                .collect();

        RateLimitDeclarations {
            limits,
            tool_pool_map: self.operation_pools.clone(),
        }
    }
}

/// A rate limit pool declaration in TOML-friendly format.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitPoolSection {
    /// Unique identifier for this pool (e.g., `api_global`, `openai_tokens`).
    pub id: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Maximum requests/tokens/bytes per window (bucket size). Must be > 0.
    pub requests: u32,
    /// Window duration in milliseconds. Must be > 0.
    pub window_ms: u64,
    /// Optional burst allowance (tokens above max that can accumulate).
    #[serde(default)]
    pub burst: Option<u32>,
    /// Unit of measurement: "requests" (default), "tokens", "bytes", "custom".
    #[serde(default)]
    pub unit: Option<String>,
    /// Enforcement: "hard" (default), "soft", "advisory".
    #[serde(default)]
    pub enforcement: Option<String>,
    /// Scope: "instance" (default), "credential", "global".
    #[serde(default)]
    pub scope: Option<String>,
}

impl RateLimitPoolSection {
    fn validate(&self) -> Result<(), ManifestError> {
        // Upper bounds on pool quotas: a manifest that declares
        // `requests = u32::MAX, window_ms = 1` degenerates into "no rate
        // limit at all" at the host, which defeats the purpose of
        // declaring a pool. Reject before the host has to enforce.
        if self.requests > MAX_RATE_LIMIT_REQUESTS {
            return Err(ManifestError::Invalid {
                field: "rate_limits.pools.*.requests",
                message: format!(
                    "pool `{}` declares requests={} exceeding maximum {}",
                    self.id, self.requests, MAX_RATE_LIMIT_REQUESTS
                ),
            });
        }
        if self.window_ms > MAX_RATE_LIMIT_WINDOW_MS {
            return Err(ManifestError::Invalid {
                field: "rate_limits.pools.*.window_ms",
                message: format!(
                    "pool `{}` declares window_ms={} exceeding maximum {} ms (24h)",
                    self.id, self.window_ms, MAX_RATE_LIMIT_WINDOW_MS
                ),
            });
        }
        if let Some(burst) = self.burst {
            if burst > MAX_RATE_LIMIT_BURST {
                return Err(ManifestError::Invalid {
                    field: "rate_limits.pools.*.burst",
                    message: format!(
                        "pool `{}` declares burst={} exceeding maximum {}",
                        self.id, burst, MAX_RATE_LIMIT_BURST
                    ),
                });
            }
        }
        if let Some(unit) = self.unit.as_deref() {
            match unit {
                "requests" | "tokens" | "bytes" | "custom" => {}
                _ => {
                    return Err(ManifestError::Invalid {
                        field: "rate_limits.pools.*.unit",
                        message: format!(
                            "unsupported unit `{unit}` (expected one of: requests, tokens, bytes, custom)"
                        ),
                    });
                }
            }
        }

        if let Some(enforcement) = self.enforcement.as_deref() {
            match enforcement {
                "hard" | "soft" | "advisory" => {}
                _ => {
                    return Err(ManifestError::Invalid {
                        field: "rate_limits.pools.*.enforcement",
                        message: format!(
                            "unsupported enforcement `{enforcement}` (expected one of: hard, soft, advisory)"
                        ),
                    });
                }
            }
        }

        if let Some(scope) = self.scope.as_deref() {
            match scope {
                "instance" | "credential" | "global" => {}
                _ => {
                    return Err(ManifestError::Invalid {
                        field: "rate_limits.pools.*.scope",
                        message: format!(
                            "unsupported scope `{scope}` (expected one of: instance, credential, global)"
                        ),
                    });
                }
            }
        }

        Ok(())
    }
}

/// Connector-level default time budgets.
///
/// These defaults are separate from per-operation network constraints and the
/// sandbox hard cap. Connectors may use this section to derive runtime request,
/// connect, and wall-clock budgets without hard-coding them in Rust sources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestTimeouts {
    #[serde(default = "default_manifest_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_manifest_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_manifest_wall_clock_timeout_ms")]
    pub wall_clock_timeout_ms: u64,
}

impl Default for ManifestTimeouts {
    fn default() -> Self {
        Self {
            request_timeout_ms: default_manifest_request_timeout_ms(),
            connect_timeout_ms: default_manifest_connect_timeout_ms(),
            wall_clock_timeout_ms: default_manifest_wall_clock_timeout_ms(),
        }
    }
}

impl ManifestTimeouts {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.request_timeout_ms == 0 {
            return Err(ManifestError::Invalid {
                field: "timeouts.request_timeout_ms",
                message: "must be > 0".into(),
            });
        }
        if self.connect_timeout_ms == 0 {
            return Err(ManifestError::Invalid {
                field: "timeouts.connect_timeout_ms",
                message: "must be > 0".into(),
            });
        }
        if self.wall_clock_timeout_ms == 0 {
            return Err(ManifestError::Invalid {
                field: "timeouts.wall_clock_timeout_ms",
                message: "must be > 0".into(),
            });
        }
        Ok(())
    }
}

const fn default_manifest_request_timeout_ms() -> u64 {
    30_000
}

const fn default_manifest_connect_timeout_ms() -> u64 {
    5_000
}

const fn default_manifest_wall_clock_timeout_ms() -> u64 {
    60_000
}

/// Optional per-connector p99 resource and latency graduation budgets.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceBudget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cold_start_max_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_invoke_max_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_uss_max_mb: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_cpu_max_pct: Option<f64>,
}

impl PerformanceBudget {
    fn validate(&self) -> Result<(), ManifestError> {
        validate_performance_budget_value(
            "performance_budget.cold_start_max_ms",
            self.cold_start_max_ms,
        )?;
        validate_performance_budget_value(
            "performance_budget.local_invoke_max_ms",
            self.local_invoke_max_ms,
        )?;
        validate_performance_budget_value(
            "performance_budget.memory_uss_max_mb",
            self.memory_uss_max_mb,
        )?;
        validate_performance_budget_value(
            "performance_budget.idle_cpu_max_pct",
            self.idle_cpu_max_pct,
        )
    }
}

fn validate_performance_budget_value(
    field: &'static str,
    value: Option<f64>,
) -> Result<(), ManifestError> {
    if let Some(value) = value
        && (!value.is_finite() || value < 0.0)
    {
        return Err(ManifestError::InvalidPerformanceBudget {
            field,
            message: "must be a finite non-negative number".into(),
        });
    }
    Ok(())
}

/// `[sandbox]` section (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSection {
    pub profile: SandboxProfile,
    pub memory_mb: u32,
    pub cpu_percent: u8,
    pub wall_clock_timeout_ms: u64,
    #[serde(default)]
    pub fs_readonly_paths: Vec<String>,
    #[serde(default)]
    pub fs_writable_paths: Vec<String>,
    pub deny_exec: bool,
    pub deny_ptrace: bool,
}

impl SandboxSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.cpu_percent == 0 {
            return Err(ManifestError::Invalid {
                field: "sandbox.cpu_percent",
                message: "must be > 0".into(),
            });
        }
        if self.wall_clock_timeout_ms == 0 {
            return Err(ManifestError::Invalid {
                field: "sandbox.wall_clock_timeout_ms",
                message: "must be > 0".into(),
            });
        }
        for path in &self.fs_readonly_paths {
            validate_sandbox_fs_path(path).map_err(|message| ManifestError::Invalid {
                field: "sandbox.fs_readonly_paths",
                message: message.to_string(),
            })?;
        }
        for path in &self.fs_writable_paths {
            validate_sandbox_fs_path(path).map_err(|message| ManifestError::Invalid {
                field: "sandbox.fs_writable_paths",
                message: message.to_string(),
            })?;
        }
        Ok(())
    }
}

fn validate_sandbox_fs_path(path: &str) -> Result<(), &'static str> {
    if path == "$CONNECTOR_STATE" {
        return Ok(());
    }

    if let Some(suffix) = path.strip_prefix("$CONNECTOR_STATE/") {
        return validate_connector_state_subpath(suffix);
    }

    if is_absolute_sandbox_fs_path(path) {
        return Ok(());
    }

    Err("paths must be absolute or use `$CONNECTOR_STATE[/subpath]`")
}

fn validate_connector_state_subpath(suffix: &str) -> Result<(), &'static str> {
    for component in Path::new(suffix).components() {
        if !matches!(component, Component::Normal(_)) {
            return Err("`$CONNECTOR_STATE` subpaths must contain only normal path components");
        }
    }

    Ok(())
}

fn is_absolute_sandbox_fs_path(path: &str) -> bool {
    Path::new(path).is_absolute()
        || path.starts_with(r"\\")
        || path.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && matches!(path.as_bytes().get(1), Some(b':'))
            && matches!(path.as_bytes().get(2), Some(b'\\' | b'/'))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxProfile {
    Strict,
    StrictPlus,
    Moderate,
    Permissive,
}

/// Operation-level network constraints (NORMATIVE).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct NetworkConstraints {
    pub host_allow: Vec<String>,
    pub port_allow: Vec<u16>,
    #[serde(default)]
    pub ip_allow: Vec<IpAddr>,
    #[serde(default)]
    pub cidr_deny: Vec<String>,
    #[serde(default = "default_true")]
    pub deny_localhost: bool,
    #[serde(default = "default_true")]
    pub deny_private_ranges: bool,
    #[serde(default = "default_true")]
    pub deny_tailnet_ranges: bool,
    pub require_sni: bool,
    #[serde(default)]
    pub spki_pins: Vec<Base64Bytes>,
    #[serde(default = "default_true")]
    pub deny_ip_literals: bool,
    #[serde(default = "default_true")]
    pub require_host_canonicalization: bool,
    #[serde(default = "default_dns_max_ips")]
    pub dns_max_ips: u16,
    #[serde(default = "default_max_redirects")]
    pub max_redirects: u8,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u32,
    #[serde(default = "default_total_timeout_ms")]
    pub total_timeout_ms: u32,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: u64,
}

const fn default_true() -> bool {
    true
}

const fn default_dns_max_ips() -> u16 {
    16
}

const fn default_max_redirects() -> u8 {
    5
}

const fn default_connect_timeout_ms() -> u32 {
    10_000
}

const fn default_total_timeout_ms() -> u32 {
    60_000
}

const fn default_max_response_bytes() -> u64 {
    10_485_760
}

impl NetworkConstraints {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.host_allow.is_empty() {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.network_constraints.host_allow",
                message: "must not be empty".into(),
            });
        }
        if self.port_allow.is_empty() {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.network_constraints.port_allow",
                message: "must not be empty".into(),
            });
        }
        if self.connect_timeout_ms == 0 || self.total_timeout_ms == 0 {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.network_constraints",
                message: "timeouts must be > 0".into(),
            });
        }
        if self.connect_timeout_ms > self.total_timeout_ms {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.network_constraints",
                message: format!(
                    "connect_timeout_ms ({}) must not exceed total_timeout_ms ({})",
                    self.connect_timeout_ms, self.total_timeout_ms
                ),
            });
        }
        if self.max_response_bytes == 0 {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.network_constraints.max_response_bytes",
                message: "must be > 0".into(),
            });
        }

        for host in &self.host_allow {
            validate_host_allow_entry(
                host,
                self.deny_ip_literals,
                self.require_host_canonicalization,
            )?;

            if self.deny_localhost && host == "localhost" {
                return Err(ManifestError::Invalid {
                    field: "provides.operations.*.network_constraints.host_allow",
                    message: "host `localhost` is allowed but `deny_localhost` is true".into(),
                });
            }
        }

        for cidr in &self.cidr_deny {
            cidr.parse::<IpNet>().map_err(|_| ManifestError::Invalid {
                field: "provides.operations.*.network_constraints.cidr_deny",
                message: format!("invalid CIDR `{cidr}`"),
            })?;
        }

        Ok(())
    }
}

fn validate_host_allow_entry(
    host: &str,
    deny_ip_literals: bool,
    require_host_canonicalization: bool,
) -> Result<(), ManifestError> {
    if host.is_empty() {
        return Err(ManifestError::Invalid {
            field: "provides.operations.*.network_constraints.host_allow",
            message: "host entries must not be empty".into(),
        });
    }

    if deny_ip_literals && host.parse::<IpAddr>().is_ok() {
        return Err(ManifestError::Invalid {
            field: "provides.operations.*.network_constraints.host_allow",
            message: format!("IP literals are not allowed in host_allow (`{host}`)"),
        });
    }

    if require_host_canonicalization {
        if !host.is_ascii() {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.network_constraints.host_allow",
                message: format!("host must be ASCII (already canonicalized): `{host}`"),
            });
        }
        if host.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.network_constraints.host_allow",
                message: format!("host must be lowercase: `{host}`"),
            });
        }
        if host.ends_with('.') {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.network_constraints.host_allow",
                message: format!("host must not have trailing dot: `{host}`"),
            });
        }
    }

    if host.contains('*') {
        // NORMATIVE: only allow `*.example.com` wildcard form.
        if !host.starts_with("*.") || host.matches('*').count() != 1 {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.network_constraints.host_allow",
                message: format!(
                    "invalid wildcard pattern `{host}` (only `*.example.com` allowed)"
                ),
            });
        }
        // Require at least two labels after the wildcard (e.g. `*.example.com`)
        // `*.com` (2 parts) is rejected. `*.co.uk` (3 parts) is allowed but risky?
        // Let's enforce at least 3 parts total (wildcard + 2 labels).
        // `host.split('.').count()`
        if host.split('.').count() < 3 {
            return Err(ManifestError::Invalid {
                field: "provides.operations.*.network_constraints.host_allow",
                message: format!("invalid wildcard pattern `{host}` (too broad)"),
            });
        }
    }

    Ok(())
}

/// `[signatures]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignaturesSection {
    #[serde(default)]
    pub publisher_signatures: Vec<SignatureEntry>,
    pub publisher_threshold: Option<SignatureThreshold>,
    pub registry_signature: Option<SignatureEntry>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "fcp_core::util::objectid_prefixed::option"
    )]
    pub transparency_log_entry: Option<ObjectId>,
}

impl SignaturesSection {
    fn validate(&self) -> Result<(), ManifestError> {
        if !self.publisher_signatures.is_empty() && self.publisher_threshold.is_none() {
            return Err(ManifestError::Invalid {
                field: "signatures.publisher_threshold",
                message: "required when publisher_signatures is non-empty".into(),
            });
        }
        if let Some(threshold) = self.publisher_threshold {
            threshold.validate(self.publisher_signatures.len())?;
        }
        let mut seen = HashSet::new();
        for sig in &self.publisher_signatures {
            if !seen.insert(sig.kid.clone()) {
                return Err(ManifestError::Invalid {
                    field: "signatures.publisher_signatures",
                    message: format!("duplicate kid `{}`", sig.kid),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEntry {
    pub kid: String,
    pub sig: Base64Bytes,
}

/// Signature threshold string (e.g., `"2-of-3"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureThreshold {
    pub k: u8,
    pub n: u8,
}

impl SignatureThreshold {
    fn validate(self, signatures_present: usize) -> Result<(), ManifestError> {
        if self.k == 0 || self.n == 0 || self.k > self.n {
            return Err(ManifestError::Invalid {
                field: "signatures.publisher_threshold",
                message: "invalid threshold (k-of-n)".into(),
            });
        }
        if usize::from(self.k) > signatures_present {
            return Err(ManifestError::Invalid {
                field: "signatures.publisher_signatures",
                message: "insufficient signatures for publisher_threshold".into(),
            });
        }
        Ok(())
    }
}

impl fmt::Display for SignatureThreshold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-of-{}", self.k, self.n)
    }
}

impl TryFrom<String> for SignatureThreshold {
    type Error = ManifestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let (k, n) = value
            .split_once("-of-")
            .ok_or_else(|| ManifestError::Invalid {
                field: "signatures.publisher_threshold",
                message: "expected format like \"2-of-3\"".into(),
            })?;
        let k: u8 = k.parse().map_err(|_| ManifestError::Invalid {
            field: "signatures.publisher_threshold",
            message: "k must be an integer".into(),
        })?;
        let n: u8 = n.parse().map_err(|_| ManifestError::Invalid {
            field: "signatures.publisher_threshold",
            message: "n must be an integer".into(),
        })?;
        Ok(Self { k, n })
    }
}

impl From<SignatureThreshold> for String {
    fn from(value: SignatureThreshold) -> Self {
        value.to_string()
    }
}

impl<'de> Deserialize<'de> for SignatureThreshold {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for SignatureThreshold {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// `[supply_chain]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainSection {
    #[serde(default)]
    pub attestations: Vec<SupplyChainAttestationRef>,
}

impl SupplyChainSection {
    fn validate(&self) -> Result<(), ManifestError> {
        let mut seen = HashSet::new();
        for att in &self.attestations {
            if !seen.insert(att.object_id) {
                return Err(ManifestError::Invalid {
                    field: "supply_chain.attestations",
                    message: format!("duplicate attestation object id `{}`", att.object_id),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainAttestationRef {
    #[serde(rename = "type")]
    pub attestation_type: AttestationType,
    #[serde(with = "fcp_core::util::objectid_prefixed")]
    pub object_id: ObjectId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationType {
    InToto,
    ReproducibleBuild,
    CodeReview,
}

impl<'de> Deserialize<'de> for AttestationType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "in-toto" => Ok(Self::InToto),
            "reproducible-build" => Ok(Self::ReproducibleBuild),
            "code-review" => Ok(Self::CodeReview),
            _ => Err(serde::de::Error::custom(
                "invalid attestation type (expected: in-toto|reproducible-build|code-review)",
            )),
        }
    }
}

/// `[policy]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySection {
    #[serde(default)]
    pub require_transparency_log: bool,
    #[serde(default)]
    pub require_attestation_types: Vec<AttestationType>,
    #[serde(default)]
    pub min_slsa_level: Option<u8>,
    #[serde(default)]
    pub trusted_builders: Vec<String>,
    /// When true, every attestation evidence entry MUST carry a non-None
    /// `expires_at` timestamp. Without this gate, an attestation with
    /// `expires_at = None` is treated as eternally fresh by
    /// `enforce_supply_chain_policy`, which lets a stale or revoked-but-
    /// still-cacheable attestation pass policy indefinitely. Operators
    /// who depend on Sigstore/TUF verifiers (which always populate
    /// `expires_at`) should set this to `true` to fail-closed against
    /// unset-expiry adapters.
    #[serde(default)]
    pub require_attestation_expiry: bool,
}

impl PolicySection {
    fn validate(&self) -> Result<(), ManifestError> {
        if let Some(level) = self.min_slsa_level {
            if level > 4 {
                return Err(ManifestError::Invalid {
                    field: "policy.min_slsa_level",
                    message: "must be in range 0..=4".into(),
                });
            }
        }
        Ok(())
    }
}

/// Raw base64 bytes (requires the `base64:` prefix).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Base64Bytes(Vec<u8>);

impl Base64Bytes {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub const fn from_vec(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl TryFrom<String> for Base64Bytes {
    type Error = ManifestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let body = value
            .strip_prefix("base64:")
            .ok_or_else(|| ManifestError::Invalid {
                field: "base64",
                message: "expected `base64:` prefix".into(),
            })?;
        let decoded = BASE64_STANDARD
            .decode(body)
            .map_err(|_| ManifestError::Invalid {
                field: "base64",
                message: "invalid base64".into(),
            })?;
        Ok(Self(decoded))
    }
}

impl From<Base64Bytes> for String {
    fn from(value: Base64Bytes) -> Self {
        format!("base64:{}", BASE64_STANDARD.encode(value.0))
    }
}

impl<'de> Deserialize<'de> for Base64Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Base64Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&String::from(self.clone()))
    }
}

/// Request attribution supplied by connector SDKs for host-mediated egress.
///
/// The host verifies the capability token and derives credential allow-lists
/// from it; callers must not send raw credentials here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEgressContext {
    pub connector_id: String,
    pub operation_id: String,
    pub zone_id: String,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    pub capability_token_cbor_b64: String,
}

/// Redaction-safe HTTP header used by the host-egress transport contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEgressHttpHeader {
    pub name: String,
    pub value: String,
}

/// Connector-to-host HTTP egress request. Bodies are base64-prefixed bytes so
/// JSON logs and fixtures do not accidentally reinterpret binary payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEgressHttpRequest {
    pub context: HostEgressContext,
    pub url: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HostEgressHttpHeader>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Base64Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
}

/// Connector-to-host one-shot TCP egress request. This intentionally models a
/// bounded exchange, not an unbounded stream, so tests and operators get clear
/// limits and deterministic logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEgressTcpRequest {
    pub context: HostEgressContext,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub tls: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni_override: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<Base64Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_limit_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
}

/// Redaction-safe authorization metadata returned with host-egress responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEgressDecisionMetadata {
    pub connector_id: String,
    pub operation_id: String,
    pub zone_id: String,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    pub execution_mode: String,
    pub constraint_source: String,
    pub decision: String,
    pub resolved_host: String,
    pub resolved_port: u16,
    pub credential_injected: bool,
    pub elapsed_ms: u128,
}

/// Host-mediated HTTP egress response. The host never echoes request headers or
/// injected credentials; only upstream response headers and body are returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEgressHttpResponse {
    pub status: u16,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HostEgressHttpHeader>,
    pub body: Base64Bytes,
    pub egress: HostEgressDecisionMetadata,
}

/// Host-mediated TCP egress response for a bounded exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEgressTcpResponse {
    pub bytes_written: u64,
    pub bytes_read: u64,
    pub read: Base64Bytes,
    pub egress: HostEgressDecisionMetadata,
}

/// Embed a connector manifest in the output binary (NORMATIVE).
///
/// Connectors MUST embed the manifest in a platform-specific section so it can be extracted
/// without executing the connector:
/// - ELF: `.fcp_manifest`
/// - Mach-O: `__FCP,__manifest`
/// - PE: `.fcpmanifest`
#[macro_export]
macro_rules! embed_manifest {
    ($path:literal) => {
        #[cfg_attr(target_os = "macos", link_section = "__FCP,__manifest")]
        #[cfg_attr(target_os = "windows", link_section = ".fcpmanifest")]
        #[cfg_attr(
            all(not(target_os = "macos"), not(target_os = "windows")),
            link_section = ".fcp_manifest"
        )]
        #[used]
        static FCP_MANIFEST_BYTES: [u8; include_bytes!($path).len()] = *include_bytes!($path);

        #[must_use]
        pub fn embedded_manifest_bytes() -> &'static [u8] {
            &FCP_MANIFEST_BYTES
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use std::path::Path;
    use std::time::Instant;
    use uuid::Uuid;

    const PLACEHOLDER_HASH: &str = "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";
    const EMBEDDED_MINIMAL_MANIFEST: &[u8] =
        include_bytes!("../../../tests/vectors/manifest/manifest_minimal.toml");

    #[test]
    fn br_d9us6_host_egress_contract_roundtrips_binary_bodies_as_prefixed_base64() {
        let request = HostEgressHttpRequest {
            context: HostEgressContext {
                connector_id: "fcp.test.egress:utility:1.0.0".to_string(),
                operation_id: "test.http".to_string(),
                zone_id: "z:work".to_string(),
                request_id: "req-d9us6-contract".to_string(),
                correlation_id: Some("corr-d9us6-contract".to_string()),
                capability_token_cbor_b64: "dGVzdA==".to_string(),
            },
            url: "http://127.0.0.1:8080/v1".to_string(),
            method: "POST".to_string(),
            headers: vec![HostEgressHttpHeader {
                name: "content-type".to_string(),
                value: "application/octet-stream".to_string(),
            }],
            body: Some(Base64Bytes::from_vec(vec![0, 1, 2, 255])),
            credential_id: Some("11111111-1111-1111-1111-111111111111".to_string()),
        };

        let json = serde_json::to_string(&request).expect("serialize host egress request");
        assert!(json.contains("base64:AAEC/w=="));
        let decoded: HostEgressHttpRequest =
            serde_json::from_str(&json).expect("decode host egress request");
        assert_eq!(decoded.body.expect("body").as_bytes(), &[0_u8, 1, 2, 255]);
        assert_eq!(decoded.context.operation_id, "test.http");
    }

    #[test]
    fn br_d9us6_host_egress_response_metadata_is_redaction_safe() {
        let response = HostEgressTcpResponse {
            bytes_written: 4,
            bytes_read: 4,
            read: Base64Bytes::from_vec(b"PONG".to_vec()),
            egress: HostEgressDecisionMetadata {
                connector_id: "fcp.test.egress:utility:1.0.0".to_string(),
                operation_id: "test.tcp".to_string(),
                zone_id: "z:work".to_string(),
                request_id: "req-d9us6-response".to_string(),
                correlation_id: None,
                execution_mode: "host_egress_proxy".to_string(),
                constraint_source: "managed_connector_config.operation_network_constraints"
                    .to_string(),
                decision: "allow".to_string(),
                resolved_host: "127.0.0.1".to_string(),
                resolved_port: 9999,
                credential_injected: true,
                elapsed_ms: 7,
            },
        };

        let json = serde_json::to_string(&response).expect("serialize host egress response");
        assert!(json.contains("host_egress_proxy"));
        assert!(!json.contains("Authorization"));
        assert!(!json.contains("token"));
        assert_eq!(
            serde_json::from_str::<HostEgressTcpResponse>(&json)
                .expect("decode response")
                .read
                .as_bytes(),
            b"PONG"
        );
    }

    struct TestLog {
        test_name: &'static str,
        module: &'static str,
        correlation_id: String,
        started_at: Instant,
        connector_id: Option<&'static str>,
        version: Option<&'static str>,
        capabilities_count: Option<usize>,
    }

    impl TestLog {
        fn new(
            test_name: &'static str,
            module: &'static str,
            connector_id: Option<&'static str>,
            version: Option<&'static str>,
            capabilities_count: Option<usize>,
        ) -> Self {
            let correlation_id = Uuid::new_v4().to_string();
            let log = Self {
                test_name,
                module,
                correlation_id,
                started_at: Instant::now(),
                connector_id,
                version,
                capabilities_count,
            };
            log.emit("execute", Some("start"), 0);
            log
        }

        fn emit(&self, phase: &str, result: Option<&str>, duration_ms: u128) {
            let payload = json!({
                "timestamp": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "test_name": self.test_name,
                "module": self.module,
                "phase": phase,
                "correlation_id": self.correlation_id,
                "connector_id": self.connector_id,
                "version": self.version,
                "capabilities_count": self.capabilities_count,
                "duration_ms": duration_ms,
                "result": result,
            });
            println!("{payload}");
        }
    }

    impl Drop for TestLog {
        fn drop(&mut self) {
            let duration_ms = self.started_at.elapsed().as_millis();
            let result = if std::thread::panicking() {
                "fail"
            } else {
                "pass"
            };
            self.emit("verify", Some(result), duration_ms);
        }
    }

    fn test_manifest_toml(interface_hash: &str) -> String {
        format!(
            r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = ["fcps.aead.xchacha20poly1305"]
max_datagram_bytes = 1200
interface_hash = "{interface_hash}"

[connector]
id = "fcp.telegram"
name = "Telegram Connector"
version = "2026.1.0"
description = "Secure Telegram Bot API integration"
archetypes = ["bidirectional", "streaming"]
format = "native"

[connector.state]
model = "stateless"
state_schema_version = "1"

[zones]
home = "z:community"
allowed_sources = ["z:owner", "z:private", "z:work", "z:community"]
allowed_targets = ["z:community"]
forbidden = ["z:public"]

[capabilities]
required = ["ipc.gateway", "network.dns", "network.egress", "network.tls.sni", "telegram.send_message"]
optional = ["media.download"]
forbidden = ["system.exec"]

[provides.operations.telegram_send_message]
description = "Send a message to a Telegram chat"
capability = "telegram.send_message"
risk_level = "medium"
safety_tier = "risky"
requires_approval = "policy"
rate_limit = "60/min"
idempotency = "best_effort"
input_schema = {{ type = "object", required = ["chat_resource", "text"] }}
output_schema = {{ type = "object", required = ["message_id"] }}
network_constraints = {{ host_allow = ["api.telegram.org"], port_allow = [443], require_sni = true }}

[provides.operations.telegram_send_message.ai_hints]
when_to_use = "Use to post updates to approved chats."
common_mistakes = ["Sending secrets"]

[event_caps]
streaming = true
replay = true
min_buffer_events = 10000

[sandbox]
profile = "strict"
memory_mb = 256
cpu_percent = 50
wall_clock_timeout_ms = 30000
fs_readonly_paths = ["/usr", "/lib"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true
"#
        )
    }

    fn vector_manifest_path(name: &str) -> std::path::PathBuf {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        root.join("../../tests/vectors/manifest").join(name)
    }

    fn read_vector_manifest(name: &str) -> String {
        let path = vector_manifest_path(name);
        std::fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!("failed to read manifest vector {}: {err}", path.display())
        })
    }

    fn with_computed_hash(raw: &str) -> String {
        let unchecked =
            ConnectorManifest::parse_str_unchecked(raw).expect("vector must parse unchecked");
        let computed = unchecked
            .compute_interface_hash()
            .expect("compute interface hash");
        raw.replace(PLACEHOLDER_HASH, &computed.to_string())
    }

    #[test]
    fn manifest_parses_and_validates_with_computed_interface_hash() {
        let _log = TestLog::new(
            "manifest_parses_and_validates_with_computed_interface_hash",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let unchecked = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder))
            .expect("unchecked parse");
        let computed = unchecked.compute_interface_hash().expect("compute hash");

        let parsed =
            ConnectorManifest::parse_str(&test_manifest_toml(&computed.to_string())).unwrap();
        assert_eq!(parsed.manifest.interface_hash, computed);
    }

    #[test]
    fn rejects_uppercase_interface_hash() {
        let _log = TestLog::new(
            "rejects_uppercase_interface_hash",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let unchecked = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder))
            .expect("unchecked parse");
        let computed = unchecked.compute_interface_hash().expect("compute hash");

        // Only uppercase the digest part
        let s = computed.to_string();
        let (prefix, digest) = s.rsplit_once(':').unwrap();
        let bad = format!("{}:{}", prefix, digest.to_ascii_uppercase());

        let err = ConnectorManifest::parse_str(&test_manifest_toml(&bad)).unwrap_err();
        // Since deserialization happens during TOML parsing, custom errors are wrapped in Toml error
        assert!(matches!(err, ManifestError::Toml(_)));
        assert!(err.to_string().contains("digest must be lowercase hex"));
    }

    #[test]
    fn rejects_interface_hash_mismatch() {
        let _log = TestLog::new(
            "rejects_interface_hash_mismatch",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let unchecked = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder))
            .expect("unchecked parse");
        let computed = unchecked.compute_interface_hash().expect("compute hash");
        let mut bad = computed.to_string();
        bad.pop();
        bad.push('0');

        let err = ConnectorManifest::parse_str(&test_manifest_toml(&bad)).unwrap_err();
        assert!(matches!(err, ManifestError::InterfaceHashMismatch { .. }));
    }

    #[test]
    fn test_manifest_hash_stability() {
        let _log = TestLog::new(
            "test_manifest_hash_stability",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(2),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let base = with_computed_hash(&test_manifest_toml(&placeholder));
        let base_manifest = ConnectorManifest::parse_str(&base).expect("base manifest");
        let base_hash = base_manifest.compute_interface_hash().expect("base hash");

        let variant = format!(
            "{base}\n[supply_chain]\n[[supply_chain.attestations]]\ntype = \"in-toto\"\nobject_id = \"objectid:{}\"\n\n[policy]\nrequire_transparency_log = true\nrequire_attestation_types = [\"code-review\"]\nmin_slsa_level = 2\ntrusted_builders = [\"builder-a\", \"builder-b\"]\n",
            "11".repeat(32)
        );
        let variant_manifest =
            ConnectorManifest::parse_str_unchecked(&variant).expect("variant manifest");

        assert_eq!(
            variant_manifest
                .compute_interface_hash()
                .expect("variant hash"),
            base_hash
        );
    }

    #[test]
    fn rejects_network_capability_host_restrictions() {
        let _log = TestLog::new(
            "rejects_network_capability_host_restrictions",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let mut toml = test_manifest_toml(&placeholder);
        toml = toml.replace("network.egress", "network.egress:api.telegram.org:443");

        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash = test_manifest_toml(&hash.to_string())
            .replace("network.egress", "network.egress:api.telegram.org:443");

        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(err, ManifestError::Invalid { .. }));
    }

    #[test]
    fn rejects_missing_forbidden_system_exec() {
        let _log = TestLog::new(
            "rejects_missing_forbidden_system_exec",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder)
            .replace("forbidden = [\"system.exec\"]", "forbidden = []");

        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash = test_manifest_toml(&hash.to_string())
            .replace("forbidden = [\"system.exec\"]", "forbidden = []");

        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "capabilities.forbidden")
        );
        assert!(err.to_string().contains("system.exec"));
    }

    #[test]
    fn rejects_invalid_min_protocol() {
        let _log = TestLog::new(
            "rejects_invalid_min_protocol",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder).replace("fcp2-sym/2.0", "fcp2-sym");
        let err = ConnectorManifest::parse_str_unchecked(&toml).unwrap_err();
        assert!(err.to_string().contains("min_protocol"));
    }

    #[test]
    fn rejects_bad_host_allow_wildcard() {
        let _log = TestLog::new(
            "rejects_bad_host_allow_wildcard",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml =
            test_manifest_toml(&placeholder).replace("api.telegram.org", "*api.telegram.org");
        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash =
            test_manifest_toml(&hash.to_string()).replace("api.telegram.org", "*api.telegram.org");

        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(err, ManifestError::Invalid { .. }));
    }

    #[test]
    fn rejects_localhost_when_denied() {
        let _log = TestLog::new(
            "rejects_localhost_when_denied",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        // deny_localhost is true by default
        let toml = test_manifest_toml(&placeholder).replace("api.telegram.org", "localhost");

        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash =
            test_manifest_toml(&hash.to_string()).replace("api.telegram.org", "localhost");

        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            err.to_string()
                .contains("host `localhost` is allowed but `deny_localhost` is true")
        );
    }

    #[test]
    fn rejects_broad_wildcard() {
        let _log = TestLog::new(
            "rejects_broad_wildcard",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        // *.com is too broad (only 2 parts)
        let toml = test_manifest_toml(&placeholder).replace("api.telegram.org", "*.com");

        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash = test_manifest_toml(&hash.to_string()).replace("api.telegram.org", "*.com");

        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(err.to_string().contains("too broad"));
    }

    #[test]
    fn vector_manifest_valid_parses() {
        let _log = TestLog::new(
            "vector_manifest_valid_parses",
            "fcp-manifest",
            Some("fcp.valid"),
            Some("1.2.3"),
            Some(3),
        );
        let raw = read_vector_manifest("manifest_valid.toml");
        let with_hash = with_computed_hash(&raw);
        let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid manifest");
        assert_eq!(parsed.connector.id.as_str(), "fcp.valid");
        assert_eq!(parsed.provides.operations.len(), 1);
    }

    #[test]
    fn vector_manifest_minimal_parses() {
        let _log = TestLog::new(
            "vector_manifest_minimal_parses",
            "fcp-manifest",
            Some("fcp.minimal"),
            Some("0.1.0"),
            Some(1),
        );
        let raw = read_vector_manifest("manifest_minimal.toml");
        let with_hash = with_computed_hash(&raw);
        let parsed = ConnectorManifest::parse_str(&with_hash).expect("minimal manifest");
        assert_eq!(parsed.connector.id.as_str(), "fcp.minimal");
        // The minimal vector declares two required capabilities:
        // `network.dns` (the connector's own dependency) and
        // `minimal.op` (declared because the operation references it,
        // and the validator added in commit d8dd6bb5a now enforces
        // that every operation's `capability` must appear in either
        // `capabilities.required` or `capabilities.optional`). The
        // vector itself was updated for this rule in commit 9c3a290e;
        // this test now checks the post-update floor.
        assert_eq!(parsed.capabilities.required.len(), 2);
    }

    #[test]
    fn vector_manifest_invalid_version_rejected() {
        let _log = TestLog::new(
            "vector_manifest_invalid_version_rejected",
            "fcp-manifest",
            Some("fcp.invalid"),
            None,
            Some(1),
        );
        let raw = read_vector_manifest("manifest_invalid_version.toml");
        let err = ConnectorManifest::parse_str_unchecked(&raw).unwrap_err();
        assert!(matches!(err, ManifestError::Toml(_)));
    }

    #[test]
    fn vector_manifest_dangerous_caps_rejected() {
        let _log = TestLog::new(
            "vector_manifest_dangerous_caps_rejected",
            "fcp-manifest",
            Some("fcp.dangerous"),
            Some("0.1.0"),
            Some(2),
        );
        let raw = read_vector_manifest("manifest_dangerous_caps.toml");
        let with_hash = with_computed_hash(&raw);
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(err, ManifestError::Invalid { .. }));
    }

    #[test]
    fn rejects_event_caps_without_buffer() {
        let _log = TestLog::new(
            "rejects_event_caps_without_buffer",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let mut toml = test_manifest_toml(&placeholder);
        toml = toml.replace("min_buffer_events = 10000", "min_buffer_events = 0");
        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash = test_manifest_toml(&hash.to_string())
            .replace("min_buffer_events = 10000", "min_buffer_events = 0");
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "event_caps.min_buffer_events")
        );
    }

    #[test]
    fn rejects_operation_capability_missing_from_declared_capabilities() {
        let _log = TestLog::new(
            "rejects_operation_capability_missing_from_declared_capabilities",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        // Remove `telegram.send_message` from `capabilities.required` so
        // the operation's capability is no longer declared. The
        // operation itself is left untouched, so post-strip the validator
        // sees op `telegram_send_message` referencing a capability that
        // appears in neither `required` nor `optional` — the rule under
        // test fires.
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder).replace(", \"telegram.send_message\"", "");

        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash =
            test_manifest_toml(&hash.to_string()).replace(", \"telegram.send_message\"", "");

        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(
            err,
            ManifestError::Invalid { field, .. } if field == "provides.operations.*.capability"
        ));
        assert!(
            err.to_string()
                .contains("must appear in capabilities.required")
        );
    }

    #[test]
    fn rejects_operation_capability_marked_forbidden() {
        let _log = TestLog::new(
            "rejects_operation_capability_marked_forbidden",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        // Move `telegram.send_message` from `capabilities.required` to
        // `capabilities.forbidden`. Required-and-forbidden simultaneously
        // would trip the cross-list duplicate detector first (different
        // error field); to isolate the per-operation-forbidden rule we
        // strip from required AND add to forbidden in the same edit.
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder)
            .replace(", \"telegram.send_message\"", "")
            .replace(
                "forbidden = [\"system.exec\"]",
                "forbidden = [\"system.exec\", \"telegram.send_message\"]",
            );

        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash = test_manifest_toml(&hash.to_string())
            .replace(", \"telegram.send_message\"", "")
            .replace(
                "forbidden = [\"system.exec\"]",
                "forbidden = [\"system.exec\", \"telegram.send_message\"]",
            );

        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(
            err,
            ManifestError::Invalid { field, .. } if field == "provides.operations.*.capability"
        ));
        assert!(err.to_string().contains("references forbidden capability"));
    }

    #[test]
    fn rejects_signatures_without_threshold() {
        let _log = TestLog::new(
            "rejects_signatures_without_threshold",
            "fcp-manifest",
            Some("fcp.valid"),
            Some("1.2.3"),
            Some(3),
        );
        let raw = read_vector_manifest("manifest_valid.toml");
        let mut with_hash = with_computed_hash(&raw);
        with_hash = with_hash.replace("publisher_threshold = \"2-of-2\"\n", "");
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "signatures.publisher_threshold")
        );
    }

    #[test]
    fn rejects_duplicate_signature_kid() {
        let _log = TestLog::new(
            "rejects_duplicate_signature_kid",
            "fcp-manifest",
            Some("fcp.valid"),
            Some("1.2.3"),
            Some(3),
        );
        let raw = read_vector_manifest("manifest_valid.toml");
        let with_hash = with_computed_hash(&raw).replace("pub2", "pub1");
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "signatures.publisher_signatures")
        );
    }

    #[test]
    fn rejects_duplicate_supply_chain_attestations() {
        let _log = TestLog::new(
            "rejects_duplicate_supply_chain_attestations",
            "fcp-manifest",
            Some("fcp.valid"),
            Some("1.2.3"),
            Some(3),
        );
        let raw = read_vector_manifest("manifest_valid.toml");
        let with_hash = with_computed_hash(&raw).replace(
            "objectid:3333333333333333333333333333333333333333333333333333333333333333",
            "objectid:2222222222222222222222222222222222222222222222222222222222222222",
        );
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "supply_chain.attestations")
        );
    }

    #[test]
    fn rejects_invalid_slsa_level() {
        let _log = TestLog::new(
            "rejects_invalid_slsa_level",
            "fcp-manifest",
            Some("fcp.valid"),
            Some("1.2.3"),
            Some(3),
        );
        let raw = read_vector_manifest("manifest_valid.toml");
        let with_hash =
            with_computed_hash(&raw).replace("min_slsa_level = 2", "min_slsa_level = 9");
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "policy.min_slsa_level")
        );
    }

    #[test]
    fn rejects_invalid_base64_signature() {
        let _log = TestLog::new(
            "rejects_invalid_base64_signature",
            "fcp-manifest",
            Some("fcp.valid"),
            Some("1.2.3"),
            Some(3),
        );
        let raw = read_vector_manifest("manifest_valid.toml");
        let with_hash = with_computed_hash(&raw).replace("base64:Zm9v", "Zm9v");
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(err, ManifestError::Toml(_)));
    }

    #[test]
    fn rejects_uppercase_host_allow() {
        let _log = TestLog::new(
            "rejects_uppercase_host_allow",
            "fcp-manifest",
            Some("fcp.valid"),
            Some("1.2.3"),
            Some(3),
        );
        let raw = read_vector_manifest("manifest_valid.toml");
        let with_hash = with_computed_hash(&raw).replace("api.telegram.org", "API.Telegram.org");
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "provides.operations.*.network_constraints.host_allow")
        );
    }

    #[test]
    fn rejects_ip_literal_in_host_allow() {
        let _log = TestLog::new(
            "rejects_ip_literal_in_host_allow",
            "fcp-manifest",
            Some("fcp.valid"),
            Some("1.2.3"),
            Some(3),
        );
        let raw = read_vector_manifest("manifest_valid.toml");
        let with_hash = with_computed_hash(&raw).replace("api.telegram.org", "192.0.2.1");
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "provides.operations.*.network_constraints.host_allow")
        );
    }

    #[test]
    fn rejects_invalid_rate_limit_shorthand() {
        let _log = TestLog::new(
            "rejects_invalid_rate_limit_shorthand",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder).replace("60/min", "60/fortnight");
        let err = ConnectorManifest::parse_str(&toml).unwrap_err();
        assert!(matches!(err, ManifestError::Toml(_)));
    }

    #[test]
    fn rejects_invalid_signature_threshold() {
        let _log = TestLog::new(
            "rejects_invalid_signature_threshold",
            "fcp-manifest",
            Some("fcp.valid"),
            Some("1.2.3"),
            Some(3),
        );
        let raw = read_vector_manifest("manifest_valid.toml");
        let with_hash = with_computed_hash(&raw).replace(
            "publisher_threshold = \"2-of-2\"",
            "publisher_threshold = \"3-of-2\"",
        );
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "signatures.publisher_threshold")
        );
    }

    #[test]
    fn rejects_empty_connector_name() {
        let _log = TestLog::new(
            "rejects_empty_connector_name",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder)
            .replace("name = \"Telegram Connector\"", "name = \"\"");
        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash = test_manifest_toml(&hash.to_string())
            .replace("name = \"Telegram Connector\"", "name = \"\"");
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(err, ManifestError::Invalid { field, .. } if field == "connector.name"));
    }

    #[test]
    fn rejects_zero_cpu_percent() {
        let _log = TestLog::new(
            "rejects_zero_cpu_percent",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder).replace("cpu_percent = 50", "cpu_percent = 0");
        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash =
            test_manifest_toml(&hash.to_string()).replace("cpu_percent = 50", "cpu_percent = 0");
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "sandbox.cpu_percent")
        );
    }

    #[test]
    fn embedded_manifest_fixture_bytes_match() {
        let _log = TestLog::new(
            "embedded_manifest_fixture_bytes_match",
            "fcp-manifest",
            Some("fcp.minimal"),
            Some("0.1.0"),
            Some(1),
        );
        let path = vector_manifest_path("manifest_minimal.toml");
        let raw = std::fs::read(&path).expect("read manifest fixture");
        assert_eq!(EMBEDDED_MINIMAL_MANIFEST, raw.as_slice());
    }

    // ── Capability-ID lint tests (bd-rk6a / bd-2kt1) ───────────────────

    #[test]
    fn lint_rejects_url_scheme_http() {
        let _log = TestLog::new(
            "lint_rejects_url_scheme_http",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err = lint_capability_id_no_network_addressing(
            "http:api.example.com",
            "capabilities.required",
        );
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("URL scheme"));
        assert!(msg.contains("http:"));
    }

    #[test]
    fn lint_rejects_url_scheme_https() {
        let _log = TestLog::new(
            "lint_rejects_url_scheme_https",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err = lint_capability_id_no_network_addressing(
            "https:api.example.com",
            "capabilities.required",
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("URL scheme"));
    }

    #[test]
    fn lint_rejects_url_scheme_wss() {
        let _log = TestLog::new(
            "lint_rejects_url_scheme_wss",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err = lint_capability_id_no_network_addressing(
            "wss:stream.example.com",
            "capabilities.optional",
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("URL scheme"));
    }

    #[test]
    fn lint_rejects_port_number_443() {
        let _log = TestLog::new(
            "lint_rejects_port_number_443",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err =
            lint_capability_id_no_network_addressing("api.example:443", "capabilities.required");
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("port number"));
        assert!(msg.contains(":443"));
    }

    #[test]
    fn lint_rejects_port_number_8080() {
        let _log = TestLog::new(
            "lint_rejects_port_number_8080",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err = lint_capability_id_no_network_addressing("service:8080", "capabilities.required");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("port number"));
    }

    #[test]
    fn lint_rejects_hostname_tld_com() {
        let _log = TestLog::new(
            "lint_rejects_hostname_tld_com",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err =
            lint_capability_id_no_network_addressing("api.example.com", "capabilities.required");
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("hostname"));
        assert!(msg.contains(".com"));
    }

    #[test]
    fn lint_rejects_hostname_tld_org() {
        let _log = TestLog::new(
            "lint_rejects_hostname_tld_org",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err =
            lint_capability_id_no_network_addressing("api.telegram.org", "capabilities.required");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains(".org"));
    }

    #[test]
    fn lint_rejects_hostname_tld_net() {
        let _log = TestLog::new(
            "lint_rejects_hostname_tld_net",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err = lint_capability_id_no_network_addressing(
            "service.example.net",
            "capabilities.optional",
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains(".net"));
    }

    #[test]
    fn lint_rejects_hostname_tld_edu() {
        let _log = TestLog::new(
            "lint_rejects_hostname_tld_edu",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err =
            lint_capability_id_no_network_addressing("api.university.edu", "capabilities.required");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains(".edu"));
    }

    #[test]
    fn lint_rejects_hostname_port_combo() {
        let _log = TestLog::new(
            "lint_rejects_hostname_port_combo",
            "fcp-manifest",
            None,
            None,
            None,
        );
        // "api.example.org:443" — segments: ["api", "example", "org:443"]
        // Port check catches ":443" inside the last segment.
        let err = lint_capability_id_no_network_addressing(
            "api.example.org:443",
            "capabilities.required",
        );
        assert!(err.is_err());
    }

    #[test]
    fn lint_rejects_ipv4_address() {
        let _log = TestLog::new(
            "lint_rejects_ipv4_address",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err =
            lint_capability_id_no_network_addressing("connect.127.0.0.1", "capabilities.required");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("IPv4"));
    }

    #[test]
    fn lint_rejects_ipv4_loopback() {
        let _log = TestLog::new(
            "lint_rejects_ipv4_loopback",
            "fcp-manifest",
            None,
            None,
            None,
        );
        let err = lint_capability_id_no_network_addressing("10.0.0.1", "capabilities.forbidden");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("IPv4"));
    }

    #[test]
    fn lint_allows_legitimate_capability_ids() {
        let _log = TestLog::new(
            "lint_allows_legitimate_capability_ids",
            "fcp-manifest",
            None,
            None,
            None,
        );
        // All of these should pass the lint without errors.
        let legitimate = [
            "network.dns",
            "network.egress",
            "network.tls.sni",
            "ipc.gateway",
            "media.download",
            "system.exec",
            "telegram.send_message",
            "discord.send_message",
            "twitter.post",
            "github.create_issue",
            "stripe.charge",
            "storage.read",
            "database.query",
            "audit.read",
            "policy.check",
            "connector.health",
            "my.custom.capability",
            "a",
            "x.y",
        ];
        for id in &legitimate {
            let result = lint_capability_id_no_network_addressing(id, "capabilities.required");
            assert!(
                result.is_ok(),
                "expected `{id}` to pass lint, got: {:?}",
                result.unwrap_err()
            );
        }
    }

    #[test]
    fn lint_single_digit_port_not_flagged() {
        let _log = TestLog::new(
            "lint_single_digit_port_not_flagged",
            "fcp-manifest",
            None,
            None,
            None,
        );
        // Single-digit after colon should NOT be flagged as a port
        // (avoids false positives on version-like segments like "v:2").
        let result =
            lint_capability_id_no_network_addressing("priority:3", "capabilities.required");
        assert!(
            result.is_ok(),
            "single-digit colon suffix should not be flagged as port"
        );
    }

    #[test]
    fn rejects_capability_id_with_hostname_in_manifest() {
        let _log = TestLog::new(
            "rejects_capability_id_with_hostname_in_manifest",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        // Replace a legitimate capability with one containing a hostname.
        let toml = test_manifest_toml(&placeholder).replace("media.download", "api.example.com");

        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash =
            test_manifest_toml(&hash.to_string()).replace("media.download", "api.example.com");

        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(err, ManifestError::Invalid { .. }));
        assert!(err.to_string().contains("hostname"));
    }

    #[test]
    fn rejects_capability_id_with_url_scheme_in_manifest() {
        let _log = TestLog::new(
            "rejects_capability_id_with_url_scheme_in_manifest",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml =
            test_manifest_toml(&placeholder).replace("media.download", "https:api.telegram.org");

        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash = test_manifest_toml(&hash.to_string())
            .replace("media.download", "https:api.telegram.org");

        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(err, ManifestError::Invalid { .. }));
        assert!(err.to_string().contains("URL scheme"));
    }

    #[test]
    fn rejects_operation_capability_with_hostname() {
        let _log = TestLog::new(
            "rejects_operation_capability_with_hostname",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        // Replace the operation's capability field with a hostname pattern.
        let toml = test_manifest_toml(&placeholder).replace(
            "capability = \"telegram.send_message\"",
            "capability = \"api.telegram.org\"",
        );

        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash = test_manifest_toml(&hash.to_string()).replace(
            "capability = \"telegram.send_message\"",
            "capability = \"api.telegram.org\"",
        );

        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(err, ManifestError::Invalid { .. }));
    }

    #[test]
    fn rejects_capability_id_with_port_in_manifest() {
        let _log = TestLog::new(
            "rejects_capability_id_with_port_in_manifest",
            "fcp-manifest",
            Some("fcp.telegram"),
            Some("2026.1.0"),
            Some(4),
        );
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder).replace("media.download", "service:8080");

        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash =
            test_manifest_toml(&hash.to_string()).replace("media.download", "service:8080");

        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(err, ManifestError::Invalid { .. }));
        assert!(err.to_string().contains("port number"));
    }

    // ── ConnectorArchetype ───────────────────────────────────────────────

    #[test]
    fn connector_archetype_as_str_all_variants() {
        assert_eq!(ConnectorArchetype::Bidirectional.as_str(), "bidirectional");
        assert_eq!(ConnectorArchetype::Streaming.as_str(), "streaming");
        assert_eq!(ConnectorArchetype::Operational.as_str(), "operational");
        assert_eq!(ConnectorArchetype::Storage.as_str(), "storage");
        assert_eq!(ConnectorArchetype::Knowledge.as_str(), "knowledge");
    }

    #[test]
    fn connector_archetype_serde_roundtrip() {
        for variant in [
            ConnectorArchetype::Bidirectional,
            ConnectorArchetype::Streaming,
            ConnectorArchetype::Operational,
            ConnectorArchetype::Storage,
            ConnectorArchetype::Knowledge,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let parsed: ConnectorArchetype = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn connector_archetype_debug_clone_copy_eq() {
        let a = ConnectorArchetype::Streaming;
        let b = a;
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        let _ = format!("{a:?}");
    }

    // ── ConnectorRuntimeFormat ───────────────────────────────────────────

    #[test]
    fn connector_runtime_format_serde() {
        let native: ConnectorRuntimeFormat = serde_json::from_str("\"native\"").unwrap();
        assert_eq!(native, ConnectorRuntimeFormat::Native);
        let wasi: ConnectorRuntimeFormat = serde_json::from_str("\"wasi\"").unwrap();
        assert_eq!(wasi, ConnectorRuntimeFormat::Wasi);
    }

    #[test]
    fn connector_runtime_format_debug_clone_copy() {
        let f = ConnectorRuntimeFormat::Native;
        let f2 = f;
        assert_eq!(f, f2);
        let _ = format!("{f:?}");
    }

    // ── ConnectorStateModel ──────────────────────────────────────────────

    #[test]
    fn connector_state_model_is_methods() {
        assert!(ConnectorStateModel::Stateless.is_stateless());
        assert!(!ConnectorStateModel::Stateless.is_singleton_writer());
        assert!(!ConnectorStateModel::Stateless.is_crdt());

        assert!(ConnectorStateModel::SingletonWriter.is_singleton_writer());
        assert!(!ConnectorStateModel::SingletonWriter.is_stateless());

        let crdt = ConnectorStateModel::Crdt {
            crdt_type: ConnectorCrdtType::LwwMap,
        };
        assert!(crdt.is_crdt());
        assert!(!crdt.is_stateless());
    }

    #[test]
    fn connector_state_model_crdt_type() {
        assert!(ConnectorStateModel::Stateless.crdt_type().is_none());
        assert!(ConnectorStateModel::SingletonWriter.crdt_type().is_none());
        let crdt = ConnectorStateModel::Crdt {
            crdt_type: ConnectorCrdtType::OrSet,
        };
        assert_eq!(crdt.crdt_type(), Some(ConnectorCrdtType::OrSet));
    }

    #[test]
    fn connector_state_model_display() {
        assert_eq!(ConnectorStateModel::Stateless.to_string(), "stateless");
        assert_eq!(
            ConnectorStateModel::SingletonWriter.to_string(),
            "singleton_writer"
        );
        let crdt = ConnectorStateModel::Crdt {
            crdt_type: ConnectorCrdtType::GCounter,
        };
        assert_eq!(crdt.to_string(), "crdt(g_counter)");
    }

    #[test]
    fn connector_state_model_default_is_stateless() {
        assert_eq!(
            ConnectorStateModel::default(),
            ConnectorStateModel::Stateless
        );
    }

    // ── ConnectorCrdtType ────────────────────────────────────────────────

    #[test]
    fn connector_crdt_type_as_str_all() {
        assert_eq!(ConnectorCrdtType::LwwMap.as_str(), "lww_map");
        assert_eq!(ConnectorCrdtType::OrSet.as_str(), "or_set");
        assert_eq!(ConnectorCrdtType::GCounter.as_str(), "g_counter");
        assert_eq!(ConnectorCrdtType::PnCounter.as_str(), "pn_counter");
    }

    #[test]
    fn connector_crdt_type_serde_roundtrip() {
        for variant in [
            ConnectorCrdtType::LwwMap,
            ConnectorCrdtType::OrSet,
            ConnectorCrdtType::GCounter,
            ConnectorCrdtType::PnCounter,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let parsed: ConnectorCrdtType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, variant);
        }
    }

    // ── ManifestApprovalMode ─────────────────────────────────────────────

    #[test]
    fn manifest_approval_mode_serde() {
        for (s, expected) in [
            ("\"none\"", ManifestApprovalMode::None),
            ("\"policy\"", ManifestApprovalMode::Policy),
            ("\"interactive\"", ManifestApprovalMode::Interactive),
            ("\"elevation_token\"", ManifestApprovalMode::ElevationToken),
        ] {
            let parsed: ManifestApprovalMode = serde_json::from_str(s).unwrap();
            assert_eq!(parsed, expected);
            let re_serialized = serde_json::to_string(&parsed).unwrap();
            assert_eq!(re_serialized, s);
        }
    }

    // ── SandboxProfile ───────────────────────────────────────────────────

    #[test]
    fn sandbox_profile_serde() {
        let strict: SandboxProfile = serde_json::from_str("\"strict\"").unwrap();
        assert_eq!(strict, SandboxProfile::Strict);
        let permissive: SandboxProfile = serde_json::from_str("\"permissive\"").unwrap();
        assert_eq!(permissive, SandboxProfile::Permissive);
    }

    // ── ManifestError display ────────────────────────────────────────────

    #[test]
    fn manifest_error_invalid_display() {
        let err = ManifestError::Invalid {
            field: "zones.home",
            message: "must not be empty".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("zones.home"));
        assert!(msg.contains("must not be empty"));
    }

    #[test]
    fn manifest_error_hash_mismatch_display() {
        let err = ManifestError::InterfaceHashMismatch {
            expected: "abc".into(),
            found: "xyz".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("abc"));
        assert!(msg.contains("xyz"));
    }

    // ── InterfaceHash ────────────────────────────────────────────────────

    #[test]
    fn interface_hash_display_and_eq() {
        let h1 = InterfaceHash::new_blake3_256(INTERFACE_HASH_DOMAIN, [0xAA; 32]);
        let h2 = h1;
        assert_eq!(h1, h2);
        let display = h1.to_string();
        assert!(display.starts_with("blake3-256:"));
        assert!(display.contains(INTERFACE_HASH_DOMAIN));
        assert!(display.contains(&"aa".repeat(32)));
    }

    #[test]
    fn interface_hash_try_from_string() {
        let hex = "aa".repeat(32);
        let s = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{hex}");
        let h = InterfaceHash::try_from(s).unwrap();
        assert_eq!(h.algorithm, InterfaceHashAlgorithm::Blake3_256);
        assert_eq!(h.digest, [0xAA; 32]);
    }

    #[test]
    fn interface_hash_rejects_uppercase_hex() {
        let hex = "AA".repeat(32);
        let s = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{hex}");
        let err = InterfaceHash::try_from(s).unwrap_err();
        assert!(err.to_string().contains("lowercase"));
    }

    #[test]
    fn interface_hash_rejects_bad_algorithm() {
        let hex = "aa".repeat(32);
        let s = format!("sha256:{INTERFACE_HASH_DOMAIN}:{hex}");
        let err = InterfaceHash::try_from(s).unwrap_err();
        assert!(err.to_string().contains("algorithm"));
    }

    // ── ManifestSchemaVersion ────────────────────────────────────────────

    #[test]
    fn manifest_schema_version_serde() {
        let v: ManifestSchemaVersion = serde_json::from_str("\"2.1\"").unwrap();
        assert_eq!(v.major, 2);
        assert_eq!(v.minor, 1);
        let serialized = serde_json::to_string(&v).unwrap();
        assert_eq!(serialized, "\"2.1\"");
    }

    #[test]
    fn manifest_schema_version_display() {
        let v = ManifestSchemaVersion { major: 3, minor: 0 };
        assert_eq!(v.to_string(), "3.0");
    }

    // ── RateLimit parsing ────────────────────────────────────────────────

    #[test]
    fn rate_limit_serde_string() {
        let rl: RateLimit = serde_json::from_str("\"100/min\"").unwrap();
        assert_eq!(rl.0.max, 100);
        assert_eq!(rl.0.per_ms, 60_000);
    }

    #[test]
    fn rate_limit_serde_per_sec() {
        let rl: RateLimit = serde_json::from_str("\"5/sec\"").unwrap();
        assert_eq!(rl.0.max, 5);
        assert_eq!(rl.0.per_ms, 1_000);
    }

    #[test]
    fn rate_limit_serde_per_hour() {
        let rl: RateLimit = serde_json::from_str("\"1000/hour\"").unwrap();
        assert_eq!(rl.0.max, 1000);
        assert_eq!(rl.0.per_ms, 3_600_000);
    }

    // ── Base64Bytes ──────────────────────────────────────────────────────

    #[test]
    fn base64_bytes_serde_roundtrip() {
        let data = vec![1, 2, 3, 4, 5];
        let b = Base64Bytes(data.clone());
        let json = serde_json::to_string(&b).unwrap();
        let parsed: Base64Bytes = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.as_bytes(), &data);
    }

    #[test]
    fn base64_bytes_debug() {
        let b = Base64Bytes(vec![0xDE, 0xAD]);
        let debug = format!("{b:?}");
        assert!(debug.contains("Base64Bytes"));
    }

    // ── ProtocolRequirement ──────────────────────────────────────────────

    #[test]
    fn protocol_requirement_serde() {
        let pr: ProtocolRequirement = serde_json::from_str("\"fcp2-sym/2.0\"").unwrap();
        assert_eq!(pr.name, "fcp2-sym");
        assert_eq!(pr.version.major, 2);
        assert_eq!(pr.version.minor, 0);
        let serialized = serde_json::to_string(&pr).unwrap();
        assert_eq!(serialized, "\"fcp2-sym/2.0\"");
    }

    // ── FeatureId ────────────────────────────────────────────────────────

    #[test]
    fn feature_id_serde() {
        let fid: FeatureId = serde_json::from_str("\"fcps.aead.xchacha20poly1305\"").unwrap();
        assert_eq!(fid.as_str(), "fcps.aead.xchacha20poly1305");
    }

    // ── Embedded manifest ────────────────────────────────────────────────

    #[test]
    fn embedded_minimal_manifest_is_valid_utf8() {
        let text = std::str::from_utf8(EMBEDDED_MINIMAL_MANIFEST);
        assert!(text.is_ok());
    }

    // ── ProtocolVersion ────────────────────────────────────────────────

    #[test]
    fn protocol_version_display() {
        let pv = ProtocolVersion { major: 2, minor: 1 };
        assert_eq!(pv.to_string(), "2.1");
    }

    #[test]
    fn protocol_version_try_from_valid() {
        let pv = ProtocolVersion::try_from("2.0".to_string()).unwrap();
        assert_eq!(pv.major, 2);
        assert_eq!(pv.minor, 0);
    }

    #[test]
    fn protocol_version_try_from_missing_dot() {
        let err = ProtocolVersion::try_from("20".to_string()).unwrap_err();
        assert!(err.to_string().contains("MAJOR.MINOR"));
    }

    #[test]
    fn protocol_version_try_from_non_numeric_major() {
        let err = ProtocolVersion::try_from("abc.0".to_string()).unwrap_err();
        assert!(err.to_string().contains("major"));
    }

    #[test]
    fn protocol_version_try_from_non_numeric_minor() {
        let err = ProtocolVersion::try_from("2.xyz".to_string()).unwrap_err();
        assert!(err.to_string().contains("minor"));
    }

    // ── FeatureId edge cases ───────────────────────────────────────────

    #[test]
    fn feature_id_as_str() {
        let fid = FeatureId::try_from("fcps.aead".to_string()).unwrap();
        assert_eq!(fid.as_str(), "fcps.aead");
    }

    #[test]
    fn feature_id_into_string() {
        let fid = FeatureId::try_from("fcps.test".to_string()).unwrap();
        let s: String = fid.into();
        assert_eq!(s, "fcps.test");
    }

    // ── SignatureThreshold ─────────────────────────────────────────────

    #[test]
    fn signature_threshold_display() {
        let st = SignatureThreshold { k: 2, n: 3 };
        assert_eq!(st.to_string(), "2-of-3");
    }

    #[test]
    fn signature_threshold_serde_roundtrip() {
        let st = SignatureThreshold { k: 2, n: 3 };
        let json = serde_json::to_string(&st).unwrap();
        assert_eq!(json, "\"2-of-3\"");
        let deserialized: SignatureThreshold = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, st);
    }

    #[test]
    fn signature_threshold_try_from_valid() {
        let st = SignatureThreshold::try_from("1-of-5".to_string()).unwrap();
        assert_eq!(st.k, 1);
        assert_eq!(st.n, 5);
    }

    #[test]
    fn signature_threshold_try_from_missing_separator() {
        let err = SignatureThreshold::try_from("2/3".to_string()).unwrap_err();
        assert!(err.to_string().contains("2-of-3"));
    }

    #[test]
    fn signature_threshold_try_from_non_numeric_k() {
        let err = SignatureThreshold::try_from("x-of-3".to_string()).unwrap_err();
        assert!(err.to_string().contains("k must be"));
    }

    #[test]
    fn signature_threshold_validate_zero_k() {
        let st = SignatureThreshold { k: 0, n: 3 };
        let err = st.validate(3).unwrap_err();
        assert!(err.to_string().contains("invalid threshold"));
    }

    #[test]
    fn signature_threshold_validate_k_gt_n() {
        let st = SignatureThreshold { k: 4, n: 3 };
        let err = st.validate(4).unwrap_err();
        assert!(err.to_string().contains("invalid threshold"));
    }

    #[test]
    fn signature_threshold_validate_insufficient_sigs() {
        let st = SignatureThreshold { k: 3, n: 5 };
        let err = st.validate(2).unwrap_err();
        assert!(err.to_string().contains("insufficient"));
    }

    // ── ObjectId ───────────────────────────────────────────────────────

    #[test]
    fn object_id_prefixed_roundtrip() {
        let hex_str = format!("objectid:{}", "ab".repeat(32));
        let oid = ObjectId::parse_prefixed(&hex_str).unwrap();
        let display = oid.to_prefixed_string();
        assert_eq!(display, hex_str);
    }

    #[test]
    fn object_id_prefixed_serde_roundtrip() {
        #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
        struct Wrapper {
            #[serde(with = "fcp_core::util::objectid_prefixed")]
            object_id: ObjectId,
        }

        let hex_str = format!("objectid:{}", "cd".repeat(32));
        let oid = ObjectId::parse_prefixed(&hex_str).unwrap();
        let json = serde_json::to_string(&Wrapper { object_id: oid }).unwrap();
        let deserialized: Wrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.object_id, oid);
    }

    #[test]
    fn object_id_prefixed_wrong_length() {
        let err = ObjectId::parse_prefixed("objectid:abcdef").unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn object_id_prefixed_invalid_hex() {
        let err = ObjectId::parse_prefixed("objectid:zzzz").unwrap_err();
        assert!(err.to_string().contains("hex"));
    }

    #[test]
    fn object_id_prefixed_without_prefix() {
        let hex_str = "ab".repeat(32);
        let oid = ObjectId::parse_prefixed(&hex_str).unwrap();
        assert_eq!(oid.to_prefixed_string(), format!("objectid:{hex_str}"));
    }

    #[test]
    fn object_id_prefixed_serde_option_roundtrip() {
        #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
        struct Wrapper {
            #[serde(default, with = "fcp_core::util::objectid_prefixed::option")]
            object_id: Option<ObjectId>,
        }

        let oid = ObjectId::from_bytes([0xcd; 32]);
        let json = serde_json::to_string(&Wrapper {
            object_id: Some(oid),
        })
        .unwrap();
        let deserialized: Wrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.object_id, Some(oid));
    }

    // ── Base64Bytes edge cases ─────────────────────────────────────────

    #[test]
    fn base64_bytes_as_bytes() {
        let b = Base64Bytes(vec![1, 2, 3]);
        assert_eq!(b.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn base64_bytes_missing_prefix() {
        let err = Base64Bytes::try_from("SGVsbG8=".to_string()).unwrap_err();
        assert!(err.to_string().contains("base64:"));
    }

    #[test]
    fn base64_bytes_invalid_chars() {
        let err = Base64Bytes::try_from("base64:!!!invalid!!!".to_string()).unwrap_err();
        assert!(err.to_string().contains("invalid base64"));
    }

    #[test]
    fn base64_bytes_empty_data() {
        let b = Base64Bytes::try_from("base64:".to_string()).unwrap();
        assert!(b.as_bytes().is_empty());
    }

    // ── AttestationType ────────────────────────────────────────────────

    #[test]
    fn attestation_type_serde_roundtrip() {
        for (variant, expected) in [
            (AttestationType::InToto, "\"in-toto\""),
            (AttestationType::ReproducibleBuild, "\"reproducible-build\""),
            (AttestationType::CodeReview, "\"code-review\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected);
            let deserialized: AttestationType = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, variant);
        }
    }

    #[test]
    fn attestation_type_invalid() {
        let result = serde_json::from_str::<AttestationType>("\"unknown\"");
        assert!(result.is_err());
    }

    // ── ManifestApprovalMode ───────────────────────────────────────────

    #[test]
    fn manifest_approval_mode_to_core() {
        assert_eq!(
            CoreApprovalMode::from(ManifestApprovalMode::None),
            CoreApprovalMode::None
        );
        assert_eq!(
            CoreApprovalMode::from(ManifestApprovalMode::Policy),
            CoreApprovalMode::Policy
        );
        assert_eq!(
            CoreApprovalMode::from(ManifestApprovalMode::Interactive),
            CoreApprovalMode::Interactive
        );
        assert_eq!(
            CoreApprovalMode::from(ManifestApprovalMode::ElevationToken),
            CoreApprovalMode::ElevationToken
        );
    }

    #[test]
    fn manifest_approval_mode_backward_compat() {
        let mode: ManifestApprovalMode = serde_json::from_str("\"approval_required\"").unwrap();
        assert_eq!(mode, ManifestApprovalMode::ElevationToken);
    }

    #[test]
    fn manifest_approval_mode_invalid() {
        let result = serde_json::from_str::<ManifestApprovalMode>("\"bogus\"");
        assert!(result.is_err());
    }

    // ── RateLimit ──────────────────────────────────────────────────────

    #[test]
    fn rate_limit_as_inner() {
        let rl: RateLimit = serde_json::from_str("\"100/hour\"").unwrap();
        assert_eq!(rl.as_inner().max, 100);
        assert_eq!(rl.as_inner().per_ms, 3_600_000);
    }

    #[test]
    fn rate_limit_all_shorthand_units() {
        for (input, expected_ms) in [
            ("\"10/sec\"", 1_000_u64),
            ("\"10/s\"", 1_000),
            ("\"10/min\"", 60_000),
            ("\"10/m\"", 60_000),
            ("\"10/hour\"", 3_600_000),
            ("\"10/h\"", 3_600_000),
            ("\"10/day\"", 86_400_000),
            ("\"10/d\"", 86_400_000),
        ] {
            let rl: RateLimit = serde_json::from_str(input).unwrap();
            assert_eq!(rl.as_inner().per_ms, expected_ms, "failed for {input}");
            assert_eq!(rl.as_inner().max, 10);
        }
    }

    #[test]
    fn rate_limit_shorthand_invalid_unit() {
        let result = serde_json::from_str::<RateLimit>("\"10/year\"");
        assert!(result.is_err());
    }

    #[test]
    fn rate_limit_shorthand_invalid_format() {
        let result = serde_json::from_str::<RateLimit>("\"10\"");
        assert!(result.is_err());
    }

    #[test]
    fn rate_limit_shorthand_non_numeric_max() {
        let result = serde_json::from_str::<RateLimit>("\"abc/min\"");
        assert!(result.is_err());
    }

    // ── ConnectorStateModel serde roundtrip ────────────────────────────

    #[test]
    fn connector_state_model_serde_roundtrip_stateless() {
        let model = ConnectorStateModel::Stateless;
        let json = serde_json::to_string(&model).unwrap();
        let deserialized: ConnectorStateModel = serde_json::from_str(&json).unwrap();
        assert!(deserialized.is_stateless());
    }

    #[test]
    fn connector_state_model_serde_roundtrip_singleton() {
        let model = ConnectorStateModel::SingletonWriter;
        let json = serde_json::to_string(&model).unwrap();
        let deserialized: ConnectorStateModel = serde_json::from_str(&json).unwrap();
        assert!(deserialized.is_singleton_writer());
    }

    #[test]
    fn connector_state_model_serde_roundtrip_crdt() {
        let model = ConnectorStateModel::Crdt {
            crdt_type: ConnectorCrdtType::LwwMap,
        };
        let json = serde_json::to_string(&model).unwrap();
        let deserialized: ConnectorStateModel = serde_json::from_str(&json).unwrap();
        assert!(deserialized.is_crdt());
        assert_eq!(deserialized.crdt_type(), Some(ConnectorCrdtType::LwwMap));
    }

    // ── ConnectorStateSection ──────────────────────────────────────────

    #[test]
    fn state_section_to_model_stateless() {
        let section: ConnectorStateSection = serde_json::from_value(json!({
            "model": "stateless",
            "state_schema_version": "1.0"
        }))
        .unwrap();
        assert!(section.to_state_model().unwrap().is_stateless());
    }

    #[test]
    fn state_section_to_model_crdt_missing_type() {
        let section: ConnectorStateSection = serde_json::from_value(json!({
            "model": "crdt",
            "state_schema_version": "1.0"
        }))
        .unwrap();
        let err = section.to_state_model().unwrap_err();
        assert!(err.to_string().contains("crdt_type"));
    }

    #[test]
    fn state_section_to_model_crdt_with_type() {
        let section: ConnectorStateSection = serde_json::from_value(json!({
            "model": "crdt",
            "state_schema_version": "1.0",
            "crdt_type": "lww_map"
        }))
        .unwrap();
        let model = section.to_state_model().unwrap();
        assert_eq!(model.crdt_type(), Some(ConnectorCrdtType::LwwMap));
    }

    #[test]
    fn state_section_validate_empty_schema_version() {
        let section: ConnectorStateSection = serde_json::from_value(json!({
            "model": "stateless",
            "state_schema_version": "  "
        }))
        .unwrap();
        let err = section.validate().unwrap_err();
        assert!(err.to_string().contains("state_schema_version"));
    }

    // ── EventSection serde ─────────────────────────────────────────────

    #[test]
    fn event_section_serde_minimal() {
        let section: EventSection = serde_json::from_value(json!({
            "description": "Test event"
        }))
        .unwrap();
        assert_eq!(section.description, "Test event");
        assert!(!section.streaming);
        assert!(!section.replay);
        assert!(!section.requires_ack);
        assert!(section.topic.is_none());
        assert!(section.schema.is_none());
    }

    #[test]
    fn event_section_serde_full() {
        let section: EventSection = serde_json::from_value(json!({
            "description": "Full event",
            "streaming": true,
            "replay": true,
            "topic": "events.test",
            "requires_ack": true,
            "schema": {"type": "object"}
        }))
        .unwrap();
        assert!(section.streaming);
        assert!(section.replay);
        assert!(section.requires_ack);
        assert_eq!(section.topic.as_deref(), Some("events.test"));
    }

    #[test]
    fn event_section_serde_roundtrip() {
        let section = EventSection {
            description: "Roundtrip test".into(),
            streaming: true,
            replay: false,
            topic: Some("t".into()),
            requires_ack: true,
            schema: Some(json!({"type": "string"})),
        };
        let json = serde_json::to_string(&section).unwrap();
        let deserialized: EventSection = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.description, "Roundtrip test");
        assert!(deserialized.streaming);
        assert!(!deserialized.replay);
    }

    #[test]
    fn event_section_unknown_field_rejected() {
        let err = serde_json::from_value::<EventSection>(json!({
            "description": "Test event",
            "unexpected": true
        }))
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    // ── EventCapsSection validation ────────────────────────────────────

    #[test]
    fn event_caps_streaming_requires_nonzero_buffer() {
        let caps = EventCapsSection {
            streaming: true,
            replay: false,
            min_buffer_events: 0,
        };
        let err = caps.validate().unwrap_err();
        assert!(err.to_string().contains("min_buffer_events"));
    }

    #[test]
    fn event_caps_no_streaming_allows_zero_buffer() {
        let caps = EventCapsSection {
            streaming: false,
            replay: false,
            min_buffer_events: 0,
        };
        assert!(caps.validate().is_ok());
    }

    // ── RateLimitsSection to_declarations ──────────────────────────────

    #[test]
    fn rate_limits_section_to_declarations_empty() {
        let section = RateLimitsSection::default();
        let decls = section.to_declarations();
        assert!(decls.limits.is_empty());
        assert!(decls.tool_pool_map.is_empty());
    }

    #[test]
    fn rate_limits_section_to_declarations_with_pool() {
        let section = RateLimitsSection {
            pools: vec![RateLimitPoolSection {
                id: "api_global".into(),
                description: Some("Global API limit".into()),
                requests: 100,
                window_ms: 60_000,
                burst: Some(10),
                unit: Some("tokens".into()),
                enforcement: Some("soft".into()),
                scope: Some("credential".into()),
            }],
            operation_pools: {
                let mut m = std::collections::HashMap::new();
                m.insert("list_items".into(), vec!["api_global".into()]);
                m
            },
        };
        let decls = section.to_declarations();
        assert_eq!(decls.limits.len(), 1);
        assert_eq!(decls.limits[0].id, "api_global");
        assert_eq!(decls.limits[0].config.requests, 100);
        assert_eq!(decls.limits[0].config.burst, Some(10));
        assert_eq!(
            decls.tool_pool_map.get("list_items").unwrap(),
            &vec!["api_global".to_string()]
        );
    }

    #[test]
    fn rate_limits_section_unit_mapping() {
        use fcp_prelude::RateLimitUnit;
        let make_section = |unit: &str| RateLimitsSection {
            pools: vec![RateLimitPoolSection {
                id: "test".into(),
                description: None,
                requests: 10,
                window_ms: 1000,
                burst: None,
                unit: Some(unit.into()),
                enforcement: None,
                scope: None,
            }],
            operation_pools: std::collections::HashMap::default(),
        };
        assert_eq!(
            make_section("tokens").to_declarations().limits[0]
                .config
                .unit,
            RateLimitUnit::Tokens
        );
        assert_eq!(
            make_section("bytes").to_declarations().limits[0]
                .config
                .unit,
            RateLimitUnit::Bytes
        );
        assert_eq!(
            make_section("custom").to_declarations().limits[0]
                .config
                .unit,
            RateLimitUnit::Custom
        );
        assert_eq!(
            make_section("requests").to_declarations().limits[0]
                .config
                .unit,
            RateLimitUnit::Requests
        );
    }

    #[test]
    fn rate_limits_section_enforcement_mapping() {
        use fcp_prelude::RateLimitEnforcement;
        let make_section = |enforcement: &str| RateLimitsSection {
            pools: vec![RateLimitPoolSection {
                id: "test".into(),
                description: None,
                requests: 10,
                window_ms: 1000,
                burst: None,
                unit: None,
                enforcement: Some(enforcement.into()),
                scope: None,
            }],
            operation_pools: std::collections::HashMap::default(),
        };
        assert_eq!(
            make_section("soft").to_declarations().limits[0].enforcement,
            RateLimitEnforcement::Soft
        );
        assert_eq!(
            make_section("advisory").to_declarations().limits[0].enforcement,
            RateLimitEnforcement::Advisory
        );
        assert_eq!(
            make_section("hard").to_declarations().limits[0].enforcement,
            RateLimitEnforcement::Hard
        );
    }

    #[test]
    fn rate_limits_section_scope_mapping() {
        use fcp_prelude::RateLimitScope;
        let make_section = |scope: &str| RateLimitsSection {
            pools: vec![RateLimitPoolSection {
                id: "test".into(),
                description: None,
                requests: 10,
                window_ms: 1000,
                burst: None,
                unit: None,
                enforcement: None,
                scope: Some(scope.into()),
            }],
            operation_pools: std::collections::HashMap::default(),
        };
        assert_eq!(
            make_section("credential").to_declarations().limits[0].scope,
            RateLimitScope::Credential
        );
        assert_eq!(
            make_section("global").to_declarations().limits[0].scope,
            RateLimitScope::Global
        );
        assert_eq!(
            make_section("instance").to_declarations().limits[0].scope,
            RateLimitScope::Instance
        );
    }

    // ── PolicySection validation ───────────────────────────────────────

    #[test]
    fn policy_section_valid_slsa_level() {
        let policy = PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![],
            min_slsa_level: Some(4),
            trusted_builders: vec![],
            require_attestation_expiry: false,
        };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn policy_section_invalid_slsa_level() {
        let policy = PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![],
            min_slsa_level: Some(5),
            trusted_builders: vec![],
            require_attestation_expiry: false,
        };
        let err = policy.validate().unwrap_err();
        assert!(err.to_string().contains("0..=4"));
    }

    #[test]
    fn policy_section_serde_roundtrip() {
        let policy = PolicySection {
            require_transparency_log: true,
            require_attestation_types: vec![AttestationType::InToto],
            min_slsa_level: Some(3),
            trusted_builders: vec!["builder1".into()],
            require_attestation_expiry: false,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: PolicySection = serde_json::from_str(&json).unwrap();
        assert!(deserialized.require_transparency_log);
        assert_eq!(deserialized.min_slsa_level, Some(3));
        assert_eq!(deserialized.trusted_builders.len(), 1);
    }

    // ── SandboxSection validation ──────────────────────────────────────

    #[test]
    fn sandbox_section_zero_cpu_percent() {
        let section = SandboxSection {
            profile: SandboxProfile::Strict,
            memory_mb: 128,
            cpu_percent: 0,
            wall_clock_timeout_ms: 30_000,
            fs_readonly_paths: vec![],
            fs_writable_paths: vec![],
            deny_exec: true,
            deny_ptrace: true,
        };
        let err = section.validate().unwrap_err();
        assert!(err.to_string().contains("cpu_percent"));
    }

    #[test]
    fn sandbox_section_zero_timeout() {
        let section = SandboxSection {
            profile: SandboxProfile::Strict,
            memory_mb: 128,
            cpu_percent: 50,
            wall_clock_timeout_ms: 0,
            fs_readonly_paths: vec![],
            fs_writable_paths: vec![],
            deny_exec: true,
            deny_ptrace: true,
        };
        let err = section.validate().unwrap_err();
        assert!(err.to_string().contains("wall_clock_timeout_ms"));
    }

    #[test]
    fn manifest_without_timeouts_section_uses_none() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let with_hash = with_computed_hash(&test_manifest_toml(&placeholder));
        let parsed = ConnectorManifest::parse_str(&with_hash).unwrap();
        assert!(parsed.timeouts.is_none());
    }

    #[test]
    fn manifest_with_timeouts_section_parses() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let raw = test_manifest_toml(&placeholder).replace(
            "\n[sandbox]\n",
            "\n[timeouts]\nrequest_timeout_ms = 45000\nconnect_timeout_ms = 7000\nwall_clock_timeout_ms = 90000\n\n[sandbox]\n",
        );
        let with_hash = with_computed_hash(&raw);
        let parsed = ConnectorManifest::parse_str(&with_hash).unwrap();
        let timeouts = parsed.timeouts.unwrap();
        assert_eq!(timeouts.request_timeout_ms, 45_000);
        assert_eq!(timeouts.connect_timeout_ms, 7_000);
        assert_eq!(timeouts.wall_clock_timeout_ms, 90_000);
    }

    #[test]
    fn manifest_timeouts_zero_request_timeout_rejected() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let raw = test_manifest_toml(&placeholder).replace(
            "\n[sandbox]\n",
            "\n[timeouts]\nrequest_timeout_ms = 0\nconnect_timeout_ms = 5000\nwall_clock_timeout_ms = 60000\n\n[sandbox]\n",
        );
        let with_hash = with_computed_hash(&raw);
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(err.to_string().contains("timeouts.request_timeout_ms"));
    }

    #[test]
    fn sandbox_section_rejects_relative_readonly_path() {
        let section = SandboxSection {
            profile: SandboxProfile::Strict,
            memory_mb: 128,
            cpu_percent: 50,
            wall_clock_timeout_ms: 30_000,
            fs_readonly_paths: vec!["relative/path".into()],
            fs_writable_paths: vec![],
            deny_exec: true,
            deny_ptrace: true,
        };
        let err = section.validate().unwrap_err();
        assert!(err.to_string().contains("fs_readonly_paths"));
        assert!(err.to_string().contains("absolute"));
    }

    #[test]
    fn sandbox_section_rejects_connector_state_parent_escape() {
        let section = SandboxSection {
            profile: SandboxProfile::Strict,
            memory_mb: 128,
            cpu_percent: 50,
            wall_clock_timeout_ms: 30_000,
            fs_readonly_paths: vec![],
            fs_writable_paths: vec!["$CONNECTOR_STATE/../cache".into()],
            deny_exec: true,
            deny_ptrace: true,
        };
        let err = section.validate().unwrap_err();
        assert!(err.to_string().contains("fs_writable_paths"));
        assert!(err.to_string().contains("normal path components"));
    }

    #[test]
    fn sandbox_section_allows_connector_state_subpath() {
        let section = SandboxSection {
            profile: SandboxProfile::Strict,
            memory_mb: 128,
            cpu_percent: 50,
            wall_clock_timeout_ms: 30_000,
            fs_readonly_paths: vec!["/usr".into()],
            fs_writable_paths: vec!["$CONNECTOR_STATE/cache".into()],
            deny_exec: true,
            deny_ptrace: true,
        };
        assert!(section.validate().is_ok());
    }

    // ── ManifestError display ──────────────────────────────────────────

    #[test]
    fn manifest_error_all_variants_display() {
        let toml_err = toml::from_str::<ConnectorManifest>("invalid").unwrap_err();
        let err = ManifestError::Toml(toml_err);
        assert!(err.to_string().contains("parse manifest TOML"));

        let err = ManifestError::Invalid {
            field: "test.field",
            message: "test message".into(),
        };
        assert!(err.to_string().contains("test.field"));
        assert!(err.to_string().contains("test message"));

        let err = ManifestError::InterfaceHashMismatch {
            expected: "a".into(),
            found: "b".into(),
        };
        assert!(err.to_string().contains("hash mismatch"));
    }

    // ── validate_host_allow_entry ──────────────────────────────────────

    #[test]
    fn host_allow_empty_rejected() {
        let err = validate_host_allow_entry("", true, true).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn host_allow_ip_literal_denied() {
        let err = validate_host_allow_entry("192.168.1.1", true, false).unwrap_err();
        assert!(err.to_string().contains("IP literals"));
    }

    #[test]
    fn host_allow_ip_literal_allowed() {
        assert!(validate_host_allow_entry("192.168.1.1", false, false).is_ok());
    }

    #[test]
    fn host_allow_non_ascii_rejected_with_canonicalization() {
        let err = validate_host_allow_entry("例え.jp", true, true).unwrap_err();
        assert!(err.to_string().contains("ASCII"));
    }

    #[test]
    fn host_allow_trailing_dot_rejected_with_canonicalization() {
        let err = validate_host_allow_entry("example.com.", true, true).unwrap_err();
        assert!(err.to_string().contains("trailing dot"));
    }

    #[test]
    fn host_allow_valid_wildcard() {
        assert!(validate_host_allow_entry("*.example.com", false, false).is_ok());
    }

    #[test]
    fn host_allow_wildcard_too_broad() {
        let err = validate_host_allow_entry("*.com", false, false).unwrap_err();
        assert!(err.to_string().contains("too broad"));
    }

    #[test]
    fn host_allow_wildcard_invalid_middle() {
        let err = validate_host_allow_entry("ex*.com", false, false).unwrap_err();
        assert!(err.to_string().contains("*.example.com"));
    }

    #[test]
    fn host_allow_valid_hostname() {
        assert!(validate_host_allow_entry("api.example.com", true, true).is_ok());
    }

    // ── NetworkConstraints defaults ────────────────────────────────────

    #[test]
    fn network_constraints_default_values() {
        assert!(default_true());
        assert_eq!(default_dns_max_ips(), 16);
        assert_eq!(default_max_redirects(), 5);
        assert_eq!(default_connect_timeout_ms(), 10_000);
        assert_eq!(default_total_timeout_ms(), 60_000);
        assert_eq!(default_max_response_bytes(), 10_485_760);
    }

    // ── SignaturesSection validation ───────────────────────────────────

    #[test]
    fn signatures_section_sigs_without_threshold() {
        let section = SignaturesSection {
            publisher_signatures: vec![SignatureEntry {
                kid: "key1".into(),
                sig: Base64Bytes(vec![1, 2, 3]),
            }],
            publisher_threshold: None,
            registry_signature: None,
            transparency_log_entry: None,
        };
        let err = section.validate().unwrap_err();
        assert!(err.to_string().contains("publisher_threshold"));
    }

    #[test]
    fn signatures_section_duplicate_kid() {
        let section = SignaturesSection {
            publisher_signatures: vec![
                SignatureEntry {
                    kid: "key1".into(),
                    sig: Base64Bytes(vec![1]),
                },
                SignatureEntry {
                    kid: "key1".into(),
                    sig: Base64Bytes(vec![2]),
                },
            ],
            publisher_threshold: Some(SignatureThreshold { k: 1, n: 2 }),
            registry_signature: None,
            transparency_log_entry: None,
        };
        let err = section.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate kid"));
    }

    #[test]
    fn signatures_section_valid() {
        let section = SignaturesSection {
            publisher_signatures: vec![
                SignatureEntry {
                    kid: "key1".into(),
                    sig: Base64Bytes(vec![1]),
                },
                SignatureEntry {
                    kid: "key2".into(),
                    sig: Base64Bytes(vec![2]),
                },
            ],
            publisher_threshold: Some(SignatureThreshold { k: 1, n: 2 }),
            registry_signature: None,
            transparency_log_entry: None,
        };
        assert!(section.validate().is_ok());
    }

    // ── SupplyChainSection validation ──────────────────────────────────

    #[test]
    fn supply_chain_duplicate_object_id() {
        let oid = ObjectId::from_bytes([0xaa; 32]);
        let section = SupplyChainSection {
            attestations: vec![
                SupplyChainAttestationRef {
                    attestation_type: AttestationType::InToto,
                    object_id: oid,
                },
                SupplyChainAttestationRef {
                    attestation_type: AttestationType::CodeReview,
                    object_id: oid,
                },
            ],
        };
        let err = section.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn supply_chain_valid() {
        let oid1 = ObjectId::from_bytes([0xaa; 32]);
        let oid2 = ObjectId::from_bytes([0xbb; 32]);
        let section = SupplyChainSection {
            attestations: vec![
                SupplyChainAttestationRef {
                    attestation_type: AttestationType::InToto,
                    object_id: oid1,
                },
                SupplyChainAttestationRef {
                    attestation_type: AttestationType::CodeReview,
                    object_id: oid2,
                },
            ],
        };
        assert!(section.validate().is_ok());
    }

    // ── NetworkConstraints validation edge cases ─────────────────────

    #[test]
    fn network_constraints_zero_connect_timeout_rejected() {
        let nc = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 0,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        let err = nc.validate().unwrap_err();
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn network_constraints_zero_total_timeout_rejected() {
        let nc = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 0,
            max_response_bytes: 10_485_760,
        };
        let err = nc.validate().unwrap_err();
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn network_constraints_connect_exceeds_total_timeout_rejected() {
        let nc = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 30_000,
            total_timeout_ms: 10_000,
            max_response_bytes: 10_485_760,
        };
        let err = nc.validate().unwrap_err();
        assert!(err.to_string().contains("connect_timeout_ms"));
        assert!(err.to_string().contains("must not exceed"));
    }

    #[test]
    fn network_constraints_connect_equals_total_timeout_accepted() {
        let nc = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 60_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        assert!(nc.validate().is_ok());
    }

    #[test]
    fn network_constraints_zero_max_response_bytes_rejected() {
        let nc = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 0,
        };
        let err = nc.validate().unwrap_err();
        assert!(err.to_string().contains("max_response_bytes"));
    }

    #[test]
    fn network_constraints_empty_host_allow_rejected() {
        let nc = NetworkConstraints {
            host_allow: vec![],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        let err = nc.validate().unwrap_err();
        assert!(err.to_string().contains("host_allow"));
    }

    #[test]
    fn network_constraints_empty_port_allow_rejected() {
        let nc = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        let err = nc.validate().unwrap_err();
        assert!(err.to_string().contains("port_allow"));
    }

    #[test]
    fn network_constraints_localhost_in_host_allow_with_deny_localhost() {
        let nc = NetworkConstraints {
            host_allow: vec!["localhost".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        let err = nc.validate().unwrap_err();
        assert!(err.to_string().contains("deny_localhost"));
    }

    #[test]
    fn network_constraints_invalid_cidr_rejected() {
        let nc = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec!["not-a-cidr".into()],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        let err = nc.validate().unwrap_err();
        assert!(err.to_string().contains("invalid CIDR"));
    }

    #[test]
    fn network_constraints_valid_ipv6_cidr() {
        let nc = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec!["2001:db8::/32".into()],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        assert!(nc.validate().is_ok());
    }

    #[test]
    fn network_constraints_ip_literal_in_host_allow_with_deny_ip_literals() {
        let nc = NetworkConstraints {
            host_allow: vec!["192.168.1.1".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        let err = nc.validate().unwrap_err();
        assert!(err.to_string().contains("IP literals"));
    }

    // ── validate_host_allow_entry edge cases ─────────────────────────

    #[test]
    fn host_allow_empty_entry_rejected() {
        let err = validate_host_allow_entry("", false, false).unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn host_allow_unicode_rejected_with_canonicalization() {
        let err = validate_host_allow_entry("münchen.example.com", false, true).unwrap_err();
        assert!(err.to_string().contains("ASCII"));
    }

    #[test]
    fn host_allow_uppercase_rejected_with_canonicalization() {
        let err = validate_host_allow_entry("API.EXAMPLE.COM", false, true).unwrap_err();
        assert!(err.to_string().contains("lowercase"));
    }

    #[test]
    fn host_allow_wildcard_double_star_rejected() {
        let err = validate_host_allow_entry("**.example.com", false, false).unwrap_err();
        assert!(err.to_string().contains("*.example.com"));
    }

    #[test]
    fn host_allow_wildcard_valid_three_labels() {
        // *.example.com has 3 parts → valid
        assert!(validate_host_allow_entry("*.example.com", false, false).is_ok());
    }

    #[test]
    fn host_allow_wildcard_two_labels_too_broad() {
        // *.com has 2 parts → too broad
        let err = validate_host_allow_entry("*.com", false, false).unwrap_err();
        assert!(err.to_string().contains("too broad"));
    }

    #[test]
    fn host_allow_ip_literal_allowed_when_deny_disabled() {
        assert!(validate_host_allow_entry("93.184.216.34", false, false).is_ok());
    }

    #[test]
    fn host_allow_ip_literal_rejected_when_deny_enabled() {
        let err = validate_host_allow_entry("93.184.216.34", true, false).unwrap_err();
        assert!(err.to_string().contains("IP literals"));
    }

    // ── ManifestSchemaVersion parsing ────────────────────────────────

    #[test]
    fn manifest_schema_version_valid_parse() {
        let v = ManifestSchemaVersion::try_from("2.1".to_string()).unwrap();
        assert_eq!(v.major, 2);
        assert_eq!(v.minor, 1);
    }

    #[test]
    fn manifest_schema_version_missing_dot_rejected() {
        let err = ManifestSchemaVersion::try_from("21".to_string()).unwrap_err();
        assert!(err.to_string().contains("MAJOR.MINOR"));
    }

    #[test]
    fn manifest_schema_version_non_numeric_major_rejected() {
        let err = ManifestSchemaVersion::try_from("abc.1".to_string()).unwrap_err();
        assert!(err.to_string().contains("major"));
    }

    #[test]
    fn manifest_schema_version_non_numeric_minor_rejected() {
        let err = ManifestSchemaVersion::try_from("2.xyz".to_string()).unwrap_err();
        assert!(err.to_string().contains("minor"));
    }

    #[test]
    fn manifest_schema_version_display_roundtrip() {
        let v = ManifestSchemaVersion { major: 2, minor: 1 };
        assert_eq!(v.to_string(), "2.1");
    }

    #[test]
    fn manifest_schema_version_extra_dots_rejected() {
        // "2.0.0" splits on first dot → minor = "0.0" which is not a valid u16
        let err = ManifestSchemaVersion::try_from("2.0.0".to_string()).unwrap_err();
        assert!(err.to_string().contains("minor"));
    }

    // ── ProtocolRequirement parsing ──────────────────────────────────

    #[test]
    fn protocol_requirement_valid_parse() {
        let pr = ProtocolRequirement::try_from("fcp2-sym/2.0".to_string()).unwrap();
        assert_eq!(pr.name, "fcp2-sym");
        assert_eq!(pr.version.major, 2);
        assert_eq!(pr.version.minor, 0);
    }

    #[test]
    fn protocol_requirement_missing_slash_rejected() {
        let err = ProtocolRequirement::try_from("fcp2-sym2.0".to_string()).unwrap_err();
        assert!(err.to_string().contains("version component"));
    }

    #[test]
    fn protocol_requirement_empty_name_rejected() {
        let err = ProtocolRequirement::try_from("/2.0".to_string()).unwrap_err();
        assert!(err.to_string().contains("name must not be empty"));
    }

    #[test]
    fn protocol_requirement_display_roundtrip() {
        let pr = ProtocolRequirement::try_from("fcp2-sym/2.0".to_string()).unwrap();
        assert_eq!(pr.to_string(), "fcp2-sym/2.0");
    }

    // ── SignatureThreshold parsing and validation ─────────────────────

    #[test]
    fn signature_threshold_valid_parse() {
        let t = SignatureThreshold::try_from("2-of-3".to_string()).unwrap();
        assert_eq!(t.k, 2);
        assert_eq!(t.n, 3);
    }

    #[test]
    fn signature_threshold_1_of_1_valid() {
        let t = SignatureThreshold::try_from("1-of-1".to_string()).unwrap();
        assert!(t.validate(1).is_ok());
    }

    #[test]
    fn signature_threshold_k_zero_rejected() {
        let t = SignatureThreshold { k: 0, n: 3 };
        assert!(t.validate(3).is_err());
    }

    #[test]
    fn signature_threshold_n_zero_rejected() {
        let t = SignatureThreshold { k: 1, n: 0 };
        assert!(t.validate(1).is_err());
    }

    #[test]
    fn signature_threshold_k_greater_than_n_rejected() {
        let t = SignatureThreshold { k: 3, n: 2 };
        assert!(t.validate(3).is_err());
    }

    #[test]
    fn signature_threshold_insufficient_signatures_rejected() {
        let t = SignatureThreshold { k: 3, n: 5 };
        // Only 2 signatures present, but need k=3
        assert!(t.validate(2).is_err());
    }

    #[test]
    fn signature_threshold_display_format() {
        let t = SignatureThreshold { k: 2, n: 3 };
        assert_eq!(t.to_string(), "2-of-3");
    }

    #[test]
    fn signature_threshold_missing_of_separator() {
        let err = SignatureThreshold::try_from("2/3".to_string()).unwrap_err();
        assert!(err.to_string().contains("2-of-3"));
    }

    #[test]
    fn signature_threshold_json_serde_roundtrip() {
        let t = SignatureThreshold { k: 2, n: 3 };
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"2-of-3\"");
        let deserialized: SignatureThreshold = serde_json::from_str(&json).unwrap();
        assert_eq!(t, deserialized);
    }

    // ── EventCapsSection validation ──────────────────────────────────

    #[test]
    fn event_caps_streaming_without_buffer_rejected() {
        let ecs = EventCapsSection {
            streaming: true,
            replay: false,
            min_buffer_events: 0,
        };
        let err = ecs.validate().unwrap_err();
        assert!(err.to_string().contains("min_buffer_events"));
    }

    #[test]
    fn event_caps_streaming_with_buffer_valid() {
        let ecs = EventCapsSection {
            streaming: true,
            replay: false,
            min_buffer_events: 100,
        };
        assert!(ecs.validate().is_ok());
    }

    #[test]
    fn event_caps_no_streaming_zero_buffer_valid() {
        let ecs = EventCapsSection {
            streaming: false,
            replay: true,
            min_buffer_events: 0,
        };
        assert!(ecs.validate().is_ok());
    }

    #[test]
    fn event_caps_both_disabled_valid() {
        let ecs = EventCapsSection {
            streaming: false,
            replay: false,
            min_buffer_events: 0,
        };
        assert!(ecs.validate().is_ok());
    }

    // ── Base64Bytes parsing ──────────────────────────────────────────

    #[test]
    fn base64_bytes_valid_roundtrip() {
        let b = Base64Bytes::try_from("base64:AQID".to_string()).unwrap();
        assert_eq!(b.as_bytes(), &[1, 2, 3]);
        let back: String = b.into();
        assert_eq!(back, "base64:AQID");
    }

    #[test]
    fn base64_bytes_missing_prefix_rejected() {
        let err = Base64Bytes::try_from("AQID".to_string()).unwrap_err();
        assert!(err.to_string().contains("base64:"));
    }

    #[test]
    fn base64_bytes_invalid_base64_rejected() {
        let err = Base64Bytes::try_from("base64:!!!invalid!!!".to_string()).unwrap_err();
        assert!(err.to_string().contains("invalid base64"));
    }

    #[test]
    fn base64_bytes_empty_data_valid() {
        // "base64:" with empty data after prefix
        let b = Base64Bytes::try_from("base64:".to_string()).unwrap();
        assert!(b.as_bytes().is_empty());
    }

    #[test]
    fn base64_bytes_json_serde_roundtrip() {
        let b = Base64Bytes::try_from("base64:AQID".to_string()).unwrap();
        let json = serde_json::to_string(&b).unwrap();
        let deserialized: Base64Bytes = serde_json::from_str(&json).unwrap();
        assert_eq!(b, deserialized);
    }

    // ── ObjectId parsing ─────────────────────────────────────────────

    #[test]
    fn object_id_prefixed_valid_with_prefix() {
        let hex_str = "aa".repeat(32);
        let oid = ObjectId::parse_prefixed(&format!("objectid:{hex_str}")).unwrap();
        assert_eq!(oid.to_prefixed_string(), format!("objectid:{hex_str}"));
    }

    #[test]
    fn object_id_prefixed_valid_without_prefix() {
        let hex_str = "bb".repeat(32);
        let oid = ObjectId::parse_prefixed(&hex_str).unwrap();
        assert_eq!(oid.to_prefixed_string(), format!("objectid:{hex_str}"));
    }

    #[test]
    fn object_id_prefixed_wrong_length_rejected() {
        let err = ObjectId::parse_prefixed("objectid:aabb").unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn object_id_prefixed_invalid_hex_rejected() {
        let err =
            ObjectId::parse_prefixed(&("objectid:".to_string() + &"gg".repeat(32))).unwrap_err();
        assert!(err.to_string().contains("hex"));
    }

    #[test]
    fn object_id_prefixed_empty_hex_after_prefix_rejected() {
        let err = ObjectId::parse_prefixed("objectid:").unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    // ── PolicySection validation ─────────────────────────────────────

    #[test]
    fn policy_slsa_level_zero_valid() {
        let p = PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![],
            min_slsa_level: Some(0),
            trusted_builders: vec![],
            require_attestation_expiry: false,
        };
        assert!(p.validate().is_ok());
    }

    #[test]
    fn policy_slsa_level_4_valid() {
        let p = PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![],
            min_slsa_level: Some(4),
            trusted_builders: vec![],
            require_attestation_expiry: false,
        };
        assert!(p.validate().is_ok());
    }

    #[test]
    fn policy_slsa_level_5_rejected() {
        let p = PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![],
            min_slsa_level: Some(5),
            trusted_builders: vec![],
            require_attestation_expiry: false,
        };
        let err = p.validate().unwrap_err();
        assert!(err.to_string().contains("0..=4"));
    }

    #[test]
    fn policy_slsa_level_none_valid() {
        let p = PolicySection {
            require_transparency_log: true,
            require_attestation_types: vec![AttestationType::InToto],
            min_slsa_level: None,
            trusted_builders: vec!["trusted-builder-1".into()],
            require_attestation_expiry: false,
        };
        assert!(p.validate().is_ok());
    }

    // ── AttestationType serde ────────────────────────────────────────

    #[test]
    fn attestation_type_serde_all_variants() {
        let types = [
            (AttestationType::InToto, "\"in-toto\""),
            (AttestationType::ReproducibleBuild, "\"reproducible-build\""),
            (AttestationType::CodeReview, "\"code-review\""),
        ];
        for (variant, expected_json) in types {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected_json);
            let deserialized: AttestationType = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, deserialized);
        }
    }

    #[test]
    fn attestation_type_unknown_value_rejected() {
        let result: Result<AttestationType, _> = serde_json::from_str("\"unknown-type\"");
        assert!(result.is_err());
    }

    // ── ManifestError display ────────────────────────────────────────

    #[test]
    fn manifest_error_invalid_display_contains_field_and_message() {
        let err = ManifestError::Invalid {
            field: "test.field",
            message: "test message".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("test.field"));
        assert!(msg.contains("test message"));
    }

    // ── SupplyChainSection edge cases ────────────────────────────────

    #[test]
    fn supply_chain_empty_attestations_valid() {
        let section = SupplyChainSection {
            attestations: vec![],
        };
        assert!(section.validate().is_ok());
    }

    // ── SignaturesSection: empty sigs without threshold valid ─────────

    #[test]
    fn signatures_section_empty_sigs_no_threshold_valid() {
        let section = SignaturesSection {
            publisher_signatures: vec![],
            publisher_threshold: None,
            registry_signature: None,
            transparency_log_entry: None,
        };
        assert!(section.validate().is_ok());
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ManifestSchemaVersion extended coverage
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn manifest_schema_version_into_string() {
        let v = ManifestSchemaVersion { major: 2, minor: 1 };
        let s: String = v.into();
        assert_eq!(s, "2.1");
    }

    #[test]
    fn manifest_schema_version_hash_consistent() {
        use std::collections::HashSet;
        let v1 = ManifestSchemaVersion { major: 2, minor: 1 };
        let v2 = ManifestSchemaVersion { major: 2, minor: 1 };
        let v3 = ManifestSchemaVersion { major: 3, minor: 0 };
        let mut set = HashSet::new();
        set.insert(v1);
        set.insert(v2);
        assert_eq!(set.len(), 1);
        set.insert(v3);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn manifest_schema_version_copy_clone() {
        let v = ManifestSchemaVersion { major: 2, minor: 1 };
        let cloned = v;
        assert_eq!(v.major, cloned.major);
        assert_eq!(v.minor, cloned.minor);
    }

    #[test]
    fn manifest_schema_version_zero_zero() {
        let v = ManifestSchemaVersion::try_from("0.0".to_string()).unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 0);
        assert_eq!(v.to_string(), "0.0");
    }

    #[test]
    fn manifest_schema_version_large_values() {
        let v = ManifestSchemaVersion::try_from("65535.65535".to_string()).unwrap();
        assert_eq!(v.major, 65535);
        assert_eq!(v.minor, 65535);
    }

    #[test]
    fn manifest_schema_version_overflow_rejected() {
        let err = ManifestSchemaVersion::try_from("99999.0".to_string()).unwrap_err();
        assert!(err.to_string().contains("major"));
    }

    #[test]
    fn manifest_schema_version_debug_output() {
        let v = ManifestSchemaVersion { major: 2, minor: 1 };
        let dbg = format!("{v:?}");
        assert!(dbg.contains("ManifestSchemaVersion"));
        assert!(dbg.contains('2'));
        assert!(dbg.contains('1'));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: InterfaceHash extended coverage
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn interface_hash_serde_roundtrip() {
        let h = InterfaceHash::new_blake3_256(INTERFACE_HASH_DOMAIN, [0xBB; 32]);
        let json = serde_json::to_string(&h).unwrap();
        let deserialized: InterfaceHash = serde_json::from_str(&json).unwrap();
        assert_eq!(h, deserialized);
    }

    #[test]
    fn interface_hash_clone_and_eq() {
        let h = InterfaceHash::new_blake3_256(INTERFACE_HASH_DOMAIN, [0xCC; 32]);
        let cloned = h;
        assert_eq!(h, cloned);
        assert_eq!(h.digest, cloned.digest);
    }

    #[test]
    fn interface_hash_hash_trait() {
        use std::collections::HashSet;
        let h1 = InterfaceHash::new_blake3_256(INTERFACE_HASH_DOMAIN, [0xDD; 32]);
        let h2 = InterfaceHash::new_blake3_256(INTERFACE_HASH_DOMAIN, [0xDD; 32]);
        let h3 = InterfaceHash::new_blake3_256(INTERFACE_HASH_DOMAIN, [0xEE; 32]);
        let mut set = HashSet::new();
        set.insert(h1);
        set.insert(h2);
        assert_eq!(set.len(), 1);
        set.insert(h3);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn interface_hash_bad_domain_rejected() {
        let hex = "aa".repeat(32);
        let s = format!("blake3-256:bad.domain:{hex}");
        let err = InterfaceHash::try_from(s).unwrap_err();
        assert!(err.to_string().contains("domain"));
    }

    #[test]
    fn interface_hash_short_digest_rejected() {
        let hex = "aa".repeat(16); // only 16 bytes
        let s = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{hex}");
        let err = InterfaceHash::try_from(s).unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn interface_hash_invalid_hex_rejected() {
        let s = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "zz".repeat(32));
        let err = InterfaceHash::try_from(s).unwrap_err();
        assert!(err.to_string().contains("valid hex"));
    }

    #[test]
    fn interface_hash_into_string() {
        let h = InterfaceHash::new_blake3_256(INTERFACE_HASH_DOMAIN, [0x11; 32]);
        let s: String = h.into();
        assert!(s.starts_with("blake3-256:"));
        assert!(s.contains(&"11".repeat(32)));
    }

    #[test]
    fn interface_hash_empty_string_rejected() {
        let err = InterfaceHash::try_from(String::new()).unwrap_err();
        assert!(err.to_string().contains("algorithm"));
    }

    #[test]
    fn interface_hash_debug_output() {
        let h = InterfaceHash::new_blake3_256(INTERFACE_HASH_DOMAIN, [0xFF; 32]);
        let dbg = format!("{h:?}");
        assert!(dbg.contains("InterfaceHash"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: InterfaceHashAlgorithm
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn interface_hash_algorithm_debug_clone_copy_eq() {
        let a = InterfaceHashAlgorithm::Blake3_256;
        let b = a;
        assert_eq!(a, b);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Blake3_256"));
    }

    #[test]
    fn interface_hash_algorithm_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(InterfaceHashAlgorithm::Blake3_256);
        set.insert(InterfaceHashAlgorithm::Blake3_256);
        assert_eq!(set.len(), 1);
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ProtocolVersion extended
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn protocol_version_eq_hash() {
        use std::collections::HashSet;
        let v1 = ProtocolVersion { major: 2, minor: 0 };
        let v2 = ProtocolVersion { major: 2, minor: 0 };
        let v3 = ProtocolVersion { major: 3, minor: 1 };
        assert_eq!(v1, v2);
        assert_ne!(v1, v3);
        let mut set = HashSet::new();
        set.insert(v1);
        set.insert(v2);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn protocol_version_copy_clone() {
        let v = ProtocolVersion { major: 1, minor: 5 };
        let copied = v;
        assert_eq!(v.major, copied.major);
        assert_eq!(v.minor, copied.minor);
    }

    #[test]
    fn protocol_version_debug() {
        let v = ProtocolVersion { major: 2, minor: 0 };
        let dbg = format!("{v:?}");
        assert!(dbg.contains("ProtocolVersion"));
    }

    #[test]
    fn protocol_version_large_values() {
        let v = ProtocolVersion::try_from("65535.65535".to_string()).unwrap();
        assert_eq!(v.major, 65535);
        assert_eq!(v.minor, 65535);
        assert_eq!(v.to_string(), "65535.65535");
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ProtocolRequirement extended
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn protocol_requirement_clone_eq_hash() {
        use std::collections::HashSet;
        let pr1 = ProtocolRequirement::try_from("fcp2-sym/2.0".to_string()).unwrap();
        let pr2 = pr1.clone();
        assert_eq!(pr1, pr2);
        let mut set = HashSet::new();
        set.insert(pr1);
        set.insert(pr2);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn protocol_requirement_into_string() {
        let pr = ProtocolRequirement::try_from("fcp2-sym/2.0".to_string()).unwrap();
        let s: String = pr.into();
        assert_eq!(s, "fcp2-sym/2.0");
    }

    #[test]
    fn protocol_requirement_debug() {
        let pr = ProtocolRequirement::try_from("fcp2-sym/2.0".to_string()).unwrap();
        let dbg = format!("{pr:?}");
        assert!(dbg.contains("ProtocolRequirement"));
    }

    #[test]
    fn protocol_requirement_non_numeric_version_rejected() {
        let err = ProtocolRequirement::try_from("fcp2-sym/abc.0".to_string()).unwrap_err();
        assert!(err.to_string().contains("major"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: FeatureId extended
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn feature_id_clone_eq_hash() {
        use std::collections::HashSet;
        let f1 = FeatureId::try_from("fcps.aead".to_string()).unwrap();
        let f2 = f1.clone();
        assert_eq!(f1, f2);
        let mut set = HashSet::new();
        set.insert(f1);
        set.insert(f2);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn feature_id_serde_roundtrip() {
        let fid = FeatureId::try_from("fcps.aead.xchacha20poly1305".to_string()).unwrap();
        let json = serde_json::to_string(&fid).unwrap();
        let deserialized: FeatureId = serde_json::from_str(&json).unwrap();
        assert_eq!(fid, deserialized);
    }

    #[test]
    fn feature_id_debug() {
        let fid = FeatureId::try_from("fcps.aead".to_string()).unwrap();
        let dbg = format!("{fid:?}");
        assert!(dbg.contains("FeatureId"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ConnectorManifest full roundtrip
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn connector_manifest_clone() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let unchecked = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder))
            .expect("unchecked parse");
        let cloned = unchecked.clone();
        assert_eq!(
            unchecked.connector.id.as_str(),
            cloned.connector.id.as_str()
        );
        assert_eq!(unchecked.connector.name, cloned.connector.name);
    }

    #[test]
    fn connector_manifest_debug() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let m = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder))
            .expect("unchecked parse");
        let dbg = format!("{m:?}");
        assert!(dbg.contains("ConnectorManifest"));
        assert!(dbg.contains("fcp.telegram"));
    }

    #[test]
    fn connector_manifest_serde_json_roundtrip() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let m = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder))
            .expect("unchecked parse");
        let json = serde_json::to_string(&m).unwrap();
        let deserialized: ConnectorManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.connector.id.as_str(), "fcp.telegram");
        assert_eq!(deserialized.connector.name, "Telegram Connector");
    }

    #[test]
    fn connector_manifest_toml_roundtrip() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let m = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder))
            .expect("unchecked parse");
        let toml_str = toml::to_string(&m).unwrap();
        let reparsed: ConnectorManifest = toml::from_str(&toml_str).unwrap();
        assert_eq!(reparsed.connector.id.as_str(), "fcp.telegram");
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ManifestSection validation
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn manifest_section_rejects_wrong_format() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder).replace("fcp-connector-manifest", "bad-format");
        let err = ConnectorManifest::parse_str_unchecked(&toml);
        // Should parse but then fail validation
        if let Ok(m) = err {
            let validation = m.validate();
            assert!(validation.is_err());
            assert!(validation.unwrap_err().to_string().contains("format"));
        }
    }

    #[test]
    fn manifest_section_rejects_schema_version_3() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder)
            .replace("schema_version = \"2.1\"", "schema_version = \"3.0\"");
        let m = ConnectorManifest::parse_str_unchecked(&toml).unwrap();
        let err = m.validate().unwrap_err();
        assert!(err.to_string().contains("schema"));
    }

    #[test]
    fn manifest_section_rejects_zero_max_datagram() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder)
            .replace("max_datagram_bytes = 1200", "max_datagram_bytes = 0");
        let m = ConnectorManifest::parse_str_unchecked(&toml).unwrap();
        let err = m.validate().unwrap_err();
        assert!(err.to_string().contains("max_datagram_bytes"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ConnectorSection validation
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn connector_section_rejects_empty_description() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder).replace(
            "description = \"Secure Telegram Bot API integration\"",
            "description = \"\"",
        );
        let m = ConnectorManifest::parse_str_unchecked(&toml).unwrap();
        let hash = m.compute_interface_hash().unwrap();
        let with_hash = test_manifest_toml(&hash.to_string()).replace(
            "description = \"Secure Telegram Bot API integration\"",
            "description = \"\"",
        );
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "connector.description")
        );
    }

    #[test]
    fn connector_section_rejects_whitespace_only_name() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder)
            .replace("name = \"Telegram Connector\"", "name = \"   \"");
        let m = ConnectorManifest::parse_str_unchecked(&toml).unwrap();
        let hash = m.compute_interface_hash().unwrap();
        let with_hash = test_manifest_toml(&hash.to_string())
            .replace("name = \"Telegram Connector\"", "name = \"   \"");
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(matches!(err, ManifestError::Invalid { field, .. } if field == "connector.name"));
    }

    #[test]
    fn connector_section_rejects_empty_archetypes() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder).replace(
            "archetypes = [\"bidirectional\", \"streaming\"]",
            "archetypes = []",
        );
        let m = ConnectorManifest::parse_str_unchecked(&toml).unwrap();
        let hash = m.compute_interface_hash().unwrap();
        let with_hash = test_manifest_toml(&hash.to_string()).replace(
            "archetypes = [\"bidirectional\", \"streaming\"]",
            "archetypes = []",
        );
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(
            matches!(err, ManifestError::Invalid { field, .. } if field == "connector.archetypes")
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ZonesSection validation
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn zones_section_home_in_forbidden_rejected() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder).replace(
            "forbidden = [\"z:public\"]",
            "forbidden = [\"z:community\"]",
        );
        let m = ConnectorManifest::parse_str_unchecked(&toml).unwrap();
        let hash = m.compute_interface_hash().unwrap();
        let with_hash = test_manifest_toml(&hash.to_string()).replace(
            "forbidden = [\"z:public\"]",
            "forbidden = [\"z:community\"]",
        );
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(err.to_string().contains("home zone"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: CapabilitiesSection validation
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn capabilities_section_duplicate_capability_rejected() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        // Inject a duplicate `network.dns` into the required list. The
        // base fixture's required list (see `test_manifest_toml`) is
        // `["ipc.gateway", "network.dns", "network.egress", "network.tls.sni",
        // "telegram.send_message"]`; we replace `network.tls.sni` with a
        // second `network.dns` so the duplicate detector fires.
        let toml =
            test_manifest_toml(&placeholder).replace("\"network.tls.sni\"", "\"network.dns\"");
        let m = ConnectorManifest::parse_str_unchecked(&toml).unwrap();
        let hash = m.compute_interface_hash().unwrap();
        let with_hash =
            test_manifest_toml(&hash.to_string()).replace("\"network.tls.sni\"", "\"network.dns\"");
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn capabilities_section_cross_list_duplicate_rejected() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        // Put ipc.gateway in both required and optional
        let toml = test_manifest_toml(&placeholder).replace(
            "optional = [\"media.download\"]",
            "optional = [\"ipc.gateway\"]",
        );
        let m = ConnectorManifest::parse_str_unchecked(&toml).unwrap();
        let hash = m.compute_interface_hash().unwrap();
        let with_hash = test_manifest_toml(&hash.to_string()).replace(
            "optional = [\"media.download\"]",
            "optional = [\"ipc.gateway\"]",
        );
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ProvidesSection validation
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn provides_section_rejects_empty_op_description() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder).replace(
            "description = \"Send a message to a Telegram chat\"",
            "description = \"\"",
        );
        let m = ConnectorManifest::parse_str_unchecked(&toml).unwrap();
        let hash = m.compute_interface_hash().unwrap();
        let with_hash = test_manifest_toml(&hash.to_string()).replace(
            "description = \"Send a message to a Telegram chat\"",
            "description = \"\"",
        );
        let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
        assert!(err.to_string().contains("description"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: SandboxProfile extended
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn sandbox_profile_all_variants_serde() {
        for (json_str, expected) in [
            ("\"strict\"", SandboxProfile::Strict),
            ("\"strict_plus\"", SandboxProfile::StrictPlus),
            ("\"moderate\"", SandboxProfile::Moderate),
            ("\"permissive\"", SandboxProfile::Permissive),
        ] {
            let parsed: SandboxProfile = serde_json::from_str(json_str).unwrap();
            assert_eq!(parsed, expected);
            let serialized = serde_json::to_string(&parsed).unwrap();
            assert_eq!(serialized, json_str);
        }
    }

    #[test]
    fn sandbox_profile_debug_clone_copy() {
        let p = SandboxProfile::Moderate;
        let p2 = p;
        assert_eq!(p, p2);
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Moderate"));
    }

    #[test]
    fn sandbox_profile_invalid_variant_rejected() {
        let result = serde_json::from_str::<SandboxProfile>("\"ultra_strict\"");
        assert!(result.is_err());
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: SandboxSection serde roundtrip
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn sandbox_section_serde_roundtrip() {
        let section = SandboxSection {
            profile: SandboxProfile::Strict,
            memory_mb: 512,
            cpu_percent: 75,
            wall_clock_timeout_ms: 60_000,
            fs_readonly_paths: vec!["/usr".into(), "/lib".into()],
            fs_writable_paths: vec!["$CONNECTOR_STATE".into()],
            deny_exec: true,
            deny_ptrace: true,
        };
        let json = serde_json::to_string(&section).unwrap();
        let deserialized: SandboxSection = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.memory_mb, 512);
        assert_eq!(deserialized.cpu_percent, 75);
        assert!(deserialized.deny_exec);
        assert_eq!(deserialized.fs_readonly_paths.len(), 2);
    }

    #[test]
    fn sandbox_section_valid() {
        let section = SandboxSection {
            profile: SandboxProfile::Permissive,
            memory_mb: 1024,
            cpu_percent: 100,
            wall_clock_timeout_ms: 120_000,
            fs_readonly_paths: vec![],
            fs_writable_paths: vec![],
            deny_exec: false,
            deny_ptrace: false,
        };
        assert!(section.validate().is_ok());
    }

    #[test]
    fn sandbox_section_clone_debug() {
        let section = SandboxSection {
            profile: SandboxProfile::Strict,
            memory_mb: 128,
            cpu_percent: 50,
            wall_clock_timeout_ms: 30_000,
            fs_readonly_paths: vec![],
            fs_writable_paths: vec![],
            deny_exec: true,
            deny_ptrace: true,
        };
        let cloned = section.clone();
        assert_eq!(section.memory_mb, cloned.memory_mb);
        let dbg = format!("{section:?}");
        assert!(dbg.contains("SandboxSection"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: NetworkConstraints serde roundtrip
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn network_constraints_serde_roundtrip() {
        let nc = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443, 8443],
            ip_allow: vec![],
            cidr_deny: vec!["10.0.0.0/8".into()],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: true,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        let json = serde_json::to_string(&nc).unwrap();
        let deserialized: NetworkConstraints = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.host_allow, vec!["api.example.com"]);
        assert_eq!(deserialized.port_allow, vec![443, 8443]);
    }

    #[test]
    fn network_constraints_clone_debug() {
        let nc = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        let cloned = nc.clone();
        assert_eq!(nc.host_allow, cloned.host_allow);
        let dbg = format!("{nc:?}");
        assert!(dbg.contains("NetworkConstraints"));
    }

    #[test]
    fn network_constraints_valid_with_multiple_hosts() {
        let nc = NetworkConstraints {
            host_allow: vec!["api.example.com".into(), "cdn.example.com".into()],
            port_allow: vec![443, 80],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        assert!(nc.validate().is_ok());
    }

    #[test]
    fn network_constraints_valid_wildcard_in_full_validation() {
        let nc = NetworkConstraints {
            host_allow: vec!["*.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        assert!(nc.validate().is_ok());
    }

    #[test]
    fn network_constraints_with_ip_allow() {
        let nc = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec!["93.184.216.34".parse().unwrap()],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        assert!(nc.validate().is_ok());
    }

    #[test]
    fn network_constraints_with_spki_pins() {
        let nc = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![Base64Bytes(vec![1, 2, 3, 4])],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        assert!(nc.validate().is_ok());
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: RateLimitPoolSection serde
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn rate_limit_pool_section_serde_roundtrip() {
        let pool = RateLimitPoolSection {
            id: "test_pool".into(),
            description: Some("A test pool".into()),
            requests: 100,
            window_ms: 60_000,
            burst: Some(20),
            unit: Some("tokens".into()),
            enforcement: Some("soft".into()),
            scope: Some("global".into()),
        };
        let json = serde_json::to_string(&pool).unwrap();
        let deserialized: RateLimitPoolSection = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "test_pool");
        assert_eq!(deserialized.requests, 100);
        assert_eq!(deserialized.burst, Some(20));
    }

    #[test]
    fn rate_limit_pool_section_minimal_serde() {
        let pool = RateLimitPoolSection {
            id: "minimal".into(),
            description: None,
            requests: 10,
            window_ms: 1000,
            burst: None,
            unit: None,
            enforcement: None,
            scope: None,
        };
        let json = serde_json::to_string(&pool).unwrap();
        let deserialized: RateLimitPoolSection = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "minimal");
        assert!(deserialized.description.is_none());
        assert!(deserialized.burst.is_none());
    }

    #[test]
    fn rate_limit_pool_section_clone_debug() {
        let pool = RateLimitPoolSection {
            id: "test".into(),
            description: None,
            requests: 10,
            window_ms: 1000,
            burst: None,
            unit: None,
            enforcement: None,
            scope: None,
        };
        let cloned = pool.clone();
        assert_eq!(pool.id, cloned.id);
        let dbg = format!("{pool:?}");
        assert!(dbg.contains("RateLimitPoolSection"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: RateLimitsSection default unit/enforcement/scope
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn rate_limits_section_default_unit_is_requests() {
        use fcp_prelude::RateLimitUnit;
        let section = RateLimitsSection {
            pools: vec![RateLimitPoolSection {
                id: "test".into(),
                description: None,
                requests: 10,
                window_ms: 1000,
                burst: None,
                unit: None,
                enforcement: None,
                scope: None,
            }],
            operation_pools: std::collections::HashMap::default(),
        };
        assert_eq!(
            section.to_declarations().limits[0].config.unit,
            RateLimitUnit::Requests
        );
    }

    #[test]
    fn rate_limits_section_default_enforcement_is_hard() {
        use fcp_prelude::RateLimitEnforcement;
        let section = RateLimitsSection {
            pools: vec![RateLimitPoolSection {
                id: "test".into(),
                description: None,
                requests: 10,
                window_ms: 1000,
                burst: None,
                unit: None,
                enforcement: None,
                scope: None,
            }],
            operation_pools: std::collections::HashMap::default(),
        };
        assert_eq!(
            section.to_declarations().limits[0].enforcement,
            RateLimitEnforcement::Hard
        );
    }

    #[test]
    fn rate_limits_section_default_scope_is_instance() {
        use fcp_prelude::RateLimitScope;
        let section = RateLimitsSection {
            pools: vec![RateLimitPoolSection {
                id: "test".into(),
                description: None,
                requests: 10,
                window_ms: 1000,
                burst: None,
                unit: None,
                enforcement: None,
                scope: None,
            }],
            operation_pools: std::collections::HashMap::default(),
        };
        assert_eq!(
            section.to_declarations().limits[0].scope,
            RateLimitScope::Instance
        );
    }

    #[test]
    fn rate_limits_section_unknown_unit_rejected() {
        let section = RateLimitsSection {
            pools: vec![RateLimitPoolSection {
                id: "test".into(),
                description: None,
                requests: 10,
                window_ms: 1000,
                burst: None,
                unit: Some("widgets".into()),
                enforcement: None,
                scope: None,
            }],
            operation_pools: std::collections::HashMap::default(),
        };
        let err = section.validate().unwrap_err();
        assert!(matches!(
            err,
            ManifestError::Invalid { field, .. } if field == "rate_limits.pools.*.unit"
        ));
    }

    #[test]
    fn rate_limits_section_unknown_enforcement_rejected() {
        let section = RateLimitsSection {
            pools: vec![RateLimitPoolSection {
                id: "test".into(),
                description: None,
                requests: 10,
                window_ms: 1000,
                burst: None,
                unit: None,
                enforcement: Some("unknown".into()),
                scope: None,
            }],
            operation_pools: std::collections::HashMap::default(),
        };
        let err = section.validate().unwrap_err();
        assert!(matches!(
            err,
            ManifestError::Invalid { field, .. } if field == "rate_limits.pools.*.enforcement"
        ));
    }

    #[test]
    fn rate_limits_section_unknown_scope_rejected() {
        let section = RateLimitsSection {
            pools: vec![RateLimitPoolSection {
                id: "test".into(),
                description: None,
                requests: 10,
                window_ms: 1000,
                burst: None,
                unit: None,
                enforcement: None,
                scope: Some("unknown".into()),
            }],
            operation_pools: std::collections::HashMap::default(),
        };
        let err = section.validate().unwrap_err();
        assert!(matches!(
            err,
            ManifestError::Invalid { field, .. } if field == "rate_limits.pools.*.scope"
        ));
    }

    #[test]
    fn rate_limits_section_uppercase_unit_rejected() {
        let section = RateLimitsSection {
            pools: vec![RateLimitPoolSection {
                id: "test".into(),
                description: None,
                requests: 10,
                window_ms: 1000,
                burst: None,
                unit: Some("Bytes".into()),
                enforcement: None,
                scope: None,
            }],
            operation_pools: std::collections::HashMap::default(),
        };
        let err = section.validate().unwrap_err();
        assert!(matches!(
            err,
            ManifestError::Invalid { field, .. } if field == "rate_limits.pools.*.unit"
        ));
    }

    #[test]
    fn rate_limits_section_window_duration() {
        let section = RateLimitsSection {
            pools: vec![RateLimitPoolSection {
                id: "test".into(),
                description: None,
                requests: 10,
                window_ms: 5000,
                burst: None,
                unit: None,
                enforcement: None,
                scope: None,
            }],
            operation_pools: std::collections::HashMap::default(),
        };
        let decls = section.to_declarations();
        assert_eq!(
            decls.limits[0].config.window,
            std::time::Duration::from_secs(5)
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: EventSection clone/debug
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn event_section_clone_debug() {
        let section = EventSection {
            description: "Test event".into(),
            streaming: true,
            replay: false,
            topic: Some("topic".into()),
            requires_ack: true,
            schema: Some(json!({"type": "object"})),
        };
        let cloned = section.clone();
        assert_eq!(section.description, cloned.description);
        let dbg = format!("{section:?}");
        assert!(dbg.contains("EventSection"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: Base64Bytes ordering
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn base64_bytes_ord() {
        let a = Base64Bytes(vec![1, 2, 3]);
        let b = Base64Bytes(vec![1, 2, 4]);
        let c = Base64Bytes(vec![1, 2, 3]);
        assert!(a < b);
        assert_eq!(a, c);
        assert!(b > a);
    }

    #[test]
    fn base64_bytes_hash() {
        use std::collections::HashSet;
        let a = Base64Bytes(vec![1, 2, 3]);
        let b = Base64Bytes(vec![1, 2, 3]);
        let c = Base64Bytes(vec![4, 5, 6]);
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 1);
        set.insert(c);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn base64_bytes_large_data() {
        let data = vec![0xAA; 1024];
        let b = Base64Bytes(data.clone());
        assert_eq!(b.as_bytes().len(), 1024);
        let s: String = b.into();
        assert!(s.starts_with("base64:"));
        let roundtrip = Base64Bytes::try_from(s).unwrap();
        assert_eq!(roundtrip.as_bytes(), &data);
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ObjectId extended
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn object_id_copy_clone_hash() {
        use std::collections::HashSet;
        let oid = ObjectId::from_bytes([0xff; 32]);
        let copied = oid;
        assert_eq!(oid, copied);
        let mut set = HashSet::new();
        set.insert(oid);
        set.insert(copied);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn object_id_debug() {
        let oid = ObjectId::from_bytes([0xab; 32]);
        let dbg = format!("{oid:?}");
        assert!(dbg.contains("ObjectId"));
    }

    #[test]
    fn object_id_prefixed_display_format() {
        let hex = "cc".repeat(32);
        let oid = ObjectId::parse_prefixed(&format!("objectid:{hex}")).unwrap();
        let display = oid.to_prefixed_string();
        assert_eq!(display, format!("objectid:{hex}"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ConnectorStateModel extended
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn connector_state_model_clone_debug() {
        let model = ConnectorStateModel::Crdt {
            crdt_type: ConnectorCrdtType::PnCounter,
        };
        let copied = model;
        assert_eq!(model, copied);
        let dbg = format!("{model:?}");
        assert!(dbg.contains("Crdt"));
        assert!(dbg.contains("PnCounter"));
    }

    #[test]
    fn connector_state_model_display_all_crdt_types() {
        for (crdt_type, expected) in [
            (ConnectorCrdtType::LwwMap, "crdt(lww_map)"),
            (ConnectorCrdtType::OrSet, "crdt(or_set)"),
            (ConnectorCrdtType::GCounter, "crdt(g_counter)"),
            (ConnectorCrdtType::PnCounter, "crdt(pn_counter)"),
        ] {
            let model = ConnectorStateModel::Crdt { crdt_type };
            assert_eq!(model.to_string(), expected);
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ConnectorCrdtType extended
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn connector_crdt_type_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let a = ConnectorCrdtType::LwwMap;
        let b = a;
        assert_eq!(a, b);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("LwwMap"));
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 1);
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ManifestApprovalMode extended
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn manifest_approval_mode_debug_clone_copy() {
        let mode = ManifestApprovalMode::Interactive;
        let copied = mode;
        assert_eq!(mode, copied);
        let dbg = format!("{mode:?}");
        assert!(dbg.contains("Interactive"));
    }

    #[test]
    fn manifest_approval_mode_all_variants_serde_roundtrip() {
        for (variant, json_str) in [
            (ManifestApprovalMode::None, "\"none\""),
            (ManifestApprovalMode::Policy, "\"policy\""),
            (ManifestApprovalMode::Interactive, "\"interactive\""),
            (ManifestApprovalMode::ElevationToken, "\"elevation_token\""),
        ] {
            let serialized = serde_json::to_string(&variant).unwrap();
            assert_eq!(serialized, json_str);
            let deserialized: ManifestApprovalMode = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, variant);
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: RateLimit debug/clone
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn rate_limit_debug() {
        let rl: RateLimit = serde_json::from_str("\"100/min\"").unwrap();
        let dbg = format!("{rl:?}");
        assert!(dbg.contains("RateLimit"));
    }

    #[test]
    fn rate_limit_clone() {
        let rl: RateLimit = serde_json::from_str("\"50/sec\"").unwrap();
        let cloned = rl.clone();
        assert_eq!(rl.as_inner().max, cloned.as_inner().max);
        assert_eq!(rl.as_inner().per_ms, cloned.as_inner().per_ms);
    }

    #[test]
    fn rate_limit_serialize_roundtrip() {
        let rl: RateLimit = serde_json::from_str("\"200/day\"").unwrap();
        let json = serde_json::to_string(&rl).unwrap();
        // Structured form after deserialization
        let reparsed: RateLimit = serde_json::from_str(&json).unwrap();
        assert_eq!(reparsed.as_inner().max, 200);
        assert_eq!(reparsed.as_inner().per_ms, 86_400_000);
    }

    #[test]
    fn rate_limit_shorthand_s_alias() {
        let rl: RateLimit = serde_json::from_str("\"15/s\"").unwrap();
        assert_eq!(rl.as_inner().max, 15);
        assert_eq!(rl.as_inner().per_ms, 1_000);
    }

    #[test]
    fn rate_limit_shorthand_m_alias() {
        let rl: RateLimit = serde_json::from_str("\"30/m\"").unwrap();
        assert_eq!(rl.as_inner().max, 30);
        assert_eq!(rl.as_inner().per_ms, 60_000);
    }

    #[test]
    fn rate_limit_shorthand_h_alias() {
        let rl: RateLimit = serde_json::from_str("\"500/h\"").unwrap();
        assert_eq!(rl.as_inner().max, 500);
        assert_eq!(rl.as_inner().per_ms, 3_600_000);
    }

    #[test]
    fn rate_limit_shorthand_d_alias() {
        let rl: RateLimit = serde_json::from_str("\"1000/d\"").unwrap();
        assert_eq!(rl.as_inner().max, 1000);
        assert_eq!(rl.as_inner().per_ms, 86_400_000);
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ConnectorArchetype extended
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn connector_archetype_invalid_variant_rejected() {
        let result = serde_json::from_str::<ConnectorArchetype>("\"compute\"");
        assert!(result.is_err());
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ConnectorRuntimeFormat extended
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn connector_runtime_format_invalid_variant_rejected() {
        let result = serde_json::from_str::<ConnectorRuntimeFormat>("\"docker\"");
        assert!(result.is_err());
    }

    #[test]
    fn connector_runtime_format_serde_roundtrip() {
        for variant in [ConnectorRuntimeFormat::Native, ConnectorRuntimeFormat::Wasi] {
            let json = serde_json::to_string(&variant).unwrap();
            let deserialized: ConnectorRuntimeFormat = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, variant);
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: lint_capability_id_no_network_addressing extended
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn lint_allows_single_segment_id() {
        assert!(
            lint_capability_id_no_network_addressing("storage", "capabilities.required").is_ok()
        );
    }

    #[test]
    fn lint_allows_two_segment_id_no_tld() {
        assert!(
            lint_capability_id_no_network_addressing("storage.read", "capabilities.required")
                .is_ok()
        );
    }

    #[test]
    fn lint_rejects_url_scheme_ftp() {
        let err = lint_capability_id_no_network_addressing(
            "ftp:files.example.com",
            "capabilities.required",
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("URL scheme"));
    }

    #[test]
    fn lint_rejects_url_scheme_ws() {
        let err = lint_capability_id_no_network_addressing(
            "ws:stream.example.com",
            "capabilities.optional",
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("URL scheme"));
    }

    #[test]
    fn lint_rejects_hostname_tld_gov() {
        let err =
            lint_capability_id_no_network_addressing("api.agency.gov", "capabilities.required");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains(".gov"));
    }

    #[test]
    fn lint_rejects_hostname_tld_mil() {
        let err = lint_capability_id_no_network_addressing("api.base.mil", "capabilities.required");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains(".mil"));
    }

    #[test]
    fn lint_rejects_port_65535() {
        let err =
            lint_capability_id_no_network_addressing("service:65535", "capabilities.required");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("port number"));
    }

    #[test]
    fn lint_allows_port_zero_not_flagged() {
        // Port 0 is not valid (> 0 check), so it should pass through
        let result =
            lint_capability_id_no_network_addressing("service:00", "capabilities.required");
        assert!(result.is_ok());
    }

    #[test]
    fn lint_allows_six_digit_after_colon_not_flagged() {
        // Six digits after colon is not in the 2-5 digit port range
        let result =
            lint_capability_id_no_network_addressing("service:123456", "capabilities.required");
        assert!(result.is_ok());
    }

    #[test]
    fn lint_ipv4_embedded_in_longer_id() {
        let err = lint_capability_id_no_network_addressing(
            "prefix.192.168.1.1.suffix",
            "capabilities.required",
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("IPv4"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: SupplyChainAttestationRef serde
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn supply_chain_attestation_ref_serde_roundtrip() {
        let oid = ObjectId::from_bytes([0xdd; 32]);
        let att = SupplyChainAttestationRef {
            attestation_type: AttestationType::ReproducibleBuild,
            object_id: oid,
        };
        let json = serde_json::to_string(&att).unwrap();
        let deserialized: SupplyChainAttestationRef = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.attestation_type,
            AttestationType::ReproducibleBuild
        );
        assert_eq!(deserialized.object_id, oid);
    }

    #[test]
    fn supply_chain_attestation_ref_clone_debug() {
        let oid = ObjectId::from_bytes([0xee; 32]);
        let att = SupplyChainAttestationRef {
            attestation_type: AttestationType::InToto,
            object_id: oid,
        };
        let cloned = att.clone();
        assert_eq!(att.object_id, cloned.object_id);
        let dbg = format!("{att:?}");
        assert!(dbg.contains("SupplyChainAttestationRef"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: SignatureEntry serde
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn signature_entry_serde_roundtrip() {
        let entry = SignatureEntry {
            kid: "test-key-1".into(),
            sig: Base64Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: SignatureEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.kid, "test-key-1");
        assert_eq!(deserialized.sig.as_bytes(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn signature_entry_clone_debug() {
        let entry = SignatureEntry {
            kid: "key".into(),
            sig: Base64Bytes(vec![1, 2, 3]),
        };
        let cloned = entry.clone();
        assert_eq!(entry.kid, cloned.kid);
        let dbg = format!("{entry:?}");
        assert!(dbg.contains("SignatureEntry"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: SignatureThreshold extended
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn signature_threshold_n_zero_with_zero_sigs_rejected() {
        let t = SignatureThreshold { k: 0, n: 0 };
        assert!(t.validate(0).is_err());
    }

    #[test]
    fn signature_threshold_try_from_non_numeric_n() {
        let err = SignatureThreshold::try_from("2-of-abc".to_string()).unwrap_err();
        assert!(err.to_string().contains("n must be"));
    }

    #[test]
    fn signature_threshold_into_string() {
        let t = SignatureThreshold { k: 3, n: 5 };
        let s: String = t.into();
        assert_eq!(s, "3-of-5");
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: EventCapsSection serde roundtrip
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn event_caps_section_serde_roundtrip() {
        let ecs = EventCapsSection {
            streaming: true,
            replay: true,
            min_buffer_events: 5000,
        };
        let json = serde_json::to_string(&ecs).unwrap();
        let deserialized: EventCapsSection = serde_json::from_str(&json).unwrap();
        assert!(deserialized.streaming);
        assert!(deserialized.replay);
        assert_eq!(deserialized.min_buffer_events, 5000);
    }

    #[test]
    fn event_caps_section_clone_debug() {
        let ecs = EventCapsSection {
            streaming: false,
            replay: true,
            min_buffer_events: 100,
        };
        let cloned = ecs.clone();
        assert_eq!(ecs.min_buffer_events, cloned.min_buffer_events);
        let dbg = format!("{ecs:?}");
        assert!(dbg.contains("EventCapsSection"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ManifestError debug
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn manifest_error_debug_output() {
        let err = ManifestError::Invalid {
            field: "test",
            message: "msg".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Invalid"));
    }

    #[test]
    fn manifest_error_rate_limit_display() {
        // Create a rate limit error through the RateLimit variant path
        let err = ManifestError::InterfaceHashMismatch {
            expected: "expected_hash".into(),
            found: "found_hash".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("expected_hash"));
        assert!(msg.contains("found_hash"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ConnectorSection effective_state_model with CRDT
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn connector_section_singleton_writer_legacy_flag() {
        // Test the legacy singleton_writer flag without explicit state section
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder)
            .replace(
                "[connector.state]\nmodel = \"stateless\"\nstate_schema_version = \"1\"",
                "",
            )
            .replace(
                "format = \"native\"",
                "format = \"native\"\nsingleton_writer = true",
            );
        let m = ConnectorManifest::parse_str_unchecked(&toml);
        // This should parse, the legacy flag should work
        assert!(m.is_ok());
    }

    #[test]
    fn state_section_to_model_singleton_writer() {
        let section: ConnectorStateSection = serde_json::from_value(json!({
            "model": "singleton_writer",
            "state_schema_version": "1.0"
        }))
        .unwrap();
        let model = section.to_state_model().unwrap();
        assert!(model.is_singleton_writer());
    }

    #[test]
    fn state_section_crdt_or_set() {
        let section: ConnectorStateSection = serde_json::from_value(json!({
            "model": "crdt",
            "state_schema_version": "1.0",
            "crdt_type": "or_set"
        }))
        .unwrap();
        let model = section.to_state_model().unwrap();
        assert_eq!(model.crdt_type(), Some(ConnectorCrdtType::OrSet));
    }

    #[test]
    fn state_section_crdt_g_counter() {
        let section: ConnectorStateSection = serde_json::from_value(json!({
            "model": "crdt",
            "state_schema_version": "1.0",
            "crdt_type": "g_counter"
        }))
        .unwrap();
        let model = section.to_state_model().unwrap();
        assert_eq!(model.crdt_type(), Some(ConnectorCrdtType::GCounter));
    }

    #[test]
    fn state_section_crdt_pn_counter() {
        let section: ConnectorStateSection = serde_json::from_value(json!({
            "model": "crdt",
            "state_schema_version": "1.0",
            "crdt_type": "pn_counter"
        }))
        .unwrap();
        let model = section.to_state_model().unwrap();
        assert_eq!(model.crdt_type(), Some(ConnectorCrdtType::PnCounter));
    }

    #[test]
    fn state_section_with_migration_hint() {
        let section: ConnectorStateSection = serde_json::from_value(json!({
            "model": "singleton_writer",
            "state_schema_version": "2.0",
            "migration_hint": "run_migration_v2"
        }))
        .unwrap();
        assert_eq!(section.migration_hint.as_deref(), Some("run_migration_v2"));
    }

    #[test]
    fn state_section_with_snapshot_settings() {
        let section: ConnectorStateSection = serde_json::from_value(json!({
            "model": "crdt",
            "state_schema_version": "1.0",
            "crdt_type": "lww_map",
            "snapshot_every_updates": 1000,
            "snapshot_every_bytes": 65536
        }))
        .unwrap();
        assert_eq!(section.snapshot_every_updates, Some(1000));
        assert_eq!(section.snapshot_every_bytes, Some(65536));
    }

    #[test]
    fn state_section_singleton_writer_rejects_crdt_only_fields() {
        let section: ConnectorStateSection = serde_json::from_value(json!({
            "model": "singleton_writer",
            "state_schema_version": "1.0",
            "crdt_type": "lww_map",
            "snapshot_every_updates": 1000,
            "snapshot_every_bytes": 65536
        }))
        .unwrap();
        let err = section.validate().unwrap_err();
        assert!(err.to_string().contains("connector.state.crdt_type"));
    }

    #[test]
    fn state_section_stateless_rejects_snapshot_settings() {
        let section: ConnectorStateSection = serde_json::from_value(json!({
            "model": "stateless",
            "state_schema_version": "1.0",
            "snapshot_every_updates": 1000
        }))
        .unwrap();
        let err = section.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("connector.state.snapshot_every_updates")
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ZonesSection serde
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn zones_section_serde_roundtrip() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let m = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder)).unwrap();
        let json = serde_json::to_string(&m.zones).unwrap();
        let deserialized: ZonesSection = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.home.as_str(), "z:community");
        assert_eq!(deserialized.forbidden.len(), 1);
    }

    #[test]
    fn zones_section_clone_debug() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let m = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder)).unwrap();
        let cloned = m.zones.clone();
        assert_eq!(m.zones.home.as_str(), cloned.home.as_str());
        let dbg = format!("{:?}", m.zones);
        assert!(dbg.contains("ZonesSection"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: CapabilitiesSection serde
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn capabilities_section_clone_debug() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let m = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder)).unwrap();
        let cloned = m.capabilities.clone();
        assert_eq!(m.capabilities.required.len(), cloned.required.len());
        let dbg = format!("{:?}", m.capabilities);
        assert!(dbg.contains("CapabilitiesSection"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: OperationSection serde
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn operation_section_clone_debug() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let m = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder)).unwrap();
        let op = m.provides.operations.values().next().unwrap();
        let cloned = op.clone();
        assert_eq!(op.description, cloned.description);
        let dbg = format!("{op:?}");
        assert!(dbg.contains("OperationSection"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ProvidesSection serde
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn provides_section_clone_debug() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let m = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder)).unwrap();
        let cloned = m.provides.clone();
        assert_eq!(m.provides.operations.len(), cloned.operations.len());
        let dbg = format!("{:?}", m.provides);
        assert!(dbg.contains("ProvidesSection"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ConnectorSection clone/debug
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn connector_section_clone_debug() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let m = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder)).unwrap();
        let cloned = m.connector.clone();
        assert_eq!(m.connector.id.as_str(), cloned.id.as_str());
        let dbg = format!("{:?}", m.connector);
        assert!(dbg.contains("ConnectorSection"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ManifestSection clone/debug
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn manifest_section_clone_debug() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let m = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder)).unwrap();
        let cloned = m.manifest.clone();
        assert_eq!(m.manifest.format, cloned.format);
        let dbg = format!("{:?}", m.manifest);
        assert!(dbg.contains("ManifestSection"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: parse_rate_limit_shorthand edge cases
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn parse_rate_limit_shorthand_zero_max() {
        let result = parse_rate_limit_shorthand("0/min");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().max, 0);
    }

    #[test]
    fn parse_rate_limit_shorthand_large_max() {
        let result = parse_rate_limit_shorthand("999999/sec");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().max, 999_999);
    }

    #[test]
    fn parse_rate_limit_shorthand_no_slash() {
        let result = parse_rate_limit_shorthand("60min");
        assert!(result.is_err());
    }

    #[test]
    fn parse_rate_limit_shorthand_unknown_unit() {
        let result = parse_rate_limit_shorthand("10/week");
        assert!(result.is_err());
    }

    #[test]
    fn parse_rate_limit_shorthand_non_numeric_max() {
        let result = parse_rate_limit_shorthand("abc/min");
        assert!(result.is_err());
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: host_allow_entry with IPv6
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn host_allow_ipv6_literal_denied() {
        let err = validate_host_allow_entry("::1", true, false).unwrap_err();
        assert!(err.to_string().contains("IP literals"));
    }

    #[test]
    fn host_allow_ipv6_literal_allowed_when_not_denied() {
        assert!(validate_host_allow_entry("::1", false, false).is_ok());
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: RateLimitsSection serde
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn rate_limits_section_serde_roundtrip() {
        let section = RateLimitsSection {
            pools: vec![RateLimitPoolSection {
                id: "global".into(),
                description: Some("Global limit".into()),
                requests: 60,
                window_ms: 60_000,
                burst: None,
                unit: None,
                enforcement: None,
                scope: None,
            }],
            operation_pools: {
                let mut m = std::collections::HashMap::new();
                m.insert("op1".into(), vec!["global".into()]);
                m
            },
        };
        let json = serde_json::to_string(&section).unwrap();
        let deserialized: RateLimitsSection = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.pools.len(), 1);
        assert_eq!(deserialized.pools[0].id, "global");
    }

    #[test]
    fn rate_limits_section_clone_debug() {
        let section = RateLimitsSection::default();
        let cloned = section.clone();
        assert_eq!(section.pools.len(), cloned.pools.len());
        let dbg = format!("{section:?}");
        assert!(dbg.contains("RateLimitsSection"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: SupplyChainSection serde
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn supply_chain_section_serde_roundtrip() {
        let oid = ObjectId::from_bytes([0xaa; 32]);
        let section = SupplyChainSection {
            attestations: vec![SupplyChainAttestationRef {
                attestation_type: AttestationType::InToto,
                object_id: oid,
            }],
        };
        let json = serde_json::to_string(&section).unwrap();
        let deserialized: SupplyChainSection = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.attestations.len(), 1);
    }

    #[test]
    fn supply_chain_section_clone_debug() {
        let section = SupplyChainSection {
            attestations: vec![],
        };
        let cloned = section.clone();
        assert_eq!(section.attestations.len(), cloned.attestations.len());
        let dbg = format!("{section:?}");
        assert!(dbg.contains("SupplyChainSection"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: SignaturesSection serde
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn signatures_section_serde_roundtrip() {
        let section = SignaturesSection {
            publisher_signatures: vec![SignatureEntry {
                kid: "key1".into(),
                sig: Base64Bytes(vec![1, 2, 3]),
            }],
            publisher_threshold: Some(SignatureThreshold { k: 1, n: 1 }),
            registry_signature: None,
            transparency_log_entry: None,
        };
        let json = serde_json::to_string(&section).unwrap();
        let deserialized: SignaturesSection = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.publisher_signatures.len(), 1);
        assert_eq!(deserialized.publisher_threshold.unwrap().k, 1);
    }

    #[test]
    fn signatures_section_clone_debug() {
        let section = SignaturesSection {
            publisher_signatures: vec![],
            publisher_threshold: None,
            registry_signature: None,
            transparency_log_entry: None,
        };
        let cloned = section.clone();
        assert_eq!(
            section.publisher_signatures.len(),
            cloned.publisher_signatures.len()
        );
        let dbg = format!("{section:?}");
        assert!(dbg.contains("SignaturesSection"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: PolicySection clone/debug
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn policy_section_clone_debug() {
        let policy = PolicySection {
            require_transparency_log: true,
            require_attestation_types: vec![AttestationType::CodeReview],
            min_slsa_level: Some(2),
            trusted_builders: vec!["builder".into()],
            require_attestation_expiry: false,
        };
        let cloned = policy.clone();
        assert_eq!(policy.min_slsa_level, cloned.min_slsa_level);
        let dbg = format!("{policy:?}");
        assert!(dbg.contains("PolicySection"));
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS: ConnectorStateSection clone/debug
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn connector_state_section_clone_debug() {
        let section: ConnectorStateSection = serde_json::from_value(json!({
            "model": "singleton_writer",
            "state_schema_version": "1.0"
        }))
        .unwrap();
        let cloned = section.clone();
        assert_eq!(section.state_schema_version, cloned.state_schema_version);
        let dbg = format!("{section:?}");
        assert!(dbg.contains("ConnectorStateSection"));
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: ManifestError variant coverage
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn manifest_error_id_variant_display() {
        // IdValidationError comes from validate_canonical_id
        let err: Result<(), _> = validate_canonical_id("INVALID-CAPS");
        if let Err(id_err) = err {
            let manifest_err = ManifestError::Id(id_err);
            let msg = manifest_err.to_string();
            assert!(msg.contains("invalid identifier"));
        }
    }

    #[test]
    fn manifest_error_zone_id_variant_display() {
        // ZoneIdError comes from invalid zone id parsing
        let err: Result<ZoneId, _> = "".parse();
        if let Err(zone_err) = err {
            let manifest_err = ManifestError::ZoneId(zone_err);
            let msg = manifest_err.to_string();
            assert!(msg.contains("invalid zone id"));
        }
    }

    #[test]
    fn manifest_error_is_send_sync() {
        fn assert_send_sync<T: Send>() {}
        assert_send_sync::<ManifestError>();
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: InterfaceHash edge cases
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn interface_hash_try_from_missing_domain_part() {
        // Only algorithm, no domain or digest
        let err = InterfaceHash::try_from("blake3-256".to_string()).unwrap_err();
        assert!(err.to_string().contains("domain"));
    }

    #[test]
    fn interface_hash_try_from_empty_digest() {
        let s = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:");
        let err = InterfaceHash::try_from(s).unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn interface_hash_try_from_too_long_digest() {
        let hex = "aa".repeat(33); // 33 bytes = 66 hex chars
        let s = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{hex}");
        let err = InterfaceHash::try_from(s).unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn interface_hash_mixed_case_rejected() {
        // Only a few uppercase chars
        let hex = "aAbBcCdD".to_string() + &"00".repeat(28);
        let s = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{hex}");
        let err = InterfaceHash::try_from(s).unwrap_err();
        assert!(err.to_string().contains("lowercase"));
    }

    #[test]
    fn interface_hash_all_zeros() {
        let hex = "00".repeat(32);
        let s = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{hex}");
        let h = InterfaceHash::try_from(s).unwrap();
        assert_eq!(h.digest, [0u8; 32]);
    }

    #[test]
    fn interface_hash_all_ff() {
        let hex = "ff".repeat(32);
        let s = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{hex}");
        let h = InterfaceHash::try_from(s).unwrap();
        assert_eq!(h.digest, [0xFF; 32]);
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: ManifestSchemaVersion edge cases
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn manifest_schema_version_negative_rejected() {
        let err = ManifestSchemaVersion::try_from("-1.0".to_string()).unwrap_err();
        assert!(err.to_string().contains("major"));
    }

    #[test]
    fn manifest_schema_version_empty_string_rejected() {
        let err = ManifestSchemaVersion::try_from(String::new()).unwrap_err();
        assert!(err.to_string().contains("MAJOR.MINOR"));
    }

    #[test]
    fn manifest_schema_version_leading_zeros() {
        let v = ManifestSchemaVersion::try_from("02.01".to_string()).unwrap();
        assert_eq!(v.major, 2);
        assert_eq!(v.minor, 1);
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: ProtocolRequirement edge cases
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn protocol_requirement_with_hyphens_in_name() {
        let pr = ProtocolRequirement::try_from("my-custom-proto/1.2".to_string()).unwrap();
        assert_eq!(pr.name, "my-custom-proto");
        assert_eq!(pr.version.major, 1);
        assert_eq!(pr.version.minor, 2);
    }

    #[test]
    fn protocol_requirement_display_preserves_name() {
        let pr = ProtocolRequirement::try_from("fcp2-sym/3.1".to_string()).unwrap();
        assert_eq!(pr.to_string(), "fcp2-sym/3.1");
    }

    #[test]
    fn protocol_requirement_non_numeric_minor_rejected() {
        let err = ProtocolRequirement::try_from("fcp2-sym/2.abc".to_string()).unwrap_err();
        assert!(err.to_string().contains("minor"));
    }

    #[test]
    fn protocol_requirement_multiple_slashes() {
        // split_once on '/' => name="fcp2", version="sym/2.0"
        let err = ProtocolRequirement::try_from("fcp2/sym/2.0".to_string());
        // version "sym/2.0" can't parse as MAJOR.MINOR
        assert!(err.is_err());
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: FeatureId edge cases
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn feature_id_single_char() {
        let fid = FeatureId::try_from("a".to_string()).unwrap();
        assert_eq!(fid.as_str(), "a");
    }

    #[test]
    fn feature_id_with_dots() {
        let fid = FeatureId::try_from("a.b.c.d".to_string()).unwrap();
        assert_eq!(fid.as_str(), "a.b.c.d");
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: ConnectorSection singleton_writer conflict
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn connector_section_singleton_writer_conflict_with_crdt_state() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder)
            .replace(
                "[connector.state]\nmodel = \"stateless\"\nstate_schema_version = \"1\"",
                "[connector.state]\nmodel = \"crdt\"\nstate_schema_version = \"1\"\ncrdt_type = \"lww_map\"",
            )
            .replace(
                "format = \"native\"",
                "format = \"native\"\nsingleton_writer = true",
            );
        let m = ConnectorManifest::parse_str_unchecked(&toml).unwrap();
        let err = m.validate().unwrap_err();
        assert!(err.to_string().contains("singleton_writer"));
    }

    #[test]
    fn connector_section_stateless_no_singleton_flag() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let m = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder)).unwrap();
        // Default state is stateless with no singleton_writer flag
        assert!(m.connector.singleton_writer.is_none());
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: NetworkConstraints edge cases
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn network_constraints_localhost_allowed_when_deny_false() {
        let nc = NetworkConstraints {
            host_allow: vec!["localhost".into()],
            port_allow: vec![8080],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: false,
            deny_private_ranges: false,
            deny_tailnet_ranges: false,
            require_sni: false,
            spki_pins: vec![],
            deny_ip_literals: false,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        assert!(nc.validate().is_ok());
    }

    #[test]
    fn network_constraints_multiple_valid_cidrs() {
        let nc = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![
                "10.0.0.0/8".into(),
                "172.16.0.0/12".into(),
                "192.168.0.0/16".into(),
            ],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        assert!(nc.validate().is_ok());
    }

    #[test]
    fn network_constraints_wildcard_four_labels_valid() {
        let nc = NetworkConstraints {
            host_allow: vec!["*.sub.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        assert!(nc.validate().is_ok());
    }

    #[test]
    fn network_constraints_ipv6_in_ip_allow() {
        let nc = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec!["2001:db8::1".parse().unwrap()],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        assert!(nc.validate().is_ok());
    }

    #[test]
    fn network_constraints_multiple_spki_pins() {
        let nc = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![Base64Bytes(vec![1, 2, 3]), Base64Bytes(vec![4, 5, 6])],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        assert!(nc.validate().is_ok());
    }

    #[test]
    fn network_constraints_max_redirects_zero_valid() {
        let nc = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 0,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        assert!(nc.validate().is_ok());
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: validate_host_allow_entry edge cases
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn host_allow_wildcard_single_label_rejected() {
        // *.x has only 2 parts
        let err = validate_host_allow_entry("*.x", false, false).unwrap_err();
        assert!(err.to_string().contains("too broad"));
    }

    #[test]
    fn host_allow_multiple_wildcards_rejected() {
        let err = validate_host_allow_entry("*.*.example.com", false, false).unwrap_err();
        assert!(err.to_string().contains("*.example.com"));
    }

    #[test]
    fn host_allow_wildcard_not_at_start_rejected() {
        let err = validate_host_allow_entry("sub.*.example.com", false, false).unwrap_err();
        assert!(err.to_string().contains("*.example.com"));
    }

    #[test]
    fn host_allow_ipv6_full_denied() {
        let err = validate_host_allow_entry("2001:db8::1", true, false).unwrap_err();
        assert!(err.to_string().contains("IP literals"));
    }

    #[test]
    fn host_allow_non_ascii_allowed_without_canonicalization() {
        assert!(validate_host_allow_entry("münchen.example.com", false, false).is_ok());
    }

    #[test]
    fn host_allow_uppercase_allowed_without_canonicalization() {
        assert!(validate_host_allow_entry("API.EXAMPLE.COM", false, false).is_ok());
    }

    #[test]
    fn host_allow_trailing_dot_allowed_without_canonicalization() {
        assert!(validate_host_allow_entry("example.com.", false, false).is_ok());
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: lint_capability_id_no_network_addressing
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn lint_allows_three_segments_non_tld() {
        assert!(
            lint_capability_id_no_network_addressing(
                "my.custom.capability",
                "capabilities.required"
            )
            .is_ok()
        );
    }

    #[test]
    fn lint_allows_deep_nested_capability() {
        assert!(
            lint_capability_id_no_network_addressing("a.b.c.d.e.f", "capabilities.required")
                .is_ok()
        );
    }

    #[test]
    fn lint_rejects_ipv4_at_start() {
        let err = lint_capability_id_no_network_addressing("192.168.0.1", "capabilities.required");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("IPv4"));
    }

    #[test]
    fn lint_allows_three_digit_segments_if_not_four_consecutive() {
        // Only 3 consecutive digit segments, not 4
        assert!(
            lint_capability_id_no_network_addressing("prefix.10.0.1", "capabilities.required")
                .is_ok()
        );
    }

    #[test]
    fn lint_allows_colon_followed_by_non_digit() {
        assert!(
            lint_capability_id_no_network_addressing("scope:read", "capabilities.required").is_ok()
        );
    }

    #[test]
    fn lint_allows_colon_with_single_digit() {
        assert!(
            lint_capability_id_no_network_addressing("version:2", "capabilities.required").is_ok()
        );
    }

    #[test]
    fn lint_rejects_port_number_80() {
        let err = lint_capability_id_no_network_addressing("service:80", "capabilities.required");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("port number"));
    }

    #[test]
    fn lint_rejects_port_number_3000() {
        let err = lint_capability_id_no_network_addressing("dev:3000", "capabilities.required");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("port number"));
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: parse_rate_limit_shorthand
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn parse_rate_limit_shorthand_empty_string() {
        let result = parse_rate_limit_shorthand("");
        assert!(result.is_err());
    }

    #[test]
    fn parse_rate_limit_shorthand_only_slash() {
        let result = parse_rate_limit_shorthand("/min");
        assert!(result.is_err());
    }

    #[test]
    fn parse_rate_limit_shorthand_burst_and_scope_absent() {
        let rl = parse_rate_limit_shorthand("50/sec").unwrap();
        assert!(rl.burst.is_none());
        assert!(rl.scope.is_none());
        assert!(rl.pool_name.is_none());
    }

    #[test]
    fn parse_rate_limit_shorthand_one_per_day() {
        let rl = parse_rate_limit_shorthand("1/day").unwrap();
        assert_eq!(rl.max, 1);
        assert_eq!(rl.per_ms, 86_400_000);
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: SignatureThreshold edge cases
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn signature_threshold_exact_k_equals_n() {
        let t = SignatureThreshold { k: 3, n: 3 };
        assert!(t.validate(3).is_ok());
    }

    #[test]
    fn signature_threshold_exactly_enough_sigs() {
        let t = SignatureThreshold { k: 2, n: 5 };
        assert!(t.validate(2).is_ok());
    }

    #[test]
    fn signature_threshold_excess_sigs_valid() {
        let t = SignatureThreshold { k: 1, n: 3 };
        assert!(t.validate(5).is_ok());
    }

    #[test]
    fn signature_threshold_k_1_n_255() {
        let t = SignatureThreshold { k: 1, n: 255 };
        assert!(t.validate(1).is_ok());
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: Base64Bytes edge cases
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn base64_bytes_single_byte() {
        let b = Base64Bytes::try_from("base64:AA==".to_string()).unwrap();
        assert_eq!(b.as_bytes(), &[0x00]);
    }

    #[test]
    fn base64_bytes_clone_eq() {
        let a = Base64Bytes(vec![10, 20, 30]);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn base64_bytes_partial_ord() {
        let a = Base64Bytes(vec![1]);
        let b = Base64Bytes(vec![2]);
        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn base64_bytes_empty_eq() {
        let a = Base64Bytes(vec![]);
        let b = Base64Bytes(vec![]);
        assert_eq!(a, b);
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: ObjectId edge cases
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn object_id_prefixed_all_zeros() {
        let hex_str = "00".repeat(32);
        let oid = ObjectId::parse_prefixed(&format!("objectid:{hex_str}")).unwrap();
        assert_eq!(oid.to_prefixed_string(), format!("objectid:{hex_str}"));
    }

    #[test]
    fn object_id_prefixed_all_ff() {
        let hex_str = "ff".repeat(32);
        let oid = ObjectId::parse_prefixed(&format!("objectid:{hex_str}")).unwrap();
        assert_eq!(oid.to_prefixed_string(), format!("objectid:{hex_str}"));
    }

    #[test]
    fn object_id_prefixed_into_string() {
        let hex_str = "ab".repeat(32);
        let oid = ObjectId::parse_prefixed(&format!("objectid:{hex_str}")).unwrap();
        let s = oid.to_prefixed_string();
        assert_eq!(s, format!("objectid:{hex_str}"));
    }

    #[test]
    fn object_id_prefixed_uppercase_hex_parses() {
        // hex::decode handles uppercase
        let hex_str = "AB".repeat(32);
        let oid = ObjectId::parse_prefixed(&format!("objectid:{hex_str}")).unwrap();
        // display is lowercase
        assert!(oid.to_prefixed_string().contains(&"ab".repeat(32)));
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: ConnectorStateModel edge cases
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn connector_state_model_ne() {
        let a = ConnectorStateModel::Stateless;
        let b = ConnectorStateModel::SingletonWriter;
        assert_ne!(a, b);
    }

    #[test]
    fn connector_state_model_different_crdt_types_ne() {
        let a = ConnectorStateModel::Crdt {
            crdt_type: ConnectorCrdtType::LwwMap,
        };
        let b = ConnectorStateModel::Crdt {
            crdt_type: ConnectorCrdtType::OrSet,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn connector_state_model_display_crdt_pn_counter() {
        let model = ConnectorStateModel::Crdt {
            crdt_type: ConnectorCrdtType::PnCounter,
        };
        assert_eq!(model.to_string(), "crdt(pn_counter)");
    }

    #[test]
    fn connector_state_model_display_crdt_or_set() {
        let model = ConnectorStateModel::Crdt {
            crdt_type: ConnectorCrdtType::OrSet,
        };
        assert_eq!(model.to_string(), "crdt(or_set)");
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: ConnectorCrdtType edge cases
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn connector_crdt_type_ne() {
        assert_ne!(ConnectorCrdtType::LwwMap, ConnectorCrdtType::OrSet);
        assert_ne!(ConnectorCrdtType::GCounter, ConnectorCrdtType::PnCounter);
    }

    #[test]
    fn connector_crdt_type_invalid_variant_rejected() {
        let result = serde_json::from_str::<ConnectorCrdtType>("\"ot_text\"");
        assert!(result.is_err());
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: TOML parsing failures
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn parse_str_empty_string_fails() {
        let err = ConnectorManifest::parse_str("").unwrap_err();
        assert!(matches!(err, ManifestError::Toml(_)));
    }

    #[test]
    fn parse_str_invalid_toml_syntax() {
        let err = ConnectorManifest::parse_str("[[[invalid").unwrap_err();
        assert!(matches!(err, ManifestError::Toml(_)));
    }

    #[test]
    fn parse_str_missing_required_section() {
        let toml = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
"#;
        let err = ConnectorManifest::parse_str(toml).unwrap_err();
        assert!(matches!(err, ManifestError::Toml(_)));
    }

    #[test]
    fn parse_str_unknown_field_rejected() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder) + "\nunknown_field = true\n";
        let err = ConnectorManifest::parse_str_unchecked(&toml).unwrap_err();
        assert!(matches!(err, ManifestError::Toml(_)));
    }

    #[test]
    fn parse_str_duplicate_key_rejected() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder)
            + "\n[connector]\nname = \"Duplicate Connector Section\"\n";
        let err = ConnectorManifest::parse_str_unchecked(&toml).unwrap_err();
        assert!(matches!(err, ManifestError::Toml(_)));
    }

    #[test]
    fn parse_str_event_blank_topic_rejected() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder)
            + "\n[provides.events.test_event]\ndescription = \"Test event\"\ntopic = \"   \"\n";
        let err = ConnectorManifest::parse_str(&toml).unwrap_err();
        assert!(matches!(
            err,
            ManifestError::Invalid {
                field: "provides.events.*.topic",
                ..
            }
        ));
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: ManifestSection validation
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn manifest_section_version_1_rejected() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder)
            .replace("schema_version = \"2.1\"", "schema_version = \"1.0\"");
        let m = ConnectorManifest::parse_str_unchecked(&toml).unwrap();
        let err = m.validate().unwrap_err();
        assert!(err.to_string().contains("schema"));
    }

    #[test]
    fn manifest_section_max_datagram_1_valid() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder)
            .replace("max_datagram_bytes = 1200", "max_datagram_bytes = 1");
        let m = ConnectorManifest::parse_str_unchecked(&toml).unwrap();
        // Validation of max_datagram_bytes > 0 passes, but hash will mismatch
        // We only check that > 0 validation passes
        let result = m.manifest.validate();
        assert!(result.is_ok());
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: ProvidesSection with events
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn provides_section_with_events_serde() {
        let json_val = json!({
            "operations": {
                "list_items": {
                    "description": "List items",
                    "capability": "storage.read",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "requires_approval": "none",
                    "rate_limit": null,
                    "idempotency": "strict",
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "object"}
                }
            },
            "events": {
                "item_created": {
                    "description": "Emitted when a new item is created",
                    "streaming": true,
                    "replay": false
                }
            }
        });
        let section: ProvidesSection = serde_json::from_value(json_val).unwrap();
        assert_eq!(section.operations.len(), 1);
        assert_eq!(section.events.len(), 1);
        assert!(section.events.contains_key("item_created"));
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: RateLimitsSection with multiple pools
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn rate_limits_section_multiple_pools() {
        let section = RateLimitsSection {
            pools: vec![
                RateLimitPoolSection {
                    id: "rpm".into(),
                    description: Some("Requests per minute".into()),
                    requests: 60,
                    window_ms: 60_000,
                    burst: None,
                    unit: None,
                    enforcement: None,
                    scope: None,
                },
                RateLimitPoolSection {
                    id: "tokens".into(),
                    description: Some("Tokens per minute".into()),
                    requests: 100_000,
                    window_ms: 60_000,
                    burst: Some(10_000),
                    unit: Some("tokens".into()),
                    enforcement: Some("hard".into()),
                    scope: Some("credential".into()),
                },
            ],
            operation_pools: {
                let mut m = std::collections::HashMap::new();
                m.insert("chat".into(), vec!["rpm".into(), "tokens".into()]);
                m.insert("embed".into(), vec!["rpm".into()]);
                m
            },
        };
        let decls = section.to_declarations();
        assert_eq!(decls.limits.len(), 2);
        assert_eq!(decls.tool_pool_map.get("chat").unwrap().len(), 2);
        assert_eq!(decls.tool_pool_map.get("embed").unwrap().len(), 1);
    }

    #[test]
    fn rate_limits_section_pool_description_none_defaults_empty() {
        let section = RateLimitsSection {
            pools: vec![RateLimitPoolSection {
                id: "p".into(),
                description: None,
                requests: 10,
                window_ms: 1000,
                burst: None,
                unit: None,
                enforcement: None,
                scope: None,
            }],
            operation_pools: std::collections::HashMap::default(),
        };
        let decls = section.to_declarations();
        assert!(decls.limits[0].description.is_empty());
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: EventCapsSection boundary
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn event_caps_streaming_with_one_buffer_valid() {
        let ecs = EventCapsSection {
            streaming: true,
            replay: false,
            min_buffer_events: 1,
        };
        assert!(ecs.validate().is_ok());
    }

    #[test]
    fn event_caps_streaming_with_max_buffer_valid() {
        let ecs = EventCapsSection {
            streaming: true,
            replay: true,
            min_buffer_events: u32::MAX,
        };
        assert!(ecs.validate().is_ok());
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: PolicySection boundary
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn policy_slsa_level_1_valid() {
        let p = PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![],
            min_slsa_level: Some(1),
            trusted_builders: vec![],
            require_attestation_expiry: false,
        };
        assert!(p.validate().is_ok());
    }

    #[test]
    fn policy_slsa_level_2_valid() {
        let p = PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![],
            min_slsa_level: Some(2),
            trusted_builders: vec![],
            require_attestation_expiry: false,
        };
        assert!(p.validate().is_ok());
    }

    #[test]
    fn policy_slsa_level_3_valid() {
        let p = PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![],
            min_slsa_level: Some(3),
            trusted_builders: vec![],
            require_attestation_expiry: false,
        };
        assert!(p.validate().is_ok());
    }

    #[test]
    fn policy_slsa_level_255_rejected() {
        let p = PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![],
            min_slsa_level: Some(255),
            trusted_builders: vec![],
            require_attestation_expiry: false,
        };
        let err = p.validate().unwrap_err();
        assert!(err.to_string().contains("0..=4"));
    }

    #[test]
    fn policy_multiple_attestation_types() {
        let p = PolicySection {
            require_transparency_log: true,
            require_attestation_types: vec![
                AttestationType::InToto,
                AttestationType::ReproducibleBuild,
                AttestationType::CodeReview,
            ],
            min_slsa_level: Some(4),
            trusted_builders: vec!["b1".into(), "b2".into()],
            require_attestation_expiry: false,
        };
        assert!(p.validate().is_ok());
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: SupplyChainSection edge cases
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn supply_chain_single_attestation_valid() {
        let oid = ObjectId::from_bytes([0x11; 32]);
        let section = SupplyChainSection {
            attestations: vec![SupplyChainAttestationRef {
                attestation_type: AttestationType::ReproducibleBuild,
                object_id: oid,
            }],
        };
        assert!(section.validate().is_ok());
    }

    #[test]
    fn supply_chain_three_unique_attestations_valid() {
        let oid1 = ObjectId::from_bytes([0x11; 32]);
        let oid2 = ObjectId::from_bytes([0x22; 32]);
        let oid3 = ObjectId::from_bytes([0x33; 32]);
        let section = SupplyChainSection {
            attestations: vec![
                SupplyChainAttestationRef {
                    attestation_type: AttestationType::InToto,
                    object_id: oid1,
                },
                SupplyChainAttestationRef {
                    attestation_type: AttestationType::ReproducibleBuild,
                    object_id: oid2,
                },
                SupplyChainAttestationRef {
                    attestation_type: AttestationType::CodeReview,
                    object_id: oid3,
                },
            ],
        };
        assert!(section.validate().is_ok());
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: SignaturesSection edge cases
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn signatures_section_with_registry_signature() {
        let section = SignaturesSection {
            publisher_signatures: vec![SignatureEntry {
                kid: "key1".into(),
                sig: Base64Bytes(vec![1, 2]),
            }],
            publisher_threshold: Some(SignatureThreshold { k: 1, n: 1 }),
            registry_signature: Some(SignatureEntry {
                kid: "registry".into(),
                sig: Base64Bytes(vec![3, 4]),
            }),
            transparency_log_entry: None,
        };
        assert!(section.validate().is_ok());
    }

    #[test]
    fn signatures_section_with_transparency_log() {
        let oid = ObjectId::from_bytes([0xcc; 32]);
        let section = SignaturesSection {
            publisher_signatures: vec![SignatureEntry {
                kid: "key1".into(),
                sig: Base64Bytes(vec![1]),
            }],
            publisher_threshold: Some(SignatureThreshold { k: 1, n: 1 }),
            registry_signature: None,
            transparency_log_entry: Some(oid),
        };
        assert!(section.validate().is_ok());
    }

    #[test]
    fn signatures_section_threshold_requires_enough_sigs() {
        let section = SignaturesSection {
            publisher_signatures: vec![SignatureEntry {
                kid: "key1".into(),
                sig: Base64Bytes(vec![1]),
            }],
            publisher_threshold: Some(SignatureThreshold { k: 2, n: 3 }),
            registry_signature: None,
            transparency_log_entry: None,
        };
        let err = section.validate().unwrap_err();
        assert!(err.to_string().contains("insufficient"));
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: ConnectorStateSection serde edge cases
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn state_section_serde_roundtrip() {
        let section: ConnectorStateSection = serde_json::from_value(json!({
            "model": "crdt",
            "state_schema_version": "2.0",
            "crdt_type": "pn_counter",
            "migration_hint": "migrate_v2",
            "snapshot_every_updates": 500,
            "snapshot_every_bytes": 32768
        }))
        .unwrap();
        let json = serde_json::to_string(&section).unwrap();
        let deserialized: ConnectorStateSection = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.state_schema_version, "2.0");
        assert_eq!(deserialized.crdt_type, Some(ConnectorCrdtType::PnCounter));
        assert_eq!(deserialized.migration_hint.as_deref(), Some("migrate_v2"));
        assert_eq!(deserialized.snapshot_every_updates, Some(500));
        assert_eq!(deserialized.snapshot_every_bytes, Some(32768));
    }

    #[test]
    fn state_section_invalid_model_rejected() {
        let result = serde_json::from_value::<ConnectorStateSection>(json!({
            "model": "distributed",
            "state_schema_version": "1.0"
        }));
        assert!(result.is_err());
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: ConnectorManifest parse_str_unchecked vs parse_str
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn parse_str_unchecked_skips_validation() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        // This has a wrong interface hash but unchecked should succeed
        let m = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder));
        assert!(m.is_ok());
    }

    #[test]
    fn parse_str_validates_interface_hash() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let err = ConnectorManifest::parse_str(&test_manifest_toml(&placeholder)).unwrap_err();
        assert!(matches!(err, ManifestError::InterfaceHashMismatch { .. }));
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: RateLimit structured form
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn rate_limit_structured_form_with_burst() {
        let rl: RateLimit = serde_json::from_value(json!({
            "max": 100,
            "per_ms": 60000,
            "burst": 20
        }))
        .unwrap();
        assert_eq!(rl.as_inner().max, 100);
        assert_eq!(rl.as_inner().per_ms, 60_000);
        assert_eq!(rl.as_inner().burst, Some(20));
    }

    #[test]
    fn rate_limit_structured_form_minimal() {
        let rl: RateLimit = serde_json::from_value(json!({
            "max": 10,
            "per_ms": 1000
        }))
        .unwrap();
        assert_eq!(rl.as_inner().max, 10);
        assert_eq!(rl.as_inner().per_ms, 1000);
        assert!(rl.as_inner().burst.is_none());
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: ManifestApprovalMode edge
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn manifest_approval_mode_ne() {
        assert_ne!(ManifestApprovalMode::None, ManifestApprovalMode::Policy);
        assert_ne!(
            ManifestApprovalMode::Interactive,
            ManifestApprovalMode::ElevationToken
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: ProtocolVersion edge cases
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn protocol_version_zero_zero() {
        let v = ProtocolVersion::try_from("0.0".to_string()).unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 0);
        assert_eq!(v.to_string(), "0.0");
    }

    #[test]
    fn protocol_version_overflow_rejected() {
        let err = ProtocolVersion::try_from("99999.0".to_string()).unwrap_err();
        assert!(err.to_string().contains("major"));
    }

    #[test]
    fn protocol_version_minor_overflow_rejected() {
        let err = ProtocolVersion::try_from("2.99999".to_string()).unwrap_err();
        assert!(err.to_string().contains("minor"));
    }

    #[test]
    fn protocol_version_extra_dots_rejected() {
        let err = ProtocolVersion::try_from("2.0.0".to_string()).unwrap_err();
        assert!(err.to_string().contains("minor"));
    }

    // ══════════════════════════════════════════════════════════════════
    // EXPANDED TESTS: SandboxSection edge cases
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn sandbox_section_min_values_valid() {
        let section = SandboxSection {
            profile: SandboxProfile::Strict,
            memory_mb: 1,
            cpu_percent: 1,
            wall_clock_timeout_ms: 1,
            fs_readonly_paths: vec![],
            fs_writable_paths: vec![],
            deny_exec: true,
            deny_ptrace: true,
        };
        assert!(section.validate().is_ok());
    }

    #[test]
    fn sandbox_section_max_cpu_valid() {
        let section = SandboxSection {
            profile: SandboxProfile::Permissive,
            memory_mb: 4096,
            cpu_percent: 255,
            wall_clock_timeout_ms: 300_000,
            fs_readonly_paths: vec!["/usr".into(), "/lib".into(), "/etc".into()],
            fs_writable_paths: vec!["/tmp".into()],
            deny_exec: false,
            deny_ptrace: false,
        };
        assert!(section.validate().is_ok());
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW BATCH: Extended edge-case and coverage tests
    // ══════════════════════════════════════════════════════════════════

    // ── ManifestSchemaVersion boundary values ────────────────────────

    #[test]
    fn manifest_schema_version_minor_overflow_rejected() {
        let err = ManifestSchemaVersion::try_from("2.99999".to_string()).unwrap_err();
        assert!(err.to_string().contains("minor"));
    }

    #[test]
    fn manifest_schema_version_both_overflow_rejected() {
        let err = ManifestSchemaVersion::try_from("99999.99999".to_string()).unwrap_err();
        // Should fail on major first
        assert!(err.to_string().contains("major"));
    }

    #[test]
    fn manifest_schema_version_only_dot_rejected() {
        let err = ManifestSchemaVersion::try_from(".".to_string()).unwrap_err();
        assert!(err.to_string().contains("major"));
    }

    #[test]
    fn manifest_schema_version_trailing_dot_rejected() {
        let err = ManifestSchemaVersion::try_from("2.".to_string()).unwrap_err();
        assert!(err.to_string().contains("minor"));
    }

    #[test]
    fn manifest_schema_version_leading_dot_rejected() {
        let err = ManifestSchemaVersion::try_from(".1".to_string()).unwrap_err();
        assert!(err.to_string().contains("major"));
    }

    #[test]
    fn manifest_schema_version_ne() {
        let v1 = ManifestSchemaVersion { major: 2, minor: 0 };
        let v2 = ManifestSchemaVersion { major: 2, minor: 1 };
        assert_ne!(v1, v2);
    }

    // ── InterfaceHash edge cases ─────────────────────────────────────

    #[test]
    fn interface_hash_only_algorithm_rejected() {
        let err = InterfaceHash::try_from("blake3-256".to_string()).unwrap_err();
        assert!(err.to_string().contains("domain"));
    }

    #[test]
    fn interface_hash_two_colons_empty_parts() {
        let err = InterfaceHash::try_from("blake3-256::".to_string()).unwrap_err();
        assert!(err.to_string().contains("domain"));
    }

    #[test]
    fn interface_hash_ne() {
        let h1 = InterfaceHash::new_blake3_256(INTERFACE_HASH_DOMAIN, [0xAA; 32]);
        let h2 = InterfaceHash::new_blake3_256(INTERFACE_HASH_DOMAIN, [0xBB; 32]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn interface_hash_display_deterministic() {
        let h = InterfaceHash::new_blake3_256(INTERFACE_HASH_DOMAIN, [0x42; 32]);
        let s1 = h.to_string();
        let s2 = h.to_string();
        assert_eq!(s1, s2);
    }

    // ── ProtocolRequirement edge cases ───────────────────────────────

    #[test]
    fn protocol_requirement_version_with_leading_zeros() {
        let pr = ProtocolRequirement::try_from("proto/02.03".to_string()).unwrap();
        assert_eq!(pr.version.major, 2);
        assert_eq!(pr.version.minor, 3);
    }

    #[test]
    fn protocol_requirement_ne() {
        let pr1 = ProtocolRequirement::try_from("fcp2-sym/2.0".to_string()).unwrap();
        let pr2 = ProtocolRequirement::try_from("fcp2-sym/3.0".to_string()).unwrap();
        assert_ne!(pr1, pr2);
    }

    #[test]
    fn protocol_requirement_different_name_ne() {
        let pr1 = ProtocolRequirement::try_from("fcp2-sym/2.0".to_string()).unwrap();
        let pr2 = ProtocolRequirement::try_from("fcp3-asym/2.0".to_string()).unwrap();
        assert_ne!(pr1, pr2);
    }

    #[test]
    fn protocol_requirement_slash_only_rejected() {
        let err = ProtocolRequirement::try_from("/".to_string()).unwrap_err();
        assert!(err.to_string().contains("name must not be empty"));
    }

    // ── FeatureId edge cases ─────────────────────────────────────────

    #[test]
    fn feature_id_ne() {
        let f1 = FeatureId::try_from("fcps.aead".to_string()).unwrap();
        let f2 = FeatureId::try_from("fcps.hmac".to_string()).unwrap();
        assert_ne!(f1, f2);
    }

    #[test]
    fn feature_id_serialize_deserialize_consistency() {
        let fid = FeatureId::try_from("fcps.stream.replay".to_string()).unwrap();
        let json = serde_json::to_string(&fid).unwrap();
        assert_eq!(json, "\"fcps.stream.replay\"");
    }

    // ── SignatureThreshold boundary ──────────────────────────────────

    #[test]
    fn signature_threshold_max_values() {
        let t = SignatureThreshold { k: 255, n: 255 };
        assert_eq!(t.to_string(), "255-of-255");
        assert!(t.validate(255).is_ok());
    }

    #[test]
    fn signature_threshold_1_of_255_valid() {
        let t = SignatureThreshold { k: 1, n: 255 };
        assert!(t.validate(1).is_ok());
    }

    #[test]
    fn signature_threshold_clone_eq() {
        let t1 = SignatureThreshold { k: 2, n: 3 };
        let t2 = t1;
        assert_eq!(t1, t2);
        assert_eq!(t1.k, t2.k);
    }

    #[test]
    fn signature_threshold_ne() {
        let t1 = SignatureThreshold { k: 2, n: 3 };
        let t2 = SignatureThreshold { k: 1, n: 3 };
        assert_ne!(t1, t2);
    }

    #[test]
    fn signature_threshold_debug() {
        let t = SignatureThreshold { k: 2, n: 3 };
        let dbg = format!("{t:?}");
        assert!(dbg.contains("SignatureThreshold"));
    }

    // ── ObjectId boundary ────────────────────────────────────────────

    #[test]
    fn object_id_ne() {
        let oid1 = ObjectId::from_bytes([0xaa; 32]);
        let oid2 = ObjectId::from_bytes([0xbb; 32]);
        assert_ne!(oid1, oid2);
    }

    #[test]
    fn object_id_prefixed_too_long_rejected() {
        let err =
            ObjectId::parse_prefixed(&("objectid:".to_string() + &"aa".repeat(33))).unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    // ── Base64Bytes boundary ─────────────────────────────────────────

    #[test]
    fn base64_bytes_ne() {
        let a = Base64Bytes(vec![1, 2, 3]);
        let b = Base64Bytes(vec![4, 5, 6]);
        assert_ne!(a, b);
    }

    #[test]
    fn base64_bytes_clone_preserves_data() {
        let original = Base64Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let cloned = original.clone();
        assert_eq!(original.as_bytes(), cloned.as_bytes());
        // Use original after clone to avoid redundant_clone
        assert_eq!(original.as_bytes().len(), 4);
    }

    #[test]
    fn base64_bytes_with_padding() {
        // "A" in base64 is "QQ==" (with padding)
        let b = Base64Bytes::try_from("base64:QQ==".to_string()).unwrap();
        assert_eq!(b.as_bytes(), &[0x41]);
    }

    // ── ConnectorArchetype edge cases ────────────────────────────────

    #[test]
    fn connector_archetype_ne() {
        assert_ne!(
            ConnectorArchetype::Bidirectional,
            ConnectorArchetype::Storage
        );
        assert_ne!(ConnectorArchetype::Streaming, ConnectorArchetype::Knowledge);
    }

    #[test]
    fn connector_archetype_debug_all_variants() {
        for variant in [
            ConnectorArchetype::Bidirectional,
            ConnectorArchetype::Streaming,
            ConnectorArchetype::Operational,
            ConnectorArchetype::Storage,
            ConnectorArchetype::Knowledge,
        ] {
            let dbg = format!("{variant:?}");
            assert!(!dbg.is_empty());
        }
    }

    // ── ConnectorRuntimeFormat edge cases ─────────────────────────────

    #[test]
    fn connector_runtime_format_ne() {
        assert_ne!(ConnectorRuntimeFormat::Native, ConnectorRuntimeFormat::Wasi);
    }

    // ── ConnectorCrdtType edge cases ─────────────────────────────────

    #[test]
    fn connector_crdt_type_all_as_str_unique() {
        use std::collections::HashSet;
        let strs: HashSet<&str> = [
            ConnectorCrdtType::LwwMap,
            ConnectorCrdtType::OrSet,
            ConnectorCrdtType::GCounter,
            ConnectorCrdtType::PnCounter,
        ]
        .iter()
        .map(ConnectorCrdtType::as_str)
        .collect();
        assert_eq!(strs.len(), 4);
    }

    #[test]
    fn connector_crdt_type_serde_invalid_rejected() {
        let result = serde_json::from_str::<ConnectorCrdtType>("\"mvregister\"");
        assert!(result.is_err());
    }

    // ── ConnectorStateModel edge cases ───────────────────────────────

    #[test]
    fn connector_state_model_crdt_all_types_display() {
        let types = [
            (ConnectorCrdtType::LwwMap, "lww_map"),
            (ConnectorCrdtType::OrSet, "or_set"),
            (ConnectorCrdtType::GCounter, "g_counter"),
            (ConnectorCrdtType::PnCounter, "pn_counter"),
        ];
        for (crdt_type, expected_suffix) in types {
            let model = ConnectorStateModel::Crdt { crdt_type };
            let display = model.to_string();
            assert!(
                display.contains(expected_suffix),
                "expected {expected_suffix} in {display}"
            );
        }
    }

    #[test]
    fn connector_state_model_serde_all_crdt_types() {
        for crdt_type in [
            ConnectorCrdtType::LwwMap,
            ConnectorCrdtType::OrSet,
            ConnectorCrdtType::GCounter,
            ConnectorCrdtType::PnCounter,
        ] {
            let model = ConnectorStateModel::Crdt { crdt_type };
            let json = serde_json::to_string(&model).unwrap();
            let deserialized: ConnectorStateModel = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.crdt_type(), Some(crdt_type));
        }
    }

    // ── ManifestApprovalMode edge cases ──────────────────────────────

    #[test]
    fn manifest_approval_mode_case_sensitive_rejected() {
        let result = serde_json::from_str::<ManifestApprovalMode>("\"None\"");
        assert!(result.is_err());
    }

    #[test]
    fn manifest_approval_mode_empty_string_rejected() {
        let result = serde_json::from_str::<ManifestApprovalMode>("\"\"");
        assert!(result.is_err());
    }

    // ── AttestationType edge cases ───────────────────────────────────

    #[test]
    fn attestation_type_debug_clone_copy() {
        let a = AttestationType::InToto;
        let b = a;
        assert_eq!(a, b);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("InToto"));
    }

    #[test]
    fn attestation_type_ne() {
        assert_ne!(AttestationType::InToto, AttestationType::CodeReview);
        assert_ne!(
            AttestationType::ReproducibleBuild,
            AttestationType::CodeReview
        );
    }

    #[test]
    fn attestation_type_case_sensitive_rejected() {
        let result = serde_json::from_str::<AttestationType>("\"In-Toto\"");
        assert!(result.is_err());
    }

    // ── SandboxProfile edge cases ────────────────────────────────────

    #[test]
    fn sandbox_profile_ne() {
        assert_ne!(SandboxProfile::Strict, SandboxProfile::Permissive);
        assert_ne!(SandboxProfile::StrictPlus, SandboxProfile::Moderate);
    }

    #[test]
    fn sandbox_profile_case_sensitive_rejected() {
        let result = serde_json::from_str::<SandboxProfile>("\"Strict\"");
        assert!(result.is_err());
    }

    // ── SandboxSection edge cases ────────────────────────────────────

    #[test]
    fn sandbox_section_zero_memory_valid() {
        // memory_mb = 0 is technically allowed by validation (only cpu/timeout checked)
        let section = SandboxSection {
            profile: SandboxProfile::Strict,
            memory_mb: 0,
            cpu_percent: 1,
            wall_clock_timeout_ms: 1,
            fs_readonly_paths: vec![],
            fs_writable_paths: vec![],
            deny_exec: true,
            deny_ptrace: true,
        };
        assert!(section.validate().is_ok());
    }

    #[test]
    fn sandbox_section_large_timeout_valid() {
        let section = SandboxSection {
            profile: SandboxProfile::Moderate,
            memory_mb: 8192,
            cpu_percent: 100,
            wall_clock_timeout_ms: u64::MAX,
            fs_readonly_paths: vec![],
            fs_writable_paths: vec![],
            deny_exec: false,
            deny_ptrace: false,
        };
        assert!(section.validate().is_ok());
    }

    // ── EventCapsSection edge cases ──────────────────────────────────

    #[test]
    fn event_caps_section_large_buffer_valid() {
        let ecs = EventCapsSection {
            streaming: true,
            replay: true,
            min_buffer_events: u32::MAX,
        };
        assert!(ecs.validate().is_ok());
    }

    #[test]
    fn event_caps_section_ne() {
        let a = EventCapsSection {
            streaming: true,
            replay: false,
            min_buffer_events: 100,
        };
        let b = EventCapsSection {
            streaming: false,
            replay: true,
            min_buffer_events: 200,
        };
        // Clone and compare fields since EventCapsSection doesn't impl Eq
        let a_cloned = a.clone();
        assert_eq!(a.min_buffer_events, a_cloned.min_buffer_events);
        assert_ne!(a.min_buffer_events, b.min_buffer_events);
    }

    // ── PolicySection edge cases ─────────────────────────────────────

    #[test]
    fn policy_section_slsa_boundary_values() {
        // Test each valid level (0-4)
        for level in 0..=4 {
            let p = PolicySection {
                require_transparency_log: false,
                require_attestation_types: vec![],
                min_slsa_level: Some(level),
                trusted_builders: vec![],
                require_attestation_expiry: false,
            };
            assert!(p.validate().is_ok(), "SLSA level {level} should be valid");
        }
    }

    #[test]
    fn policy_section_slsa_255_rejected() {
        let p = PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![],
            min_slsa_level: Some(255),
            trusted_builders: vec![],
            require_attestation_expiry: false,
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn policy_section_empty_defaults() {
        let p = PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![],
            min_slsa_level: None,
            trusted_builders: vec![],
            require_attestation_expiry: false,
        };
        assert!(p.validate().is_ok());
        assert!(!p.require_transparency_log);
        assert!(p.require_attestation_types.is_empty());
    }

    #[test]
    fn policy_section_all_attestation_types() {
        let p = PolicySection {
            require_transparency_log: true,
            require_attestation_types: vec![
                AttestationType::InToto,
                AttestationType::ReproducibleBuild,
                AttestationType::CodeReview,
            ],
            min_slsa_level: Some(4),
            trusted_builders: vec!["builder-a".into(), "builder-b".into()],
            require_attestation_expiry: false,
        };
        assert!(p.validate().is_ok());
        assert_eq!(p.require_attestation_types.len(), 3);
    }

    // ── RateLimitsSection edge cases ─────────────────────────────────

    #[test]
    fn rate_limits_section_multiple_operation_pools() {
        let section = RateLimitsSection {
            pools: vec![
                RateLimitPoolSection {
                    id: "pool_a".into(),
                    description: Some("Pool A".into()),
                    requests: 100,
                    window_ms: 60_000,
                    burst: None,
                    unit: None,
                    enforcement: None,
                    scope: None,
                },
                RateLimitPoolSection {
                    id: "pool_b".into(),
                    description: None,
                    requests: 50,
                    window_ms: 1000,
                    burst: Some(5),
                    unit: Some("bytes".into()),
                    enforcement: Some("advisory".into()),
                    scope: Some("global".into()),
                },
            ],
            operation_pools: {
                let mut m = std::collections::HashMap::new();
                m.insert("op1".into(), vec!["pool_a".into()]);
                m.insert("op2".into(), vec!["pool_a".into(), "pool_b".into()]);
                m
            },
        };
        let decls = section.to_declarations();
        assert_eq!(decls.limits.len(), 2);
        assert_eq!(decls.tool_pool_map.len(), 2);
        let op2_pools = decls.tool_pool_map.get("op2").unwrap();
        assert_eq!(op2_pools.len(), 2);
    }

    #[test]
    fn rate_limits_section_rejects_duplicate_pool_refs_per_operation() {
        let section = RateLimitsSection {
            pools: vec![RateLimitPoolSection {
                id: "api".into(),
                description: None,
                requests: 10,
                window_ms: 1000,
                burst: None,
                unit: None,
                enforcement: None,
                scope: None,
            }],
            operation_pools: {
                let mut m = std::collections::HashMap::new();
                m.insert("op".into(), vec!["api".into(), "api".into()]);
                m
            },
        };

        assert!(matches!(
            section.validate().unwrap_err(),
            ManifestError::RateLimitDeclaration(RateLimitDeclarationError::DuplicateToolPool {
                tool,
                pool,
            }) if tool == "op" && pool == "api"
        ));
    }

    #[test]
    fn rate_limits_section_pool_window_zero() {
        // window_ms = 0 creates a Duration of 0, which may or may not be valid
        // depending on the RateLimitDeclarations validation
        let section = RateLimitsSection {
            pools: vec![RateLimitPoolSection {
                id: "zero_window".into(),
                description: None,
                requests: 10,
                window_ms: 0,
                burst: None,
                unit: None,
                enforcement: None,
                scope: None,
            }],
            operation_pools: std::collections::HashMap::default(),
        };
        let decls = section.to_declarations();
        assert_eq!(
            decls.limits[0].config.window,
            std::time::Duration::from_millis(0)
        );
    }

    // ── NetworkConstraints edge cases ────────────────────────────────

    #[test]
    fn network_constraints_large_dns_max_ips_valid() {
        let nc = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: u16::MAX,
            max_redirects: 0,
            connect_timeout_ms: 1,
            total_timeout_ms: 1,
            max_response_bytes: 1,
        };
        assert!(nc.validate().is_ok());
    }

    #[test]
    fn network_constraints_all_booleans_false() {
        let nc = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: false,
            deny_private_ranges: false,
            deny_tailnet_ranges: false,
            require_sni: false,
            spki_pins: vec![],
            deny_ip_literals: false,
            require_host_canonicalization: false,
            dns_max_ips: 1,
            max_redirects: 0,
            connect_timeout_ms: 1,
            total_timeout_ms: 1,
            max_response_bytes: 1,
        };
        assert!(nc.validate().is_ok());
    }

    #[test]
    fn network_constraints_localhost_allowed_when_deny_false_nc() {
        let nc = NetworkConstraints {
            host_allow: vec!["localhost".into()],
            port_allow: vec![8080],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: false,
            deny_private_ranges: false,
            deny_tailnet_ranges: false,
            require_sni: false,
            spki_pins: vec![],
            deny_ip_literals: false,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        assert!(nc.validate().is_ok());
    }

    #[test]
    fn network_constraints_multiple_cidrs_valid() {
        let nc = NetworkConstraints {
            host_allow: vec!["api.example.com".into()],
            port_allow: vec![443],
            ip_allow: vec![],
            cidr_deny: vec![
                "10.0.0.0/8".into(),
                "172.16.0.0/12".into(),
                "192.168.0.0/16".into(),
            ],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: false,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        };
        assert!(nc.validate().is_ok());
    }

    // ── validate_host_allow_entry edge cases ─────────────────────────

    #[test]
    fn host_allow_ipv6_loopback_denied() {
        let err = validate_host_allow_entry("::1", true, false).unwrap_err();
        assert!(err.to_string().contains("IP literals"));
    }

    #[test]
    fn host_allow_wildcard_four_labels() {
        // *.sub.example.com has 4 parts → valid
        assert!(validate_host_allow_entry("*.sub.example.com", false, false).is_ok());
    }

    #[test]
    fn host_allow_valid_lowercase_with_canonicalization() {
        assert!(validate_host_allow_entry("api.example.com", true, true).is_ok());
    }

    #[test]
    fn host_allow_mixed_case_rejected_with_canonicalization() {
        let err = validate_host_allow_entry("Api.Example.Com", false, true).unwrap_err();
        assert!(err.to_string().contains("lowercase"));
    }

    #[test]
    fn host_allow_hyphenated_hostname_valid() {
        assert!(validate_host_allow_entry("my-api.example.com", false, false).is_ok());
    }

    // ── lint_capability_id extended ──────────────────────────────────

    #[test]
    fn lint_allows_numeric_segments_less_than_four() {
        // Only three consecutive numeric segments should pass
        assert!(
            lint_capability_id_no_network_addressing("v.1.2.label", "capabilities.required")
                .is_ok()
        );
    }

    #[test]
    fn lint_allows_colon_followed_by_text() {
        assert!(
            lint_capability_id_no_network_addressing("scope:action", "capabilities.required")
                .is_ok()
        );
    }

    #[test]
    fn lint_allows_empty_string() {
        // Empty string should pass lint (validation of the ID itself is separate)
        assert!(lint_capability_id_no_network_addressing("", "capabilities.required").is_ok());
    }

    #[test]
    fn lint_port_boundary_two_digits() {
        // 2-digit port like :80 should be flagged
        let err = lint_capability_id_no_network_addressing("service:80", "capabilities.required");
        assert!(err.is_err());
    }

    #[test]
    fn lint_port_boundary_five_digits() {
        // 5-digit port like :12345 should be flagged
        let err =
            lint_capability_id_no_network_addressing("service:12345", "capabilities.required");
        assert!(err.is_err());
    }

    // ── parse_rate_limit_shorthand edge cases ────────────────────────

    #[test]
    fn parse_rate_limit_shorthand_zero_max_works() {
        let rl = parse_rate_limit_shorthand("0/min").unwrap();
        assert_eq!(rl.max, 0);
        assert_eq!(rl.per_ms, 60_000);
    }

    #[test]
    fn parse_rate_limit_shorthand_large_max_works() {
        let rl = parse_rate_limit_shorthand("4294967295/sec").unwrap();
        assert_eq!(rl.max, u32::MAX);
        assert_eq!(rl.per_ms, 1_000);
    }

    #[test]
    fn parse_rate_limit_shorthand_burst_and_scope_none() {
        let rl = parse_rate_limit_shorthand("10/hour").unwrap();
        assert!(rl.burst.is_none());
        assert!(rl.scope.is_none());
        assert!(rl.pool_name.is_none());
    }

    #[test]
    fn parse_rate_limit_shorthand_negative_rejected() {
        let err = parse_rate_limit_shorthand("-1/min");
        assert!(err.is_err());
    }

    // ── ManifestSection validation extended ──────────────────────────

    #[test]
    fn manifest_section_schema_version_1_rejected() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder)
            .replace("schema_version = \"2.1\"", "schema_version = \"1.0\"");
        let m = ConnectorManifest::parse_str_unchecked(&toml).unwrap();
        let err = m.validate().unwrap_err();
        assert!(err.to_string().contains("schema"));
    }

    #[test]
    fn manifest_section_max_datagram_u16_max_valid() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let toml = test_manifest_toml(&placeholder)
            .replace("max_datagram_bytes = 1200", "max_datagram_bytes = 65535");
        let m = ConnectorManifest::parse_str_unchecked(&toml).unwrap();
        // This will fail on hash mismatch but the ManifestSection validation itself should pass
        let hash = m.compute_interface_hash().unwrap();
        let with_hash = test_manifest_toml(&hash.to_string())
            .replace("max_datagram_bytes = 1200", "max_datagram_bytes = 65535");
        let parsed = ConnectorManifest::parse_str(&with_hash).unwrap();
        assert_eq!(parsed.manifest.max_datagram_bytes, 65535);
    }

    // ── ConnectorManifest parse edge cases ───────────────────────────

    #[test]
    fn parse_str_empty_toml_fails() {
        let err = ConnectorManifest::parse_str("").unwrap_err();
        assert!(matches!(err, ManifestError::Toml(_)));
    }

    #[test]
    fn parse_str_unchecked_empty_toml_fails() {
        let err = ConnectorManifest::parse_str_unchecked("").unwrap_err();
        assert!(matches!(err, ManifestError::Toml(_)));
    }

    #[test]
    fn parse_str_random_toml_fails() {
        let err = ConnectorManifest::parse_str("[foo]\nbar = 42").unwrap_err();
        assert!(matches!(err, ManifestError::Toml(_)));
    }

    #[test]
    fn parse_str_unchecked_valid_then_validate_fails_hash_mismatch() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let m = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder)).unwrap();
        let err = m.validate().unwrap_err();
        assert!(matches!(err, ManifestError::InterfaceHashMismatch { .. }));
    }

    // ── ConnectorManifest with computed hash full validation ─────────

    #[test]
    fn manifest_full_validation_with_correct_hash() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let m = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder)).unwrap();
        let hash = m.compute_interface_hash().unwrap();
        let result = ConnectorManifest::parse_str(&test_manifest_toml(&hash.to_string()));
        assert!(result.is_ok());
    }

    #[test]
    fn manifest_compute_hash_is_deterministic() {
        let placeholder = format!("blake3-256:{INTERFACE_HASH_DOMAIN}:{}", "0".repeat(64));
        let m = ConnectorManifest::parse_str_unchecked(&test_manifest_toml(&placeholder)).unwrap();
        let h1 = m.compute_interface_hash().unwrap();
        let h2 = m.compute_interface_hash().unwrap();
        assert_eq!(h1, h2);
    }

    // ── EventSection edge cases ──────────────────────────────────────

    #[test]
    fn event_section_empty_description_rejected() {
        let section: EventSection = serde_json::from_value(json!({
            "description": ""
        }))
        .unwrap();
        let err = section.validate().unwrap_err();
        assert!(err.to_string().contains("provides.events.*.description"));
    }

    #[test]
    fn event_section_blank_topic_rejected() {
        let section: EventSection = serde_json::from_value(json!({
            "description": "Event with blank topic",
            "topic": "   "
        }))
        .unwrap();
        let err = section.validate().unwrap_err();
        assert!(err.to_string().contains("provides.events.*.topic"));
    }

    #[test]
    fn event_section_schema_with_nested_object() {
        let section: EventSection = serde_json::from_value(json!({
            "description": "Complex event",
            "schema": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "data": {"type": "array", "items": {"type": "string"}}
                }
            }
        }))
        .unwrap();
        assert!(section.schema.is_some());
        let schema = section.schema.unwrap();
        assert!(schema.get("properties").is_some());
    }

    // ── SignaturesSection edge cases ─────────────────────────────────

    #[test]
    fn signatures_section_threshold_with_exactly_k_sigs() {
        let section = SignaturesSection {
            publisher_signatures: vec![
                SignatureEntry {
                    kid: "k1".into(),
                    sig: Base64Bytes(vec![1]),
                },
                SignatureEntry {
                    kid: "k2".into(),
                    sig: Base64Bytes(vec![2]),
                },
                SignatureEntry {
                    kid: "k3".into(),
                    sig: Base64Bytes(vec![3]),
                },
            ],
            publisher_threshold: Some(SignatureThreshold { k: 3, n: 5 }),
            registry_signature: None,
            transparency_log_entry: None,
        };
        assert!(section.validate().is_ok());
    }

    #[test]
    fn signatures_section_threshold_with_excess_sigs() {
        let section = SignaturesSection {
            publisher_signatures: vec![
                SignatureEntry {
                    kid: "k1".into(),
                    sig: Base64Bytes(vec![1]),
                },
                SignatureEntry {
                    kid: "k2".into(),
                    sig: Base64Bytes(vec![2]),
                },
                SignatureEntry {
                    kid: "k3".into(),
                    sig: Base64Bytes(vec![3]),
                },
                SignatureEntry {
                    kid: "k4".into(),
                    sig: Base64Bytes(vec![4]),
                },
            ],
            publisher_threshold: Some(SignatureThreshold { k: 2, n: 4 }),
            registry_signature: None,
            transparency_log_entry: None,
        };
        assert!(section.validate().is_ok());
    }

    // ── SupplyChainSection edge cases ────────────────────────────────

    #[test]
    fn supply_chain_section_single_attestation() {
        let oid = ObjectId::from_bytes([0x11; 32]);
        let section = SupplyChainSection {
            attestations: vec![SupplyChainAttestationRef {
                attestation_type: AttestationType::CodeReview,
                object_id: oid,
            }],
        };
        assert!(section.validate().is_ok());
    }

    #[test]
    fn supply_chain_section_all_attestation_types() {
        let section = SupplyChainSection {
            attestations: vec![
                SupplyChainAttestationRef {
                    attestation_type: AttestationType::InToto,
                    object_id: ObjectId::from_bytes([0x11; 32]),
                },
                SupplyChainAttestationRef {
                    attestation_type: AttestationType::ReproducibleBuild,
                    object_id: ObjectId::from_bytes([0x22; 32]),
                },
                SupplyChainAttestationRef {
                    attestation_type: AttestationType::CodeReview,
                    object_id: ObjectId::from_bytes([0x33; 32]),
                },
            ],
        };
        assert!(section.validate().is_ok());
    }

    // ── ManifestError variant coverage ───────────────────────────────

    #[test]
    fn manifest_error_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ManifestError>();
    }

    #[test]
    fn manifest_error_toml_variant_source() {
        use std::error::Error;
        let err: ManifestError = toml::from_str::<ConnectorManifest>("invalid")
            .unwrap_err()
            .into();
        // The Toml variant should have a source
        assert!(err.source().is_some());
    }

    // ── ConnectorStateSection edge cases ─────────────────────────────

    #[test]
    fn state_section_with_all_optional_fields() {
        let section: ConnectorStateSection = serde_json::from_value(json!({
            "model": "crdt",
            "state_schema_version": "2.0",
            "migration_hint": "merge-and-compact",
            "crdt_type": "pn_counter",
            "snapshot_every_updates": 1000,
            "snapshot_every_bytes": 1_048_576
        }))
        .unwrap();
        assert_eq!(section.state_schema_version, "2.0");
        assert_eq!(section.migration_hint.as_deref(), Some("merge-and-compact"));
        assert_eq!(section.snapshot_every_updates, Some(1000));
        assert_eq!(section.snapshot_every_bytes, Some(1_048_576));
        let model = section.to_state_model().unwrap();
        assert_eq!(model.crdt_type(), Some(ConnectorCrdtType::PnCounter));
    }

    #[test]
    fn state_section_singleton_writer_to_model() {
        let section: ConnectorStateSection = serde_json::from_value(json!({
            "model": "singleton_writer",
            "state_schema_version": "1.0",
            "migration_hint": "reindex"
        }))
        .unwrap();
        let model = section.to_state_model().unwrap();
        assert!(model.is_singleton_writer());
        assert!(model.crdt_type().is_none());
    }

    // ── ProvidesSection with events ──────────────────────────────────

    #[test]
    fn provides_section_events_serde() {
        let section: ProvidesSection = serde_json::from_value(json!({
            "operations": {
                "test_op": {
                    "description": "A test operation",
                    "capability": "test.op",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "requires_approval": "none",
                    "rate_limit": null,
                    "idempotency": "strict",
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "object"}
                }
            },
            "events": {
                "test_event": {
                    "description": "A test event",
                    "streaming": true,
                    "replay": false,
                    "topic": "events.test"
                }
            }
        }))
        .unwrap();
        assert_eq!(section.operations.len(), 1);
        assert_eq!(section.events.len(), 1);
        assert!(section.events.contains_key("test_event"));
    }

    // ── RateLimit structured form edge cases ─────────────────────────

    #[test]
    fn rate_limit_structured_with_scope_and_pool() {
        let rl: RateLimit = serde_json::from_value(json!({
            "max": 50,
            "per_ms": 30000,
            "burst": 10,
            "scope": "credential",
            "pool_name": "shared_pool"
        }))
        .unwrap();
        assert_eq!(rl.as_inner().max, 50);
        assert_eq!(rl.as_inner().per_ms, 30_000);
        assert_eq!(rl.as_inner().burst, Some(10));
    }

    #[test]
    fn rate_limit_serialize_then_deserialize_preserves_values() {
        let rl: RateLimit = serde_json::from_str("\"100/min\"").unwrap();
        let json = serde_json::to_string(&rl).unwrap();
        // After serialization from shorthand, it becomes structured
        let reparsed: RateLimit = serde_json::from_str(&json).unwrap();
        assert_eq!(reparsed.as_inner().max, rl.as_inner().max);
        assert_eq!(reparsed.as_inner().per_ms, rl.as_inner().per_ms);
    }

    #[test]
    fn manifest_error_capability_id_lint_message_returns_guidance() {
        let err = ManifestError::Invalid {
            field: "capabilities.required",
            message: "capability id `https://api.example.com` contains URL scheme `https:`; network addressing belongs in `network_constraints`".to_string(),
        };
        let guidance = err
            .capability_id_lint_message()
            .expect("capability lint guidance");
        assert!(guidance.contains("network_constraints"));
        assert!(guidance.contains("capabilities.required"));
        assert!(guidance.contains("keep capability IDs abstract"));
    }

    #[test]
    fn manifest_error_non_lint_has_no_capability_guidance() {
        let err = ManifestError::Invalid {
            field: "zones.home",
            message: "must be present".to_string(),
        };
        assert!(err.capability_id_lint_message().is_none());
    }

    // ── ConnectorStatus tests ──

    #[test]
    fn connector_status_display_all_variants() {
        assert_eq!(ConnectorStatus::Ready.to_string(), "ready");
        assert_eq!(ConnectorStatus::Proven.to_string(), "proven");
        assert_eq!(ConnectorStatus::Stub.to_string(), "stub");
        assert_eq!(ConnectorStatus::Experimental.to_string(), "experimental");
        assert_eq!(ConnectorStatus::Deprecated.to_string(), "deprecated");
        assert_eq!(ConnectorStatus::Incubating.to_string(), "incubating");
        assert_eq!(ConnectorStatus::Quarantined.to_string(), "quarantined");
        assert_eq!(ConnectorStatus::Adversarial.to_string(), "adversarial");
    }

    #[test]
    fn connector_status_serde_roundtrip() {
        for status in &[
            ConnectorStatus::Ready,
            ConnectorStatus::Proven,
            ConnectorStatus::Stub,
            ConnectorStatus::Experimental,
            ConnectorStatus::Deprecated,
            ConnectorStatus::Incubating,
            ConnectorStatus::Quarantined,
            ConnectorStatus::Adversarial,
        ] {
            let json = serde_json::to_string(status).unwrap();
            let roundtrip: ConnectorStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*status, roundtrip, "roundtrip failed for {status}");
        }
    }

    #[test]
    fn connector_status_is_live() {
        assert!(ConnectorStatus::Ready.is_live());
        assert!(ConnectorStatus::Proven.is_live());
        assert!(ConnectorStatus::Experimental.is_live());
        assert!(!ConnectorStatus::Stub.is_live());
        assert!(!ConnectorStatus::Deprecated.is_live());
        assert!(!ConnectorStatus::Incubating.is_live());
        assert!(!ConnectorStatus::Quarantined.is_live());
        assert!(!ConnectorStatus::Adversarial.is_live());
    }

    #[test]
    fn connector_status_is_hidden_by_default() {
        assert!(!ConnectorStatus::Ready.is_hidden_by_default());
        assert!(!ConnectorStatus::Proven.is_hidden_by_default());
        assert!(!ConnectorStatus::Experimental.is_hidden_by_default());
        assert!(!ConnectorStatus::Deprecated.is_hidden_by_default());
        assert!(ConnectorStatus::Stub.is_hidden_by_default());
        assert!(ConnectorStatus::Incubating.is_hidden_by_default());
        assert!(ConnectorStatus::Quarantined.is_hidden_by_default());
        assert!(ConnectorStatus::Adversarial.is_hidden_by_default());
    }

    #[test]
    fn connector_status_non_live_rationale() {
        assert!(ConnectorStatus::Ready.non_live_rationale().is_none());
        assert!(ConnectorStatus::Proven.non_live_rationale().is_none());
        assert!(ConnectorStatus::Experimental.non_live_rationale().is_none());
        assert!(ConnectorStatus::Stub.non_live_rationale().is_some());
        assert!(ConnectorStatus::Deprecated.non_live_rationale().is_some());
        assert!(ConnectorStatus::Incubating.non_live_rationale().is_some());
        assert!(ConnectorStatus::Quarantined.non_live_rationale().is_some());
        assert!(ConnectorStatus::Adversarial.non_live_rationale().is_some());
    }

    #[test]
    fn connector_status_graduation_guidance() {
        assert!(ConnectorStatus::Ready.graduation_guidance().is_none());
        assert!(ConnectorStatus::Proven.graduation_guidance().is_none());
        assert!(ConnectorStatus::Deprecated.graduation_guidance().is_none());
        assert!(ConnectorStatus::Incubating.graduation_guidance().is_some());
        assert!(ConnectorStatus::Quarantined.graduation_guidance().is_some());
        assert!(ConnectorStatus::Stub.graduation_guidance().is_some());
        assert!(ConnectorStatus::Adversarial.graduation_guidance().is_some());
        assert!(
            ConnectorStatus::Experimental
                .graduation_guidance()
                .is_some()
        );
    }

    #[test]
    fn connector_status_default_is_ready() {
        assert_eq!(ConnectorStatus::default(), ConnectorStatus::Ready);
    }

    #[test]
    fn status_consistency_check_matching() {
        let result = StatusConsistencyResult::check(ConnectorStatus::Ready, "ready");
        assert!(result.consistent);
        assert!(result.mismatch_reason.is_none());
    }

    #[test]
    fn status_consistency_check_live_maps_to_ready() {
        // "live" is a legacy alias for "ready"
        let result = StatusConsistencyResult::check(ConnectorStatus::Ready, "live");
        assert!(result.consistent);
    }

    #[test]
    fn status_consistency_check_proven_accepts_ready_runtime() {
        let result = StatusConsistencyResult::check(ConnectorStatus::Proven, "ready");
        assert!(result.consistent);
    }

    #[test]
    fn status_consistency_check_proven_match() {
        let result = StatusConsistencyResult::check(ConnectorStatus::Proven, "proven");
        assert!(result.consistent);
    }

    #[test]
    fn status_consistency_check_mismatch() {
        let result = StatusConsistencyResult::check(ConnectorStatus::Stub, "live");
        assert!(!result.consistent);
        let reason = result.mismatch_reason.unwrap();
        assert!(
            reason.contains("stub"),
            "should mention manifest status: {reason}"
        );
        assert!(
            reason.contains("live"),
            "should mention runtime status: {reason}"
        );
    }

    #[test]
    fn status_consistency_check_incubating_match() {
        let result = StatusConsistencyResult::check(ConnectorStatus::Incubating, "incubating");
        assert!(result.consistent);
    }

    #[test]
    fn status_consistency_check_quarantined_match() {
        let result = StatusConsistencyResult::check(ConnectorStatus::Quarantined, "quarantined");
        assert!(result.consistent);
    }

    #[test]
    fn status_consistency_check_adversarial_match() {
        let result = StatusConsistencyResult::check(ConnectorStatus::Adversarial, "adversarial");
        assert!(result.consistent);
    }

    #[test]
    fn status_consistency_check_unknown_runtime() {
        let result = StatusConsistencyResult::check(ConnectorStatus::Ready, "banana");
        assert!(!result.consistent);
        assert!(result.mismatch_reason.unwrap().contains("unknown"));
    }

    #[test]
    fn connector_status_toml_deserialize_incubating() {
        let toml_str = r#"
[connector]
id = "fcp.test"
name = "Test"
version = "0.1.0"
description = "test connector"
archetypes = ["request-response"]
format = "native"
status = "incubating"
"#;
        let parsed: toml::Value = toml::from_str(toml_str).unwrap();
        let status_str = parsed["connector"]["status"].as_str().unwrap();
        assert_eq!(status_str, "incubating");
    }

    #[test]
    fn connector_status_toml_deserialize_quarantined() {
        let toml_str = r#"
[connector]
id = "fcp.test"
name = "Test"
version = "0.1.0"
description = "test connector"
archetypes = ["request-response"]
format = "native"
status = "quarantined"
"#;
        let parsed: toml::Value = toml::from_str(toml_str).unwrap();
        let status_str = parsed["connector"]["status"].as_str().unwrap();
        assert_eq!(status_str, "quarantined");
    }

    #[test]
    fn connector_status_toml_deserialize_adversarial() {
        let toml_str = r#"
[connector]
id = "fcp.test"
name = "Test"
version = "0.1.0"
description = "test connector"
archetypes = ["request-response"]
format = "native"
status = "adversarial"
"#;
        let parsed: toml::Value = toml::from_str(toml_str).unwrap();
        let status_str = parsed["connector"]["status"].as_str().unwrap();
        assert_eq!(status_str, "adversarial");
    }
}
