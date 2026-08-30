//! Device posture attestation for FCP2 policy enforcement.
//!
//! This module provides:
//! - [`PostureAttestation`] - Signed device posture claims from a trusted verifier
//! - [`PostureAttributeKey`] - Individual posture attributes (OS version, disk encryption, etc.)
//! - [`PostureRequirement`] - Policy-level requirements for device posture
//!
//! # Overview
//!
//! Device Posture Attestation proves that a device has been verified to meet certain
//! posture requirements at a point in time. This is distinct from
//! [`NodeKeyAttestation`](fcp-tailscale) which binds node identity to keys.
//!
//! # Example
//!
//! ```rust
//! use fcp_core::{PostureAttestation, PostureAttributeKey, PostureRequirements};
//!
//! // Create posture requirements for a zone
//! let requirements = PostureRequirements::builder()
//!     .require_disk_encryption(true)
//!     .require_os_min_version("14.0")
//!     .build();
//!
//! // Verify an attestation meets requirements
//! // (attestation would come from a trusted verifier)
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt};

use crate::NodeId;
use crate::object::ObjectId;

// ─────────────────────────────────────────────────────────────────────────────
// Posture Attributes
// ─────────────────────────────────────────────────────────────────────────────

/// Individual posture attribute types.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureAttributeKey {
    /// Operating system type (e.g., "macos", "windows", "linux").
    OsType,
    /// Operating system version (e.g., "14.2.1").
    OsVersion,
    /// Whether disk encryption is enabled.
    DiskEncryption,
    /// Whether firewall is enabled.
    FirewallEnabled,
    /// Whether screen lock is enabled.
    ScreenLockEnabled,
    /// Screen lock timeout in seconds.
    ScreenLockTimeout,
    /// Whether antivirus is installed and active.
    AntivirusActive,
    /// Whether the device is managed (MDM enrolled).
    DeviceManaged,
    /// Whether secure boot is enabled.
    SecureBootEnabled,
    /// Whether the device has a TPM/Secure Enclave.
    TpmPresent,
    /// Custom attribute (for extensibility).
    Custom(String),
}

impl PostureAttributeKey {
    /// Get the string representation of this key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::OsType => "os_type",
            Self::OsVersion => "os_version",
            Self::DiskEncryption => "disk_encryption",
            Self::FirewallEnabled => "firewall_enabled",
            Self::ScreenLockEnabled => "screen_lock_enabled",
            Self::ScreenLockTimeout => "screen_lock_timeout",
            Self::AntivirusActive => "antivirus_active",
            Self::DeviceManaged => "device_managed",
            Self::SecureBootEnabled => "secure_boot_enabled",
            Self::TpmPresent => "tpm_present",
            Self::Custom(s) => s.as_str(),
        }
    }
}

/// A posture attribute value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PostureAttributeValue {
    /// Boolean value (e.g., `disk_encryption`: true).
    Bool(bool),
    /// String value (e.g., `os_version`: "14.2.1").
    String(String),
    /// Numeric value (e.g., `screen_lock_timeout`: 300).
    Number(i64),
}

impl PostureAttributeValue {
    /// Get as boolean if this is a bool value.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Get as string if this is a string value.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Get as number if this is a numeric value.
    #[must_use]
    pub const fn as_number(&self) -> Option<i64> {
        match self {
            Self::Number(n) => Some(*n),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Posture Attestation
// ─────────────────────────────────────────────────────────────────────────────

/// Signed device posture attestation from a trusted verifier.
///
/// This attestation proves that a device has been verified to meet certain
/// posture requirements at a point in time. The attestation is signed by
/// a trusted posture verifier (e.g., MDM, endpoint agent, or Tailscale).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureAttestation {
    /// Schema identifier for this attestation format.
    pub schema: String,

    /// Unique identifier for this attestation.
    pub attestation_id: String,

    /// Node ID of the device being attested.
    pub node_id: NodeId,

    /// Posture attributes collected from the device.
    pub attributes: HashMap<PostureAttributeKey, PostureAttributeValue>,

    /// When this attestation was issued.
    pub issued_at: DateTime<Utc>,

    /// When this attestation expires.
    pub expires_at: DateTime<Utc>,

    /// Identity of the verifier that issued this attestation.
    pub verifier_id: String,

    /// Signature over the attestation payload (base64-encoded).
    pub signature: String,

    /// Key ID of the verifier key that signed this attestation.
    pub verifier_kid: String,
}

impl PostureAttestation {
    /// Schema identifier for FCP posture attestations.
    pub const SCHEMA: &'static str = "fcp.posture.v1";

    /// Check if this attestation has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at <= Utc::now()
    }

    /// Check if this attestation has expired at a specific time.
    #[must_use]
    pub fn is_expired_at(&self, now_ms: u64) -> bool {
        let now_i64 = i64::try_from(now_ms).unwrap_or(i64::MAX);
        self.expires_at.timestamp_millis() <= now_i64
    }

    /// Check if this attestation is valid (not expired and has correct schema).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && self.schema == Self::SCHEMA
    }

    /// Check if this attestation is for the specified node.
    #[must_use]
    pub fn is_for_node(&self, node_id: &NodeId) -> bool {
        self.node_id == *node_id
    }

    /// Get an attribute value.
    #[must_use]
    pub fn get_attribute(&self, key: &PostureAttributeKey) -> Option<&PostureAttributeValue> {
        self.attributes.get(key)
    }

    /// Check if disk encryption is enabled according to this attestation.
    #[must_use]
    pub fn disk_encryption_enabled(&self) -> Option<bool> {
        self.get_attribute(&PostureAttributeKey::DiskEncryption)
            .and_then(PostureAttributeValue::as_bool)
    }

    /// Get the OS version from this attestation.
    #[must_use]
    pub fn os_version(&self) -> Option<&str> {
        self.get_attribute(&PostureAttributeKey::OsVersion)
            .and_then(PostureAttributeValue::as_str)
    }

    /// Get the OS type from this attestation.
    #[must_use]
    pub fn os_type(&self) -> Option<&str> {
        self.get_attribute(&PostureAttributeKey::OsType)
            .and_then(PostureAttributeValue::as_str)
    }

    /// Get the remaining validity duration.
    #[must_use]
    pub fn remaining_validity(&self) -> chrono::Duration {
        self.expires_at - Utc::now()
    }

    /// Generate an object ID for this attestation (content-addressed).
    #[must_use]
    pub fn object_id(&self) -> ObjectId {
        ObjectId::from_unscoped_bytes(self.attestation_id.as_bytes())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Posture Requirements
// ─────────────────────────────────────────────────────────────────────────────

/// A single posture requirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PostureRequirement {
    /// Require a boolean attribute to be true.
    RequireTrue {
        /// The attribute that must be true.
        attribute: PostureAttributeKey,
    },
    /// Require a boolean attribute to be false.
    RequireFalse {
        /// The attribute that must be false.
        attribute: PostureAttributeKey,
    },
    /// Require a string attribute to match exactly.
    RequireEqual {
        /// The attribute to check.
        attribute: PostureAttributeKey,
        /// The expected value.
        value: String,
    },
    /// Require a string attribute to be in a list of allowed values.
    RequireOneOf {
        /// The attribute to check.
        attribute: PostureAttributeKey,
        /// Allowed values.
        values: Vec<String>,
    },
    /// Require a version attribute to be at least a minimum version.
    RequireMinVersion {
        /// The attribute to check.
        attribute: PostureAttributeKey,
        /// Minimum version (semver or simple numeric comparison).
        min_version: String,
    },
    /// Require a numeric attribute to be at least a minimum value.
    RequireMinValue {
        /// The attribute to check.
        attribute: PostureAttributeKey,
        /// Minimum value.
        min_value: i64,
    },
    /// Require a numeric attribute to be at most a maximum value.
    RequireMaxValue {
        /// The attribute to check.
        attribute: PostureAttributeKey,
        /// Maximum value.
        max_value: i64,
    },
}

impl PostureRequirement {
    /// Return the canonical requirement-kind display and serde tag.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RequireTrue { .. } => "require_true",
            Self::RequireFalse { .. } => "require_false",
            Self::RequireEqual { .. } => "require_equal",
            Self::RequireOneOf { .. } => "require_one_of",
            Self::RequireMinVersion { .. } => "require_min_version",
            Self::RequireMinValue { .. } => "require_min_value",
            Self::RequireMaxValue { .. } => "require_max_value",
        }
    }

    /// Check if an attestation satisfies this requirement.
    #[must_use]
    pub fn is_satisfied_by(&self, attestation: &PostureAttestation) -> bool {
        match self {
            Self::RequireTrue { attribute } => attestation
                .get_attribute(attribute)
                .and_then(PostureAttributeValue::as_bool)
                .unwrap_or(false),

            Self::RequireFalse { attribute } => attestation
                .get_attribute(attribute)
                .and_then(PostureAttributeValue::as_bool)
                .is_none_or(|v| !v),

            Self::RequireEqual { attribute, value } => attestation
                .get_attribute(attribute)
                .and_then(PostureAttributeValue::as_str)
                .is_some_and(|v| v == value),

            Self::RequireOneOf { attribute, values } => attestation
                .get_attribute(attribute)
                .and_then(PostureAttributeValue::as_str)
                .is_some_and(|v| values.iter().any(|allowed| allowed == v)),

            Self::RequireMinVersion {
                attribute,
                min_version,
            } => attestation
                .get_attribute(attribute)
                .and_then(PostureAttributeValue::as_str)
                .is_some_and(|v| version_gte(v, min_version)),

            Self::RequireMinValue {
                attribute,
                min_value,
            } => attestation
                .get_attribute(attribute)
                .and_then(PostureAttributeValue::as_number)
                .is_some_and(|v| v >= *min_value),

            Self::RequireMaxValue {
                attribute,
                max_value,
            } => attestation
                .get_attribute(attribute)
                .and_then(PostureAttributeValue::as_number)
                .is_some_and(|v| v <= *max_value),
        }
    }

    /// Get the attribute this requirement applies to.
    #[must_use]
    pub const fn attribute(&self) -> &PostureAttributeKey {
        match self {
            Self::RequireTrue { attribute }
            | Self::RequireFalse { attribute }
            | Self::RequireEqual { attribute, .. }
            | Self::RequireOneOf { attribute, .. }
            | Self::RequireMinVersion { attribute, .. }
            | Self::RequireMinValue { attribute, .. }
            | Self::RequireMaxValue { attribute, .. } => attribute,
        }
    }
}

impl fmt::Display for PostureRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Collection of posture requirements for a zone policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PostureRequirements {
    /// List of requirements that must all be satisfied.
    pub requirements: Vec<PostureRequirement>,

    /// Maximum age of attestation in seconds (default: 24 hours).
    #[serde(default = "default_max_attestation_age")]
    pub max_attestation_age_secs: u64,

    /// Allowed verifier IDs (empty means any verifier is allowed).
    #[serde(default)]
    pub allowed_verifiers: Vec<String>,
}

const fn default_max_attestation_age() -> u64 {
    86400 // 24 hours
}

impl PostureRequirements {
    /// Create a new builder for posture requirements.
    #[must_use]
    pub fn builder() -> PostureRequirementsBuilder {
        PostureRequirementsBuilder::default()
    }

    /// Check if an attestation satisfies all requirements.
    #[must_use]
    pub fn is_satisfied_by(&self, attestation: &PostureAttestation) -> PostureCheckResult {
        self.is_satisfied_by_at(
            attestation,
            Utc::now().timestamp_millis().try_into().unwrap_or(0),
        )
    }

    /// Check if an attestation satisfies all requirements at a specific time.
    #[must_use]
    pub fn is_satisfied_by_at(
        &self,
        attestation: &PostureAttestation,
        now_ms: u64,
    ) -> PostureCheckResult {
        // Check attestation is valid
        if attestation.is_expired_at(now_ms) {
            return PostureCheckResult::AttestationExpired;
        }

        // Check attestation age
        let now_i64 = i64::try_from(now_ms).unwrap_or(i64::MAX);
        let now_dt = chrono::DateTime::from_timestamp_millis(now_i64).unwrap_or_else(Utc::now);
        let age_secs = (now_dt - attestation.issued_at).num_seconds();
        let max_age = i64::try_from(self.max_attestation_age_secs).unwrap_or(i64::MAX);
        if age_secs < 0 || age_secs > max_age {
            return PostureCheckResult::AttestationTooOld;
        }

        // Check verifier is allowed
        if !self.allowed_verifiers.is_empty()
            && !self.allowed_verifiers.contains(&attestation.verifier_id)
        {
            return PostureCheckResult::VerifierNotAllowed;
        }

        // Check all requirements
        for requirement in &self.requirements {
            if !requirement.is_satisfied_by(attestation) {
                return PostureCheckResult::RequirementNotMet {
                    attribute: requirement.attribute().clone(),
                };
            }
        }

        PostureCheckResult::Satisfied
    }

    /// Check if this requirements set is empty (no requirements).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.requirements.is_empty()
    }
}

/// Result of checking posture requirements against an attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostureCheckResult {
    /// All requirements are satisfied.
    Satisfied,
    /// Attestation has expired.
    AttestationExpired,
    /// Attestation is too old.
    AttestationTooOld,
    /// Verifier is not in the allowed list.
    VerifierNotAllowed,
    /// A specific requirement was not met.
    RequirementNotMet {
        /// The attribute that failed.
        attribute: PostureAttributeKey,
    },
}

impl PostureCheckResult {
    /// Check if the result indicates satisfaction.
    #[must_use]
    pub const fn is_satisfied(&self) -> bool {
        matches!(self, Self::Satisfied)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Builder
// ─────────────────────────────────────────────────────────────────────────────

/// Builder for [`PostureRequirements`].
#[derive(Debug, Default)]
pub struct PostureRequirementsBuilder {
    requirements: Vec<PostureRequirement>,
    max_attestation_age_secs: Option<u64>,
    allowed_verifiers: Vec<String>,
}

impl PostureRequirementsBuilder {
    /// Require disk encryption to be enabled.
    #[must_use]
    pub fn require_disk_encryption(mut self, required: bool) -> Self {
        if required {
            self.requirements.push(PostureRequirement::RequireTrue {
                attribute: PostureAttributeKey::DiskEncryption,
            });
        }
        self
    }

    /// Require firewall to be enabled.
    #[must_use]
    pub fn require_firewall(mut self, required: bool) -> Self {
        if required {
            self.requirements.push(PostureRequirement::RequireTrue {
                attribute: PostureAttributeKey::FirewallEnabled,
            });
        }
        self
    }

    /// Require screen lock to be enabled.
    #[must_use]
    pub fn require_screen_lock(mut self, required: bool) -> Self {
        if required {
            self.requirements.push(PostureRequirement::RequireTrue {
                attribute: PostureAttributeKey::ScreenLockEnabled,
            });
        }
        self
    }

    /// Require a minimum OS version.
    #[must_use]
    pub fn require_os_min_version(mut self, min_version: impl Into<String>) -> Self {
        self.requirements
            .push(PostureRequirement::RequireMinVersion {
                attribute: PostureAttributeKey::OsVersion,
                min_version: min_version.into(),
            });
        self
    }

    /// Require a specific OS type.
    #[must_use]
    pub fn require_os_type(mut self, os_type: impl Into<String>) -> Self {
        self.requirements.push(PostureRequirement::RequireEqual {
            attribute: PostureAttributeKey::OsType,
            value: os_type.into(),
        });
        self
    }

    /// Require the OS type to be one of the given types.
    #[must_use]
    pub fn require_os_type_one_of(mut self, os_types: Vec<String>) -> Self {
        self.requirements.push(PostureRequirement::RequireOneOf {
            attribute: PostureAttributeKey::OsType,
            values: os_types,
        });
        self
    }

    /// Require device to be managed (MDM enrolled).
    #[must_use]
    pub fn require_device_managed(mut self, required: bool) -> Self {
        if required {
            self.requirements.push(PostureRequirement::RequireTrue {
                attribute: PostureAttributeKey::DeviceManaged,
            });
        }
        self
    }

    /// Require secure boot to be enabled.
    #[must_use]
    pub fn require_secure_boot(mut self, required: bool) -> Self {
        if required {
            self.requirements.push(PostureRequirement::RequireTrue {
                attribute: PostureAttributeKey::SecureBootEnabled,
            });
        }
        self
    }

    /// Require TPM/Secure Enclave to be present.
    #[must_use]
    pub fn require_tpm(mut self, required: bool) -> Self {
        if required {
            self.requirements.push(PostureRequirement::RequireTrue {
                attribute: PostureAttributeKey::TpmPresent,
            });
        }
        self
    }

    /// Add a custom requirement.
    #[must_use]
    pub fn require(mut self, requirement: PostureRequirement) -> Self {
        self.requirements.push(requirement);
        self
    }

    /// Set maximum attestation age in seconds.
    #[must_use]
    pub const fn max_attestation_age_secs(mut self, secs: u64) -> Self {
        self.max_attestation_age_secs = Some(secs);
        self
    }

    /// Add an allowed verifier.
    #[must_use]
    pub fn allow_verifier(mut self, verifier_id: impl Into<String>) -> Self {
        self.allowed_verifiers.push(verifier_id.into());
        self
    }

    /// Build the requirements.
    #[must_use]
    pub fn build(self) -> PostureRequirements {
        PostureRequirements {
            requirements: self.requirements,
            max_attestation_age_secs: self.max_attestation_age_secs.unwrap_or(86400),
            allowed_verifiers: self.allowed_verifiers,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Simple version comparison (>=).
///
/// Supports semver-style versions (e.g., "14.2.1" >= "14.0.0").
fn version_gte(actual: &str, required: &str) -> bool {
    let actual_parts: Vec<u64> = actual.split('.').filter_map(|s| s.parse().ok()).collect();
    let required_parts: Vec<u64> = required.split('.').filter_map(|s| s.parse().ok()).collect();

    for i in 0..required_parts.len().max(actual_parts.len()) {
        let a = actual_parts.get(i).copied().unwrap_or(0);
        let r = required_parts.get(i).copied().unwrap_or(0);
        if a > r {
            return true;
        }
        if a < r {
            return false;
        }
    }
    true // Equal versions
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_attestation() -> PostureAttestation {
        let mut attributes = HashMap::new();
        attributes.insert(
            PostureAttributeKey::OsType,
            PostureAttributeValue::String("macos".to_string()),
        );
        attributes.insert(
            PostureAttributeKey::OsVersion,
            PostureAttributeValue::String("14.2.1".to_string()),
        );
        attributes.insert(
            PostureAttributeKey::DiskEncryption,
            PostureAttributeValue::Bool(true),
        );
        attributes.insert(
            PostureAttributeKey::FirewallEnabled,
            PostureAttributeValue::Bool(true),
        );
        attributes.insert(
            PostureAttributeKey::ScreenLockEnabled,
            PostureAttributeValue::Bool(true),
        );
        attributes.insert(
            PostureAttributeKey::ScreenLockTimeout,
            PostureAttributeValue::Number(300),
        );

        PostureAttestation {
            schema: PostureAttestation::SCHEMA.to_string(),
            attestation_id: "att-12345".to_string(),
            node_id: NodeId::new("node-test"),
            attributes,
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
            verifier_id: "verifier-1".to_string(),
            signature: "signature".to_string(),
            verifier_kid: "kid-1".to_string(),
        }
    }

    #[test]
    fn test_attestation_is_valid() {
        let attestation = create_test_attestation();
        assert!(attestation.is_valid());
        assert!(!attestation.is_expired());
    }

    #[test]
    fn test_attestation_expired() {
        let mut attestation = create_test_attestation();
        attestation.expires_at = Utc::now() - chrono::Duration::hours(1);
        assert!(attestation.is_expired());
        assert!(!attestation.is_valid());
    }

    #[test]
    fn test_attestation_attribute_access() {
        let attestation = create_test_attestation();
        assert_eq!(attestation.os_type(), Some("macos"));
        assert_eq!(attestation.os_version(), Some("14.2.1"));
        assert_eq!(attestation.disk_encryption_enabled(), Some(true));
    }

    #[test]
    fn test_requirement_require_true() {
        let attestation = create_test_attestation();

        let req = PostureRequirement::RequireTrue {
            attribute: PostureAttributeKey::DiskEncryption,
        };
        assert!(req.is_satisfied_by(&attestation));

        let req = PostureRequirement::RequireTrue {
            attribute: PostureAttributeKey::AntivirusActive,
        };
        assert!(!req.is_satisfied_by(&attestation));
    }

    #[test]
    fn test_requirement_min_version() {
        let attestation = create_test_attestation();

        let req = PostureRequirement::RequireMinVersion {
            attribute: PostureAttributeKey::OsVersion,
            min_version: "14.0.0".to_string(),
        };
        assert!(req.is_satisfied_by(&attestation));

        let req = PostureRequirement::RequireMinVersion {
            attribute: PostureAttributeKey::OsVersion,
            min_version: "15.0.0".to_string(),
        };
        assert!(!req.is_satisfied_by(&attestation));
    }

    #[test]
    fn test_requirement_one_of() {
        let attestation = create_test_attestation();

        let req = PostureRequirement::RequireOneOf {
            attribute: PostureAttributeKey::OsType,
            values: vec!["macos".to_string(), "windows".to_string()],
        };
        assert!(req.is_satisfied_by(&attestation));

        let req = PostureRequirement::RequireOneOf {
            attribute: PostureAttributeKey::OsType,
            values: vec!["linux".to_string()],
        };
        assert!(!req.is_satisfied_by(&attestation));
    }

    #[test]
    fn test_requirements_builder() {
        let requirements = PostureRequirements::builder()
            .require_disk_encryption(true)
            .require_os_min_version("14.0")
            .require_os_type_one_of(vec!["macos".to_string(), "windows".to_string()])
            .max_attestation_age_secs(3600)
            .allow_verifier("verifier-1")
            .build();

        assert_eq!(requirements.requirements.len(), 3);
        assert_eq!(requirements.max_attestation_age_secs, 3600);
        assert_eq!(requirements.allowed_verifiers, vec!["verifier-1"]);

        let attestation = create_test_attestation();
        assert!(requirements.is_satisfied_by(&attestation).is_satisfied());
    }

    #[test]
    fn test_requirements_verifier_check() {
        let requirements = PostureRequirements::builder()
            .allow_verifier("trusted-verifier")
            .build();

        let attestation = create_test_attestation();
        assert_eq!(
            requirements.is_satisfied_by(&attestation),
            PostureCheckResult::VerifierNotAllowed
        );
    }

    #[test]
    fn test_version_comparison() {
        assert!(version_gte("14.2.1", "14.0.0"));
        assert!(version_gte("14.2.1", "14.2.1"));
        assert!(version_gte("15.0.0", "14.2.1"));
        assert!(!version_gte("14.0.0", "14.2.1"));
        assert!(!version_gte("13.0.0", "14.0.0"));
        assert!(version_gte("14", "14.0.0"));
        assert!(version_gte("14.2", "14.0"));
    }

    // ── PostureAttributeKey ────────────────────────────────────────────────

    #[test]
    fn attribute_key_as_str_all_variants() {
        assert_eq!(PostureAttributeKey::OsType.as_str(), "os_type");
        assert_eq!(PostureAttributeKey::OsVersion.as_str(), "os_version");
        assert_eq!(
            PostureAttributeKey::DiskEncryption.as_str(),
            "disk_encryption"
        );
        assert_eq!(
            PostureAttributeKey::FirewallEnabled.as_str(),
            "firewall_enabled"
        );
        assert_eq!(
            PostureAttributeKey::ScreenLockEnabled.as_str(),
            "screen_lock_enabled"
        );
        assert_eq!(
            PostureAttributeKey::ScreenLockTimeout.as_str(),
            "screen_lock_timeout"
        );
        assert_eq!(
            PostureAttributeKey::AntivirusActive.as_str(),
            "antivirus_active"
        );
        assert_eq!(
            PostureAttributeKey::DeviceManaged.as_str(),
            "device_managed"
        );
        assert_eq!(
            PostureAttributeKey::SecureBootEnabled.as_str(),
            "secure_boot_enabled"
        );
        assert_eq!(PostureAttributeKey::TpmPresent.as_str(), "tpm_present");
    }

    #[test]
    fn attribute_key_custom_as_str() {
        let key = PostureAttributeKey::Custom("my_custom_attr".into());
        assert_eq!(key.as_str(), "my_custom_attr");
    }

    #[test]
    fn attribute_key_serde_roundtrip() {
        let key = PostureAttributeKey::DiskEncryption;
        let json = serde_json::to_string(&key).unwrap();
        let back: PostureAttributeKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key, back);
    }

    // ── PostureAttributeValue ──────────────────────────────────────────────

    #[test]
    fn attribute_value_as_bool_wrong_type() {
        assert!(
            PostureAttributeValue::String("true".into())
                .as_bool()
                .is_none()
        );
        assert!(PostureAttributeValue::Number(1).as_bool().is_none());
    }

    #[test]
    fn attribute_value_as_str_wrong_type() {
        assert!(PostureAttributeValue::Bool(true).as_str().is_none());
        assert!(PostureAttributeValue::Number(42).as_str().is_none());
    }

    #[test]
    fn attribute_value_as_number_wrong_type() {
        assert!(PostureAttributeValue::Bool(true).as_number().is_none());
        assert!(
            PostureAttributeValue::String("42".into())
                .as_number()
                .is_none()
        );
    }

    #[test]
    fn attribute_value_serde_roundtrip_all_variants() {
        let vals = [
            PostureAttributeValue::Bool(true),
            PostureAttributeValue::String("hello".into()),
            PostureAttributeValue::Number(42),
        ];
        for val in &vals {
            let json = serde_json::to_string(val).unwrap();
            let back: PostureAttributeValue = serde_json::from_str(&json).unwrap();
            assert_eq!(val, &back);
        }
    }

    // ── PostureAttestation ─────────────────────────────────────────────────

    #[test]
    fn attestation_invalid_schema() {
        let mut att = create_test_attestation();
        att.schema = "wrong.schema".into();
        assert!(!att.is_valid());
        assert!(!att.is_expired()); // not expired, just wrong schema
    }

    #[test]
    fn attestation_is_for_node() {
        let att = create_test_attestation();
        assert!(att.is_for_node(&NodeId::new("node-test")));
        assert!(!att.is_for_node(&NodeId::new("node-other")));
    }

    #[test]
    fn attestation_object_id_deterministic() {
        let att = create_test_attestation();
        let id1 = att.object_id();
        let id2 = att.object_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn attestation_get_attribute_missing() {
        let att = create_test_attestation();
        assert!(
            att.get_attribute(&PostureAttributeKey::AntivirusActive)
                .is_none()
        );
    }

    #[test]
    fn attestation_serde_roundtrip() {
        let att = create_test_attestation();
        let json = serde_json::to_string(&att).unwrap();
        let back: PostureAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema, att.schema);
        assert_eq!(back.attestation_id, att.attestation_id);
        assert_eq!(back.verifier_id, att.verifier_id);
    }

    // ── PostureRequirement ─────────────────────────────────────────────────

    #[test]
    fn requirement_require_false_satisfied() {
        let att = create_test_attestation();
        // AntivirusActive is not in attestation → RequireFalse is satisfied (missing = not true)
        let req = PostureRequirement::RequireFalse {
            attribute: PostureAttributeKey::AntivirusActive,
        };
        assert!(req.is_satisfied_by(&att));
    }

    #[test]
    fn requirement_require_false_fails_on_true() {
        let att = create_test_attestation();
        // DiskEncryption is true → RequireFalse should fail
        let req = PostureRequirement::RequireFalse {
            attribute: PostureAttributeKey::DiskEncryption,
        };
        assert!(!req.is_satisfied_by(&att));
    }

    #[test]
    fn requirement_require_equal() {
        let att = create_test_attestation();
        let req = PostureRequirement::RequireEqual {
            attribute: PostureAttributeKey::OsType,
            value: "macos".into(),
        };
        assert!(req.is_satisfied_by(&att));

        let req = PostureRequirement::RequireEqual {
            attribute: PostureAttributeKey::OsType,
            value: "windows".into(),
        };
        assert!(!req.is_satisfied_by(&att));
    }

    #[test]
    fn requirement_min_value() {
        let att = create_test_attestation();
        // ScreenLockTimeout is 300
        let req = PostureRequirement::RequireMinValue {
            attribute: PostureAttributeKey::ScreenLockTimeout,
            min_value: 200,
        };
        assert!(req.is_satisfied_by(&att));

        let req = PostureRequirement::RequireMinValue {
            attribute: PostureAttributeKey::ScreenLockTimeout,
            min_value: 500,
        };
        assert!(!req.is_satisfied_by(&att));
    }

    #[test]
    fn requirement_max_value() {
        let att = create_test_attestation();
        let req = PostureRequirement::RequireMaxValue {
            attribute: PostureAttributeKey::ScreenLockTimeout,
            max_value: 600,
        };
        assert!(req.is_satisfied_by(&att));

        let req = PostureRequirement::RequireMaxValue {
            attribute: PostureAttributeKey::ScreenLockTimeout,
            max_value: 100,
        };
        assert!(!req.is_satisfied_by(&att));
    }

    #[test]
    fn requirement_attribute_accessor() {
        let req = PostureRequirement::RequireTrue {
            attribute: PostureAttributeKey::TpmPresent,
        };
        assert_eq!(*req.attribute(), PostureAttributeKey::TpmPresent);

        let req = PostureRequirement::RequireMaxValue {
            attribute: PostureAttributeKey::ScreenLockTimeout,
            max_value: 100,
        };
        assert_eq!(*req.attribute(), PostureAttributeKey::ScreenLockTimeout);
    }

    // ── PostureRequirements ────────────────────────────────────────────────

    #[test]
    fn requirements_is_empty() {
        let empty = PostureRequirements::default();
        assert!(empty.is_empty());

        let non_empty = PostureRequirements::builder()
            .require_disk_encryption(true)
            .build();
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn requirements_attestation_expired() {
        let requirements = PostureRequirements::builder().build();
        let mut att = create_test_attestation();
        att.expires_at = Utc::now() - chrono::Duration::hours(1);
        assert_eq!(
            requirements.is_satisfied_by(&att),
            PostureCheckResult::AttestationExpired,
        );
    }

    #[test]
    fn requirements_attestation_too_old() {
        let requirements = PostureRequirements::builder()
            .max_attestation_age_secs(60)
            .build();
        let mut att = create_test_attestation();
        // Issued 2 hours ago but not yet expired
        att.issued_at = Utc::now() - chrono::Duration::hours(2);
        assert_eq!(
            requirements.is_satisfied_by(&att),
            PostureCheckResult::AttestationTooOld,
        );
    }

    #[test]
    fn requirements_requirement_not_met() {
        let requirements = PostureRequirements::builder().require_tpm(true).build();
        let att = create_test_attestation(); // no TpmPresent attribute
        let result = requirements.is_satisfied_by(&att);
        assert_eq!(
            result,
            PostureCheckResult::RequirementNotMet {
                attribute: PostureAttributeKey::TpmPresent,
            },
        );
    }

    // ── PostureCheckResult ─────────────────────────────────────────────────

    #[test]
    fn check_result_is_satisfied() {
        assert!(PostureCheckResult::Satisfied.is_satisfied());
        assert!(!PostureCheckResult::AttestationExpired.is_satisfied());
        assert!(!PostureCheckResult::AttestationTooOld.is_satisfied());
        assert!(!PostureCheckResult::VerifierNotAllowed.is_satisfied());
        assert!(
            !PostureCheckResult::RequirementNotMet {
                attribute: PostureAttributeKey::TpmPresent,
            }
            .is_satisfied()
        );
    }

    // ── Builder coverage ───────────────────────────────────────────────────

    #[test]
    fn builder_require_firewall() {
        let req = PostureRequirements::builder()
            .require_firewall(true)
            .build();
        assert_eq!(req.requirements.len(), 1);
        assert_eq!(
            *req.requirements[0].attribute(),
            PostureAttributeKey::FirewallEnabled
        );
    }

    #[test]
    fn builder_require_screen_lock() {
        let req = PostureRequirements::builder()
            .require_screen_lock(true)
            .build();
        assert_eq!(req.requirements.len(), 1);
        assert_eq!(
            *req.requirements[0].attribute(),
            PostureAttributeKey::ScreenLockEnabled
        );
    }

    #[test]
    fn builder_require_os_type() {
        let req = PostureRequirements::builder()
            .require_os_type("linux")
            .build();
        assert_eq!(req.requirements.len(), 1);
    }

    #[test]
    fn builder_require_device_managed() {
        let req = PostureRequirements::builder()
            .require_device_managed(true)
            .build();
        assert_eq!(req.requirements.len(), 1);
        assert_eq!(
            *req.requirements[0].attribute(),
            PostureAttributeKey::DeviceManaged
        );
    }

    #[test]
    fn builder_require_secure_boot() {
        let req = PostureRequirements::builder()
            .require_secure_boot(true)
            .build();
        assert_eq!(req.requirements.len(), 1);
        assert_eq!(
            *req.requirements[0].attribute(),
            PostureAttributeKey::SecureBootEnabled
        );
    }

    #[test]
    fn builder_false_flag_adds_nothing() {
        let req = PostureRequirements::builder()
            .require_disk_encryption(false)
            .require_firewall(false)
            .require_screen_lock(false)
            .require_device_managed(false)
            .require_secure_boot(false)
            .require_tpm(false)
            .build();
        assert!(req.is_empty());
    }

    #[test]
    fn builder_custom_requirement() {
        let custom = PostureRequirement::RequireTrue {
            attribute: PostureAttributeKey::Custom("custom_check".into()),
        };
        let req = PostureRequirements::builder().require(custom).build();
        assert_eq!(req.requirements.len(), 1);
    }

    #[test]
    fn builder_default_max_age() {
        let req = PostureRequirements::builder().build();
        assert_eq!(req.max_attestation_age_secs, 86400);
    }

    // ── version_gte edge cases ─────────────────────────────────────────────

    #[test]
    fn version_gte_equal_versions() {
        assert!(version_gte("1.0.0", "1.0.0"));
        assert!(version_gte("0.0.0", "0.0.0"));
    }

    #[test]
    fn version_gte_single_component() {
        assert!(version_gte("15", "14"));
        assert!(!version_gte("13", "14"));
        assert!(version_gte("14", "14"));
    }

    #[test]
    fn version_gte_mismatched_depth() {
        // "14" vs "14.0.0" — implicit zeros
        assert!(version_gte("14", "14.0.0"));
        assert!(version_gte("14.0.0", "14"));
        // "14.1" > "14.0.0"
        assert!(version_gte("14.1", "14.0.0"));
    }

    // ── PostureRequirement serde roundtrip ─────────────────────────────────

    #[test]
    fn posture_requirement_serde_roundtrip() {
        let req = PostureRequirement::RequireMinVersion {
            attribute: PostureAttributeKey::OsVersion,
            min_version: "14.0".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: PostureRequirement = serde_json::from_str(&json).unwrap();
        assert_eq!(*back.attribute(), PostureAttributeKey::OsVersion);
    }

    // ── PostureAttributeKey trait coverage ────────────────────────────────

    #[test]
    fn attribute_key_clone() {
        let key = PostureAttributeKey::DiskEncryption;
        let cloned = key.clone();
        assert_eq!(key, cloned);
    }

    #[test]
    fn attribute_key_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let key = PostureAttributeKey::FirewallEnabled;
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        key.hash(&mut h1);
        key.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn attribute_key_inequality() {
        assert_ne!(PostureAttributeKey::OsType, PostureAttributeKey::OsVersion);
        assert_ne!(
            PostureAttributeKey::Custom("a".into()),
            PostureAttributeKey::Custom("b".into())
        );
    }

    #[test]
    fn attribute_key_serde_custom_roundtrip() {
        let key = PostureAttributeKey::Custom("my_attr".into());
        let json = serde_json::to_string(&key).unwrap();
        let back: PostureAttributeKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key, back);
    }

    // ── PostureAttributeValue trait coverage ──────────────────────────────

    #[test]
    fn attribute_value_clone() {
        let val = PostureAttributeValue::String("test".into());
        let cloned = val.clone();
        assert_eq!(val, cloned);
    }

    #[test]
    fn attribute_value_bool_accessors() {
        let val = PostureAttributeValue::Bool(false);
        assert_eq!(val.as_bool(), Some(false));
        assert!(val.as_str().is_none());
        assert!(val.as_number().is_none());
    }

    #[test]
    fn attribute_value_number_accessor() {
        let val = PostureAttributeValue::Number(-42);
        assert_eq!(val.as_number(), Some(-42));
    }

    // ── PostureAttestation trait coverage ─────────────────────────────────

    #[test]
    fn attestation_clone() {
        let att = create_test_attestation();
        let cloned = att.clone();
        assert_eq!(cloned.attestation_id, att.attestation_id);
        assert_eq!(cloned.schema, att.schema);
        assert_eq!(cloned.node_id, att.node_id);
    }

    #[test]
    fn attestation_schema_constant() {
        assert_eq!(PostureAttestation::SCHEMA, "fcp.posture.v1");
    }

    #[test]
    fn attestation_remaining_validity_positive() {
        let att = create_test_attestation();
        let remaining = att.remaining_validity();
        assert!(remaining.num_seconds() > 0);
    }

    #[test]
    fn attestation_remaining_validity_negative_when_expired() {
        let mut att = create_test_attestation();
        att.expires_at = Utc::now() - chrono::Duration::hours(1);
        let remaining = att.remaining_validity();
        assert!(remaining.num_seconds() < 0);
    }

    // ── PostureRequirement serde all variants ────────────────────────────

    #[test]
    fn requirement_serde_require_true() {
        let req = PostureRequirement::RequireTrue {
            attribute: PostureAttributeKey::DiskEncryption,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: PostureRequirement = serde_json::from_str(&json).unwrap();
        assert_eq!(*back.attribute(), PostureAttributeKey::DiskEncryption);
    }

    #[test]
    fn requirement_serde_require_false() {
        let req = PostureRequirement::RequireFalse {
            attribute: PostureAttributeKey::AntivirusActive,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: PostureRequirement = serde_json::from_str(&json).unwrap();
        assert_eq!(*back.attribute(), PostureAttributeKey::AntivirusActive);
    }

    #[test]
    fn requirement_serde_require_equal() {
        let req = PostureRequirement::RequireEqual {
            attribute: PostureAttributeKey::OsType,
            value: "linux".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: PostureRequirement = serde_json::from_str(&json).unwrap();
        assert_eq!(*back.attribute(), PostureAttributeKey::OsType);
    }

    #[test]
    fn requirement_serde_require_one_of() {
        let req = PostureRequirement::RequireOneOf {
            attribute: PostureAttributeKey::OsType,
            values: vec!["macos".into(), "linux".into()],
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: PostureRequirement = serde_json::from_str(&json).unwrap();
        assert_eq!(*back.attribute(), PostureAttributeKey::OsType);
    }

    #[test]
    fn requirement_serde_require_min_value() {
        let req = PostureRequirement::RequireMinValue {
            attribute: PostureAttributeKey::ScreenLockTimeout,
            min_value: 300,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: PostureRequirement = serde_json::from_str(&json).unwrap();
        assert_eq!(*back.attribute(), PostureAttributeKey::ScreenLockTimeout);
    }

    #[test]
    fn requirement_serde_require_max_value() {
        let req = PostureRequirement::RequireMaxValue {
            attribute: PostureAttributeKey::ScreenLockTimeout,
            max_value: 600,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: PostureRequirement = serde_json::from_str(&json).unwrap();
        assert_eq!(*back.attribute(), PostureAttributeKey::ScreenLockTimeout);
    }

    #[test]
    fn requirement_clone() {
        let req = PostureRequirement::RequireTrue {
            attribute: PostureAttributeKey::TpmPresent,
        };
        let cloned = Clone::clone(&req);
        assert_eq!(*cloned.attribute(), PostureAttributeKey::TpmPresent);
    }

    // ── PostureRequirements trait coverage ────────────────────────────────

    #[test]
    fn requirements_clone() {
        let reqs = PostureRequirements::builder()
            .require_disk_encryption(true)
            .require_firewall(true)
            .allow_verifier("v1")
            .build();
        let cloned = Clone::clone(&reqs);
        assert_eq!(cloned.requirements.len(), 2);
        assert_eq!(cloned.allowed_verifiers, vec!["v1"]);
    }

    #[test]
    fn requirements_default() {
        let reqs = PostureRequirements::default();
        assert!(reqs.requirements.is_empty());
        // Default derive sets to 0; the 86400 default is only for serde deserialization
        assert_eq!(reqs.max_attestation_age_secs, 0);
        assert!(reqs.allowed_verifiers.is_empty());
    }

    #[test]
    fn requirements_serde_roundtrip() {
        let reqs = PostureRequirements::builder()
            .require_disk_encryption(true)
            .require_os_min_version("14.0")
            .max_attestation_age_secs(7200)
            .allow_verifier("trusted-v")
            .build();
        let json = serde_json::to_string(&reqs).unwrap();
        let back: PostureRequirements = serde_json::from_str(&json).unwrap();
        assert_eq!(back.requirements.len(), 2);
        assert_eq!(back.max_attestation_age_secs, 7200);
        assert_eq!(back.allowed_verifiers, vec!["trusted-v"]);
    }

    // ── PostureCheckResult trait coverage ─────────────────────────────────

    #[test]
    fn check_result_clone() {
        let result = PostureCheckResult::RequirementNotMet {
            attribute: PostureAttributeKey::TpmPresent,
        };
        let cloned = result.clone();
        assert_eq!(result, cloned);
    }

    #[test]
    fn check_result_equality() {
        assert_eq!(PostureCheckResult::Satisfied, PostureCheckResult::Satisfied);
        assert_eq!(
            PostureCheckResult::AttestationExpired,
            PostureCheckResult::AttestationExpired,
        );
        assert_ne!(
            PostureCheckResult::Satisfied,
            PostureCheckResult::VerifierNotAllowed,
        );
    }

    // ── version_gte additional edge cases ────────────────────────────────

    #[test]
    fn version_gte_empty_strings() {
        // Both empty → equal → true
        assert!(version_gte("", ""));
    }

    #[test]
    fn version_gte_non_numeric_parts_filtered() {
        // Non-numeric parts are filtered out by parse().ok()
        assert!(version_gte("14.abc.1", "14"));
    }

    // ── PostureRequirementsBuilder Default ────────────────────────────────

    #[test]
    fn builder_default_trait() {
        let builder = PostureRequirementsBuilder::default();
        let reqs = builder.build();
        assert!(reqs.is_empty());
        assert_eq!(reqs.max_attestation_age_secs, 86400);
    }

    // ── PostureAttributeValue edge cases ────────────────────────────────

    #[test]
    fn attribute_value_bool_true_accessor() {
        let val = PostureAttributeValue::Bool(true);
        assert_eq!(val.as_bool(), Some(true));
    }

    #[test]
    fn attribute_value_string_accessor() {
        let val = PostureAttributeValue::String("hello world".into());
        assert_eq!(val.as_str(), Some("hello world"));
        assert!(val.as_bool().is_none());
        assert!(val.as_number().is_none());
    }

    #[test]
    fn attribute_value_number_positive_accessor() {
        let val = PostureAttributeValue::Number(0);
        assert_eq!(val.as_number(), Some(0));
    }

    #[test]
    fn attribute_value_number_max_accessor() {
        let val = PostureAttributeValue::Number(i64::MAX);
        assert_eq!(val.as_number(), Some(i64::MAX));
    }

    #[test]
    fn attribute_value_number_min_accessor() {
        let val = PostureAttributeValue::Number(i64::MIN);
        assert_eq!(val.as_number(), Some(i64::MIN));
    }

    // ── PostureAttestation edge cases ────────────────────────────────────

    #[test]
    fn attestation_disk_encryption_missing() {
        let mut att = create_test_attestation();
        att.attributes.remove(&PostureAttributeKey::DiskEncryption);
        assert_eq!(att.disk_encryption_enabled(), None);
    }

    #[test]
    fn attestation_disk_encryption_wrong_type() {
        let mut att = create_test_attestation();
        att.attributes.insert(
            PostureAttributeKey::DiskEncryption,
            PostureAttributeValue::String("yes".into()),
        );
        // as_bool returns None for String variant
        assert_eq!(att.disk_encryption_enabled(), None);
    }

    #[test]
    fn attestation_disk_encryption_false() {
        let mut att = create_test_attestation();
        att.attributes.insert(
            PostureAttributeKey::DiskEncryption,
            PostureAttributeValue::Bool(false),
        );
        assert_eq!(att.disk_encryption_enabled(), Some(false));
    }

    #[test]
    fn attestation_os_version_missing() {
        let mut att = create_test_attestation();
        att.attributes.remove(&PostureAttributeKey::OsVersion);
        assert_eq!(att.os_version(), None);
    }

    #[test]
    fn attestation_os_type_missing() {
        let mut att = create_test_attestation();
        att.attributes.remove(&PostureAttributeKey::OsType);
        assert_eq!(att.os_type(), None);
    }

    #[test]
    fn attestation_os_type_wrong_type() {
        let mut att = create_test_attestation();
        att.attributes.insert(
            PostureAttributeKey::OsType,
            PostureAttributeValue::Number(42),
        );
        assert_eq!(att.os_type(), None);
    }

    #[test]
    fn attestation_object_id_differs_for_different_ids() {
        let att1 = create_test_attestation();
        let mut att2 = create_test_attestation();
        att2.attestation_id = "att-99999".to_string();
        assert_ne!(att1.object_id(), att2.object_id());
    }

    #[test]
    fn attestation_debug_impl() {
        let att = create_test_attestation();
        let debug = format!("{att:?}");
        assert!(debug.contains("PostureAttestation"));
        assert!(debug.contains("att-12345"));
    }

    // ── PostureRequirement edge cases ────────────────────────────────────

    #[test]
    fn requirement_require_true_wrong_type_value() {
        // When attribute exists but is a String, as_bool returns None -> false
        let mut att = create_test_attestation();
        att.attributes.insert(
            PostureAttributeKey::AntivirusActive,
            PostureAttributeValue::String("true".into()),
        );
        let req = PostureRequirement::RequireTrue {
            attribute: PostureAttributeKey::AntivirusActive,
        };
        assert!(!req.is_satisfied_by(&att));
    }

    #[test]
    fn requirement_require_false_with_bool_false_value() {
        // RequireFalse should be satisfied when attribute is explicitly Bool(false)
        let mut att = create_test_attestation();
        att.attributes.insert(
            PostureAttributeKey::AntivirusActive,
            PostureAttributeValue::Bool(false),
        );
        let req = PostureRequirement::RequireFalse {
            attribute: PostureAttributeKey::AntivirusActive,
        };
        assert!(req.is_satisfied_by(&att));
    }

    #[test]
    fn requirement_require_false_wrong_type_value() {
        // RequireFalse with a String value -> as_bool returns None -> is_none_or(|v| !v) -> true
        let mut att = create_test_attestation();
        att.attributes.insert(
            PostureAttributeKey::AntivirusActive,
            PostureAttributeValue::String("false".into()),
        );
        let req = PostureRequirement::RequireFalse {
            attribute: PostureAttributeKey::AntivirusActive,
        };
        assert!(req.is_satisfied_by(&att));
    }

    #[test]
    fn requirement_require_equal_missing_attribute() {
        let att = create_test_attestation();
        let req = PostureRequirement::RequireEqual {
            attribute: PostureAttributeKey::AntivirusActive,
            value: "active".into(),
        };
        assert!(!req.is_satisfied_by(&att));
    }

    #[test]
    fn requirement_require_equal_wrong_type() {
        // Attribute is a Bool, RequireEqual expects string via as_str
        let att = create_test_attestation();
        let req = PostureRequirement::RequireEqual {
            attribute: PostureAttributeKey::DiskEncryption,
            value: "true".into(),
        };
        assert!(!req.is_satisfied_by(&att));
    }

    #[test]
    fn requirement_require_one_of_empty_values() {
        let att = create_test_attestation();
        let req = PostureRequirement::RequireOneOf {
            attribute: PostureAttributeKey::OsType,
            values: vec![],
        };
        assert!(!req.is_satisfied_by(&att));
    }

    #[test]
    fn requirement_require_one_of_missing_attribute() {
        let att = create_test_attestation();
        let req = PostureRequirement::RequireOneOf {
            attribute: PostureAttributeKey::OsType,
            values: vec!["linux".to_string()],
        };
        assert!(!req.is_satisfied_by(&att));
    }

    #[test]
    fn requirement_require_min_version_missing_attribute() {
        let att = create_test_attestation();
        let req = PostureRequirement::RequireMinVersion {
            attribute: PostureAttributeKey::AntivirusActive,
            min_version: "1.0".into(),
        };
        assert!(!req.is_satisfied_by(&att));
    }

    #[test]
    fn requirement_require_min_value_missing_attribute() {
        let att = create_test_attestation();
        let req = PostureRequirement::RequireMinValue {
            attribute: PostureAttributeKey::AntivirusActive,
            min_value: 100,
        };
        assert!(!req.is_satisfied_by(&att));
    }

    #[test]
    fn requirement_require_min_value_wrong_type() {
        // OsType is a String, not a Number
        let att = create_test_attestation();
        let req = PostureRequirement::RequireMinValue {
            attribute: PostureAttributeKey::OsType,
            min_value: 14,
        };
        assert!(!req.is_satisfied_by(&att));
    }

    #[test]
    fn requirement_require_min_value_exact_boundary() {
        let att = create_test_attestation();
        // ScreenLockTimeout is 300
        let req = PostureRequirement::RequireMinValue {
            attribute: PostureAttributeKey::ScreenLockTimeout,
            min_value: 300,
        };
        assert!(req.is_satisfied_by(&att));
    }

    #[test]
    fn requirement_require_max_value_missing_attribute() {
        let att = create_test_attestation();
        let req = PostureRequirement::RequireMaxValue {
            attribute: PostureAttributeKey::AntivirusActive,
            max_value: 100,
        };
        assert!(!req.is_satisfied_by(&att));
    }

    #[test]
    fn requirement_require_max_value_exact_boundary() {
        let att = create_test_attestation();
        // ScreenLockTimeout is 300
        let req = PostureRequirement::RequireMaxValue {
            attribute: PostureAttributeKey::ScreenLockTimeout,
            max_value: 300,
        };
        assert!(req.is_satisfied_by(&att));
    }

    #[test]
    fn requirement_require_max_value_wrong_type() {
        let att = create_test_attestation();
        let req = PostureRequirement::RequireMaxValue {
            attribute: PostureAttributeKey::OsType,
            max_value: 100,
        };
        assert!(!req.is_satisfied_by(&att));
    }

    #[test]
    fn requirement_attribute_accessor_all_variants() {
        let variants: Vec<PostureRequirement> = vec![
            PostureRequirement::RequireTrue {
                attribute: PostureAttributeKey::DiskEncryption,
            },
            PostureRequirement::RequireFalse {
                attribute: PostureAttributeKey::AntivirusActive,
            },
            PostureRequirement::RequireEqual {
                attribute: PostureAttributeKey::OsType,
                value: "linux".into(),
            },
            PostureRequirement::RequireOneOf {
                attribute: PostureAttributeKey::OsType,
                values: vec!["macos".into()],
            },
            PostureRequirement::RequireMinVersion {
                attribute: PostureAttributeKey::OsVersion,
                min_version: "14.0".into(),
            },
            PostureRequirement::RequireMinValue {
                attribute: PostureAttributeKey::ScreenLockTimeout,
                min_value: 100,
            },
            PostureRequirement::RequireMaxValue {
                attribute: PostureAttributeKey::ScreenLockTimeout,
                max_value: 600,
            },
        ];
        let expected = [
            PostureAttributeKey::DiskEncryption,
            PostureAttributeKey::AntivirusActive,
            PostureAttributeKey::OsType,
            PostureAttributeKey::OsType,
            PostureAttributeKey::OsVersion,
            PostureAttributeKey::ScreenLockTimeout,
            PostureAttributeKey::ScreenLockTimeout,
        ];
        for (req, exp) in variants.iter().zip(expected.iter()) {
            assert_eq!(req.attribute(), exp);
        }
    }

    // ── PostureRequirements composite checks ─────────────────────────────

    #[test]
    fn requirements_multiple_satisfied() {
        let reqs = PostureRequirements::builder()
            .require_disk_encryption(true)
            .require_firewall(true)
            .require_screen_lock(true)
            .require_os_min_version("14.0")
            .build();
        let att = create_test_attestation();
        assert!(reqs.is_satisfied_by(&att).is_satisfied());
    }

    #[test]
    fn requirements_first_fails_short_circuits() {
        let reqs = PostureRequirements::builder()
            .require_tpm(true) // not in attestation → fails
            .require_disk_encryption(true) // would pass
            .build();
        let att = create_test_attestation();
        let result = reqs.is_satisfied_by(&att);
        assert_eq!(
            result,
            PostureCheckResult::RequirementNotMet {
                attribute: PostureAttributeKey::TpmPresent,
            }
        );
    }

    #[test]
    fn requirements_future_issued_at_rejected() {
        // issued_at in the future → age is negative → fails age check
        let reqs = PostureRequirements::builder()
            .max_attestation_age_secs(3600)
            .build();
        let mut att = create_test_attestation();
        att.issued_at = Utc::now() + chrono::Duration::hours(2);
        assert_eq!(
            reqs.is_satisfied_by(&att),
            PostureCheckResult::AttestationTooOld,
        );
    }

    #[test]
    fn requirements_multiple_verifiers_one_matches() {
        let reqs = PostureRequirements::builder()
            .allow_verifier("verifier-a")
            .allow_verifier("verifier-1") // matches
            .allow_verifier("verifier-b")
            .build();
        let att = create_test_attestation();
        assert!(reqs.is_satisfied_by(&att).is_satisfied());
    }

    #[test]
    fn requirements_empty_verifier_list_allows_any() {
        // No allowed_verifiers means any verifier is allowed
        let reqs = PostureRequirements::builder().build();
        let att = create_test_attestation();
        assert!(reqs.is_satisfied_by(&att).is_satisfied());
    }

    #[test]
    fn requirements_serde_default_max_age() {
        // When deserialized without max_attestation_age_secs, the serde default kicks in
        let json = r#"{"requirements":[],"allowed_verifiers":[]}"#;
        let reqs: PostureRequirements = serde_json::from_str(json).unwrap();
        assert_eq!(reqs.max_attestation_age_secs, 86400);
    }

    // ── version_gte additional edge cases ────────────────────────────────

    #[test]
    fn version_gte_four_segment_versions() {
        assert!(version_gte("1.2.3.4", "1.2.3.3"));
        assert!(!version_gte("1.2.3.3", "1.2.3.4"));
        assert!(version_gte("1.2.3.4", "1.2.3.4"));
    }

    #[test]
    fn version_gte_actual_longer_with_trailing_zeros() {
        // "14.0.0.0" vs "14" → all implicit zeros match
        assert!(version_gte("14.0.0.0", "14"));
    }

    #[test]
    fn version_gte_actual_shorter_than_required() {
        // "14" vs "14.0.1" → implicit zero < 1
        assert!(!version_gte("14", "14.0.1"));
    }

    #[test]
    fn version_gte_with_zero_versions() {
        assert!(version_gte("0.0.1", "0.0.0"));
        assert!(!version_gte("0.0.0", "0.0.1"));
    }

    #[test]
    fn version_gte_non_numeric_filtered_out() {
        // "14.beta.2" → [14, 2] vs "14.1" → [14, 1]
        // Comparing [14,2] vs [14,1] → 14==14, 2>1 → true
        assert!(version_gte("14.beta.2", "14.1"));
    }

    #[test]
    fn version_gte_all_non_numeric() {
        // Both sides parse to empty → loop runs 0 iterations → true (equal)
        assert!(version_gte("abc", "def"));
    }

    #[test]
    fn version_gte_one_side_empty() {
        // "" parses to [] vs "1.0" parses to [1,0]
        // loop: i=0: a=0, r=1 → a<r → false
        assert!(!version_gte("", "1.0"));
        // "1.0" parses to [1,0] vs "" parses to []
        // loop: i=0: a=1, r=0 → a>r → true
        assert!(version_gte("1.0", ""));
    }

    // ── PostureCheckResult Debug ─────────────────────────────────────────

    #[test]
    fn check_result_debug_all_variants() {
        let debug_satisfied = format!("{:?}", PostureCheckResult::Satisfied);
        assert!(debug_satisfied.contains("Satisfied"));

        let debug_expired = format!("{:?}", PostureCheckResult::AttestationExpired);
        assert!(debug_expired.contains("AttestationExpired"));

        let debug_old = format!("{:?}", PostureCheckResult::AttestationTooOld);
        assert!(debug_old.contains("AttestationTooOld"));

        let debug_verifier = format!("{:?}", PostureCheckResult::VerifierNotAllowed);
        assert!(debug_verifier.contains("VerifierNotAllowed"));

        let debug_req = format!(
            "{:?}",
            PostureCheckResult::RequirementNotMet {
                attribute: PostureAttributeKey::DiskEncryption,
            }
        );
        assert!(debug_req.contains("RequirementNotMet"));
        assert!(debug_req.contains("DiskEncryption"));
    }

    // ── PostureRequirementsBuilder Debug ──────────────────────────────────

    #[test]
    fn builder_debug_impl() {
        let builder = PostureRequirements::builder()
            .require_disk_encryption(true)
            .allow_verifier("v1");
        let debug = format!("{builder:?}");
        assert!(debug.contains("PostureRequirementsBuilder"));
    }

    // ── PostureAttributeKey HashMap usage ────────────────────────────────

    #[test]
    fn attribute_key_as_hashmap_key() {
        let mut map = HashMap::new();
        map.insert(
            PostureAttributeKey::OsType,
            PostureAttributeValue::String("macos".into()),
        );
        map.insert(
            PostureAttributeKey::Custom("custom".into()),
            PostureAttributeValue::Bool(true),
        );
        assert_eq!(map.len(), 2);
        assert!(map.contains_key(&PostureAttributeKey::OsType));
        assert!(map.contains_key(&PostureAttributeKey::Custom("custom".into())));
        assert!(!map.contains_key(&PostureAttributeKey::Custom("other".into())));
    }

    // ── Builder chaining ─────────────────────────────────────────────────

    #[test]
    fn builder_all_options_combined() {
        let reqs = PostureRequirements::builder()
            .require_disk_encryption(true)
            .require_firewall(true)
            .require_screen_lock(true)
            .require_os_min_version("14.0")
            .require_os_type("macos")
            .require_os_type_one_of(vec!["macos".into(), "linux".into()])
            .require_device_managed(true)
            .require_secure_boot(true)
            .require_tpm(true)
            .require(PostureRequirement::RequireMinValue {
                attribute: PostureAttributeKey::ScreenLockTimeout,
                min_value: 60,
            })
            .max_attestation_age_secs(1800)
            .allow_verifier("v1")
            .allow_verifier("v2")
            .build();
        assert_eq!(reqs.requirements.len(), 10);
        assert_eq!(reqs.max_attestation_age_secs, 1800);
        assert_eq!(reqs.allowed_verifiers.len(), 2);
    }

    #[test]
    fn builder_require_os_type_one_of_empty() {
        let reqs = PostureRequirements::builder()
            .require_os_type_one_of(vec![])
            .build();
        assert_eq!(reqs.requirements.len(), 1);
        // With empty allowed values, no attestation can satisfy
        let att = create_test_attestation();
        let result = reqs.is_satisfied_by(&att);
        assert_eq!(
            result,
            PostureCheckResult::RequirementNotMet {
                attribute: PostureAttributeKey::OsType,
            }
        );
    }

    // ── PostureRequirements with custom attributes ───────────────────────

    #[test]
    fn requirements_with_custom_attribute() {
        let mut att = create_test_attestation();
        att.attributes.insert(
            PostureAttributeKey::Custom("compliance_level".into()),
            PostureAttributeValue::String("high".into()),
        );
        let reqs = PostureRequirements::builder()
            .require(PostureRequirement::RequireEqual {
                attribute: PostureAttributeKey::Custom("compliance_level".into()),
                value: "high".into(),
            })
            .build();
        assert!(reqs.is_satisfied_by(&att).is_satisfied());
    }

    #[test]
    fn requirements_with_custom_attribute_fails() {
        let att = create_test_attestation();
        let reqs = PostureRequirements::builder()
            .require(PostureRequirement::RequireEqual {
                attribute: PostureAttributeKey::Custom("compliance_level".into()),
                value: "high".into(),
            })
            .build();
        let result = reqs.is_satisfied_by(&att);
        assert_eq!(
            result,
            PostureCheckResult::RequirementNotMet {
                attribute: PostureAttributeKey::Custom("compliance_level".into()),
            }
        );
    }
}
