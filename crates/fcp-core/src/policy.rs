//! Policy objects and evaluation helpers for FCP2.
//!
//! This module defines zone policy objects and a minimal evaluation pipeline
//! that produces stable decision reason codes and decision receipts.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

use chrono::{DateTime, Utc};
use fcp_cbor::SchemaId;
use fcp_crypto::{canonical_signing_bytes, canonicalize::to_deterministic_cbor};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    ApprovalScope, ApprovalToken, CapabilityGrant, CapabilityId, CapabilityObject,
    ConfidentialityLevel, ConnectorId, Decision, DecisionReceipt, FlowCheckResult, IntegrityLevel,
    InvokeRequest, NodeId, NodeSignature, ObjectHeader, ObjectId, OperationId, PrincipalId,
    Provenance, ProvenanceRecord, ProvenanceViolation, RoleObject, SafetyTier, SanitizerReceipt,
    TaintFlag, TaintFlags, TaintLevel, UsageMetricKind, ZoneId,
};

// ─────────────────────────────────────────────────────────────────────────────
// Zone Transport Policy
// ─────────────────────────────────────────────────────────────────────────────

/// Transport modes observed by the policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    /// Direct LAN/peer-to-peer transport.
    Lan,
    /// DERP relay transport.
    Derp,
    /// Funnel ingress transport.
    Funnel,
}

/// Zone transport policy (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneTransportPolicy {
    pub allow_lan: bool,
    pub allow_derp: bool,
    pub allow_funnel: bool,
}

impl ZoneTransportPolicy {
    /// Check whether a transport mode is permitted.
    #[must_use]
    pub const fn allows(&self, mode: TransportMode) -> bool {
        match mode {
            TransportMode::Lan => self.allow_lan,
            TransportMode::Derp => self.allow_derp,
            TransportMode::Funnel => self.allow_funnel,
        }
    }
}

impl Default for ZoneTransportPolicy {
    fn default() -> Self {
        Self {
            allow_lan: true,
            allow_derp: false,
            allow_funnel: false,
        }
    }
}

/// Decision receipt emission policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionReceiptPolicy {
    pub emit_on_allow: bool,
    pub emit_on_deny: bool,
}

impl Default for DecisionReceiptPolicy {
    fn default() -> Self {
        Self {
            emit_on_allow: false,
            emit_on_deny: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Usage Budget Policy (Zone-Level Guardrails)
// ─────────────────────────────────────────────────────────────────────────────

/// Budget enforcement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetEnforcement {
    /// Exceeding a budget should emit warnings but not deny operations.
    Warn,
    /// Exceeding a budget should deny operations.
    Deny,
}

/// Budget limit for a specific usage metric.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageBudgetLimit {
    /// Metric that the budget applies to.
    pub metric: UsageMetricKind,
    /// Maximum allowed usage within the window.
    pub limit: u64,
    /// Budget window in seconds.
    pub window_seconds: u64,
}

/// Usage budget policy for a zone (NORMATIVE when present).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageBudgetPolicy {
    /// Enforcement mode when budgets are exceeded.
    pub enforcement: BudgetEnforcement,
    /// Metric budgets enforced for the zone.
    pub budgets: Vec<UsageBudgetLimit>,
}

/// Budget usage status for a metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetStatus {
    /// Usage is within budget.
    Ok,
    /// Usage exceeds the configured budget.
    Exceeded,
}

impl BudgetStatus {
    /// Stable tag used by serde and operator-facing displays.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Exceeded => "exceeded",
        }
    }
}

impl std::fmt::Display for BudgetStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Usage vs budget report for a specific metric.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageBudgetUsage {
    /// Metric covered by this budget.
    pub metric: UsageMetricKind,
    /// Usage observed within the window.
    pub used: u64,
    /// Budget limit for the window.
    pub limit: u64,
    /// Remaining usage before exceeding the budget (0 if exceeded).
    pub remaining: u64,
    /// Window start timestamp (Unix seconds).
    pub window_started_at: u64,
    /// Window reset timestamp (Unix seconds).
    pub window_resets_at: u64,
    /// Budget status for this metric.
    pub status: BudgetStatus,
}

/// Usage budget snapshot for a zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageBudgetSnapshot {
    /// Zone that this snapshot applies to.
    pub zone_id: ZoneId,
    /// Enforcement mode in effect.
    pub enforcement: BudgetEnforcement,
    /// Budget usage entries.
    pub budgets: Vec<UsageBudgetUsage>,
    /// When the snapshot was generated (Unix seconds).
    pub updated_at: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy Objects
// ─────────────────────────────────────────────────────────────────────────────

/// `ZoneDefinitionObject` (owner-signed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneDefinitionObject {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub name: String,
    pub integrity_level: IntegrityLevel,
    pub confidentiality_level: ConfidentialityLevel,
    pub symbol_port: u16,
    pub control_port: u16,
    pub transport_policy: ZoneTransportPolicy,
    pub policy_object_id: ObjectId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<ObjectId>,
    pub signature: NodeSignature,
}

/// `ZonePolicyObject` (owner-signed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZonePolicyObject {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    #[serde(default)]
    pub principal_allow: Vec<PolicyPattern>,
    #[serde(default)]
    pub principal_deny: Vec<PolicyPattern>,
    #[serde(default)]
    pub connector_allow: Vec<PolicyPattern>,
    #[serde(default)]
    pub connector_deny: Vec<PolicyPattern>,
    #[serde(default)]
    pub capability_allow: Vec<PolicyPattern>,
    #[serde(default)]
    pub capability_deny: Vec<PolicyPattern>,
    #[serde(default)]
    pub capability_ceiling: Vec<CapabilityId>,
    #[serde(default)]
    pub transport_policy: ZoneTransportPolicy,
    #[serde(default)]
    pub decision_receipts: DecisionReceiptPolicy,
    /// Optional usage budget policy for this zone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_budget: Option<UsageBudgetPolicy>,
    /// Device posture requirements for this zone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_posture: Option<crate::posture::PostureRequirements>,
}

/// A bounded glob-only policy pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPattern {
    pub pattern: String,
}

impl PolicyPattern {
    #[must_use]
    pub fn matches(&self, value: &str) -> bool {
        pattern_matches(&self.pattern, value)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy Bundles
// ─────────────────────────────────────────────────────────────────────────────

/// Format identifier for policy bundle JSON.
pub const POLICY_BUNDLE_FORMAT: &str = "fcp-policy-bundle";

/// Schema version for policy bundles.
pub const POLICY_BUNDLE_SCHEMA_VERSION: &str = "1.0";

/// Schema ID for policy bundle signing bytes.
pub const POLICY_BUNDLE_SCHEMA_ID: &str = "fcp://schemas/policybundle/v1";

/// Hash algorithm for policy bundles.
pub const POLICY_BUNDLE_HASH_ALGO: &str = "blake3-256";

/// Fields included in policy bundle signatures (stable ordering).
pub const POLICY_BUNDLE_SIGNED_FIELDS: &[&str] = &[
    "format",
    "schema_version",
    "bundle_id",
    "zone_id",
    "policy_seq",
    "created_at",
    "previous_bundle",
    "hash_algo",
    "bundle_hash",
    "policies",
];

#[derive(Debug, Clone, Serialize)]
struct PolicyBundleHashable {
    format: String,
    schema_version: String,
    bundle_id: String,
    zone_id: ZoneId,
    policy_seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_bundle: Option<String>,
    hash_algo: String,
    policies: Vec<PolicyBundlePolicyRef>,
}

/// Compute the deterministic bundle hash for a policy bundle.
///
/// The hash is computed over a canonicalized payload that excludes the
/// signature and the bundle hash itself.
///
/// # Errors
/// Returns [`PolicyBundleError::InvalidBundle`] if policies are empty.
/// Returns [`PolicyBundleError::CanonicalizationFailed`] if serialization fails.
pub fn compute_policy_bundle_hash(
    bundle_id: &str,
    zone_id: &ZoneId,
    policy_seq: u64,
    created_at: Option<DateTime<Utc>>,
    previous_bundle: Option<&str>,
    policies: &[PolicyBundlePolicyRef],
) -> Result<String, PolicyBundleError> {
    if policies.is_empty() {
        return Err(PolicyBundleError::InvalidBundle {
            reason: "policies cannot be empty".to_string(),
        });
    }

    let mut policies_sorted = policies.to_vec();
    policies_sorted.sort_by(|a, b| {
        a.object_id
            .cmp(&b.object_id)
            .then(a.schema_id.cmp(&b.schema_id))
            .then(a.object_hash.cmp(&b.object_hash))
    });

    let hashable = PolicyBundleHashable {
        format: POLICY_BUNDLE_FORMAT.to_string(),
        schema_version: POLICY_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_id: bundle_id.to_string(),
        zone_id: zone_id.clone(),
        policy_seq,
        created_at,
        previous_bundle: previous_bundle.map(ToString::to_string),
        hash_algo: POLICY_BUNDLE_HASH_ALGO.to_string(),
        policies: policies_sorted,
    };

    let cbor = to_deterministic_cbor(&hashable).map_err(|err| {
        PolicyBundleError::CanonicalizationFailed {
            reason: err.to_string(),
        }
    })?;
    let hash = blake3::hash(&cbor).to_hex().to_string();

    Ok(format!("{POLICY_BUNDLE_HASH_ALGO}:{hash}"))
}

/// Signed policy bundle (NORMATIVE).
///
/// Matches the `PolicyBundle_v1.schema.json` specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBundle {
    /// Format identifier (always "fcp-policy-bundle").
    pub format: String,

    /// Schema version (always "1.0" for v1).
    pub schema_version: String,

    /// Unique bundle identifier.
    pub bundle_id: String,

    /// Zone this bundle applies to.
    pub zone_id: ZoneId,

    /// Monotonic policy sequence number.
    pub policy_seq: u64,

    /// Bundle creation timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,

    /// Previous bundle ID, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_bundle: Option<String>,

    /// Hash algorithm for bundle hash (always "blake3-256").
    pub hash_algo: String,

    /// Bundle hash in format `blake3-256:<hex>`.
    pub bundle_hash: String,

    /// Policies referenced by this bundle.
    pub policies: Vec<PolicyBundlePolicyRef>,

    /// Ed25519 signature.
    pub signature: PolicyBundleSignature,
}

impl PolicyBundle {
    /// Create a new policy bundle builder.
    #[must_use]
    pub fn builder(
        bundle_id: impl Into<String>,
        zone_id: ZoneId,
        policy_seq: u64,
    ) -> PolicyBundleBuilder {
        PolicyBundleBuilder::new(bundle_id, zone_id, policy_seq)
    }

    /// Compute deterministic signing bytes for the policy bundle.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyBundleError::CanonicalizationFailed`] if serialization fails.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, PolicyBundleError> {
        let signable = PolicyBundleSignable {
            format: self.format.clone(),
            schema_version: self.schema_version.clone(),
            bundle_id: self.bundle_id.clone(),
            zone_id: self.zone_id.clone(),
            policy_seq: self.policy_seq,
            created_at: self.created_at,
            previous_bundle: self.previous_bundle.clone(),
            hash_algo: self.hash_algo.clone(),
            bundle_hash: self.bundle_hash.clone(),
            policies: self.policies.clone(),
        };

        let cbor = to_deterministic_cbor(&signable).map_err(|err| {
            PolicyBundleError::CanonicalizationFailed {
                reason: err.to_string(),
            }
        })?;
        Ok(canonical_signing_bytes(POLICY_BUNDLE_SCHEMA_ID, &cbor))
    }

    /// Validate the policy bundle structure.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyBundleError::InvalidBundle`] if validation fails.
    pub fn validate(&self) -> Result<(), PolicyBundleError> {
        if self.format != POLICY_BUNDLE_FORMAT {
            return Err(PolicyBundleError::InvalidBundle {
                reason: format!(
                    "format must be '{POLICY_BUNDLE_FORMAT}', got '{}'",
                    self.format
                ),
            });
        }
        if self.schema_version != POLICY_BUNDLE_SCHEMA_VERSION {
            return Err(PolicyBundleError::InvalidBundle {
                reason: format!(
                    "schema_version must be '{POLICY_BUNDLE_SCHEMA_VERSION}', got '{}'",
                    self.schema_version
                ),
            });
        }
        if self.bundle_id.is_empty() {
            return Err(PolicyBundleError::InvalidBundle {
                reason: "bundle_id cannot be empty".to_string(),
            });
        }
        if self.hash_algo != POLICY_BUNDLE_HASH_ALGO {
            return Err(PolicyBundleError::InvalidBundle {
                reason: format!(
                    "hash_algo must be '{POLICY_BUNDLE_HASH_ALGO}', got '{}'",
                    self.hash_algo
                ),
            });
        }
        if !hash_has_blake3_prefix(&self.bundle_hash) {
            return Err(PolicyBundleError::InvalidBundle {
                reason: "bundle_hash must be in format 'blake3-256:<hex>'".to_string(),
            });
        }
        if self.policies.is_empty() {
            return Err(PolicyBundleError::InvalidBundle {
                reason: "policies cannot be empty".to_string(),
            });
        }
        for policy in &self.policies {
            policy.validate()?;
        }
        self.signature.validate()?;
        let expected_signed_fields: Vec<String> = POLICY_BUNDLE_SIGNED_FIELDS
            .iter()
            .map(|field| (*field).to_string())
            .collect();
        if self.signature.signed_fields != expected_signed_fields {
            return Err(PolicyBundleError::InvalidBundle {
                reason: format!(
                    "signature.signed_fields must exactly match [{}]",
                    POLICY_BUNDLE_SIGNED_FIELDS.join(", ")
                ),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
struct PolicyBundleSignable {
    format: String,
    schema_version: String,
    bundle_id: String,
    zone_id: ZoneId,
    policy_seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_bundle: Option<String>,
    hash_algo: String,
    bundle_hash: String,
    policies: Vec<PolicyBundlePolicyRef>,
}

/// Reference to a policy object within a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBundlePolicyRef {
    pub object_id: String,
    pub schema_id: String,
    pub object_hash: String,
}

impl PolicyBundlePolicyRef {
    /// Validate the policy reference structure.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyBundleError::InvalidBundle`] if validation fails.
    pub fn validate(&self) -> Result<(), PolicyBundleError> {
        if self.object_id.is_empty() {
            return Err(PolicyBundleError::InvalidBundle {
                reason: "policies.object_id cannot be empty".to_string(),
            });
        }
        if self.schema_id.is_empty() {
            return Err(PolicyBundleError::InvalidBundle {
                reason: "policies.schema_id cannot be empty".to_string(),
            });
        }
        if !hash_has_blake3_prefix(&self.object_hash) {
            return Err(PolicyBundleError::InvalidBundle {
                reason: "policies.object_hash must be in format 'blake3-256:<hex>'".to_string(),
            });
        }
        Ok(())
    }
}

/// Ed25519 signature for policy bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBundleSignature {
    /// Signature algorithm (always "ed25519").
    pub algorithm: String,

    /// Key identifier used for signing.
    pub key_id: String,

    /// Base64 or hex encoded signature.
    pub signature: String,

    /// Fields that were signed.
    pub signed_fields: Vec<String>,
}

impl PolicyBundleSignature {
    /// Create a new Ed25519 signature.
    #[must_use]
    pub fn new(
        key_id: impl Into<String>,
        signature: impl Into<String>,
        signed_fields: Vec<String>,
    ) -> Self {
        Self {
            algorithm: "ed25519".to_string(),
            key_id: key_id.into(),
            signature: signature.into(),
            signed_fields,
        }
    }

    /// Validate the signature structure.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyBundleError::InvalidBundle`] if validation fails.
    pub fn validate(&self) -> Result<(), PolicyBundleError> {
        if self.algorithm != "ed25519" {
            return Err(PolicyBundleError::InvalidBundle {
                reason: format!("algorithm must be 'ed25519', got '{}'", self.algorithm),
            });
        }
        if self.key_id.is_empty() {
            return Err(PolicyBundleError::InvalidBundle {
                reason: "key_id cannot be empty".to_string(),
            });
        }
        if self.signature.is_empty() {
            return Err(PolicyBundleError::InvalidBundle {
                reason: "signature cannot be empty".to_string(),
            });
        }
        if self.signed_fields.is_empty() {
            return Err(PolicyBundleError::InvalidBundle {
                reason: "signed_fields cannot be empty".to_string(),
            });
        }
        Ok(())
    }
}

/// Builder for [`PolicyBundle`].
#[derive(Debug, Clone)]
pub struct PolicyBundleBuilder {
    bundle_id: String,
    zone_id: ZoneId,
    policy_seq: u64,
    created_at: Option<DateTime<Utc>>,
    previous_bundle: Option<String>,
    bundle_hash: Option<String>,
    policies: Option<Vec<PolicyBundlePolicyRef>>,
    signature: Option<PolicyBundleSignature>,
}

impl PolicyBundleBuilder {
    fn new(bundle_id: impl Into<String>, zone_id: ZoneId, policy_seq: u64) -> Self {
        Self {
            bundle_id: bundle_id.into(),
            zone_id,
            policy_seq,
            created_at: None,
            previous_bundle: None,
            bundle_hash: None,
            policies: None,
            signature: None,
        }
    }

    /// Set creation timestamp.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn created_at(mut self, created_at: DateTime<Utc>) -> Self {
        self.created_at = Some(created_at);
        self
    }

    /// Set previous bundle ID.
    #[must_use]
    pub fn previous_bundle(mut self, previous_bundle: impl Into<String>) -> Self {
        self.previous_bundle = Some(previous_bundle.into());
        self
    }

    /// Set bundle hash.
    #[must_use]
    pub fn bundle_hash(mut self, bundle_hash: impl Into<String>) -> Self {
        self.bundle_hash = Some(bundle_hash.into());
        self
    }

    /// Set policy references.
    #[must_use]
    pub fn policies(mut self, policies: Vec<PolicyBundlePolicyRef>) -> Self {
        self.policies = Some(policies);
        self
    }

    /// Set the signature.
    #[must_use]
    pub fn signature(mut self, signature: PolicyBundleSignature) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Build the policy bundle.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyBundleError::InvalidBundle`] if required fields are missing.
    pub fn build(self) -> Result<PolicyBundle, PolicyBundleError> {
        let bundle_hash = self
            .bundle_hash
            .ok_or_else(|| PolicyBundleError::InvalidBundle {
                reason: "bundle_hash is required".to_string(),
            })?;
        let policies = self
            .policies
            .ok_or_else(|| PolicyBundleError::InvalidBundle {
                reason: "policies are required".to_string(),
            })?;
        let signature = self
            .signature
            .ok_or_else(|| PolicyBundleError::InvalidBundle {
                reason: "signature is required".to_string(),
            })?;

        let bundle = PolicyBundle {
            format: POLICY_BUNDLE_FORMAT.to_string(),
            schema_version: POLICY_BUNDLE_SCHEMA_VERSION.to_string(),
            bundle_id: self.bundle_id,
            zone_id: self.zone_id,
            policy_seq: self.policy_seq,
            created_at: self.created_at,
            previous_bundle: self.previous_bundle,
            hash_algo: POLICY_BUNDLE_HASH_ALGO.to_string(),
            bundle_hash,
            policies,
            signature,
        };

        bundle.validate()?;
        Ok(bundle)
    }
}

/// Errors that can occur during policy bundle operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyBundleError {
    /// Invalid policy bundle.
    InvalidBundle {
        /// Reason for invalidity.
        reason: String,
    },

    /// Canonicalization failed.
    CanonicalizationFailed {
        /// Details about the failure.
        reason: String,
    },
}

impl fmt::Display for PolicyBundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBundle { reason } => write!(f, "invalid policy bundle: {reason}"),
            Self::CanonicalizationFailed { reason } => {
                write!(f, "canonicalization failed: {reason}")
            }
        }
    }
}

impl std::error::Error for PolicyBundleError {}

fn hash_has_blake3_prefix(value: &str) -> bool {
    value.strip_prefix("blake3-256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy Bundle Diff + Risk Summary
// ─────────────────────────────────────────────────────────────────────────────

/// Resolved policy bundle with referenced objects loaded.
#[derive(Debug, Clone)]
pub struct PolicyBundleResolved {
    pub bundle: PolicyBundle,
    pub objects: BTreeMap<String, PolicyBundleObject>,
}

impl PolicyBundleResolved {
    #[allow(clippy::missing_const_for_fn)]
    #[must_use]
    pub fn new(bundle: PolicyBundle, objects: BTreeMap<String, PolicyBundleObject>) -> Self {
        Self { bundle, objects }
    }
}

/// Policy bundle object variants.
#[derive(Debug, Clone)]
pub enum PolicyBundleObject {
    ZonePolicy(ZonePolicyObject),
    ZoneDefinition(ZoneDefinitionObject),
    Role(RoleObject),
    Resource(ResourceObject),
    Capability(CapabilityObject),
}

/// Policy bundle reference change (same `object_id`, different hash/schema).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBundlePolicyRefChange {
    pub object_id: String,
    pub schema_id_before: String,
    pub schema_id_after: String,
    pub hash_before: String,
    pub hash_after: String,
}

/// Zone policy diff (stable ordering).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ZonePolicyDiff {
    pub added: PolicyListDiff,
    pub removed: PolicyListDiff,
    pub changed: PolicyChangedFields,
}

/// List diff for policy allow/deny/ceiling sets.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyListDiff {
    pub principal_allow: Vec<String>,
    pub principal_deny: Vec<String>,
    pub connector_allow: Vec<String>,
    pub connector_deny: Vec<String>,
    pub capability_allow: Vec<String>,
    pub capability_deny: Vec<String>,
    pub capability_ceiling: Vec<String>,
}

/// Changed scalar fields in a policy object.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyChangedFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_policy: Option<TransportPolicyChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_receipts: Option<Change<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_posture: Option<Change<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_budget: Option<Change<Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportPolicyChange {
    pub before: ZoneTransportPolicy,
    pub after: ZoneTransportPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change<T> {
    pub before: T,
    pub after: T,
}

/// Zone definition diff (JSON field-level).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneDefinitionDiff {
    pub added: BTreeMap<String, Value>,
    pub removed: BTreeMap<String, Value>,
    pub changed: BTreeMap<String, Change<Value>>,
}

/// Role diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDiff {
    pub name: String,
    pub added_caps: Vec<String>,
    pub removed_caps: Vec<String>,
    pub added_includes: Vec<String>,
    pub removed_includes: Vec<String>,
}

/// Resource diff (integrity/confidentiality only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDiff {
    pub resource_uri: String,
    pub integrity_before: IntegrityLevel,
    pub integrity_after: IntegrityLevel,
    pub confidentiality_before: ConfidentialityLevel,
    pub confidentiality_after: ConfidentialityLevel,
}

/// Capability object diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityDiff {
    pub object_id: String,
    pub added_caps: Vec<String>,
    pub removed_caps: Vec<String>,
    pub resource_allow_added: Vec<String>,
    pub resource_allow_removed: Vec<String>,
}

/// Risk summary with stable ordering.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyRiskSummary {
    pub flags: Vec<PolicyRiskFlag>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRiskFlag {
    pub code: PolicyRiskCode,
    pub severity: PolicyRiskSeverity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRiskCode {
    PrincipalAllowExpanded,
    ConnectorAllowExpanded,
    CapabilityAllowExpanded,
    CapabilityCeilingExpanded,
    CapabilityDenyReduced,
    RoleExpanded,
    EgressExpanded,
    TransportDerpEnabled,
    TransportFunnelEnabled,
    TransportLanEnabled,
    IntegrityLowered,
    ConfidentialityLowered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRiskSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Diff output for policy bundles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBundleDiff {
    pub zone_id: ZoneId,
    pub before_bundle_id: String,
    pub after_bundle_id: String,
    pub added: Vec<PolicyBundlePolicyRef>,
    pub removed: Vec<PolicyBundlePolicyRef>,
    pub changed: Vec<PolicyBundlePolicyRefChange>,
    pub zone_policy: Option<ZonePolicyDiff>,
    pub zone_definition: Option<ZoneDefinitionDiff>,
    pub roles: Vec<RoleDiff>,
    pub resources: Vec<ResourceDiff>,
    pub capabilities: Vec<CapabilityDiff>,
    pub missing_objects: Vec<String>,
    pub risk: PolicyRiskSummary,
}

/// Errors raised during policy diffing.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PolicyDiffError {
    #[error("zone mismatch: {before} vs {after}")]
    ZoneMismatch { before: ZoneId, after: ZoneId },
    #[error("serialization failed: {0}")]
    Serialization(String),
}

/// Diff two resolved policy bundles with deterministic ordering.
///
/// # Errors
/// Returns [`PolicyDiffError`] if zones mismatch or serialization fails.
pub fn diff_policy_bundles(
    before: &PolicyBundleResolved,
    after: &PolicyBundleResolved,
) -> Result<PolicyBundleDiff, PolicyDiffError> {
    if before.bundle.zone_id != after.bundle.zone_id {
        return Err(PolicyDiffError::ZoneMismatch {
            before: before.bundle.zone_id.clone(),
            after: after.bundle.zone_id.clone(),
        });
    }

    let (added, removed, changed) = diff_policy_refs(&before.bundle, &after.bundle);

    let mut missing_objects = Vec::new();
    let zone_policy_before = resolve_zone_policy(before, &mut missing_objects);
    let zone_policy_after = resolve_zone_policy(after, &mut missing_objects);
    let zone_policy = match (zone_policy_before, zone_policy_after) {
        (Some(before_policy), Some(after_policy)) => {
            Some(diff_zone_policy(before_policy, after_policy)?)
        }
        _ => None,
    };

    let zone_definition_before = resolve_zone_definition(before, &mut missing_objects);
    let zone_definition_after = resolve_zone_definition(after, &mut missing_objects);
    let zone_definition = match (zone_definition_before, zone_definition_after) {
        (Some(before_def), Some(after_def)) => Some(diff_zone_definition(before_def, after_def)?),
        _ => None,
    };

    let roles = diff_roles(before, after, &mut missing_objects);
    let resources = diff_resources(before, after, &mut missing_objects);
    let capabilities = diff_capabilities(before, after, &mut missing_objects);
    let missing_objects = missing_objects
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let risk = compute_policy_risk_summary(
        zone_policy.as_ref(),
        zone_definition_before,
        zone_definition_after,
        &roles,
        &resources,
        &capabilities,
    );

    Ok(PolicyBundleDiff {
        zone_id: before.bundle.zone_id.clone(),
        before_bundle_id: before.bundle.bundle_id.clone(),
        after_bundle_id: after.bundle.bundle_id.clone(),
        added,
        removed,
        changed,
        zone_policy,
        zone_definition,
        roles,
        resources,
        capabilities,
        missing_objects,
        risk,
    })
}

fn diff_policy_refs(
    before: &PolicyBundle,
    after: &PolicyBundle,
) -> (
    Vec<PolicyBundlePolicyRef>,
    Vec<PolicyBundlePolicyRef>,
    Vec<PolicyBundlePolicyRefChange>,
) {
    let before_map = policy_ref_map(before);
    let after_map = policy_ref_map(after);
    let before_keys: BTreeSet<String> = before_map.keys().cloned().collect();
    let after_keys: BTreeSet<String> = after_map.keys().cloned().collect();

    let added = after_keys
        .difference(&before_keys)
        .filter_map(|key| after_map.get(key).cloned())
        .collect::<Vec<_>>();
    let removed = before_keys
        .difference(&after_keys)
        .filter_map(|key| before_map.get(key).cloned())
        .collect::<Vec<_>>();

    let mut changed = Vec::new();
    for key in before_keys.intersection(&after_keys) {
        if let (Some(before_ref), Some(after_ref)) = (before_map.get(key), after_map.get(key)) {
            if before_ref.schema_id != after_ref.schema_id
                || before_ref.object_hash != after_ref.object_hash
            {
                changed.push(PolicyBundlePolicyRefChange {
                    object_id: key.clone(),
                    schema_id_before: before_ref.schema_id.clone(),
                    schema_id_after: after_ref.schema_id.clone(),
                    hash_before: before_ref.object_hash.clone(),
                    hash_after: after_ref.object_hash.clone(),
                });
            }
        }
    }

    (added, removed, changed)
}

fn policy_ref_map(bundle: &PolicyBundle) -> BTreeMap<String, PolicyBundlePolicyRef> {
    bundle
        .policies
        .iter()
        .map(|policy| (policy.object_id.clone(), policy.clone()))
        .collect()
}

fn resolve_zone_policy<'a>(
    bundle: &'a PolicyBundleResolved,
    missing: &mut Vec<String>,
) -> Option<&'a ZonePolicyObject> {
    resolve_object_by_schema(bundle, "ZonePolicy", missing).and_then(|obj| match obj {
        PolicyBundleObject::ZonePolicy(policy) => Some(policy),
        _ => None,
    })
}

fn resolve_zone_definition<'a>(
    bundle: &'a PolicyBundleResolved,
    missing: &mut Vec<String>,
) -> Option<&'a ZoneDefinitionObject> {
    resolve_object_by_schema(bundle, "ZoneDefinition", missing).and_then(|obj| match obj {
        PolicyBundleObject::ZoneDefinition(definition) => Some(definition),
        _ => None,
    })
}

fn resolve_object_by_schema<'a>(
    bundle: &'a PolicyBundleResolved,
    schema_name: &str,
    missing: &mut Vec<String>,
) -> Option<&'a PolicyBundleObject> {
    let schema_prefix = format!("fcp.core:{schema_name}@");
    let policy_ref = bundle
        .bundle
        .policies
        .iter()
        .find(|policy| policy.schema_id.starts_with(&schema_prefix))?;

    bundle.objects.get(&policy_ref.object_id).map_or_else(
        || {
            missing.push(policy_ref.object_id.clone());
            None
        },
        Some,
    )
}

fn diff_zone_policy(
    before: &ZonePolicyObject,
    after: &ZonePolicyObject,
) -> Result<ZonePolicyDiff, PolicyDiffError> {
    let (added, removed) = diff_policy_lists(before, after);
    let changed = diff_policy_changed(before, after)?;

    Ok(ZonePolicyDiff {
        added,
        removed,
        changed,
    })
}

fn diff_zone_definition(
    before: &ZoneDefinitionObject,
    after: &ZoneDefinitionObject,
) -> Result<ZoneDefinitionDiff, PolicyDiffError> {
    let before_json = serde_json::to_value(before).map_err(|err| {
        PolicyDiffError::Serialization(format!("zone definition serialize: {err}"))
    })?;
    let after_json = serde_json::to_value(after).map_err(|err| {
        PolicyDiffError::Serialization(format!("zone definition serialize: {err}"))
    })?;

    diff_json_objects(&before_json, &after_json)
}

fn diff_policy_lists(
    before: &ZonePolicyObject,
    after: &ZonePolicyObject,
) -> (PolicyListDiff, PolicyListDiff) {
    let (principal_allow_added, principal_allow_removed) =
        diff_patterns(&before.principal_allow, &after.principal_allow);
    let (principal_deny_added, principal_deny_removed) =
        diff_patterns(&before.principal_deny, &after.principal_deny);
    let (connector_allow_added, connector_allow_removed) =
        diff_patterns(&before.connector_allow, &after.connector_allow);
    let (connector_deny_added, connector_deny_removed) =
        diff_patterns(&before.connector_deny, &after.connector_deny);
    let (capability_allow_added, capability_allow_removed) =
        diff_patterns(&before.capability_allow, &after.capability_allow);
    let (capability_deny_added, capability_deny_removed) =
        diff_patterns(&before.capability_deny, &after.capability_deny);
    let (capability_ceiling_added, capability_ceiling_removed) =
        diff_capability_ids(&before.capability_ceiling, &after.capability_ceiling);

    let added = PolicyListDiff {
        principal_allow: principal_allow_added,
        principal_deny: principal_deny_added,
        connector_allow: connector_allow_added,
        connector_deny: connector_deny_added,
        capability_allow: capability_allow_added,
        capability_deny: capability_deny_added,
        capability_ceiling: capability_ceiling_added,
    };
    let removed = PolicyListDiff {
        principal_allow: principal_allow_removed,
        principal_deny: principal_deny_removed,
        connector_allow: connector_allow_removed,
        connector_deny: connector_deny_removed,
        capability_allow: capability_allow_removed,
        capability_deny: capability_deny_removed,
        capability_ceiling: capability_ceiling_removed,
    };

    (added, removed)
}

fn diff_policy_changed(
    before: &ZonePolicyObject,
    after: &ZonePolicyObject,
) -> Result<PolicyChangedFields, PolicyDiffError> {
    let mut changed = PolicyChangedFields::default();

    if transport_policy_changed(&before.transport_policy, &after.transport_policy) {
        changed.transport_policy = Some(TransportPolicyChange {
            before: before.transport_policy.clone(),
            after: after.transport_policy.clone(),
        });
    }

    let decision_before = serde_json::to_value(&before.decision_receipts).map_err(|err| {
        PolicyDiffError::Serialization(format!("decision_receipts serialize: {err}"))
    })?;
    let decision_after = serde_json::to_value(&after.decision_receipts).map_err(|err| {
        PolicyDiffError::Serialization(format!("decision_receipts serialize: {err}"))
    })?;
    if decision_before != decision_after {
        changed.decision_receipts = Some(Change {
            before: decision_before,
            after: decision_after,
        });
    }

    let posture_before = serde_json::to_value(&before.requires_posture).map_err(|err| {
        PolicyDiffError::Serialization(format!("requires_posture serialize: {err}"))
    })?;
    let posture_after = serde_json::to_value(&after.requires_posture).map_err(|err| {
        PolicyDiffError::Serialization(format!("requires_posture serialize: {err}"))
    })?;
    if posture_before != posture_after {
        changed.requires_posture = Some(Change {
            before: posture_before,
            after: posture_after,
        });
    }

    let usage_before = serde_json::to_value(&before.usage_budget)
        .map_err(|err| PolicyDiffError::Serialization(format!("usage_budget serialize: {err}")))?;
    let usage_after = serde_json::to_value(&after.usage_budget)
        .map_err(|err| PolicyDiffError::Serialization(format!("usage_budget serialize: {err}")))?;
    if usage_before != usage_after {
        changed.usage_budget = Some(Change {
            before: usage_before,
            after: usage_after,
        });
    }

    Ok(changed)
}

fn diff_json_objects(before: &Value, after: &Value) -> Result<ZoneDefinitionDiff, PolicyDiffError> {
    let before_obj = before
        .as_object()
        .ok_or_else(|| PolicyDiffError::Serialization("before is not object".to_string()))?;
    let after_obj = after
        .as_object()
        .ok_or_else(|| PolicyDiffError::Serialization("after is not object".to_string()))?;

    let mut added = BTreeMap::new();
    let mut removed = BTreeMap::new();
    let mut changed = BTreeMap::new();

    let ignore_keys = ["signature", "header", "prev"];

    for (key, value) in before_obj {
        if ignore_keys.contains(&key.as_str()) {
            continue;
        }
        if !after_obj.contains_key(key) {
            removed.insert(key.clone(), value.clone());
        } else if let Some(after_value) = after_obj.get(key) {
            if after_value != value {
                changed.insert(
                    key.clone(),
                    Change {
                        before: value.clone(),
                        after: after_value.clone(),
                    },
                );
            }
        }
    }

    for (key, value) in after_obj {
        if ignore_keys.contains(&key.as_str()) {
            continue;
        }
        if !before_obj.contains_key(key) {
            added.insert(key.clone(), value.clone());
        }
    }

    Ok(ZoneDefinitionDiff {
        added,
        removed,
        changed,
    })
}

fn diff_patterns(before: &[PolicyPattern], after: &[PolicyPattern]) -> (Vec<String>, Vec<String>) {
    let before_set: BTreeSet<String> = before.iter().map(|p| p.pattern.clone()).collect();
    let after_set: BTreeSet<String> = after.iter().map(|p| p.pattern.clone()).collect();

    let added = after_set
        .difference(&before_set)
        .cloned()
        .collect::<Vec<_>>();
    let removed = before_set
        .difference(&after_set)
        .cloned()
        .collect::<Vec<_>>();

    (added, removed)
}

fn diff_capability_ids(
    before: &[CapabilityId],
    after: &[CapabilityId],
) -> (Vec<String>, Vec<String>) {
    let before_set: BTreeSet<String> = before.iter().map(|c| c.as_str().to_string()).collect();
    let after_set: BTreeSet<String> = after.iter().map(|c| c.as_str().to_string()).collect();

    let added = after_set
        .difference(&before_set)
        .cloned()
        .collect::<Vec<_>>();
    let removed = before_set
        .difference(&after_set)
        .cloned()
        .collect::<Vec<_>>();

    (added, removed)
}

const fn transport_policy_changed(
    before: &ZoneTransportPolicy,
    after: &ZoneTransportPolicy,
) -> bool {
    before.allow_lan != after.allow_lan
        || before.allow_derp != after.allow_derp
        || before.allow_funnel != after.allow_funnel
}

fn diff_roles(
    before: &PolicyBundleResolved,
    after: &PolicyBundleResolved,
    missing: &mut Vec<String>,
) -> Vec<RoleDiff> {
    let before_roles = collect_roles(before, missing);
    let after_roles = collect_roles(after, missing);
    let names: BTreeSet<String> = before_roles
        .keys()
        .chain(after_roles.keys())
        .cloned()
        .collect();

    let mut diffs = Vec::new();
    for name in names {
        let before_role = before_roles.get(&name);
        let after_role = after_roles.get(&name);
        let (added_caps, removed_caps, added_includes, removed_includes) =
            diff_role_fields(before_role, after_role);

        if added_caps.is_empty()
            && removed_caps.is_empty()
            && added_includes.is_empty()
            && removed_includes.is_empty()
        {
            continue;
        }

        diffs.push(RoleDiff {
            name: name.clone(),
            added_caps,
            removed_caps,
            added_includes,
            removed_includes,
        });
    }

    diffs
}

fn collect_roles(
    bundle: &PolicyBundleResolved,
    missing: &mut Vec<String>,
) -> BTreeMap<String, RoleObject> {
    let schema_prefix = "fcp.core:RoleObject@";
    let mut roles = BTreeMap::new();

    for policy_ref in &bundle.bundle.policies {
        if !policy_ref.schema_id.starts_with(schema_prefix) {
            continue;
        }
        match bundle.objects.get(&policy_ref.object_id) {
            Some(PolicyBundleObject::Role(role)) => {
                roles.insert(role.name.clone(), role.clone());
            }
            Some(_) => {}
            None => missing.push(policy_ref.object_id.clone()),
        }
    }

    roles
}

fn diff_role_fields(
    before: Option<&RoleObject>,
    after: Option<&RoleObject>,
) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    let before_caps = before.map_or_else(BTreeSet::new, |role| {
        role.caps.iter().map(capability_grant_key).collect()
    });
    let after_caps = after.map_or_else(BTreeSet::new, |role| {
        role.caps.iter().map(capability_grant_key).collect()
    });

    let added_caps = after_caps
        .difference(&before_caps)
        .cloned()
        .collect::<Vec<_>>();
    let removed_caps = before_caps
        .difference(&after_caps)
        .cloned()
        .collect::<Vec<_>>();

    let before_includes = before.map_or_else(BTreeSet::new, |role| {
        role.includes.iter().map(ToString::to_string).collect()
    });
    let after_includes = after.map_or_else(BTreeSet::new, |role| {
        role.includes.iter().map(ToString::to_string).collect()
    });

    let added_includes = after_includes
        .difference(&before_includes)
        .cloned()
        .collect::<Vec<_>>();
    let removed_includes = before_includes
        .difference(&after_includes)
        .cloned()
        .collect::<Vec<_>>();

    (added_caps, removed_caps, added_includes, removed_includes)
}

fn capability_grant_key(grant: &CapabilityGrant) -> String {
    grant.operation.as_ref().map_or_else(
        || grant.capability.as_str().to_string(),
        |operation| format!("{}/{}", grant.capability.as_str(), operation.as_str()),
    )
}

fn diff_resources(
    before: &PolicyBundleResolved,
    after: &PolicyBundleResolved,
    missing: &mut Vec<String>,
) -> Vec<ResourceDiff> {
    let before_resources = collect_resources(before, missing);
    let after_resources = collect_resources(after, missing);
    let keys: BTreeSet<String> = before_resources
        .keys()
        .chain(after_resources.keys())
        .cloned()
        .collect();

    let mut diffs = Vec::new();
    for key in keys {
        let before_res = before_resources.get(&key);
        let after_res = after_resources.get(&key);
        if let (Some(before_obj), Some(after_obj)) = (before_res, after_res) {
            if before_obj.integrity_label != after_obj.integrity_label
                || before_obj.confidentiality_label != after_obj.confidentiality_label
            {
                diffs.push(ResourceDiff {
                    resource_uri: key.clone(),
                    integrity_before: before_obj.integrity_label,
                    integrity_after: after_obj.integrity_label,
                    confidentiality_before: before_obj.confidentiality_label,
                    confidentiality_after: after_obj.confidentiality_label,
                });
            }
        } else if let Some(before_obj) = before_res {
            diffs.push(ResourceDiff {
                resource_uri: key.clone(),
                integrity_before: before_obj.integrity_label,
                integrity_after: before_obj.integrity_label,
                confidentiality_before: before_obj.confidentiality_label,
                confidentiality_after: before_obj.confidentiality_label,
            });
        } else if let Some(after_obj) = after_res {
            diffs.push(ResourceDiff {
                resource_uri: key.clone(),
                integrity_before: after_obj.integrity_label,
                integrity_after: after_obj.integrity_label,
                confidentiality_before: after_obj.confidentiality_label,
                confidentiality_after: after_obj.confidentiality_label,
            });
        }
    }

    diffs
}

fn collect_resources(
    bundle: &PolicyBundleResolved,
    missing: &mut Vec<String>,
) -> BTreeMap<String, ResourceObject> {
    let schema_prefix = "fcp.core:ResourceObject@";
    let mut resources = BTreeMap::new();

    for policy_ref in &bundle.bundle.policies {
        if !policy_ref.schema_id.starts_with(schema_prefix) {
            continue;
        }
        match bundle.objects.get(&policy_ref.object_id) {
            Some(PolicyBundleObject::Resource(resource)) => {
                resources.insert(resource.resource_uri.clone(), resource.clone());
            }
            Some(_) => {}
            None => missing.push(policy_ref.object_id.clone()),
        }
    }

    resources
}

fn diff_capabilities(
    before: &PolicyBundleResolved,
    after: &PolicyBundleResolved,
    missing: &mut Vec<String>,
) -> Vec<CapabilityDiff> {
    let before_caps = collect_capabilities(before, missing);
    let after_caps = collect_capabilities(after, missing);
    let keys: BTreeSet<String> = before_caps
        .keys()
        .chain(after_caps.keys())
        .cloned()
        .collect();

    let mut diffs = Vec::new();
    for key in keys {
        let before_obj = before_caps.get(&key);
        let after_obj = after_caps.get(&key);
        let (added_caps, removed_caps) = diff_capability_grants(before_obj, after_obj);
        let (resource_allow_added, resource_allow_removed) =
            diff_resource_allow(before_obj, after_obj);

        if added_caps.is_empty()
            && removed_caps.is_empty()
            && resource_allow_added.is_empty()
            && resource_allow_removed.is_empty()
        {
            continue;
        }

        diffs.push(CapabilityDiff {
            object_id: key.clone(),
            added_caps,
            removed_caps,
            resource_allow_added,
            resource_allow_removed,
        });
    }

    diffs
}

fn collect_capabilities(
    bundle: &PolicyBundleResolved,
    missing: &mut Vec<String>,
) -> BTreeMap<String, CapabilityObject> {
    let schema_prefix = "fcp.core:CapabilityObject@";
    let mut caps = BTreeMap::new();

    for policy_ref in &bundle.bundle.policies {
        if !policy_ref.schema_id.starts_with(schema_prefix) {
            continue;
        }
        match bundle.objects.get(&policy_ref.object_id) {
            Some(PolicyBundleObject::Capability(capability)) => {
                caps.insert(policy_ref.object_id.clone(), capability.clone());
            }
            Some(_) => {}
            None => missing.push(policy_ref.object_id.clone()),
        }
    }

    caps
}

fn diff_capability_grants(
    before: Option<&CapabilityObject>,
    after: Option<&CapabilityObject>,
) -> (Vec<String>, Vec<String>) {
    let before_set = before.map_or_else(BTreeSet::new, |cap| {
        cap.caps.iter().map(capability_grant_key).collect()
    });
    let after_set = after.map_or_else(BTreeSet::new, |cap| {
        cap.caps.iter().map(capability_grant_key).collect()
    });

    let added = after_set
        .difference(&before_set)
        .cloned()
        .collect::<Vec<_>>();
    let removed = before_set
        .difference(&after_set)
        .cloned()
        .collect::<Vec<_>>();

    (added, removed)
}

fn diff_resource_allow(
    before: Option<&CapabilityObject>,
    after: Option<&CapabilityObject>,
) -> (Vec<String>, Vec<String>) {
    let before_set = before.map_or_else(BTreeSet::new, |cap| {
        cap.constraints.resource_allow.iter().cloned().collect()
    });
    let after_set = after.map_or_else(BTreeSet::new, |cap| {
        cap.constraints.resource_allow.iter().cloned().collect()
    });

    let added = after_set
        .difference(&before_set)
        .cloned()
        .collect::<Vec<_>>();
    let removed = before_set
        .difference(&after_set)
        .cloned()
        .collect::<Vec<_>>();

    (added, removed)
}

fn compute_policy_risk_summary(
    zone_policy: Option<&ZonePolicyDiff>,
    zone_definition_before: Option<&ZoneDefinitionObject>,
    zone_definition_after: Option<&ZoneDefinitionObject>,
    roles: &[RoleDiff],
    resources: &[ResourceDiff],
    capabilities: &[CapabilityDiff],
) -> PolicyRiskSummary {
    let mut flags: BTreeMap<PolicyRiskCode, PolicyRiskFlag> = BTreeMap::new();

    add_zone_policy_risks(&mut flags, zone_policy);
    add_role_risks(&mut flags, roles);
    add_capability_risks(&mut flags, capabilities);
    add_zone_definition_risks(&mut flags, zone_definition_before, zone_definition_after);
    add_resource_risks(&mut flags, resources);

    PolicyRiskSummary {
        flags: flags.into_values().collect(),
    }
}

fn add_zone_policy_risks(
    flags: &mut BTreeMap<PolicyRiskCode, PolicyRiskFlag>,
    zone_policy: Option<&ZonePolicyDiff>,
) {
    let Some(diff) = zone_policy else { return };

    if !diff.added.principal_allow.is_empty() {
        push_risk(
            flags,
            PolicyRiskCode::PrincipalAllowExpanded,
            PolicyRiskSeverity::Medium,
            None,
        );
    }
    if !diff.added.connector_allow.is_empty() {
        push_risk(
            flags,
            PolicyRiskCode::ConnectorAllowExpanded,
            PolicyRiskSeverity::Medium,
            None,
        );
    }
    if !diff.added.capability_allow.is_empty() {
        push_risk(
            flags,
            PolicyRiskCode::CapabilityAllowExpanded,
            PolicyRiskSeverity::High,
            None,
        );
    }
    if !diff.added.capability_ceiling.is_empty() {
        push_risk(
            flags,
            PolicyRiskCode::CapabilityCeilingExpanded,
            PolicyRiskSeverity::High,
            None,
        );
    }
    if !diff.removed.capability_deny.is_empty() {
        push_risk(
            flags,
            PolicyRiskCode::CapabilityDenyReduced,
            PolicyRiskSeverity::Medium,
            None,
        );
    }
    if let Some(ref transport) = diff.changed.transport_policy {
        if !transport.before.allow_derp && transport.after.allow_derp {
            push_risk(
                flags,
                PolicyRiskCode::TransportDerpEnabled,
                PolicyRiskSeverity::High,
                None,
            );
        }
        if !transport.before.allow_funnel && transport.after.allow_funnel {
            push_risk(
                flags,
                PolicyRiskCode::TransportFunnelEnabled,
                PolicyRiskSeverity::High,
                None,
            );
        }
        if !transport.before.allow_lan && transport.after.allow_lan {
            push_risk(
                flags,
                PolicyRiskCode::TransportLanEnabled,
                PolicyRiskSeverity::Medium,
                None,
            );
        }
    }
}

fn add_role_risks(flags: &mut BTreeMap<PolicyRiskCode, PolicyRiskFlag>, roles: &[RoleDiff]) {
    for role in roles {
        if !role.added_caps.is_empty() || !role.added_includes.is_empty() {
            push_risk(
                flags,
                PolicyRiskCode::RoleExpanded,
                PolicyRiskSeverity::Medium,
                Some(role.name.clone()),
            );
        }
    }
}

fn add_capability_risks(
    flags: &mut BTreeMap<PolicyRiskCode, PolicyRiskFlag>,
    capabilities: &[CapabilityDiff],
) {
    for capability in capabilities {
        if !capability.added_caps.is_empty() {
            push_risk(
                flags,
                PolicyRiskCode::CapabilityAllowExpanded,
                PolicyRiskSeverity::High,
                Some(capability.object_id.clone()),
            );
        }
        if !capability.resource_allow_added.is_empty() {
            push_risk(
                flags,
                PolicyRiskCode::EgressExpanded,
                PolicyRiskSeverity::High,
                Some(capability.object_id.clone()),
            );
        }
    }
}

fn add_zone_definition_risks(
    flags: &mut BTreeMap<PolicyRiskCode, PolicyRiskFlag>,
    before: Option<&ZoneDefinitionObject>,
    after: Option<&ZoneDefinitionObject>,
) {
    let (Some(before), Some(after)) = (before, after) else {
        return;
    };

    if after.integrity_level < before.integrity_level {
        push_risk(
            flags,
            PolicyRiskCode::IntegrityLowered,
            PolicyRiskSeverity::High,
            Some(format!(
                "{} -> {}",
                before.integrity_level, after.integrity_level
            )),
        );
    }
    if after.confidentiality_level < before.confidentiality_level {
        push_risk(
            flags,
            PolicyRiskCode::ConfidentialityLowered,
            PolicyRiskSeverity::High,
            Some(format!(
                "{} -> {}",
                before.confidentiality_level, after.confidentiality_level
            )),
        );
    }
}

fn add_resource_risks(
    flags: &mut BTreeMap<PolicyRiskCode, PolicyRiskFlag>,
    resources: &[ResourceDiff],
) {
    for resource in resources {
        if resource.integrity_after < resource.integrity_before {
            push_risk(
                flags,
                PolicyRiskCode::IntegrityLowered,
                PolicyRiskSeverity::High,
                Some(resource.resource_uri.clone()),
            );
        }
        if resource.confidentiality_after < resource.confidentiality_before {
            push_risk(
                flags,
                PolicyRiskCode::ConfidentialityLowered,
                PolicyRiskSeverity::High,
                Some(resource.resource_uri.clone()),
            );
        }
    }
}

fn push_risk(
    flags: &mut BTreeMap<PolicyRiskCode, PolicyRiskFlag>,
    code: PolicyRiskCode,
    severity: PolicyRiskSeverity,
    detail: Option<String>,
) {
    flags
        .entry(code)
        .and_modify(|flag| {
            if severity > flag.severity {
                flag.severity = severity;
            }
            if flag.detail.is_none() {
                flag.detail.clone_from(&detail);
            }
        })
        .or_insert(PolicyRiskFlag {
            code,
            severity,
            detail,
        });
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy Bundle Preview
// ─────────────────────────────────────────────────────────────────────────────

/// Policy preview sample for would-allow/deny evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPreviewSample {
    /// Sample identifier for stable reporting.
    pub id: String,
    /// Invocation request to evaluate.
    pub invoke_request: InvokeRequest,
    /// Transport mode to evaluate (default: LAN).
    #[serde(default = "default_transport_mode")]
    pub transport: TransportMode,
    /// Whether checkpoints are considered fresh.
    #[serde(default = "default_true")]
    pub checkpoint_fresh: bool,
    /// Whether revocations are considered fresh.
    #[serde(default = "default_true")]
    pub revocation_fresh: bool,
    /// Whether execution approval is required.
    #[serde(default)]
    pub execution_approval_required: bool,
    /// Sanitizer receipts to apply (optional).
    #[serde(default)]
    pub sanitizer_receipts: Vec<SanitizerReceipt>,
    /// Related object IDs (optional).
    #[serde(default)]
    pub related_object_ids: Vec<ObjectId>,
    /// Explicit request object ID override (optional).
    #[serde(default)]
    pub request_object_id: Option<ObjectId>,
    /// Explicit input hash override (optional).
    #[serde(default)]
    pub request_input_hash: Option<[u8; 32]>,
    /// Safety tier for the requested operation.
    #[serde(default = "default_safety_tier")]
    pub safety_tier: SafetyTier,
    /// Optional principal override (otherwise derived from capability token).
    #[serde(default)]
    pub principal: Option<String>,
    /// Optional capability id override (otherwise derived from capability token).
    #[serde(default)]
    pub capability_id: Option<String>,
    /// Optional explicit provenance record (otherwise derived from request/zone).
    #[serde(default)]
    pub provenance_record: Option<ProvenanceRecord>,
    /// Optional override for evaluation time (epoch ms).
    #[serde(default)]
    pub now_ms: Option<u64>,
    /// Optional device posture attestation.
    #[serde(default)]
    pub posture_attestation: Option<crate::posture::PostureAttestation>,
}

impl PolicyPreviewSample {
    fn to_simulation_input(&self, zone_policy: ZonePolicyObject) -> PolicySimulationInput {
        PolicySimulationInput {
            zone_policy,
            invoke_request: self.invoke_request.clone(),
            transport: self.transport,
            checkpoint_fresh: self.checkpoint_fresh,
            revocation_fresh: self.revocation_fresh,
            execution_approval_required: self.execution_approval_required,
            sanitizer_receipts: self.sanitizer_receipts.clone(),
            related_object_ids: self.related_object_ids.clone(),
            request_object_id: self.request_object_id,
            request_input_hash: self.request_input_hash,
            safety_tier: self.safety_tier,
            principal: self.principal.clone(),
            capability_id: self.capability_id.clone(),
            provenance_record: self.provenance_record.clone(),
            now_ms: self.now_ms,
            posture_attestation: self.posture_attestation.clone(),
        }
    }
}

/// Preview decision classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyPreviewDecision {
    Allow,
    Deny,
    RequireApproval,
}

/// Preview delta classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyPreviewDelta {
    WouldAllow,
    WouldDeny,
    WouldRequireApproval,
    ReasonChanged,
}

impl PolicyPreviewDelta {
    /// Stable operator-facing policy effect token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WouldAllow => "would_allow",
            Self::WouldDeny => "would_deny",
            Self::WouldRequireApproval => "would_require_approval",
            Self::ReasonChanged => "reason_changed",
        }
    }
}

impl fmt::Display for PolicyPreviewDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Preview evaluation for a single sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPreviewEntry {
    pub sample_id: String,
    pub before: DecisionReceipt,
    pub after: DecisionReceipt,
    pub before_decision: PolicyPreviewDecision,
    pub after_decision: PolicyPreviewDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<PolicyPreviewDelta>,
}

/// Summary of preview outcomes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyPreviewSummary {
    pub total: usize,
    pub would_allow: usize,
    pub would_deny: usize,
    pub would_require_approval: usize,
    pub reason_changed: usize,
}

/// Policy bundle preview report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPreviewReport {
    pub zone_id: ZoneId,
    pub before_bundle_id: String,
    pub after_bundle_id: String,
    pub entries: Vec<PolicyPreviewEntry>,
    pub summary: PolicyPreviewSummary,
}

/// Errors raised during policy preview.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PolicyPreviewError {
    #[error("zone mismatch: {before} vs {after}")]
    ZoneMismatch { before: ZoneId, after: ZoneId },
    #[error("missing zone policy in {which} bundle")]
    MissingZonePolicy { which: &'static str },
    #[error("policy simulation failed for sample '{sample_id}' ({stage}): {message}")]
    SimulationFailed {
        sample_id: String,
        stage: &'static str,
        message: String,
    },
}

/// Preview a policy bundle change with sample invocations.
///
/// # Errors
/// Returns [`PolicyPreviewError`] if zones mismatch, required policies are missing,
/// or simulation fails.
pub fn preview_policy_bundles(
    before: &PolicyBundleResolved,
    after: &PolicyBundleResolved,
    samples: &[PolicyPreviewSample],
) -> Result<PolicyPreviewReport, PolicyPreviewError> {
    if before.bundle.zone_id != after.bundle.zone_id {
        return Err(PolicyPreviewError::ZoneMismatch {
            before: before.bundle.zone_id.clone(),
            after: after.bundle.zone_id.clone(),
        });
    }

    let zone_policy_before = resolve_zone_policy(before, &mut Vec::new())
        .ok_or(PolicyPreviewError::MissingZonePolicy { which: "before" })?;
    let zone_policy_after = resolve_zone_policy(after, &mut Vec::new())
        .ok_or(PolicyPreviewError::MissingZonePolicy { which: "after" })?;

    let mut entries = Vec::with_capacity(samples.len());
    let mut summary = PolicyPreviewSummary::default();

    for sample in samples {
        let before_input = sample.to_simulation_input(zone_policy_before.clone());
        let after_input = sample.to_simulation_input(zone_policy_after.clone());

        let before_receipt = simulate_policy_decision(&before_input).map_err(|err| {
            PolicyPreviewError::SimulationFailed {
                sample_id: sample.id.clone(),
                stage: "before",
                message: err.to_string(),
            }
        })?;
        let after_receipt = simulate_policy_decision(&after_input).map_err(|err| {
            PolicyPreviewError::SimulationFailed {
                sample_id: sample.id.clone(),
                stage: "after",
                message: err.to_string(),
            }
        })?;

        let before_decision = preview_decision_kind(&before_receipt);
        let after_decision = preview_decision_kind(&after_receipt);
        let delta = preview_delta(&before_receipt, &after_receipt);
        if let Some(change) = delta {
            match change {
                PolicyPreviewDelta::WouldAllow => summary.would_allow += 1,
                PolicyPreviewDelta::WouldDeny => summary.would_deny += 1,
                PolicyPreviewDelta::WouldRequireApproval => summary.would_require_approval += 1,
                PolicyPreviewDelta::ReasonChanged => summary.reason_changed += 1,
            }
        }
        summary.total += 1;

        entries.push(PolicyPreviewEntry {
            sample_id: sample.id.clone(),
            before: before_receipt,
            after: after_receipt,
            before_decision,
            after_decision,
            delta,
        });
    }

    Ok(PolicyPreviewReport {
        zone_id: before.bundle.zone_id.clone(),
        before_bundle_id: before.bundle.bundle_id.clone(),
        after_bundle_id: after.bundle.bundle_id.clone(),
        entries,
        summary,
    })
}

fn preview_decision_kind(receipt: &DecisionReceipt) -> PolicyPreviewDecision {
    match receipt.decision {
        Decision::Allow => PolicyPreviewDecision::Allow,
        Decision::Deny => {
            if receipt.reason_code.starts_with("approval.") {
                PolicyPreviewDecision::RequireApproval
            } else {
                PolicyPreviewDecision::Deny
            }
        }
    }
}

fn preview_delta(before: &DecisionReceipt, after: &DecisionReceipt) -> Option<PolicyPreviewDelta> {
    let before_decision = preview_decision_kind(before);
    let after_decision = preview_decision_kind(after);

    if before_decision != after_decision {
        return Some(match after_decision {
            PolicyPreviewDecision::Allow => PolicyPreviewDelta::WouldAllow,
            PolicyPreviewDecision::Deny => PolicyPreviewDelta::WouldDeny,
            PolicyPreviewDecision::RequireApproval => PolicyPreviewDelta::WouldRequireApproval,
        });
    }
    if before.reason_code != after.reason_code {
        return Some(PolicyPreviewDelta::ReasonChanged);
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Resource Objects
// ─────────────────────────────────────────────────────────────────────────────

/// Zone-bound handle to an external resource (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceObject {
    pub header: ObjectHeader,
    pub resource_uri: String,
    pub integrity_label: IntegrityLevel,
    pub confidentiality_label: ConfidentialityLevel,
    #[serde(default)]
    pub taint_flags: TaintFlags,
}

// ─────────────────────────────────────────────────────────────────────────────
// Decision Reason Codes
// ─────────────────────────────────────────────────────────────────────────────

/// Stable policy decision reason codes (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DecisionReasonCode {
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "capability.insufficient")]
    CapabilityInsufficient,
    #[serde(rename = "checkpoint.stale_frontier")]
    CheckpointStaleFrontier,
    #[serde(rename = "revocation.stale_frontier")]
    RevocationStaleFrontier,
    #[serde(rename = "taint.public_input_dangerous")]
    TaintPublicInputDangerous,
    #[serde(rename = "taint.unverified_link_risky")]
    TaintUnverifiedLinkRisky,
    #[serde(rename = "taint.malicious_input")]
    TaintMaliciousInput,
    #[serde(rename = "taint.risky_requires_elevation")]
    TaintRiskyRequiresElevation,
    #[serde(rename = "taint.cross_zone_unapproved")]
    TaintCrossZoneUnapproved,
    #[serde(rename = "integrity.insufficient")]
    IntegrityInsufficient,
    #[serde(rename = "zone_policy.principal_denied")]
    ZonePolicyPrincipalDenied,
    #[serde(rename = "zone_policy.connector_denied")]
    ZonePolicyConnectorDenied,
    #[serde(rename = "zone_policy.capability_denied")]
    ZonePolicyCapabilityDenied,
    #[serde(rename = "zone_policy.principal_not_allowed")]
    ZonePolicyPrincipalNotAllowed,
    #[serde(rename = "zone_policy.connector_not_allowed")]
    ZonePolicyConnectorNotAllowed,
    #[serde(rename = "zone_policy.capability_not_allowed")]
    ZonePolicyCapabilityNotAllowed,
    #[serde(rename = "approval.missing_elevation")]
    ApprovalMissingElevation,
    #[serde(rename = "approval.missing_declassification")]
    ApprovalMissingDeclassification,
    #[serde(rename = "approval.missing_execution")]
    ApprovalMissingExecution,
    #[serde(rename = "approval.elevation_scope_mismatch")]
    ApprovalElevationScopeMismatch,
    #[serde(rename = "approval.execution_scope_mismatch")]
    ApprovalExecutionScopeMismatch,
    #[serde(rename = "approval.expired")]
    ApprovalExpired,
    #[serde(rename = "approval.zone_mismatch")]
    ApprovalZoneMismatch,
    #[serde(rename = "approval.token_invalid")]
    ApprovalTokenInvalid,
    #[serde(rename = "transport.derp_forbidden")]
    TransportDerpForbidden,
    #[serde(rename = "transport.funnel_forbidden")]
    TransportFunnelForbidden,
    #[serde(rename = "transport.lan_forbidden")]
    TransportLanForbidden,
    #[serde(rename = "taint.sanitizer_invalid")]
    SanitizerReceiptInvalid,
    #[serde(rename = "taint.sanitizer_coverage_insufficient")]
    SanitizerCoverageInsufficient,
    #[serde(rename = "posture.attestation_missing")]
    PostureAttestationMissing,
    #[serde(rename = "posture.attestation_expired")]
    PostureAttestationExpired,
    #[serde(rename = "posture.attestation_invalid")]
    PostureAttestationInvalid,
    #[serde(rename = "posture.requirement_not_met")]
    PostureRequirementNotMet,
    #[serde(rename = "posture.verifier_not_allowed")]
    PostureVerifierNotAllowed,
    #[serde(rename = "operation.forbidden")]
    OperationForbidden,
}

impl DecisionReasonCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::CapabilityInsufficient => "capability.insufficient",
            Self::CheckpointStaleFrontier => "checkpoint.stale_frontier",
            Self::RevocationStaleFrontier => "revocation.stale_frontier",
            Self::TaintPublicInputDangerous => "taint.public_input_dangerous",
            Self::TaintUnverifiedLinkRisky => "taint.unverified_link_risky",
            Self::TaintMaliciousInput => "taint.malicious_input",
            Self::TaintRiskyRequiresElevation => "taint.risky_requires_elevation",
            Self::TaintCrossZoneUnapproved => "taint.cross_zone_unapproved",
            Self::IntegrityInsufficient => "integrity.insufficient",
            Self::ZonePolicyPrincipalDenied => "zone_policy.principal_denied",
            Self::ZonePolicyConnectorDenied => "zone_policy.connector_denied",
            Self::ZonePolicyCapabilityDenied => "zone_policy.capability_denied",
            Self::ZonePolicyPrincipalNotAllowed => "zone_policy.principal_not_allowed",
            Self::ZonePolicyConnectorNotAllowed => "zone_policy.connector_not_allowed",
            Self::ZonePolicyCapabilityNotAllowed => "zone_policy.capability_not_allowed",
            Self::ApprovalMissingElevation => "approval.missing_elevation",
            Self::ApprovalMissingDeclassification => "approval.missing_declassification",
            Self::ApprovalMissingExecution => "approval.missing_execution",
            Self::ApprovalElevationScopeMismatch => "approval.elevation_scope_mismatch",
            Self::ApprovalExecutionScopeMismatch => "approval.execution_scope_mismatch",
            Self::ApprovalExpired => "approval.expired",
            Self::ApprovalZoneMismatch => "approval.zone_mismatch",
            Self::ApprovalTokenInvalid => "approval.token_invalid",
            Self::TransportDerpForbidden => "transport.derp_forbidden",
            Self::TransportFunnelForbidden => "transport.funnel_forbidden",
            Self::TransportLanForbidden => "transport.lan_forbidden",
            Self::SanitizerReceiptInvalid => "taint.sanitizer_invalid",
            Self::SanitizerCoverageInsufficient => "taint.sanitizer_coverage_insufficient",
            Self::PostureAttestationMissing => "posture.attestation_missing",
            Self::PostureAttestationExpired => "posture.attestation_expired",
            Self::PostureAttestationInvalid => "posture.attestation_invalid",
            Self::PostureRequirementNotMet => "posture.requirement_not_met",
            Self::PostureVerifierNotAllowed => "posture.verifier_not_allowed",
            Self::OperationForbidden => "operation.forbidden",
        }
    }

    #[must_use]
    pub const fn from_provenance_violation(error: &ProvenanceViolation) -> Self {
        match error {
            ProvenanceViolation::PublicInputForDangerousOperation => {
                Self::TaintPublicInputDangerous
            }
            ProvenanceViolation::MaliciousInputDetected => Self::TaintMaliciousInput,
            ProvenanceViolation::TaintedInputForRiskyOperation { .. } => {
                Self::TaintRiskyRequiresElevation
            }
            ProvenanceViolation::InsufficientIntegrity { .. } => Self::IntegrityInsufficient,
            ProvenanceViolation::InvalidElevation { .. } => Self::ApprovalMissingElevation,
            ProvenanceViolation::InvalidDeclassification { .. } => {
                Self::ApprovalMissingDeclassification
            }
            ProvenanceViolation::CrossZoneUnapprovedForDangerousOperation => {
                Self::TaintCrossZoneUnapproved
            }
            ProvenanceViolation::SanitizerCoverageInsufficient => {
                Self::SanitizerCoverageInsufficient
            }
            ProvenanceViolation::ApprovalTokenInvalid => Self::ApprovalTokenInvalid,
            ProvenanceViolation::ForbiddenOperation => Self::OperationForbidden,
        }
    }
}

impl fmt::Display for DecisionReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Decision Models
// ─────────────────────────────────────────────────────────────────────────────

/// Policy decision result.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub reason_code: DecisionReasonCode,
    pub evidence: Vec<ObjectId>,
    pub explanation: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy Simulation (CLI/Test Harness Support)
// ─────────────────────────────────────────────────────────────────────────────

/// Input payload for policy simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySimulationInput {
    /// Zone policy to evaluate (authoritative for simulation).
    pub zone_policy: ZonePolicyObject,
    /// Invoke request under evaluation.
    pub invoke_request: InvokeRequest,
    /// Transport mode to evaluate against.
    #[serde(default = "default_transport_mode")]
    pub transport: TransportMode,
    /// Whether checkpoint freshness is satisfied.
    #[serde(default = "default_true")]
    pub checkpoint_fresh: bool,
    /// Whether revocation freshness is satisfied.
    #[serde(default = "default_true")]
    pub revocation_fresh: bool,
    /// Whether execution approvals are required for this operation.
    #[serde(default)]
    pub execution_approval_required: bool,
    /// Sanitizer receipts to apply (optional).
    #[serde(default)]
    pub sanitizer_receipts: Vec<SanitizerReceipt>,
    /// Related object ids (optional).
    #[serde(default)]
    pub related_object_ids: Vec<ObjectId>,
    /// Explicit request object id override (optional).
    #[serde(default)]
    pub request_object_id: Option<ObjectId>,
    /// Explicit input hash override (optional).
    #[serde(default)]
    pub request_input_hash: Option<[u8; 32]>,
    /// Safety tier for the requested operation.
    #[serde(default = "default_safety_tier")]
    pub safety_tier: SafetyTier,
    /// Optional principal override (otherwise derived from capability token).
    #[serde(default)]
    pub principal: Option<String>,
    /// Optional capability id override (otherwise derived from capability token).
    #[serde(default)]
    pub capability_id: Option<String>,
    /// Optional explicit provenance record (otherwise derived from request/zone).
    #[serde(default)]
    pub provenance_record: Option<ProvenanceRecord>,
    /// Optional override for evaluation time (epoch ms).
    #[serde(default)]
    pub now_ms: Option<u64>,
    /// Optional device posture attestation.
    #[serde(default)]
    pub posture_attestation: Option<crate::posture::PostureAttestation>,
}

/// Errors returned by policy simulation.
#[derive(Debug, thiserror::Error)]
pub enum PolicySimulationError {
    #[error("missing required claim: {claim}")]
    MissingClaim { claim: &'static str },
    #[error("invalid principal id '{value}': {message}")]
    InvalidPrincipal { value: String, message: String },
    #[error("invalid capability id '{value}': {message}")]
    InvalidCapability { value: String, message: String },
    #[error("failed to parse token claims: {message}")]
    TokenClaims { message: String },
    #[error("zone mismatch: request zone '{request_zone}' vs policy zone '{policy_zone}'")]
    ZoneMismatch {
        request_zone: String,
        policy_zone: String,
    },
}

/// Simulate a policy decision for a given invocation.
///
/// This does NOT execute connector logic or write mesh objects.
///
/// # Safety (unverified claim access)
///
/// This function intentionally reads claims from an unverified token
/// for policy *simulation* purposes. The claims are used only to
/// extract principal and capability metadata for the dry-run decision —
/// no authorization is granted based on these claims.  Real enforcement
/// uses [`CapabilityVerifier::verify_bound`] (full 5/5 verification)
/// which returns `CapabilityToken<BoundVerified>`, or
/// [`CapabilityVerifier::verify_unbound`] at gateway vantage.
///
/// # Errors
/// Returns [`PolicySimulationError`] if required inputs are missing or invalid.
pub fn simulate_policy_decision(
    input: &PolicySimulationInput,
) -> Result<DecisionReceipt, PolicySimulationError> {
    let invoke = &input.invoke_request;
    if invoke.zone_id != input.zone_policy.zone_id {
        return Err(PolicySimulationError::ZoneMismatch {
            request_zone: invoke.zone_id.as_str().to_string(),
            policy_zone: input.zone_policy.zone_id.as_str().to_string(),
        });
    }

    // SAFETY: Unverified claim access is acceptable here because this is
    // a policy *simulation* — no authorization is granted.  The claims
    // are used solely to populate the DecisionReceipt for dry-run UX.
    let claims = invoke.capability_token.raw().claims_unverified().map_err(
        |err: fcp_crypto::CryptoError| PolicySimulationError::TokenClaims {
            message: err.to_string(),
        },
    )?;

    let principal_str = input
        .principal
        .as_deref()
        .or_else(|| claims.get_subject())
        .ok_or(PolicySimulationError::MissingClaim { claim: "sub" })?;
    let principal =
        PrincipalId::new(principal_str).map_err(|err| PolicySimulationError::InvalidPrincipal {
            value: principal_str.to_string(),
            message: err.to_string(),
        })?;

    let capability_str = input
        .capability_id
        .as_deref()
        .or_else(|| claims.get_capability_id())
        .ok_or(PolicySimulationError::MissingClaim {
            claim: "capability_id",
        })?;
    let capability_id = CapabilityId::new(capability_str).map_err(|err| {
        PolicySimulationError::InvalidCapability {
            value: capability_str.to_string(),
            message: err.to_string(),
        }
    })?;

    let request_object_id = input
        .request_object_id
        .unwrap_or_else(|| ObjectId::from_unscoped_bytes(invoke.id.0.as_bytes()));

    let provenance = input
        .provenance_record
        .clone()
        .unwrap_or_else(|| provenance_from_request(invoke));

    let now_ms = input
        .now_ms
        .unwrap_or_else(|| u64::try_from(Utc::now().timestamp_millis()).unwrap_or(0));

    let decision_input = PolicyDecisionInput {
        request_object_id,
        zone_id: invoke.zone_id.clone(),
        principal,
        connector_id: invoke.connector_id.clone(),
        operation_id: invoke.operation.clone(),
        capability_id,
        safety_tier: input.safety_tier,
        provenance,
        approval_tokens: &invoke.approval_tokens,
        sanitizer_receipts: &input.sanitizer_receipts,
        request_input: Some(&invoke.input),
        request_input_hash: input.request_input_hash,
        related_object_ids: &input.related_object_ids,
        transport: input.transport,
        checkpoint_fresh: input.checkpoint_fresh,
        revocation_fresh: input.revocation_fresh,
        execution_approval_required: input.execution_approval_required,
        now_ms,
        posture_attestation: input.posture_attestation.as_ref(),
    };

    let engine = PolicyEngine {
        zone_policy: input.zone_policy.clone(),
    };
    let decision = engine.evaluate_invoke(&decision_input);
    let header = ObjectHeader {
        schema: SchemaId::new("fcp.core", "DecisionReceipt", Version::new(1, 0, 0)),
        zone_id: invoke.zone_id.clone(),
        created_at: now_ms / 1000,
        provenance: Provenance::new(invoke.zone_id.clone()),
        refs: Vec::new(),
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    };
    let signature = NodeSignature::new(NodeId::new("policy-sim"), [0u8; 64], now_ms / 1000);

    Ok(decision.to_receipt(header, request_object_id, signature))
}

const fn default_true() -> bool {
    true
}

const fn default_transport_mode() -> TransportMode {
    TransportMode::Lan
}

const fn default_safety_tier() -> SafetyTier {
    SafetyTier::Safe
}

fn provenance_from_request(req: &InvokeRequest) -> ProvenanceRecord {
    let origin = req
        .provenance
        .as_ref()
        .map_or_else(|| req.zone_id.clone(), |p| p.origin_zone.clone());
    let mut record = ProvenanceRecord::new(origin);

    if let Some(prov) = &req.provenance {
        match prov.taint {
            TaintLevel::Untainted => {}
            TaintLevel::Tainted => {
                record.taint_flags.insert(TaintFlag::PublicInput);
            }
            TaintLevel::HighlyTainted => {
                record.taint_flags.insert(TaintFlag::PublicInput);
                record.taint_flags.insert(TaintFlag::PotentiallyMalicious);
            }
        }
    }

    record
}

impl PolicyDecision {
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub const fn allow(evidence: Vec<ObjectId>) -> Self {
        Self {
            decision: Decision::Allow,
            reason_code: DecisionReasonCode::Allow,
            evidence,
            explanation: None,
        }
    }

    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub const fn deny(reason_code: DecisionReasonCode, evidence: Vec<ObjectId>) -> Self {
        Self {
            decision: Decision::Deny,
            reason_code,
            evidence,
            explanation: None,
        }
    }

    #[must_use]
    pub fn to_receipt(
        &self,
        header: ObjectHeader,
        request_object_id: ObjectId,
        signature: NodeSignature,
    ) -> DecisionReceipt {
        DecisionReceipt {
            header,
            request_object_id,
            decision: self.decision,
            reason_code: self.reason_code.as_str().to_string(),
            evidence: self.evidence.clone(),
            explanation: self.explanation.clone(),
            signature,
        }
    }
}

/// Invocation context for policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyDecisionInput<'a> {
    pub request_object_id: ObjectId,
    pub zone_id: ZoneId,
    pub principal: PrincipalId,
    pub connector_id: ConnectorId,
    pub operation_id: OperationId,
    pub capability_id: CapabilityId,
    pub safety_tier: SafetyTier,
    pub provenance: ProvenanceRecord,
    pub approval_tokens: &'a [ApprovalToken],
    pub sanitizer_receipts: &'a [SanitizerReceipt],
    pub request_input: Option<&'a serde_json::Value>,
    pub request_input_hash: Option<[u8; 32]>,
    pub related_object_ids: &'a [ObjectId],
    pub transport: TransportMode,
    pub checkpoint_fresh: bool,
    pub revocation_fresh: bool,
    pub execution_approval_required: bool,
    pub now_ms: u64,
    /// Device posture attestation for the requesting node.
    pub posture_attestation: Option<&'a crate::posture::PostureAttestation>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy Engine
// ─────────────────────────────────────────────────────────────────────────────

/// Policy evaluator for `ZonePolicyObject` instances.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    pub zone_policy: ZonePolicyObject,
}

impl PolicyEngine {
    /// Evaluate an invocation request against the zone policy.
    #[must_use]
    pub fn evaluate_invoke(&self, input: &PolicyDecisionInput<'_>) -> PolicyDecision {
        if !input.revocation_fresh {
            return PolicyDecision::deny(DecisionReasonCode::RevocationStaleFrontier, Vec::new());
        }
        if !input.checkpoint_fresh {
            return PolicyDecision::deny(DecisionReasonCode::CheckpointStaleFrontier, Vec::new());
        }

        if let Some(reason) = check_transport(&self.zone_policy.transport_policy, input.transport) {
            return PolicyDecision::deny(reason, Vec::new());
        }

        if let Some(reason) = check_pattern_lists(&self.zone_policy, input) {
            return PolicyDecision::deny(reason, Vec::new());
        }

        // Check posture requirements.
        //
        // Run check_posture whenever the zone policy declares
        // `requires_posture: Some(_)` — including the case where the
        // attribute-level `requirements` Vec happens to be empty. Such a
        // bundle still meaningfully constrains attestations through
        // `allowed_verifiers` (whitelist of acceptable verifier IDs) and
        // `max_attestation_age_secs` (default 24h ceiling). Gating on
        // `posture_requirements.is_empty()` here would skip those checks
        // and silently accept requests with no attestation at all,
        // attestations from arbitrary verifiers, or attestations days old.
        // The Some/None distinction on `requires_posture` is the
        // enforcement signal; once the admin opts into Some(_), every
        // declared constraint must run.
        if let Some(ref posture_requirements) = self.zone_policy.requires_posture {
            if let Some(reason) = check_posture(posture_requirements, input) {
                return PolicyDecision::deny(reason, Vec::new());
            }
        }

        if !self.zone_policy.capability_ceiling.is_empty()
            && !self
                .zone_policy
                .capability_ceiling
                .contains(&input.capability_id)
        {
            return PolicyDecision::deny(DecisionReasonCode::CapabilityInsufficient, Vec::new());
        }

        let mut evidence = Vec::new();
        let mut provenance = input.provenance.clone();

        if let Some(reason) = apply_sanitizer_receipts(input, &mut provenance, &mut evidence) {
            return PolicyDecision::deny(reason, evidence);
        }

        if matches!(
            input.safety_tier,
            SafetyTier::Risky
                | SafetyTier::Dangerous
                | SafetyTier::Critical
                | SafetyTier::Forbidden
        ) && provenance.taint_flags.contains(TaintFlag::UnverifiedLink)
        {
            return PolicyDecision::deny(DecisionReasonCode::TaintUnverifiedLinkRisky, evidence);
        }

        if matches!(
            input.safety_tier,
            SafetyTier::Dangerous | SafetyTier::Critical | SafetyTier::Forbidden
        ) && provenance.taint_flags.contains(TaintFlag::PublicInput)
        {
            return PolicyDecision::deny(DecisionReasonCode::TaintPublicInputDangerous, evidence);
        }

        if let Some(reason) = apply_flow_approvals(input, &mut provenance, &mut evidence) {
            return PolicyDecision::deny(reason, evidence);
        }

        if input.execution_approval_required {
            match find_execution_approval(input) {
                Ok(Some(token)) => evidence.push(approval_token_object_id(token)),
                Ok(None) => {
                    return PolicyDecision::deny(
                        DecisionReasonCode::ApprovalMissingExecution,
                        evidence,
                    );
                }
                Err(reason) => return PolicyDecision::deny(reason, evidence),
            }
        }

        if let Err(error) = provenance.can_drive_operation(input.safety_tier) {
            return PolicyDecision::deny(
                DecisionReasonCode::from_provenance_violation(&error),
                evidence,
            );
        }

        PolicyDecision::allow(evidence)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Role Graph (DAG enforcement)
// ─────────────────────────────────────────────────────────────────────────────

/// Role graph validation errors.
#[derive(Debug, thiserror::Error)]
pub enum RoleGraphError {
    #[error("unknown role id: {role_id}")]
    UnknownRole { role_id: ObjectId },

    #[error("role inheritance cycle detected: {cycle:?}")]
    RoleCycle { cycle: Vec<ObjectId> },
}

/// Role graph for resolving role inheritance.
#[derive(Debug, Clone)]
pub struct RoleGraph {
    roles: HashMap<ObjectId, RoleObject>,
}

impl RoleGraph {
    #[must_use]
    pub const fn new(roles: HashMap<ObjectId, RoleObject>) -> Self {
        Self { roles }
    }

    /// Validate that role inheritance is acyclic.
    ///
    /// # Errors
    /// Returns [`RoleGraphError::RoleCycle`] if a cycle is detected or
    /// [`RoleGraphError::UnknownRole`] if a referenced role is missing.
    pub fn validate_acyclic(&self) -> Result<(), RoleGraphError> {
        let mut visiting = HashSet::new();
        let mut visited = HashSet::new();

        for role_id in self.roles.keys() {
            self.visit(role_id, &mut visiting, &mut visited, &mut Vec::new())?;
        }

        Ok(())
    }

    fn visit(
        &self,
        role_id: &ObjectId,
        visiting: &mut HashSet<ObjectId>,
        visited: &mut HashSet<ObjectId>,
        stack: &mut Vec<ObjectId>,
    ) -> Result<(), RoleGraphError> {
        if visited.contains(role_id) {
            return Ok(());
        }
        if visiting.contains(role_id) {
            stack.push(*role_id);
            return Err(RoleGraphError::RoleCycle {
                cycle: stack.clone(),
            });
        }

        let role = self
            .roles
            .get(role_id)
            .ok_or(RoleGraphError::UnknownRole { role_id: *role_id })?;

        visiting.insert(*role_id);
        stack.push(*role_id);

        for included in &role.includes {
            self.visit(included, visiting, visited, stack)?;
        }

        visiting.remove(role_id);
        visited.insert(*role_id);
        stack.pop();
        Ok(())
    }

    /// Resolve effective capability grants for a role set.
    ///
    /// # Errors
    /// Returns [`RoleGraphError::UnknownRole`] if any role id is missing.
    pub fn resolve_caps(
        &self,
        role_ids: &[ObjectId],
    ) -> Result<Vec<CapabilityGrant>, RoleGraphError> {
        let mut resolved = Vec::new();
        let mut seen = HashSet::new();

        for role_id in role_ids {
            self.collect_caps(role_id, &mut seen, &mut resolved)?;
        }

        Ok(resolved)
    }

    fn collect_caps(
        &self,
        role_id: &ObjectId,
        seen: &mut HashSet<ObjectId>,
        out: &mut Vec<CapabilityGrant>,
    ) -> Result<(), RoleGraphError> {
        if seen.contains(role_id) {
            return Ok(());
        }
        let role = self
            .roles
            .get(role_id)
            .ok_or(RoleGraphError::UnknownRole { role_id: *role_id })?;
        seen.insert(*role_id);
        out.extend(role.caps.iter().cloned());
        for included in &role.includes {
            self.collect_caps(included, seen, out)?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal Helpers
// ─────────────────────────────────────────────────────────────────────────────

const fn check_transport(
    policy: &ZoneTransportPolicy,
    mode: TransportMode,
) -> Option<DecisionReasonCode> {
    if policy.allows(mode) {
        None
    } else {
        Some(match mode {
            TransportMode::Lan => DecisionReasonCode::TransportLanForbidden,
            TransportMode::Derp => DecisionReasonCode::TransportDerpForbidden,
            TransportMode::Funnel => DecisionReasonCode::TransportFunnelForbidden,
        })
    }
}

fn check_pattern_lists(
    policy: &ZonePolicyObject,
    input: &PolicyDecisionInput<'_>,
) -> Option<DecisionReasonCode> {
    if matches_any(&policy.principal_deny, input.principal.as_ref()) {
        return Some(DecisionReasonCode::ZonePolicyPrincipalDenied);
    }
    if matches_any(&policy.connector_deny, input.connector_id.as_ref()) {
        return Some(DecisionReasonCode::ZonePolicyConnectorDenied);
    }
    if matches_any(&policy.capability_deny, input.capability_id.as_ref()) {
        return Some(DecisionReasonCode::ZonePolicyCapabilityDenied);
    }

    if !policy.principal_allow.is_empty()
        && !matches_any(&policy.principal_allow, input.principal.as_ref())
    {
        return Some(DecisionReasonCode::ZonePolicyPrincipalNotAllowed);
    }
    if !policy.connector_allow.is_empty()
        && !matches_any(&policy.connector_allow, input.connector_id.as_ref())
    {
        return Some(DecisionReasonCode::ZonePolicyConnectorNotAllowed);
    }
    if !policy.capability_allow.is_empty()
        && !matches_any(&policy.capability_allow, input.capability_id.as_ref())
    {
        return Some(DecisionReasonCode::ZonePolicyCapabilityNotAllowed);
    }

    None
}

fn matches_any(patterns: &[PolicyPattern], value: &str) -> bool {
    patterns.iter().any(|pattern| pattern.matches(value))
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) const fn pattern_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();

    let mut pattern_index = 0usize;
    let mut value_index = 0usize;
    let mut last_star = None;
    let mut last_star_match = 0usize;

    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == value[value_index]
                || (pattern[pattern_index] == b'?' && value[value_index].is_ascii()))
        {
            pattern_index += 1;
            value_index += 1;
            continue;
        }

        if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            last_star = Some(pattern_index);
            pattern_index += 1;
            last_star_match = value_index;
            continue;
        }

        if let Some(star_index) = last_star {
            pattern_index = star_index + 1;
            last_star_match += 1;
            value_index = last_star_match;
            continue;
        }

        return false;
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }

    pattern_index == pattern.len()
}

fn check_posture(
    requirements: &crate::posture::PostureRequirements,
    input: &PolicyDecisionInput<'_>,
) -> Option<DecisionReasonCode> {
    use crate::posture::{PostureAttestation, PostureCheckResult};

    let Some(attestation) = input.posture_attestation else {
        return Some(DecisionReasonCode::PostureAttestationMissing);
    };

    // Check expiry first (before is_valid which also checks expiry)
    if attestation.is_expired_at(input.now_ms) {
        return Some(DecisionReasonCode::PostureAttestationExpired);
    }

    // Check schema validity
    if attestation.schema != PostureAttestation::SCHEMA {
        return Some(DecisionReasonCode::PostureAttestationInvalid);
    }

    match requirements.is_satisfied_by_at(attestation, input.now_ms) {
        PostureCheckResult::Satisfied => None,
        PostureCheckResult::AttestationExpired | PostureCheckResult::AttestationTooOld => {
            Some(DecisionReasonCode::PostureAttestationExpired)
        }
        PostureCheckResult::VerifierNotAllowed => {
            Some(DecisionReasonCode::PostureVerifierNotAllowed)
        }
        PostureCheckResult::RequirementNotMet { .. } => {
            Some(DecisionReasonCode::PostureRequirementNotMet)
        }
    }
}

fn apply_flow_approvals(
    input: &PolicyDecisionInput<'_>,
    provenance: &mut ProvenanceRecord,
    evidence: &mut Vec<ObjectId>,
) -> Option<DecisionReasonCode> {
    match provenance.can_flow_to(&input.zone_id) {
        FlowCheckResult::Allowed => None,
        FlowCheckResult::RequiresElevation => apply_elevation(input, provenance, evidence).err(),
        FlowCheckResult::RequiresDeclassification => {
            apply_declassification(input, provenance, evidence).err()
        }
        FlowCheckResult::RequiresBoth => {
            if let Err(reason) = apply_elevation(input, provenance, evidence) {
                return Some(reason);
            }
            if let Err(reason) = apply_declassification(input, provenance, evidence) {
                return Some(reason);
            }
            None
        }
    }
}

fn apply_elevation(
    input: &PolicyDecisionInput<'_>,
    provenance: &mut ProvenanceRecord,
    evidence: &mut Vec<ObjectId>,
) -> Result<(), DecisionReasonCode> {
    let required = IntegrityLevel::from_zone(&input.zone_id);

    // NORMATIVE: requests may carry multiple approval tokens (CDDL:
    // `approval_tokens: [* approval_token]`). A single scan that stops at
    // the first valid+zone-matching token and THEN checks scope would miss
    // a correctly-scoped Elevation token if it came after an unrelated
    // Declassification/Execution token in the array. Iterate through every
    // token and evaluate all criteria per-token, mirroring
    // `find_execution_approval` so we can distinguish
    // `ApprovalMissingElevation` (no elevation-scoped token at all) from
    // `ApprovalElevationScopeMismatch` (elevation-scoped token present but
    // its operation_id / target_integrity / original_provenance_id did not
    // line up with this request).
    let mut saw_elevation_scope = false;
    let mut had_mismatch = false;
    let mut matched: Option<&ApprovalToken> = None;
    for token in input.approval_tokens {
        if !token.is_valid(input.now_ms) || token.zone_id != input.zone_id {
            continue;
        }
        let ApprovalScope::Elevation(scope) = &token.scope else {
            continue;
        };
        saw_elevation_scope = true;
        if scope.operation_id != input.operation_id.as_str() {
            had_mismatch = true;
            continue;
        }
        if scope.target_integrity < required {
            had_mismatch = true;
            continue;
        }
        // SECURITY: bind the elevation to a specific request. Without this
        // check, a legitimate elevation token issued for request A in zone
        // Z could be replayed against request B in zone Z carrying the
        // same operation_id — silently granting an unauthorized integrity
        // elevation on B's provenance. The CDDL declares
        // `original_provenance_id` as a required field on `elevation_scope`
        // precisely for this binding; enforce it here.
        if scope.original_provenance_id != input.request_object_id {
            had_mismatch = true;
            continue;
        }
        matched = Some(token);
        break;
    }
    let token = match matched {
        Some(t) => t,
        None if saw_elevation_scope && had_mismatch => {
            return Err(DecisionReasonCode::ApprovalElevationScopeMismatch);
        }
        None => return Err(DecisionReasonCode::ApprovalMissingElevation),
    };

    let token_id = approval_token_object_id(token);
    let target = match &token.scope {
        ApprovalScope::Elevation(scope) => scope.target_integrity,
        _ => required,
    };

    provenance
        .apply_elevation(target, token_id, input.now_ms)
        .map_err(|_| DecisionReasonCode::ApprovalMissingElevation)?;

    evidence.push(token_id);
    Ok(())
}

fn apply_declassification(
    input: &PolicyDecisionInput<'_>,
    provenance: &mut ProvenanceRecord,
    evidence: &mut Vec<ObjectId>,
) -> Result<(), DecisionReasonCode> {
    let target = ConfidentialityLevel::from_zone(&input.zone_id);

    // See apply_elevation for why all criteria must be in one predicate:
    // requests can carry multiple approval tokens and `.find(valid).and_then(scope)`
    // would short-circuit on the first valid+zone-matching token even if its
    // scope is Elevation/Execution rather than Declassification.
    let token = input
        .approval_tokens
        .iter()
        .find(|token| {
            if !token.is_valid(input.now_ms) || token.zone_id != input.zone_id {
                return false;
            }
            let ApprovalScope::Declassification(scope) = &token.scope else {
                return false;
            };
            let objects_match = if input.related_object_ids.is_empty() {
                scope.object_ids.contains(&input.request_object_id)
            } else {
                input
                    .related_object_ids
                    .iter()
                    .all(|id| scope.object_ids.contains(id))
            };
            scope.from_zone == provenance.current_zone
                && scope.to_zone == input.zone_id
                && scope.target_confidentiality <= provenance.confidentiality_label
                && scope.target_confidentiality == target
                && objects_match
        })
        .ok_or(DecisionReasonCode::ApprovalMissingDeclassification)?;

    let token_id = approval_token_object_id(token);
    let new_level = match &token.scope {
        ApprovalScope::Declassification(scope) => scope.target_confidentiality,
        _ => target,
    };

    provenance
        .apply_declassification(new_level, token_id, input.now_ms)
        .map_err(|_| DecisionReasonCode::ApprovalMissingDeclassification)?;

    evidence.push(token_id);
    Ok(())
}

fn find_execution_approval<'a>(
    input: &PolicyDecisionInput<'a>,
) -> Result<Option<&'a ApprovalToken>, DecisionReasonCode> {
    let mut saw_execution_scope = false;
    let mut had_mismatch = false;

    for token in input.approval_tokens {
        if !token.is_valid(input.now_ms) || token.zone_id != input.zone_id {
            continue;
        }

        let ApprovalScope::Execution(scope) = &token.scope else {
            continue;
        };
        saw_execution_scope = true;

        if scope.connector_id != input.connector_id.as_str() {
            continue;
        }
        if !pattern_matches(&scope.method_pattern, input.operation_id.as_str()) {
            continue;
        }
        if let Some(request_id) = scope.request_object_id {
            if request_id != input.request_object_id {
                had_mismatch = true;
                continue;
            }
        }
        if let Some(expected_hash) = scope.input_hash {
            if input.request_input_hash != Some(expected_hash) {
                had_mismatch = true;
                continue;
            }
        }
        if !scope.input_constraints.is_empty()
            && !input_constraints_match(scope.input_constraints.as_slice(), input.request_input)
        {
            had_mismatch = true;
            continue;
        }

        return Ok(Some(token));
    }

    if saw_execution_scope && had_mismatch {
        Err(DecisionReasonCode::ApprovalExecutionScopeMismatch)
    } else {
        Ok(None)
    }
}

fn input_constraints_match(
    constraints: &[crate::InputConstraint],
    input: Option<&serde_json::Value>,
) -> bool {
    let Some(value) = input else {
        return false;
    };

    constraints
        .iter()
        .all(|constraint| value.pointer(&constraint.pointer) == Some(&constraint.expected))
}

fn apply_sanitizer_receipts(
    input: &PolicyDecisionInput<'_>,
    provenance: &mut ProvenanceRecord,
    evidence: &mut Vec<ObjectId>,
) -> Option<DecisionReasonCode> {
    for receipt in input.sanitizer_receipts {
        if !receipt.is_valid() {
            return Some(DecisionReasonCode::SanitizerReceiptInvalid);
        }

        if !receipt_covers_inputs(receipt, &provenance.input_sources) {
            return Some(DecisionReasonCode::SanitizerCoverageInsufficient);
        }

        let receipt_id = sanitizer_receipt_object_id(receipt);
        provenance.apply_taint_reduction(
            &receipt.cleared_flags,
            receipt_id,
            receipt.covered_inputs.clone(),
            receipt.timestamp_ms,
        );
        evidence.push(receipt_id);
    }

    None
}

fn receipt_covers_inputs(receipt: &SanitizerReceipt, inputs: &[ObjectId]) -> bool {
    if inputs.is_empty() {
        return true;
    }
    inputs.iter().all(|input| receipt.covers_input(input))
}

fn approval_token_object_id(token: &ApprovalToken) -> ObjectId {
    // SECURITY: Use a content-addressed ID to prevent malleability.
    // Primary path: canonical CBOR — this is the stable wire encoding.
    if let Ok(bytes) = fcp_cbor::to_canonical_cbor(token) {
        return ObjectId::from_unscoped_bytes(&bytes);
    }
    // Fallback: canonical CBOR can fail when a token exceeds
    // MAX_CANONICAL_OBJECT_BYTES (e.g., an attacker-supplied oversized
    // signature). The previous fallback hashed only `token_id`, letting two
    // distinct tokens collide on a value the attacker controls. Hash every
    // field through length-delimited framing so the fallback ID still binds
    // to the full token content.
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(b"FCP/ApprovalToken/fallback/v1");
    let scope_bytes = serde_json::to_vec(&token.scope).unwrap_or_default();
    let sig_bytes: Vec<u8> = token
        .signature
        .as_deref()
        .map(<[u8]>::to_vec)
        .unwrap_or_default();
    let fields: [&[u8]; 7] = [
        token.token_id.as_bytes(),
        &token.issued_at_ms.to_le_bytes(),
        &token.expires_at_ms.to_le_bytes(),
        token.issuer.as_bytes(),
        token.zone_id.as_str().as_bytes(),
        &scope_bytes,
        &sig_bytes,
    ];
    for field in fields {
        buf.extend_from_slice(&(field.len() as u64).to_le_bytes());
        buf.extend_from_slice(field);
    }
    // Distinguish None vs Some(empty) for `signature`.
    buf.push(u8::from(token.signature.is_some()));
    ObjectId::from_unscoped_bytes(&buf)
}

fn sanitizer_receipt_object_id(receipt: &SanitizerReceipt) -> ObjectId {
    // SECURITY: Content-address the full receipt to prevent two distinct
    // receipts that happen to share `receipt_id` from collapsing onto the
    // same ObjectId. The previous implementation hashed only `receipt_id`,
    // so an issuer that minted two receipts with the same id (different
    // covered_inputs, sanitizer_zone, signature, or cleared_flags) would
    // produce indistinguishable ObjectIds. Once a content-addressed
    // receipt store ships (the docstring on `receipt_id` calls it out as
    // "becomes ObjectId when stored"), that collision becomes an actual
    // overwrite — and even today, the audit chain stores the ObjectId in
    // `TaintReduction.sanitizer_receipt_id` so a duplicate id makes
    // post-hoc receipt lookup ambiguous.
    //
    // Mirrors the same primary/fallback split used by
    // `approval_token_object_id` so the two evidence types follow the
    // same content-addressing contract.
    if let Ok(bytes) = fcp_cbor::to_canonical_cbor(receipt) {
        return ObjectId::from_unscoped_bytes(&bytes);
    }
    // Fallback: canonical CBOR can fail when an attacker-supplied
    // signature pushes the receipt past MAX_CANONICAL_OBJECT_BYTES.
    // Length-delimit every field so the fallback hash also depends on
    // the full content, not just `receipt_id`.
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(b"FCP/SanitizerReceipt/fallback/v1");
    let auth_bytes = serde_json::to_vec(&receipt.authorized_flags).unwrap_or_default();
    let cleared_bytes = serde_json::to_vec(&receipt.cleared_flags).unwrap_or_default();
    let covered_bytes = serde_json::to_vec(&receipt.covered_inputs).unwrap_or_default();
    let sig_bytes: Vec<u8> = receipt
        .signature
        .as_deref()
        .map(<[u8]>::to_vec)
        .unwrap_or_default();
    let fields: [&[u8]; 8] = [
        receipt.receipt_id.as_bytes(),
        &receipt.timestamp_ms.to_le_bytes(),
        receipt.sanitizer_id.as_bytes(),
        receipt.sanitizer_zone.as_str().as_bytes(),
        &auth_bytes,
        &cleared_bytes,
        &covered_bytes,
        &sig_bytes,
    ];
    for field in fields {
        buf.extend_from_slice(&(field.len() as u64).to_le_bytes());
        buf.extend_from_slice(field);
    }
    // Distinguish `None` vs `Some(empty)` for `signature`.
    buf.push(u8::from(receipt.signature.is_some()));
    ObjectId::from_unscoped_bytes(&buf)
}

// ─────────────────────────────────────────────────────────────────────────────
// Direct Zone Policy Preview (would-allow without bundle resolution)
//
// VISIBILITY NOTE: every type and free function in this section is
// gated behind `#[cfg(test)]`. The canonical public preview API is
// `preview_policy_bundles` (line 1937 above), which is what fwc and
// every other external consumer call — `Grep "PolicyPreviewSample\|
// preview_policy_bundles" crates` lists fwc/src/policy_cmd.rs and the
// internal tests, no other site. The "direct zone policy preview"
// surface here was originally exposed `pub` and re-exported through
// `crates/fcp-core/src/lib.rs:78`'s wildcard, but it has no production
// caller in the workspace today; its only users are the four
// `direct_preview_*` tests below in this file's `tests` module
// (lines 5364, 5405, 5442, 5457). Gating the whole section on
// `#[cfg(test)]` (a) removes the parallel `Preview*`/`PolicyPreview*`
// type-family duplication from the public API surface so future
// migration of fcp-core to its FCP3 owner crates is not blocked by
// downstream consumers reaching for the wrong family, and (b) keeps
// dead-code analysis honest — these items are genuinely test-only
// today. If a real consumer materialises later, lifting each item out
// from behind the `#[cfg(test)]` guard and giving it appropriate
// visibility is a localized change.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
/// Outcome of a single sample in the direct zone policy preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PreviewOutcome {
    /// The policy allows the operation.
    Allow,
    /// The policy denies the operation.
    Deny,
}

#[cfg(test)]
impl From<Decision> for PreviewOutcome {
    fn from(d: Decision) -> Self {
        match d {
            Decision::Allow => Self::Allow,
            Decision::Deny => Self::Deny,
        }
    }
}

#[cfg(test)]
/// A single row in the preview delta report.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PreviewDeltaEntry {
    /// Index of the sample in the input list.
    pub sample_index: usize,
    /// Decision under the *current* (baseline) policy.
    pub baseline_outcome: PreviewOutcome,
    /// Reason code under the baseline policy.
    pub baseline_reason: String,
    /// Decision under the *proposed* policy.
    pub proposed_outcome: PreviewOutcome,
    /// Reason code under the proposed policy.
    pub proposed_reason: String,
    /// Whether the decision changed between baseline and proposed.
    pub changed: bool,
}

#[cfg(test)]
/// Aggregate summary of changes in a preview evaluation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PreviewSummary {
    /// Total samples evaluated.
    pub total_samples: usize,
    /// Samples whose decision changed.
    pub changed_count: usize,
    /// Samples that went from deny to allow.
    pub newly_allowed: usize,
    /// Samples that went from allow to deny.
    pub newly_denied: usize,
    /// Samples whose outcome was unchanged.
    pub unchanged: usize,
}

#[cfg(test)]
/// Full result of a preview evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PreviewResult {
    /// Per-sample delta entries.
    pub deltas: Vec<PreviewDeltaEntry>,
    /// Aggregate summary.
    pub summary: PreviewSummary,
}

#[cfg(test)]
/// Input for the preview evaluator.
///
/// Compares a *baseline* (current) policy against a *proposed* policy
/// using a set of sample operations. The evaluator is read-only and
/// never mutates state.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PreviewInput {
    /// Current policy in effect.
    pub baseline_policy: ZonePolicyObject,
    /// Proposed replacement policy.
    pub proposed_policy: ZonePolicyObject,
    /// Sample operations to evaluate against both policies.
    pub samples: Vec<PolicySimulationInput>,
}

/// Evaluate proposed policy changes without side effects.
///
/// Runs each sample against both the baseline and proposed policies,
/// producing a deterministic delta report showing which decisions
/// would change.
///
/// # Errors
///
/// Returns [`PolicySimulationError`] if any sample cannot be evaluated
/// (e.g., missing required token claims).
#[cfg(test)]
fn preview_policy_changes(input: &PreviewInput) -> Result<PreviewResult, PolicySimulationError> {
    let mut deltas = Vec::with_capacity(input.samples.len());
    let mut summary = PreviewSummary {
        total_samples: input.samples.len(),
        ..Default::default()
    };

    for (idx, sample) in input.samples.iter().enumerate() {
        let mut baseline_sample = sample.clone();
        baseline_sample.zone_policy = input.baseline_policy.clone();
        let baseline_receipt = simulate_policy_decision(&baseline_sample)?;

        let mut proposed_sample = sample.clone();
        proposed_sample.zone_policy = input.proposed_policy.clone();
        let proposed_receipt = simulate_policy_decision(&proposed_sample)?;

        let baseline_outcome = PreviewOutcome::from(baseline_receipt.decision);
        let proposed_outcome = PreviewOutcome::from(proposed_receipt.decision);
        let changed = baseline_outcome != proposed_outcome;

        if changed {
            summary.changed_count += 1;
            match (&baseline_outcome, &proposed_outcome) {
                (PreviewOutcome::Deny, PreviewOutcome::Allow) => summary.newly_allowed += 1,
                (PreviewOutcome::Allow, PreviewOutcome::Deny) => summary.newly_denied += 1,
                _ => {}
            }
        } else {
            summary.unchanged += 1;
        }

        deltas.push(PreviewDeltaEntry {
            sample_index: idx,
            baseline_outcome,
            baseline_reason: baseline_receipt.reason_code.clone(),
            proposed_outcome,
            proposed_reason: proposed_receipt.reason_code.clone(),
            changed,
        });
    }

    Ok(PreviewResult { deltas, summary })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ApprovalScope, CapabilityGrant, CapabilityId, CapabilityToken, ConfidentialityLevel,
        ConnectorId, Decision, ElevationScope, IntegrityLevel, NodeId, NodeSignature, ObjectId,
        OperationId, PrincipalId, Provenance, ProvenanceRecord, ProvenanceViolation, RequestId,
        SafetyTier, TaintFlag, ZoneId,
    };
    use fcp_cbor::SchemaId;
    use semver::Version;

    // ── helpers ────────────────────────────────────────────────────────────

    fn test_header() -> ObjectHeader {
        ObjectHeader {
            schema: SchemaId::new("fcp.core", "Test", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_signature() -> NodeSignature {
        NodeSignature::new(NodeId::new("test-node"), [0u8; 64], 1_000)
    }

    fn test_invoke_request(zone_id: ZoneId) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::new("req-1"),
            connector_id: ConnectorId::new("test", "request_response", "1.0.0")
                .expect("connector id"),
            operation: OperationId::from_static("op.test"),
            zone_id,
            input: serde_json::json!({ "example": true }),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }
    }

    fn preview_sample(sample_id: &str, invoke: InvokeRequest) -> PolicyPreviewSample {
        PolicyPreviewSample {
            id: sample_id.to_string(),
            invoke_request: invoke,
            transport: TransportMode::Lan,
            checkpoint_fresh: true,
            revocation_fresh: true,
            execution_approval_required: false,
            sanitizer_receipts: Vec::new(),
            related_object_ids: Vec::new(),
            request_object_id: None,
            request_input_hash: None,
            safety_tier: SafetyTier::Safe,
            principal: Some("user:alice".to_string()),
            capability_id: Some("cap.all".to_string()),
            provenance_record: None,
            now_ms: None,
            posture_attestation: None,
        }
    }

    fn minimal_zone_policy() -> ZonePolicyObject {
        ZonePolicyObject {
            header: test_header(),
            zone_id: ZoneId::work(),
            principal_allow: Vec::new(),
            principal_deny: Vec::new(),
            connector_allow: Vec::new(),
            connector_deny: Vec::new(),
            capability_allow: Vec::new(),
            capability_deny: Vec::new(),
            capability_ceiling: Vec::new(),
            transport_policy: ZoneTransportPolicy {
                allow_lan: true,
                allow_derp: true,
                allow_funnel: true,
            },
            decision_receipts: DecisionReceiptPolicy::default(),
            usage_budget: None,
            requires_posture: None,
        }
    }

    fn minimal_decision_input() -> PolicyDecisionInput<'static> {
        static EMPTY_APPROVALS: &[ApprovalToken] = &[];
        static EMPTY_RECEIPTS: &[SanitizerReceipt] = &[];
        static EMPTY_OBJECTS: &[ObjectId] = &[];

        PolicyDecisionInput {
            request_object_id: ObjectId::from_unscoped_bytes(b"req-1"),
            zone_id: ZoneId::work(),
            principal: PrincipalId::new("user:alice").unwrap(),
            connector_id: ConnectorId::from_static("test:conn:v1"),
            operation_id: OperationId::from_static("op.test"),
            capability_id: CapabilityId::new("cap.test").unwrap(),
            safety_tier: SafetyTier::Safe,
            provenance: ProvenanceRecord::new(ZoneId::work()),
            approval_tokens: EMPTY_APPROVALS,
            sanitizer_receipts: EMPTY_RECEIPTS,
            request_input: None,
            request_input_hash: None,
            related_object_ids: EMPTY_OBJECTS,
            transport: TransportMode::Lan,
            checkpoint_fresh: true,
            revocation_fresh: true,
            execution_approval_required: false,
            now_ms: 1_000,
            posture_attestation: None,
        }
    }

    // ── existing test ──────────────────────────────────────────────────────

    #[test]
    fn test_approval_token_object_id_is_content_addressed() {
        let mut token = ApprovalToken {
            token_id: "test-token-123".to_string(),
            issued_at_ms: 1000,
            expires_at_ms: 2000,
            issuer: "issuer".to_string(),
            scope: ApprovalScope::Elevation(ElevationScope {
                operation_id: "op".to_string(),
                original_provenance_id: ObjectId::from_unscoped_bytes(b"prov"),
                target_integrity: IntegrityLevel::Owner,
            }),
            zone_id: ZoneId::work(),
            signature: None,
            _state: std::marker::PhantomData,
        };

        let id1 = approval_token_object_id(&token);

        if let ApprovalScope::Elevation(ref mut scope) = token.scope {
            scope.target_integrity = IntegrityLevel::Untrusted;
        }
        let id2 = approval_token_object_id(&token);

        assert_ne!(id1, id2);
        assert_ne!(id1, ObjectId::from_unscoped_bytes(b"test-token-123"));
    }

    #[test]
    fn test_sanitizer_receipt_object_id_collision_resistance() {
        // Two distinct receipts that share `receipt_id` but cover different
        // inputs MUST produce different ObjectIds. The previous behavior
        // hashed only `receipt_id`, so an issuer minting "rcpt-x" twice
        // with different `covered_inputs` got the same ObjectId — and that
        // ObjectId was then stored in `TaintReduction.sanitizer_receipt_id`
        // as the audit reference, making the two events indistinguishable
        // in the audit trail and primed for an actual data overwrite the
        // moment a content-addressed receipt store ships.
        let base = SanitizerReceipt {
            receipt_id: "rcpt-collision".to_string(),
            timestamp_ms: 1_700_000_000_000,
            sanitizer_id: "sanitizer-a".to_string(),
            sanitizer_zone: ZoneId::work(),
            authorized_flags: vec![TaintFlag::PublicInput],
            covered_inputs: vec![ObjectId::from_unscoped_bytes(b"input-A")],
            cleared_flags: vec![TaintFlag::PublicInput],
            signature: None,
        };
        let mut other = base.clone();
        other.covered_inputs = vec![ObjectId::from_unscoped_bytes(b"input-B")];

        let id_base = sanitizer_receipt_object_id(&base);
        let id_other = sanitizer_receipt_object_id(&other);

        assert_ne!(
            id_base, id_other,
            "receipts that differ only in covered_inputs MUST get distinct ObjectIds"
        );
        assert_ne!(
            id_base,
            ObjectId::from_unscoped_bytes(b"rcpt-collision"),
            "ObjectId MUST NOT be derivable from receipt_id alone"
        );

        // Same receipt_id, same covered_inputs, different sanitizer_zone:
        // also must differ.
        let mut other_zone = base.clone();
        other_zone.sanitizer_zone = ZoneId::owner();
        let id_other_zone = sanitizer_receipt_object_id(&other_zone);
        assert_ne!(
            id_base, id_other_zone,
            "receipts that differ only in sanitizer_zone MUST get distinct ObjectIds"
        );

        // Same receipt_id, same covered_inputs, signature added:
        // also must differ. This is the standard "issuer re-signed an
        // existing receipt id" attack surface.
        let mut other_sig = base.clone();
        other_sig.signature = Some(vec![0xAA; 64]);
        let id_other_sig = sanitizer_receipt_object_id(&other_sig);
        assert_ne!(
            id_base, id_other_sig,
            "receipts that differ only in signature presence MUST get distinct ObjectIds"
        );

        // Determinism: same receipt → same id across calls.
        assert_eq!(id_base, sanitizer_receipt_object_id(&base));
    }

    // ── TransportMode ──────────────────────────────────────────────────────

    #[test]
    fn transport_mode_serde_roundtrip() {
        for mode in [
            TransportMode::Lan,
            TransportMode::Derp,
            TransportMode::Funnel,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: TransportMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
    }

    #[test]
    fn transport_mode_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&TransportMode::Lan).unwrap(),
            "\"lan\""
        );
        assert_eq!(
            serde_json::to_string(&TransportMode::Derp).unwrap(),
            "\"derp\""
        );
        assert_eq!(
            serde_json::to_string(&TransportMode::Funnel).unwrap(),
            "\"funnel\""
        );
    }

    // ── ZoneTransportPolicy ────────────────────────────────────────────────

    #[test]
    fn zone_transport_policy_default_allows_only_lan() {
        let policy = ZoneTransportPolicy::default();
        assert!(policy.allow_lan);
        assert!(!policy.allow_derp);
        assert!(!policy.allow_funnel);
    }

    #[test]
    fn zone_transport_policy_allows_checks_each_mode() {
        let policy = ZoneTransportPolicy {
            allow_lan: false,
            allow_derp: true,
            allow_funnel: false,
        };
        assert!(!policy.allows(TransportMode::Lan));
        assert!(policy.allows(TransportMode::Derp));
        assert!(!policy.allows(TransportMode::Funnel));
    }

    #[test]
    fn zone_transport_policy_allows_all_when_all_true() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        assert!(policy.allows(TransportMode::Lan));
        assert!(policy.allows(TransportMode::Derp));
        assert!(policy.allows(TransportMode::Funnel));
    }

    // ── PolicyBundle ────────────────────────────────────────────────────────

    fn test_bundle_hash() -> String {
        format!("blake3-256:{}", "a".repeat(64))
    }

    fn test_policy_ref() -> PolicyBundlePolicyRef {
        PolicyBundlePolicyRef {
            object_id: "obj-001".to_string(),
            schema_id: "fcp.core:ZonePolicy@1.0".to_string(),
            object_hash: test_bundle_hash(),
        }
    }

    fn test_bundle_signature() -> PolicyBundleSignature {
        PolicyBundleSignature::new(
            "key-001",
            "sig-data",
            POLICY_BUNDLE_SIGNED_FIELDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
        )
    }

    #[test]
    fn policy_bundle_validate_accepts_minimal() {
        let bundle = PolicyBundle::builder("bundle-001", ZoneId::work(), 1)
            .bundle_hash(test_bundle_hash())
            .policies(vec![test_policy_ref()])
            .signature(test_bundle_signature())
            .build()
            .expect("bundle build");

        assert!(bundle.validate().is_ok());
    }

    #[test]
    fn policy_bundle_validate_rejects_bad_hash() {
        let mut bundle = PolicyBundle::builder("bundle-001", ZoneId::work(), 1)
            .bundle_hash(test_bundle_hash())
            .policies(vec![test_policy_ref()])
            .signature(test_bundle_signature())
            .build()
            .expect("bundle build");

        bundle.bundle_hash = "sha256:deadbeef".to_string();
        let err = bundle.validate().expect_err("expected invalid bundle");
        assert!(err.to_string().contains("bundle_hash must be in format"));
    }

    #[test]
    fn policy_bundle_validate_rejects_missing_signed_field() {
        let mut signature = test_bundle_signature();
        signature.signed_fields.pop();

        let err = PolicyBundle::builder("bundle-001", ZoneId::work(), 1)
            .bundle_hash(test_bundle_hash())
            .policies(vec![test_policy_ref()])
            .signature(signature)
            .build()
            .expect_err("bundle should fail signed_fields validation");

        assert!(
            err.to_string()
                .contains("signature.signed_fields must exactly match")
        );
    }

    #[test]
    fn policy_bundle_validate_rejects_extra_signed_field() {
        let mut signature = test_bundle_signature();
        signature.signed_fields.push("unexpected".to_string());

        let err = PolicyBundle::builder("bundle-001", ZoneId::work(), 1)
            .bundle_hash(test_bundle_hash())
            .policies(vec![test_policy_ref()])
            .signature(signature)
            .build()
            .expect_err("bundle should fail signed_fields validation");

        assert!(
            err.to_string()
                .contains("signature.signed_fields must exactly match")
        );
    }

    #[test]
    fn policy_bundle_validate_rejects_reordered_signed_fields() {
        let mut signature = test_bundle_signature();
        signature.signed_fields.swap(0, 1);

        let err = PolicyBundle::builder("bundle-001", ZoneId::work(), 1)
            .bundle_hash(test_bundle_hash())
            .policies(vec![test_policy_ref()])
            .signature(signature)
            .build()
            .expect_err("bundle should fail signed_fields validation");

        assert!(
            err.to_string()
                .contains("signature.signed_fields must exactly match")
        );
    }

    #[test]
    fn policy_bundle_signing_bytes_deterministic() {
        let bundle = PolicyBundle::builder("bundle-001", ZoneId::work(), 1)
            .bundle_hash(test_bundle_hash())
            .policies(vec![test_policy_ref()])
            .signature(test_bundle_signature())
            .build()
            .expect("bundle build");

        let bytes1 = bundle.signing_bytes().expect("signing bytes");
        let bytes2 = bundle.signing_bytes().expect("signing bytes");
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn policy_bundle_signing_bytes_change_with_seq() {
        let bundle1 = PolicyBundle::builder("bundle-001", ZoneId::work(), 1)
            .bundle_hash(test_bundle_hash())
            .policies(vec![test_policy_ref()])
            .signature(test_bundle_signature())
            .build()
            .expect("bundle build");

        let bundle2 = PolicyBundle::builder("bundle-001", ZoneId::work(), 2)
            .bundle_hash(test_bundle_hash())
            .policies(vec![test_policy_ref()])
            .signature(test_bundle_signature())
            .build()
            .expect("bundle build");

        let bytes1 = bundle1.signing_bytes().expect("signing bytes");
        let bytes2 = bundle2.signing_bytes().expect("signing bytes");
        assert_ne!(bytes1, bytes2);
    }

    fn test_header_for(schema_name: &str, zone_id: ZoneId) -> ObjectHeader {
        ObjectHeader {
            schema: SchemaId::new("fcp.core", schema_name, Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 0,
            provenance: Provenance::new(zone_id),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_zone_policy(zone_id: ZoneId) -> ZonePolicyObject {
        ZonePolicyObject {
            header: test_header_for("ZonePolicy", zone_id.clone()),
            zone_id,
            principal_allow: Vec::new(),
            principal_deny: Vec::new(),
            connector_allow: Vec::new(),
            connector_deny: Vec::new(),
            capability_allow: Vec::new(),
            capability_deny: Vec::new(),
            capability_ceiling: Vec::new(),
            transport_policy: ZoneTransportPolicy::default(),
            decision_receipts: DecisionReceiptPolicy::default(),
            usage_budget: None,
            requires_posture: None,
        }
    }

    fn test_zone_definition(
        zone_id: ZoneId,
        integrity: IntegrityLevel,
        confidentiality: ConfidentialityLevel,
    ) -> ZoneDefinitionObject {
        ZoneDefinitionObject {
            header: test_header_for("ZoneDefinition", zone_id.clone()),
            zone_id,
            name: "zone".to_string(),
            integrity_level: integrity,
            confidentiality_level: confidentiality,
            symbol_port: 7777,
            control_port: 8888,
            transport_policy: ZoneTransportPolicy::default(),
            policy_object_id: ObjectId::from_unscoped_bytes(b"policy"),
            prev: None,
            signature: NodeSignature::new(NodeId::new("node-1"), [0u8; 64], 0),
        }
    }

    fn policy_ref(object_id: &str, schema_id: &str) -> PolicyBundlePolicyRef {
        PolicyBundlePolicyRef {
            object_id: object_id.to_string(),
            schema_id: schema_id.to_string(),
            object_hash: test_bundle_hash(),
        }
    }

    fn policy_bundle(
        bundle_id: &str,
        zone_id: ZoneId,
        policies: Vec<PolicyBundlePolicyRef>,
    ) -> PolicyBundle {
        PolicyBundle::builder(bundle_id, zone_id, 1)
            .bundle_hash(test_bundle_hash())
            .policies(policies)
            .signature(test_bundle_signature())
            .build()
            .expect("bundle build")
    }

    #[test]
    fn policy_bundle_diff_flags_capability_and_transport() {
        let zone = ZoneId::work();
        let before_policy = test_zone_policy(zone.clone());
        let mut after_policy = test_zone_policy(zone.clone());

        after_policy.capability_allow.push(PolicyPattern {
            pattern: "cap.read".to_string(),
        });
        after_policy.transport_policy.allow_derp = true;

        let before_bundle = policy_bundle(
            "bundle-before",
            zone.clone(),
            vec![policy_ref("policy-1", "fcp.core:ZonePolicy@1.0")],
        );
        let after_bundle = policy_bundle(
            "bundle-after",
            zone,
            vec![policy_ref("policy-1", "fcp.core:ZonePolicy@1.0")],
        );

        let mut before_objects = BTreeMap::new();
        before_objects.insert(
            "policy-1".to_string(),
            PolicyBundleObject::ZonePolicy(before_policy),
        );
        let mut after_objects = BTreeMap::new();
        after_objects.insert(
            "policy-1".to_string(),
            PolicyBundleObject::ZonePolicy(after_policy),
        );

        let before_resolved = PolicyBundleResolved::new(before_bundle, before_objects);
        let after_resolved = PolicyBundleResolved::new(after_bundle, after_objects);

        let diff = diff_policy_bundles(&before_resolved, &after_resolved).expect("bundle diff");
        let codes: BTreeSet<PolicyRiskCode> = diff.risk.flags.iter().map(|f| f.code).collect();

        assert!(codes.contains(&PolicyRiskCode::CapabilityAllowExpanded));
        assert!(codes.contains(&PolicyRiskCode::TransportDerpEnabled));
    }

    #[test]
    fn policy_bundle_diff_flags_integrity_lowered() {
        let zone = ZoneId::work();
        let before_def = test_zone_definition(
            zone.clone(),
            IntegrityLevel::Owner,
            ConfidentialityLevel::Owner,
        );
        let after_def = test_zone_definition(
            zone.clone(),
            IntegrityLevel::Work,
            ConfidentialityLevel::Owner,
        );

        let before_bundle = policy_bundle(
            "bundle-before",
            zone.clone(),
            vec![policy_ref("def-1", "fcp.core:ZoneDefinition@1.0")],
        );
        let after_bundle = policy_bundle(
            "bundle-after",
            zone,
            vec![policy_ref("def-1", "fcp.core:ZoneDefinition@1.0")],
        );

        let mut before_objects = BTreeMap::new();
        before_objects.insert(
            "def-1".to_string(),
            PolicyBundleObject::ZoneDefinition(before_def),
        );
        let mut after_objects = BTreeMap::new();
        after_objects.insert(
            "def-1".to_string(),
            PolicyBundleObject::ZoneDefinition(after_def),
        );

        let before_resolved = PolicyBundleResolved::new(before_bundle, before_objects);
        let after_resolved = PolicyBundleResolved::new(after_bundle, after_objects);

        let diff = diff_policy_bundles(&before_resolved, &after_resolved).expect("bundle diff");
        let codes: BTreeSet<PolicyRiskCode> = diff.risk.flags.iter().map(|f| f.code).collect();

        assert!(codes.contains(&PolicyRiskCode::IntegrityLowered));
    }

    #[test]
    fn policy_bundle_diff_missing_objects_sorted_and_deduplicated() {
        let zone = ZoneId::work();
        let before_bundle = policy_bundle(
            "bundle-before",
            zone.clone(),
            vec![
                policy_ref("missing-role-b", "fcp.core:RoleObject@1.0"),
                policy_ref("missing-role-a", "fcp.core:RoleObject@1.0"),
                policy_ref("missing-cap-a", "fcp.core:CapabilityObject@1.0"),
                policy_ref("missing-policy", "fcp.core:ZonePolicy@1.0"),
            ],
        );
        let after_bundle = policy_bundle(
            "bundle-after",
            zone,
            vec![
                policy_ref("missing-resource-a", "fcp.core:ResourceObject@1.0"),
                policy_ref("missing-cap-a", "fcp.core:CapabilityObject@1.0"),
                policy_ref("missing-role-a", "fcp.core:RoleObject@1.0"),
            ],
        );

        let before_resolved = PolicyBundleResolved::new(before_bundle, BTreeMap::new());
        let after_resolved = PolicyBundleResolved::new(after_bundle, BTreeMap::new());

        let diff = diff_policy_bundles(&before_resolved, &after_resolved).expect("bundle diff");

        assert_eq!(
            diff.missing_objects,
            vec![
                "missing-cap-a".to_string(),
                "missing-policy".to_string(),
                "missing-resource-a".to_string(),
                "missing-role-a".to_string(),
                "missing-role-b".to_string(),
            ]
        );
    }

    #[test]
    fn policy_bundle_diff_matches_golden_snapshot() {
        let zone = ZoneId::work();
        let before_policy = test_zone_policy(zone.clone());
        let mut after_policy = test_zone_policy(zone.clone());
        after_policy.connector_allow.push(PolicyPattern {
            pattern: "fcp.test:*".to_string(),
        });
        after_policy.transport_policy.allow_derp = true;

        let before_bundle = policy_bundle(
            "bundle-before",
            zone.clone(),
            vec![policy_ref("policy-1", "fcp.core:ZonePolicy@1.0")],
        );
        let after_bundle = policy_bundle(
            "bundle-after",
            zone,
            vec![policy_ref("policy-1", "fcp.core:ZonePolicy@1.0")],
        );

        let mut before_objects = BTreeMap::new();
        before_objects.insert(
            "policy-1".to_string(),
            PolicyBundleObject::ZonePolicy(before_policy),
        );
        let mut after_objects = BTreeMap::new();
        after_objects.insert(
            "policy-1".to_string(),
            PolicyBundleObject::ZonePolicy(after_policy),
        );

        let before_resolved = PolicyBundleResolved::new(before_bundle, before_objects);
        let after_resolved = PolicyBundleResolved::new(after_bundle, after_objects);
        let diff = diff_policy_bundles(&before_resolved, &after_resolved).expect("bundle diff");

        let actual = serde_json::to_value(&diff).expect("serialize diff");
        let expected = serde_json::json!({
            "zone_id": "z:work",
            "before_bundle_id": "bundle-before",
            "after_bundle_id": "bundle-after",
            "added": [],
            "removed": [],
            "changed": [],
            "zone_policy": {
                "added": {
                    "principal_allow": [],
                    "principal_deny": [],
                    "connector_allow": ["fcp.test:*"],
                    "connector_deny": [],
                    "capability_allow": [],
                    "capability_deny": [],
                    "capability_ceiling": []
                },
                "removed": {
                    "principal_allow": [],
                    "principal_deny": [],
                    "connector_allow": [],
                    "connector_deny": [],
                    "capability_allow": [],
                    "capability_deny": [],
                    "capability_ceiling": []
                },
                "changed": {
                    "transport_policy": {
                        "before": {
                            "allow_lan": true,
                            "allow_derp": false,
                            "allow_funnel": false
                        },
                        "after": {
                            "allow_lan": true,
                            "allow_derp": true,
                            "allow_funnel": false
                        }
                    }
                }
            },
            "zone_definition": null,
            "roles": [],
            "resources": [],
            "capabilities": [],
            "missing_objects": [],
            "risk": {
                "flags": [
                    {
                        "code": "connector_allow_expanded",
                        "severity": "medium"
                    },
                    {
                        "code": "transport_derp_enabled",
                        "severity": "high"
                    }
                ]
            }
        });

        assert_eq!(actual, expected);
    }

    #[test]
    fn policy_bundle_preview_reports_decision_deltas() {
        let zone = ZoneId::work();
        let before_policy = test_zone_policy(zone.clone());
        let mut after_policy = test_zone_policy(zone.clone());
        after_policy.capability_deny.push(PolicyPattern {
            pattern: "cap.all".to_string(),
        });

        let before_bundle = policy_bundle(
            "bundle-before",
            zone.clone(),
            vec![policy_ref("policy-1", "fcp.core:ZonePolicy@1.0")],
        );
        let after_bundle = policy_bundle(
            "bundle-after",
            zone.clone(),
            vec![policy_ref("policy-1", "fcp.core:ZonePolicy@1.0")],
        );

        let mut before_objects = BTreeMap::new();
        before_objects.insert(
            "policy-1".to_string(),
            PolicyBundleObject::ZonePolicy(before_policy),
        );
        let mut after_objects = BTreeMap::new();
        after_objects.insert(
            "policy-1".to_string(),
            PolicyBundleObject::ZonePolicy(after_policy),
        );

        let before_resolved = PolicyBundleResolved::new(before_bundle, before_objects);
        let after_resolved = PolicyBundleResolved::new(after_bundle, after_objects);

        let invoke = test_invoke_request(zone);
        let allow_sample = preview_sample("allow-to-deny", invoke.clone());

        let mut require_sample = preview_sample("require-approval", invoke);
        require_sample.execution_approval_required = true;

        let report = preview_policy_bundles(
            &before_resolved,
            &after_resolved,
            &[allow_sample, require_sample],
        )
        .expect("preview report");

        assert_eq!(report.entries.len(), 2);
        assert_eq!(
            report.entries[0].before_decision,
            PolicyPreviewDecision::Allow
        );
        assert_eq!(
            report.entries[0].after_decision,
            PolicyPreviewDecision::Deny
        );
        assert!(report.entries[0].delta.is_some());

        assert_eq!(
            report.entries[1].before_decision,
            PolicyPreviewDecision::RequireApproval
        );
        assert_eq!(
            report.entries[1].after_decision,
            PolicyPreviewDecision::Deny
        );
        assert_eq!(report.summary.would_deny, 2);
    }

    #[test]
    fn zone_transport_policy_serde_roundtrip() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: false,
            allow_funnel: true,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: ZoneTransportPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.allow_lan, policy.allow_lan);
        assert_eq!(back.allow_derp, policy.allow_derp);
        assert_eq!(back.allow_funnel, policy.allow_funnel);
    }

    // ── DecisionReceiptPolicy ──────────────────────────────────────────────

    #[test]
    fn decision_receipt_policy_default_emits_on_deny_only() {
        let policy = DecisionReceiptPolicy::default();
        assert!(!policy.emit_on_allow);
        assert!(policy.emit_on_deny);
    }

    #[test]
    fn decision_receipt_policy_serde_roundtrip() {
        let policy = DecisionReceiptPolicy {
            emit_on_allow: true,
            emit_on_deny: false,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: DecisionReceiptPolicy = serde_json::from_str(&json).unwrap();
        assert!(back.emit_on_allow);
        assert!(!back.emit_on_deny);
    }

    // ── UsageBudgetPolicy ──────────────────────────────────────────────────

    #[test]
    fn usage_budget_policy_serde_roundtrip() {
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 1000,
                window_seconds: 60,
            }],
        };

        let json = serde_json::to_string(&policy).unwrap();
        let back: UsageBudgetPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.enforcement, BudgetEnforcement::Warn);
        assert_eq!(back.budgets.len(), 1);
        assert_eq!(back.budgets[0].metric, UsageMetricKind::Tokens);
        assert_eq!(back.budgets[0].limit, 1000);
        assert_eq!(back.budgets[0].window_seconds, 60);
    }

    // ── PolicyPattern ──────────────────────────────────────────────────────

    #[test]
    fn policy_pattern_exact_match() {
        let pat = PolicyPattern {
            pattern: "user:alice".into(),
        };
        assert!(pat.matches("user:alice"));
        assert!(!pat.matches("user:bob"));
    }

    #[test]
    fn policy_pattern_wildcard_star_matches_all() {
        let pat = PolicyPattern {
            pattern: "*".into(),
        };
        assert!(pat.matches("anything"));
        assert!(pat.matches(""));
    }

    #[test]
    fn policy_pattern_prefix_wildcard() {
        let pat = PolicyPattern {
            pattern: "user:*".into(),
        };
        assert!(pat.matches("user:alice"));
        assert!(pat.matches("user:bob"));
        assert!(!pat.matches("service:foo"));
    }

    #[test]
    fn policy_pattern_suffix_wildcard() {
        let pat = PolicyPattern {
            pattern: "*:admin".into(),
        };
        assert!(pat.matches("user:admin"));
        assert!(pat.matches("service:admin"));
        assert!(!pat.matches("user:alice"));
    }

    #[test]
    fn policy_pattern_middle_wildcard() {
        let pat = PolicyPattern {
            pattern: "a*z".into(),
        };
        assert!(pat.matches("az"));
        assert!(pat.matches("abcz"));
        assert!(!pat.matches("bz"));
        assert!(!pat.matches("ay"));
    }

    #[test]
    fn policy_pattern_single_char_wildcard() {
        let pat = PolicyPattern {
            pattern: "user:?lice".into(),
        };
        assert!(pat.matches("user:alice"));
        assert!(pat.matches("user:1lice"));
        assert!(!pat.matches("user:malice"));
        assert!(!pat.matches("user:lice"));
    }

    #[test]
    fn policy_pattern_single_char_wildcard_does_not_match_non_ascii() {
        let pat = PolicyPattern {
            pattern: "*?*".into(),
        };
        assert!(!pat.matches("é"));
        assert!(pat.matches("a"));
    }

    #[test]
    fn policy_pattern_multi_wildcard() {
        let pat = PolicyPattern {
            pattern: "a*b*c".into(),
        };
        assert!(pat.matches("abc"));
        assert!(pat.matches("aXXbYYc"));
        assert!(!pat.matches("aXXc")); // missing 'b'
    }

    #[test]
    fn policy_pattern_empty_matches_empty() {
        let pat = PolicyPattern {
            pattern: String::new(),
        };
        assert!(pat.matches(""));
        assert!(!pat.matches("anything"));
    }

    // ── DecisionReasonCode ─────────────────────────────────────────────────

    #[test]
    fn decision_reason_code_as_str_select_variants() {
        assert_eq!(DecisionReasonCode::Allow.as_str(), "allow");
        assert_eq!(
            DecisionReasonCode::CapabilityInsufficient.as_str(),
            "capability.insufficient"
        );
        assert_eq!(
            DecisionReasonCode::TransportDerpForbidden.as_str(),
            "transport.derp_forbidden"
        );
        assert_eq!(
            DecisionReasonCode::ZonePolicyPrincipalDenied.as_str(),
            "zone_policy.principal_denied"
        );
        assert_eq!(
            DecisionReasonCode::PostureAttestationMissing.as_str(),
            "posture.attestation_missing"
        );
        assert_eq!(
            DecisionReasonCode::SanitizerReceiptInvalid.as_str(),
            "taint.sanitizer_invalid"
        );
    }

    #[test]
    fn decision_reason_code_serde_roundtrip() {
        let code = DecisionReasonCode::TaintPublicInputDangerous;
        let json = serde_json::to_string(&code).unwrap();
        let back: DecisionReasonCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, back);
    }

    #[test]
    fn decision_reason_code_from_provenance_violation() {
        assert_eq!(
            DecisionReasonCode::from_provenance_violation(
                &ProvenanceViolation::PublicInputForDangerousOperation
            ),
            DecisionReasonCode::TaintPublicInputDangerous,
        );
        assert_eq!(
            DecisionReasonCode::from_provenance_violation(
                &ProvenanceViolation::MaliciousInputDetected
            ),
            DecisionReasonCode::TaintMaliciousInput,
        );
        assert_eq!(
            DecisionReasonCode::from_provenance_violation(
                &ProvenanceViolation::CrossZoneUnapprovedForDangerousOperation
            ),
            DecisionReasonCode::TaintCrossZoneUnapproved,
        );
        assert_eq!(
            DecisionReasonCode::from_provenance_violation(
                &ProvenanceViolation::SanitizerCoverageInsufficient
            ),
            DecisionReasonCode::SanitizerCoverageInsufficient,
        );
        assert_eq!(
            DecisionReasonCode::from_provenance_violation(
                &ProvenanceViolation::ApprovalTokenInvalid
            ),
            DecisionReasonCode::ApprovalTokenInvalid,
        );
    }

    // ── PolicyDecision ─────────────────────────────────────────────────────

    #[test]
    fn policy_decision_allow_has_allow_fields() {
        let ev = vec![ObjectId::from_unscoped_bytes(b"ev1")];
        let d = PolicyDecision::allow(ev.clone());
        assert_eq!(d.decision, Decision::Allow);
        assert_eq!(d.reason_code, DecisionReasonCode::Allow);
        assert_eq!(d.evidence, ev);
        assert!(d.explanation.is_none());
    }

    #[test]
    fn policy_decision_deny_has_deny_fields() {
        let d = PolicyDecision::deny(DecisionReasonCode::TransportDerpForbidden, Vec::new());
        assert_eq!(d.decision, Decision::Deny);
        assert_eq!(d.reason_code, DecisionReasonCode::TransportDerpForbidden);
    }

    #[test]
    fn policy_decision_to_receipt_preserves_decision() {
        let d = PolicyDecision::deny(
            DecisionReasonCode::CapabilityInsufficient,
            vec![ObjectId::from_unscoped_bytes(b"ev")],
        );
        let receipt = d.to_receipt(
            test_header(),
            ObjectId::from_unscoped_bytes(b"req"),
            test_signature(),
        );
        assert_eq!(receipt.decision, Decision::Deny);
        assert_eq!(receipt.reason_code, "capability.insufficient");
        assert_eq!(receipt.evidence.len(), 1);
        assert_eq!(
            receipt.request_object_id,
            ObjectId::from_unscoped_bytes(b"req")
        );
    }

    // ── ResourceObject ─────────────────────────────────────────────────────

    #[test]
    fn resource_object_serde_roundtrip() {
        let obj = ResourceObject {
            header: test_header(),
            resource_uri: "https://example.com/file.pdf".to_string(),
            integrity_label: IntegrityLevel::Private,
            confidentiality_label: ConfidentialityLevel::Private,
            taint_flags: TaintFlags::default(),
        };
        let json = serde_json::to_string(&obj).unwrap();
        let back: ResourceObject = serde_json::from_str(&json).unwrap();
        assert_eq!(back.resource_uri, "https://example.com/file.pdf");
    }

    // ── RoleGraph ──────────────────────────────────────────────────────────

    #[test]
    fn role_graph_acyclic_single_role() {
        let id_a = ObjectId::from_unscoped_bytes(b"role-a");
        let role_a = RoleObject {
            name: "admin".into(),
            caps: vec![CapabilityGrant {
                capability: CapabilityId::new("cap.read").unwrap(),
                operation: None,
            }],
            includes: Vec::new(),
        };
        let mut roles = HashMap::new();
        roles.insert(id_a, role_a);
        let graph = RoleGraph::new(roles);
        assert!(graph.validate_acyclic().is_ok());
    }

    #[test]
    fn role_graph_acyclic_linear_chain() {
        let id_a = ObjectId::from_unscoped_bytes(b"role-a");
        let id_b = ObjectId::from_unscoped_bytes(b"role-b");
        let role_a = RoleObject {
            name: "base".into(),
            caps: vec![],
            includes: Vec::new(),
        };
        let role_b = RoleObject {
            name: "admin".into(),
            caps: vec![],
            includes: vec![id_a],
        };
        let mut roles = HashMap::new();
        roles.insert(id_a, role_a);
        roles.insert(id_b, role_b);
        let graph = RoleGraph::new(roles);
        assert!(graph.validate_acyclic().is_ok());
    }

    #[test]
    fn role_graph_detects_cycle() {
        let id_a = ObjectId::from_unscoped_bytes(b"role-a");
        let id_b = ObjectId::from_unscoped_bytes(b"role-b");
        let role_a = RoleObject {
            name: "alpha".into(),
            caps: vec![],
            includes: vec![id_b],
        };
        let role_b = RoleObject {
            name: "beta".into(),
            caps: vec![],
            includes: vec![id_a],
        };
        let mut roles = HashMap::new();
        roles.insert(id_a, role_a);
        roles.insert(id_b, role_b);
        let graph = RoleGraph::new(roles);
        let err = graph.validate_acyclic().unwrap_err();
        assert!(matches!(err, RoleGraphError::RoleCycle { .. }));
    }

    #[test]
    fn role_graph_detects_unknown_role() {
        let id_a = ObjectId::from_unscoped_bytes(b"role-a");
        let id_missing = ObjectId::from_unscoped_bytes(b"role-missing");
        let role_a = RoleObject {
            name: "orphan".into(),
            caps: vec![],
            includes: vec![id_missing],
        };
        let mut roles = HashMap::new();
        roles.insert(id_a, role_a);
        let graph = RoleGraph::new(roles);
        let err = graph.validate_acyclic().unwrap_err();
        assert!(matches!(err, RoleGraphError::UnknownRole { .. }));
    }

    #[test]
    fn role_graph_resolve_caps_collects_inherited() {
        let id_a = ObjectId::from_unscoped_bytes(b"role-base");
        let id_b = ObjectId::from_unscoped_bytes(b"role-derived");
        let cap_read = CapabilityGrant {
            capability: CapabilityId::new("cap.read").unwrap(),
            operation: None,
        };
        let cap_write = CapabilityGrant {
            capability: CapabilityId::new("cap.write").unwrap(),
            operation: None,
        };
        let role_a = RoleObject {
            name: "base".into(),
            caps: vec![cap_read.clone()],
            includes: Vec::new(),
        };
        let role_b = RoleObject {
            name: "derived".into(),
            caps: vec![cap_write.clone()],
            includes: vec![id_a],
        };
        let mut roles = HashMap::new();
        roles.insert(id_a, role_a);
        roles.insert(id_b, role_b);
        let graph = RoleGraph::new(roles);
        let caps = graph.resolve_caps(&[id_b]).unwrap();
        assert_eq!(caps.len(), 2);
        assert!(caps.contains(&cap_write));
        assert!(caps.contains(&cap_read));
    }

    #[test]
    fn role_graph_resolve_caps_deduplicates_diamond() {
        let id_a = ObjectId::from_unscoped_bytes(b"role-root");
        let id_b = ObjectId::from_unscoped_bytes(b"role-left");
        let id_c = ObjectId::from_unscoped_bytes(b"role-right");
        let cap_root = CapabilityGrant {
            capability: CapabilityId::new("cap.root").unwrap(),
            operation: None,
        };
        let role_a = RoleObject {
            name: "root".into(),
            caps: vec![cap_root],
            includes: Vec::new(),
        };
        let role_b = RoleObject {
            name: "left".into(),
            caps: vec![],
            includes: vec![id_a],
        };
        let role_c = RoleObject {
            name: "right".into(),
            caps: vec![],
            includes: vec![id_a],
        };
        let mut roles = HashMap::new();
        roles.insert(id_a, role_a);
        roles.insert(id_b, role_b);
        roles.insert(id_c, role_c);
        let graph = RoleGraph::new(roles);
        // Resolve from both branches — root caps should appear once
        let caps = graph.resolve_caps(&[id_b, id_c]).unwrap();
        assert_eq!(caps.len(), 1);
    }

    // ── PolicyEngine ───────────────────────────────────────────────────────

    #[test]
    fn engine_allow_minimal_input() {
        let engine = PolicyEngine {
            zone_policy: minimal_zone_policy(),
        };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Allow);
        assert_eq!(decision.reason_code, DecisionReasonCode::Allow);
    }

    #[test]
    fn engine_deny_revocation_stale() {
        let engine = PolicyEngine {
            zone_policy: minimal_zone_policy(),
        };
        let mut input = minimal_decision_input();
        input.revocation_fresh = false;
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::RevocationStaleFrontier
        );
    }

    #[test]
    fn engine_deny_checkpoint_stale() {
        let engine = PolicyEngine {
            zone_policy: minimal_zone_policy(),
        };
        let mut input = minimal_decision_input();
        input.checkpoint_fresh = false;
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::CheckpointStaleFrontier
        );
    }

    #[test]
    fn engine_deny_transport_derp_forbidden() {
        let mut policy = minimal_zone_policy();
        policy.transport_policy.allow_derp = false;
        let engine = PolicyEngine {
            zone_policy: policy,
        };
        let mut input = minimal_decision_input();
        input.transport = TransportMode::Derp;
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::TransportDerpForbidden
        );
    }

    #[test]
    fn engine_deny_transport_funnel_forbidden() {
        let mut policy = minimal_zone_policy();
        policy.transport_policy.allow_funnel = false;
        let engine = PolicyEngine {
            zone_policy: policy,
        };
        let mut input = minimal_decision_input();
        input.transport = TransportMode::Funnel;
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::TransportFunnelForbidden
        );
    }

    #[test]
    fn engine_deny_transport_lan_forbidden() {
        let mut policy = minimal_zone_policy();
        policy.transport_policy.allow_lan = false;
        let engine = PolicyEngine {
            zone_policy: policy,
        };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::TransportLanForbidden
        );
    }

    #[test]
    fn engine_deny_principal_on_deny_list() {
        let mut policy = minimal_zone_policy();
        policy.principal_deny.push(PolicyPattern {
            pattern: "user:alice".into(),
        });
        let engine = PolicyEngine {
            zone_policy: policy,
        };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::ZonePolicyPrincipalDenied
        );
    }

    #[test]
    fn engine_deny_connector_on_deny_list() {
        let mut policy = minimal_zone_policy();
        policy.connector_deny.push(PolicyPattern {
            pattern: "test:conn:*".into(),
        });
        let engine = PolicyEngine {
            zone_policy: policy,
        };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::ZonePolicyConnectorDenied
        );
    }

    #[test]
    fn engine_deny_capability_on_deny_list() {
        let mut policy = minimal_zone_policy();
        policy.capability_deny.push(PolicyPattern {
            pattern: "cap.*".into(),
        });
        let engine = PolicyEngine {
            zone_policy: policy,
        };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::ZonePolicyCapabilityDenied
        );
    }

    #[test]
    fn engine_deny_posture_with_empty_requirements_still_runs_check() {
        // Regression for the short-circuit where
        // `if !posture_requirements.is_empty()` skipped check_posture when
        // the attribute-level `requirements` Vec was empty — even though
        // the same struct could still impose `allowed_verifiers` and
        // `max_attestation_age_secs` constraints. With an empty
        // requirements list and no attestation supplied, the engine MUST
        // surface PostureAttestationMissing rather than allow the request.
        let mut policy = minimal_zone_policy();
        policy.requires_posture = Some(crate::posture::PostureRequirements {
            requirements: Vec::new(),
            max_attestation_age_secs: 3600,
            allowed_verifiers: vec!["intel-tdx-verifier".to_string()],
        });
        let engine = PolicyEngine {
            zone_policy: policy,
        };
        let mut input = minimal_decision_input();
        input.posture_attestation = None;
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::PostureAttestationMissing
        );
    }

    #[test]
    fn engine_deny_principal_not_on_allow_list() {
        let mut policy = minimal_zone_policy();
        policy.principal_allow.push(PolicyPattern {
            pattern: "user:bob".into(),
        });
        let engine = PolicyEngine {
            zone_policy: policy,
        };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::ZonePolicyPrincipalNotAllowed
        );
    }

    #[test]
    fn engine_allow_principal_on_allow_list() {
        let mut policy = minimal_zone_policy();
        policy.principal_allow.push(PolicyPattern {
            pattern: "user:*".into(),
        });
        let engine = PolicyEngine {
            zone_policy: policy,
        };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Allow);
    }

    #[test]
    fn engine_deny_connector_not_on_allow_list() {
        let mut policy = minimal_zone_policy();
        policy.connector_allow.push(PolicyPattern {
            pattern: "other:conn:*".into(),
        });
        let engine = PolicyEngine {
            zone_policy: policy,
        };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::ZonePolicyConnectorNotAllowed
        );
    }

    #[test]
    fn engine_deny_capability_not_on_allow_list() {
        let mut policy = minimal_zone_policy();
        policy.capability_allow.push(PolicyPattern {
            pattern: "cap.other".into(),
        });
        let engine = PolicyEngine {
            zone_policy: policy,
        };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::ZonePolicyCapabilityNotAllowed
        );
    }

    #[test]
    fn engine_deny_capability_ceiling_blocks() {
        let mut policy = minimal_zone_policy();
        policy
            .capability_ceiling
            .push(CapabilityId::new("cap.other").unwrap());
        let engine = PolicyEngine {
            zone_policy: policy,
        };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::CapabilityInsufficient
        );
    }

    #[test]
    fn engine_allow_capability_in_ceiling() {
        let mut policy = minimal_zone_policy();
        policy
            .capability_ceiling
            .push(CapabilityId::new("cap.test").unwrap());
        let engine = PolicyEngine {
            zone_policy: policy,
        };
        let input = minimal_decision_input();
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Allow);
    }

    #[test]
    fn engine_deny_tainted_public_input_dangerous_tier() {
        let engine = PolicyEngine {
            zone_policy: minimal_zone_policy(),
        };
        let mut input = minimal_decision_input();
        input.safety_tier = SafetyTier::Dangerous;
        input.provenance.taint_flags.insert(TaintFlag::PublicInput);
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::TaintPublicInputDangerous
        );
    }

    #[test]
    fn engine_deny_unverified_link_risky_tier() {
        let engine = PolicyEngine {
            zone_policy: minimal_zone_policy(),
        };
        let mut input = minimal_decision_input();
        input.safety_tier = SafetyTier::Risky;
        input
            .provenance
            .taint_flags
            .insert(TaintFlag::UnverifiedLink);
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::TaintUnverifiedLinkRisky
        );
    }

    #[test]
    fn engine_allow_tainted_safe_tier() {
        let engine = PolicyEngine {
            zone_policy: minimal_zone_policy(),
        };
        let mut input = minimal_decision_input();
        input.safety_tier = SafetyTier::Safe;
        input.provenance.taint_flags.insert(TaintFlag::PublicInput);
        let decision = engine.evaluate_invoke(&input);
        // PublicInput with Safe tier should still be allowed
        assert_eq!(decision.decision, Decision::Allow);
    }

    #[test]
    fn engine_execution_approval_missing_denies() {
        let engine = PolicyEngine {
            zone_policy: minimal_zone_policy(),
        };
        let mut input = minimal_decision_input();
        input.execution_approval_required = true;
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::ApprovalMissingExecution
        );
    }

    // ── Elevation scope binding (C3.x) ─────────────────────────────────────
    //
    // Regression guard: ElevationScope carries `original_provenance_id` as a
    // REQUIRED field (FCP_CDDL_V2.cddl:165). The policy engine must refuse
    // to apply an elevation token whose `original_provenance_id` does not
    // bind to this request. Without that check, a legitimate elevation
    // token issued for request A can be replayed against request B in the
    // same zone with the same operation_id, silently raising B's
    // provenance integrity.

    fn elevation_flow_input(
        request_id: ObjectId,
        approvals: &'static [ApprovalToken],
    ) -> PolicyDecisionInput<'static> {
        static EMPTY_RECEIPTS: &[SanitizerReceipt] = &[];
        static EMPTY_OBJECTS: &[ObjectId] = &[];
        PolicyDecisionInput {
            request_object_id: request_id,
            zone_id: ZoneId::work(),
            principal: PrincipalId::new("user:alice").unwrap(),
            connector_id: ConnectorId::from_static("test:conn:v1"),
            operation_id: OperationId::from_static("op.elev"),
            capability_id: CapabilityId::new("cap.test").unwrap(),
            safety_tier: SafetyTier::Safe,
            // Community integrity flowing into Work zone → RequiresElevation.
            provenance: ProvenanceRecord::new(ZoneId::community()),
            approval_tokens: approvals,
            sanitizer_receipts: EMPTY_RECEIPTS,
            request_input: None,
            request_input_hash: None,
            related_object_ids: EMPTY_OBJECTS,
            transport: TransportMode::Lan,
            checkpoint_fresh: true,
            revocation_fresh: true,
            execution_approval_required: false,
            now_ms: 1_000,
            posture_attestation: None,
        }
    }

    fn elevation_token(original: ObjectId) -> ApprovalToken {
        ApprovalToken {
            token_id: "tok-elev".into(),
            issued_at_ms: 0,
            expires_at_ms: u64::MAX,
            issuer: "node:authority".into(),
            scope: ApprovalScope::Elevation(ElevationScope {
                operation_id: "op.elev".into(),
                original_provenance_id: original,
                target_integrity: IntegrityLevel::Work,
            }),
            zone_id: ZoneId::work(),
            signature: None,
            _state: std::marker::PhantomData,
        }
    }

    #[test]
    fn engine_elevation_rejects_token_bound_to_different_request() {
        static APPROVALS: std::sync::OnceLock<Vec<ApprovalToken>> = std::sync::OnceLock::new();

        // Token was issued for request A; attacker replays it against
        // request B. The engine must surface
        // ApprovalElevationScopeMismatch, not Allow.
        let request_b = ObjectId::from_unscoped_bytes(b"req-B");
        let approvals = APPROVALS
            .get_or_init(|| vec![elevation_token(ObjectId::from_unscoped_bytes(b"req-A"))]);
        let input = elevation_flow_input(request_b, approvals.as_slice());
        let engine = PolicyEngine {
            zone_policy: minimal_zone_policy(),
        };
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::ApprovalElevationScopeMismatch,
            "elevation token bound to a different request must not apply to this one",
        );
    }

    #[test]
    fn engine_elevation_accepts_token_bound_to_this_request() {
        static APPROVALS: std::sync::OnceLock<Vec<ApprovalToken>> = std::sync::OnceLock::new();

        let request = ObjectId::from_unscoped_bytes(b"req-match");
        let approvals = APPROVALS
            .get_or_init(|| vec![elevation_token(ObjectId::from_unscoped_bytes(b"req-match"))]);
        let input = elevation_flow_input(request, approvals.as_slice());
        let engine = PolicyEngine {
            zone_policy: minimal_zone_policy(),
        };
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(
            decision.decision,
            Decision::Allow,
            "elevation bound to this request must allow; got reason {:?}",
            decision.reason_code
        );
    }

    #[test]
    fn engine_elevation_missing_with_no_elevation_scope_reports_missing_not_mismatch() {
        static APPROVALS: std::sync::OnceLock<Vec<ApprovalToken>> = std::sync::OnceLock::new();

        // If there are no elevation-scoped tokens at all, the engine should
        // return ApprovalMissingElevation (preserving the existing
        // distinction between "missing" and "mismatch"). This guards
        // against the refactor collapsing the two states.
        let request = ObjectId::from_unscoped_bytes(b"req-no-elev");
        let approvals = APPROVALS.get_or_init(Vec::new);
        let input = elevation_flow_input(request, approvals.as_slice());
        let engine = PolicyEngine {
            zone_policy: minimal_zone_policy(),
        };
        let decision = engine.evaluate_invoke(&input);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::ApprovalMissingElevation,
        );
    }

    // ── check_transport (via PolicyEngine) ─────────────────────────────────

    #[test]
    fn check_transport_returns_correct_reason_per_mode() {
        // Deny all transports
        let policy = ZoneTransportPolicy {
            allow_lan: false,
            allow_derp: false,
            allow_funnel: false,
        };
        assert_eq!(
            check_transport(&policy, TransportMode::Lan),
            Some(DecisionReasonCode::TransportLanForbidden)
        );
        assert_eq!(
            check_transport(&policy, TransportMode::Derp),
            Some(DecisionReasonCode::TransportDerpForbidden)
        );
        assert_eq!(
            check_transport(&policy, TransportMode::Funnel),
            Some(DecisionReasonCode::TransportFunnelForbidden)
        );
    }

    #[test]
    fn check_transport_none_when_allowed() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        assert_eq!(check_transport(&policy, TransportMode::Lan), None);
        assert_eq!(check_transport(&policy, TransportMode::Derp), None);
        assert_eq!(check_transport(&policy, TransportMode::Funnel), None);
    }

    // ── input_constraints_match ────────────────────────────────────────────

    #[test]
    fn input_constraints_match_returns_false_when_no_input() {
        let constraints = vec![crate::InputConstraint {
            pointer: "/key".into(),
            expected: serde_json::Value::String("val".into()),
        }];
        assert!(!input_constraints_match(&constraints, None));
    }

    #[test]
    fn input_constraints_match_returns_true_when_matched() {
        let constraints = vec![crate::InputConstraint {
            pointer: "/key".into(),
            expected: serde_json::json!("val"),
        }];
        let input = serde_json::json!({"key": "val"});
        assert!(input_constraints_match(&constraints, Some(&input)));
    }

    #[test]
    fn input_constraints_match_returns_false_on_mismatch() {
        let constraints = vec![crate::InputConstraint {
            pointer: "/key".into(),
            expected: serde_json::json!("val"),
        }];
        let input = serde_json::json!({"key": "wrong"});
        assert!(!input_constraints_match(&constraints, Some(&input)));
    }

    #[test]
    fn input_constraints_match_empty_constraints_always_true() {
        let input = serde_json::json!({"anything": true});
        assert!(input_constraints_match(&[], Some(&input)));
    }

    // ── pattern_matches edge cases ─────────────────────────────────────────

    #[test]
    fn pattern_matches_double_wildcard() {
        // "**" is just two wildcards — matches anything
        let pat = PolicyPattern {
            pattern: "**".into(),
        };
        assert!(pat.matches("anything"));
        assert!(pat.matches(""));
    }

    #[test]
    fn pattern_matches_no_match_when_prefix_differs() {
        let pat = PolicyPattern {
            pattern: "abc*".into(),
        };
        assert!(pat.matches("abcdef"));
        assert!(!pat.matches("xabc"));
    }

    #[test]
    fn pattern_matches_no_match_when_suffix_differs() {
        let pat = PolicyPattern {
            pattern: "*xyz".into(),
        };
        assert!(pat.matches("abcxyz"));
        assert!(!pat.matches("xyzabc"));
    }

    // ── Preview Evaluator Tests ───────────────────────────────────────────

    #[test]
    fn preview_bundles_detects_allow_to_deny_transition() {
        let zone = ZoneId::work();
        let before_policy = test_zone_policy(zone.clone());
        let mut after_policy = test_zone_policy(zone.clone());
        // Add a deny rule that blocks the test capability
        after_policy.capability_deny.push(PolicyPattern {
            pattern: "cap.all".to_string(),
        });

        let before_bundle = policy_bundle(
            "b-before",
            zone.clone(),
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );
        let after_bundle = policy_bundle(
            "b-after",
            zone.clone(),
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );

        let mut before_objects = BTreeMap::new();
        before_objects.insert(
            "p-1".to_string(),
            PolicyBundleObject::ZonePolicy(before_policy),
        );
        let mut after_objects = BTreeMap::new();
        after_objects.insert(
            "p-1".to_string(),
            PolicyBundleObject::ZonePolicy(after_policy),
        );

        let before_r = PolicyBundleResolved::new(before_bundle, before_objects);
        let after_r = PolicyBundleResolved::new(after_bundle, after_objects);

        let sample = preview_sample("s1", test_invoke_request(zone));
        let report =
            preview_policy_bundles(&before_r, &after_r, &[sample]).expect("preview report");

        assert_eq!(report.entries.len(), 1);
        assert_eq!(
            report.entries[0].before_decision,
            PolicyPreviewDecision::Allow
        );
        assert_eq!(
            report.entries[0].after_decision,
            PolicyPreviewDecision::Deny
        );
        assert_eq!(report.entries[0].delta, Some(PolicyPreviewDelta::WouldDeny));
        assert_eq!(report.summary.would_deny, 1);
        assert_eq!(report.summary.total, 1);
    }

    #[test]
    fn preview_bundles_detects_deny_to_allow_transition() {
        let zone = ZoneId::work();
        // Before: deny cap.all
        let mut before_policy = test_zone_policy(zone.clone());
        before_policy.capability_deny.push(PolicyPattern {
            pattern: "cap.all".to_string(),
        });
        // After: no deny rules → allow
        let after_policy = test_zone_policy(zone.clone());

        let before_bundle = policy_bundle(
            "b-1",
            zone.clone(),
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );
        let after_bundle = policy_bundle(
            "b-2",
            zone.clone(),
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );

        let mut before_objects = BTreeMap::new();
        before_objects.insert(
            "p-1".to_string(),
            PolicyBundleObject::ZonePolicy(before_policy),
        );
        let mut after_objects = BTreeMap::new();
        after_objects.insert(
            "p-1".to_string(),
            PolicyBundleObject::ZonePolicy(after_policy),
        );

        let before_r = PolicyBundleResolved::new(before_bundle, before_objects);
        let after_r = PolicyBundleResolved::new(after_bundle, after_objects);

        let sample = preview_sample("s1", test_invoke_request(zone));
        let report =
            preview_policy_bundles(&before_r, &after_r, &[sample]).expect("preview report");

        assert_eq!(
            report.entries[0].delta,
            Some(PolicyPreviewDelta::WouldAllow)
        );
        assert_eq!(report.summary.would_allow, 1);
    }

    #[test]
    fn preview_bundles_no_change_when_policies_identical() {
        let zone = ZoneId::work();
        let policy = test_zone_policy(zone.clone());

        let bundle = policy_bundle(
            "b-same",
            zone.clone(),
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );

        let mut objects = BTreeMap::new();
        objects.insert("p-1".to_string(), PolicyBundleObject::ZonePolicy(policy));

        let resolved_a = PolicyBundleResolved::new(bundle.clone(), objects.clone());
        let resolved_b = PolicyBundleResolved::new(bundle, objects);

        let sample = preview_sample("s1", test_invoke_request(zone));
        let report =
            preview_policy_bundles(&resolved_a, &resolved_b, &[sample]).expect("preview report");

        assert_eq!(report.entries.len(), 1);
        assert!(report.entries[0].delta.is_none());
        assert_eq!(report.summary.total, 1);
        assert_eq!(report.summary.would_allow, 0);
        assert_eq!(report.summary.would_deny, 0);
    }

    #[test]
    fn preview_bundles_rejects_zone_mismatch() {
        let zone_a = ZoneId::work();
        let zone_b = ZoneId::community();

        let bundle_a = policy_bundle(
            "ba",
            zone_a.clone(),
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );
        let bundle_b = policy_bundle(
            "bb",
            zone_b,
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );

        let mut objs = BTreeMap::new();
        objs.insert(
            "p-1".to_string(),
            PolicyBundleObject::ZonePolicy(test_zone_policy(zone_a)),
        );

        let a = PolicyBundleResolved::new(bundle_a, objs.clone());
        let b = PolicyBundleResolved::new(bundle_b, objs);

        let result = preview_policy_bundles(&a, &b, &[]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, PolicyPreviewError::ZoneMismatch { .. }),
            "expected ZoneMismatch, got: {err}"
        );
    }

    #[test]
    fn preview_bundles_missing_zone_policy_returns_error() {
        let zone = ZoneId::work();
        let bundle = policy_bundle(
            "b1",
            zone,
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );

        // Before has objects, after is empty (missing policy)
        let a = PolicyBundleResolved::new(bundle.clone(), BTreeMap::new());
        let b = PolicyBundleResolved::new(bundle, BTreeMap::new());

        let result = preview_policy_bundles(&a, &b, &[]);
        assert!(matches!(
            result,
            Err(PolicyPreviewError::MissingZonePolicy { .. })
        ));
    }

    #[test]
    fn preview_bundles_transport_change_deny_to_allow() {
        let zone = ZoneId::work();
        // Before: deny DERP
        let before_policy = test_zone_policy(zone.clone()); // default denies DERP
        // After: allow DERP
        let mut after_policy = test_zone_policy(zone.clone());
        after_policy.transport_policy.allow_derp = true;

        let before_bundle = policy_bundle(
            "b1",
            zone.clone(),
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );
        let after_bundle = policy_bundle(
            "b2",
            zone.clone(),
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );

        let mut before_objs = BTreeMap::new();
        before_objs.insert(
            "p-1".to_string(),
            PolicyBundleObject::ZonePolicy(before_policy),
        );
        let mut after_objs = BTreeMap::new();
        after_objs.insert(
            "p-1".to_string(),
            PolicyBundleObject::ZonePolicy(after_policy),
        );

        let br = PolicyBundleResolved::new(before_bundle, before_objs);
        let ar = PolicyBundleResolved::new(after_bundle, after_objs);

        let mut sample = preview_sample("derp-test", test_invoke_request(zone));
        sample.transport = TransportMode::Derp;

        let report = preview_policy_bundles(&br, &ar, &[sample]).expect("preview");
        assert_eq!(
            report.entries[0].delta,
            Some(PolicyPreviewDelta::WouldAllow)
        );
        assert_eq!(report.summary.would_allow, 1);
    }

    #[test]
    fn preview_bundles_reason_changed_same_decision() {
        let zone = ZoneId::work();
        // Both policies deny — but for different reasons
        let mut before_policy = test_zone_policy(zone.clone());
        before_policy.transport_policy.allow_lan = false;

        let mut after_policy = test_zone_policy(zone.clone());
        after_policy.principal_deny.push(PolicyPattern {
            pattern: "user:*".to_string(),
        });

        let before_bundle = policy_bundle(
            "b1",
            zone.clone(),
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );
        let after_bundle = policy_bundle(
            "b2",
            zone.clone(),
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );

        let mut before_objs = BTreeMap::new();
        before_objs.insert(
            "p-1".to_string(),
            PolicyBundleObject::ZonePolicy(before_policy),
        );
        let mut after_objs = BTreeMap::new();
        after_objs.insert(
            "p-1".to_string(),
            PolicyBundleObject::ZonePolicy(after_policy),
        );

        let br = PolicyBundleResolved::new(before_bundle, before_objs);
        let ar = PolicyBundleResolved::new(after_bundle, after_objs);

        let sample = preview_sample("reason-change", test_invoke_request(zone));
        let report = preview_policy_bundles(&br, &ar, &[sample]).expect("preview");

        // Both deny, but reason codes differ
        assert_eq!(
            report.entries[0].before_decision,
            PolicyPreviewDecision::Deny
        );
        assert_eq!(
            report.entries[0].after_decision,
            PolicyPreviewDecision::Deny
        );
        assert_eq!(
            report.entries[0].delta,
            Some(PolicyPreviewDelta::ReasonChanged)
        );
        assert_eq!(report.summary.reason_changed, 1);
    }

    #[test]
    fn preview_bundles_multiple_samples_mixed_deltas() {
        let zone = ZoneId::work();
        let before_policy = test_zone_policy(zone.clone());
        let mut after_policy = test_zone_policy(zone.clone());
        after_policy.transport_policy.allow_derp = true;
        after_policy.capability_deny.push(PolicyPattern {
            pattern: "cap.all".to_string(),
        });

        let before_bundle = policy_bundle(
            "b1",
            zone.clone(),
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );
        let after_bundle = policy_bundle(
            "b2",
            zone.clone(),
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );

        let mut before_objs = BTreeMap::new();
        before_objs.insert(
            "p-1".to_string(),
            PolicyBundleObject::ZonePolicy(before_policy),
        );
        let mut after_objs = BTreeMap::new();
        after_objs.insert(
            "p-1".to_string(),
            PolicyBundleObject::ZonePolicy(after_policy),
        );

        let br = PolicyBundleResolved::new(before_bundle, before_objs);
        let ar = PolicyBundleResolved::new(after_bundle, after_objs);

        // Sample 1: LAN request → was allow, now denied (cap.all in deny list)
        let s1 = preview_sample("lan-req", test_invoke_request(zone.clone()));
        // Sample 2: DERP request → was denied (DERP forbidden), now denied (cap.all deny overrides)
        let mut s2 = preview_sample("derp-req", test_invoke_request(zone));
        s2.transport = TransportMode::Derp;

        let report = preview_policy_bundles(&br, &ar, &[s1, s2]).expect("preview");

        assert_eq!(report.summary.total, 2);
        // First: allow → deny
        assert_eq!(report.entries[0].delta, Some(PolicyPreviewDelta::WouldDeny));
        // Second: deny(transport) → deny(capability) = reason changed
        assert_eq!(
            report.entries[1].before_decision,
            PolicyPreviewDecision::Deny
        );
        assert_eq!(
            report.entries[1].after_decision,
            PolicyPreviewDecision::Deny
        );
    }

    #[test]
    fn preview_bundles_empty_samples_produces_empty_report() {
        let zone = ZoneId::work();
        let policy = test_zone_policy(zone.clone());
        let bundle = policy_bundle(
            "b1",
            zone,
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );

        let mut objs = BTreeMap::new();
        objs.insert("p-1".to_string(), PolicyBundleObject::ZonePolicy(policy));

        let r = PolicyBundleResolved::new(bundle, objs);
        let report = preview_policy_bundles(&r, &r, &[]).expect("preview");

        assert!(report.entries.is_empty());
        assert_eq!(report.summary.total, 0);
    }

    #[test]
    fn preview_bundles_is_deterministic() {
        let zone = ZoneId::work();
        let before_policy = test_zone_policy(zone.clone());
        let mut after_policy = test_zone_policy(zone.clone());
        after_policy.capability_deny.push(PolicyPattern {
            pattern: "cap.all".to_string(),
        });

        let before_bundle = policy_bundle(
            "b1",
            zone.clone(),
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );
        let after_bundle = policy_bundle(
            "b2",
            zone.clone(),
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );

        let mut before_objs = BTreeMap::new();
        before_objs.insert(
            "p-1".to_string(),
            PolicyBundleObject::ZonePolicy(before_policy),
        );
        let mut after_objs = BTreeMap::new();
        after_objs.insert(
            "p-1".to_string(),
            PolicyBundleObject::ZonePolicy(after_policy),
        );

        let br = PolicyBundleResolved::new(before_bundle.clone(), before_objs.clone());
        let ar = PolicyBundleResolved::new(after_bundle.clone(), after_objs.clone());

        let sample = preview_sample("det-test", test_invoke_request(zone));
        let r1 = preview_policy_bundles(&br, &ar, std::slice::from_ref(&sample)).expect("r1");

        let br2 = PolicyBundleResolved::new(before_bundle, before_objs);
        let ar2 = PolicyBundleResolved::new(after_bundle, after_objs);
        let r2 = preview_policy_bundles(&br2, &ar2, &[sample]).expect("r2");

        assert_eq!(r1.entries.len(), r2.entries.len());
        assert_eq!(r1.entries[0].before.decision, r2.entries[0].before.decision);
        assert_eq!(r1.entries[0].after.decision, r2.entries[0].after.decision);
        assert_eq!(
            r1.entries[0].before.reason_code,
            r2.entries[0].before.reason_code
        );
        assert_eq!(
            r1.entries[0].after.reason_code,
            r2.entries[0].after.reason_code
        );
        assert_eq!(r1.summary.total, r2.summary.total);
        assert_eq!(r1.summary.would_deny, r2.summary.would_deny);
    }

    // ── Direct Zone Policy Preview Tests ──────────────────────────────────

    #[test]
    fn direct_preview_detects_allow_to_deny() {
        let zone = ZoneId::work();
        let baseline = minimal_zone_policy();
        let mut proposed = minimal_zone_policy();
        proposed.capability_deny.push(PolicyPattern {
            pattern: "cap.all".to_string(),
        });

        let sample = PolicySimulationInput {
            zone_policy: baseline.clone(), // overridden by preview
            invoke_request: test_invoke_request(zone),
            transport: TransportMode::Lan,
            checkpoint_fresh: true,
            revocation_fresh: true,
            execution_approval_required: false,
            sanitizer_receipts: Vec::new(),
            related_object_ids: Vec::new(),
            request_object_id: None,
            request_input_hash: None,
            safety_tier: SafetyTier::Safe,
            principal: Some("user:alice".to_string()),
            capability_id: Some("cap.all".to_string()),
            provenance_record: None,
            now_ms: None,
            posture_attestation: None,
        };

        let input = PreviewInput {
            baseline_policy: baseline,
            proposed_policy: proposed,
            samples: vec![sample],
        };
        let result = preview_policy_changes(&input).expect("preview");

        assert_eq!(result.deltas.len(), 1);
        assert_eq!(result.deltas[0].baseline_outcome, PreviewOutcome::Allow);
        assert_eq!(result.deltas[0].proposed_outcome, PreviewOutcome::Deny);
        assert!(result.deltas[0].changed);
        assert_eq!(result.summary.changed_count, 1);
        assert_eq!(result.summary.newly_denied, 1);
    }

    #[test]
    fn direct_preview_detects_deny_to_allow() {
        let zone = ZoneId::work();
        let mut baseline = minimal_zone_policy();
        baseline.transport_policy.allow_lan = false;
        let proposed = minimal_zone_policy();

        let sample = PolicySimulationInput {
            zone_policy: baseline.clone(),
            invoke_request: test_invoke_request(zone),
            transport: TransportMode::Lan,
            checkpoint_fresh: true,
            revocation_fresh: true,
            execution_approval_required: false,
            sanitizer_receipts: Vec::new(),
            related_object_ids: Vec::new(),
            request_object_id: None,
            request_input_hash: None,
            safety_tier: SafetyTier::Safe,
            principal: Some("user:alice".to_string()),
            capability_id: Some("cap.all".to_string()),
            provenance_record: None,
            now_ms: None,
            posture_attestation: None,
        };

        let input = PreviewInput {
            baseline_policy: baseline,
            proposed_policy: proposed,
            samples: vec![sample],
        };
        let result = preview_policy_changes(&input).expect("preview");

        assert_eq!(result.deltas[0].baseline_outcome, PreviewOutcome::Deny);
        assert_eq!(result.deltas[0].proposed_outcome, PreviewOutcome::Allow);
        assert!(result.deltas[0].changed);
        assert_eq!(result.summary.newly_allowed, 1);
    }

    #[test]
    fn direct_preview_no_change_reports_unchanged() {
        let zone = ZoneId::work();
        let policy = minimal_zone_policy();

        let sample = PolicySimulationInput {
            zone_policy: policy.clone(),
            invoke_request: test_invoke_request(zone),
            transport: TransportMode::Lan,
            checkpoint_fresh: true,
            revocation_fresh: true,
            execution_approval_required: false,
            sanitizer_receipts: Vec::new(),
            related_object_ids: Vec::new(),
            request_object_id: None,
            request_input_hash: None,
            safety_tier: SafetyTier::Safe,
            principal: Some("user:alice".to_string()),
            capability_id: Some("cap.all".to_string()),
            provenance_record: None,
            now_ms: None,
            posture_attestation: None,
        };

        let input = PreviewInput {
            baseline_policy: policy.clone(),
            proposed_policy: policy,
            samples: vec![sample],
        };
        let result = preview_policy_changes(&input).expect("preview");

        assert!(!result.deltas[0].changed);
        assert_eq!(result.summary.unchanged, 1);
        assert_eq!(result.summary.changed_count, 0);
    }

    #[test]
    fn direct_preview_empty_samples() {
        let policy = minimal_zone_policy();
        let input = PreviewInput {
            baseline_policy: policy.clone(),
            proposed_policy: policy,
            samples: vec![],
        };
        let result = preview_policy_changes(&input).expect("preview");

        assert!(result.deltas.is_empty());
        assert_eq!(result.summary.total_samples, 0);
    }

    #[test]
    fn preview_outcome_serde_roundtrip() {
        let allow = serde_json::to_string(&PreviewOutcome::Allow).unwrap();
        assert_eq!(allow, "\"allow\"");
        let deny = serde_json::to_string(&PreviewOutcome::Deny).unwrap();
        assert_eq!(deny, "\"deny\"");
        let rt: PreviewOutcome = serde_json::from_str(&allow).unwrap();
        assert_eq!(rt, PreviewOutcome::Allow);
    }

    #[test]
    fn preview_delta_entry_serde_roundtrip() {
        let entry = PreviewDeltaEntry {
            sample_index: 0,
            baseline_outcome: PreviewOutcome::Allow,
            baseline_reason: "allow".to_string(),
            proposed_outcome: PreviewOutcome::Deny,
            proposed_reason: "zone_policy.capability_denied".to_string(),
            changed: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: PreviewDeltaEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.sample_index, 0);
        assert!(back.changed);
        assert_eq!(back.proposed_outcome, PreviewOutcome::Deny);
    }

    #[test]
    fn preview_result_serde_roundtrip() {
        let result = PreviewResult {
            deltas: vec![PreviewDeltaEntry {
                sample_index: 0,
                baseline_outcome: PreviewOutcome::Allow,
                baseline_reason: "allow".to_string(),
                proposed_outcome: PreviewOutcome::Deny,
                proposed_reason: "transport.lan_forbidden".to_string(),
                changed: true,
            }],
            summary: PreviewSummary {
                total_samples: 1,
                changed_count: 1,
                newly_allowed: 0,
                newly_denied: 1,
                unchanged: 0,
            },
        };
        let json = serde_json::to_string_pretty(&result).unwrap();
        let back: PreviewResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.deltas.len(), 1);
        assert_eq!(back.summary.newly_denied, 1);
    }

    // ── Bundle Signature Tests (bead 2ady) ────────────────────────────────

    #[test]
    fn bundle_signing_bytes_change_when_policy_seq_changes() {
        let zone = ZoneId::work();
        let refs = vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")];
        let b1 = PolicyBundle::builder("b", zone.clone(), 1)
            .bundle_hash(test_bundle_hash())
            .policies(refs.clone())
            .signature(test_bundle_signature())
            .build()
            .expect("b1");
        let b2 = PolicyBundle::builder("b", zone, 2)
            .bundle_hash(test_bundle_hash())
            .policies(refs)
            .signature(test_bundle_signature())
            .build()
            .expect("b2");

        let s1 = b1.signing_bytes().expect("s1");
        let s2 = b2.signing_bytes().expect("s2");
        assert_ne!(
            s1, s2,
            "different policy_seq must produce different signing bytes"
        );
    }

    #[test]
    fn bundle_validate_rejects_empty_bundle_id() {
        let zone = ZoneId::work();
        let result = PolicyBundle::builder("", zone, 1)
            .bundle_hash(test_bundle_hash())
            .policies(vec![policy_ref("p", "fcp.core:ZonePolicy@1.0")])
            .signature(test_bundle_signature())
            .build();

        assert!(
            result.is_err() || {
                let b = result.unwrap();
                b.validate().is_err()
            }
        );
    }

    #[test]
    fn bundle_validate_rejects_wrong_hash_algo() {
        let zone = ZoneId::work();
        let mut bundle = PolicyBundle::builder("b", zone, 1)
            .bundle_hash(test_bundle_hash())
            .policies(vec![policy_ref("p", "fcp.core:ZonePolicy@1.0")])
            .signature(test_bundle_signature())
            .build()
            .expect("bundle");
        bundle.hash_algo = "sha256".to_string();

        let err = bundle.validate();
        assert!(err.is_err());
    }

    #[test]
    fn bundle_signing_bytes_include_all_fields() {
        let zone = ZoneId::work();
        let bundle = PolicyBundle::builder("b", zone, 1)
            .bundle_hash(test_bundle_hash())
            .policies(vec![policy_ref("p", "fcp.core:ZonePolicy@1.0")])
            .signature(test_bundle_signature())
            .build()
            .expect("bundle");

        let bytes = bundle.signing_bytes().expect("signing bytes");
        // Signing bytes must be non-empty and reproducible
        assert!(!bytes.is_empty());
        let bytes2 = bundle.signing_bytes().expect("signing bytes 2");
        assert_eq!(bytes, bytes2, "signing bytes must be deterministic");
    }

    // ── Diff Stability & Risk Summary Tests (bead 2ady) ──────────────────

    #[test]
    fn diff_risk_flags_capability_allow_expansion() {
        let zone = ZoneId::work();
        let before_policy = test_zone_policy(zone.clone());
        let mut after_policy = test_zone_policy(zone.clone());
        after_policy.capability_allow.push(PolicyPattern {
            pattern: "cap.read".to_string(),
        });

        let before_bundle = policy_bundle(
            "b1",
            zone.clone(),
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );
        let after_bundle = policy_bundle(
            "b2",
            zone,
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );

        let mut before_objs = BTreeMap::new();
        before_objs.insert(
            "p-1".to_string(),
            PolicyBundleObject::ZonePolicy(before_policy),
        );
        let mut after_objs = BTreeMap::new();
        after_objs.insert(
            "p-1".to_string(),
            PolicyBundleObject::ZonePolicy(after_policy),
        );

        let br = PolicyBundleResolved::new(before_bundle, before_objs);
        let ar = PolicyBundleResolved::new(after_bundle, after_objs);

        let diff = diff_policy_bundles(&br, &ar).expect("diff");
        assert!(
            diff.risk
                .flags
                .iter()
                .map(|flag| flag.code)
                .any(|code| code == PolicyRiskCode::CapabilityAllowExpanded),
            "expanding capability_allow should flag CapabilityAllowExpanded"
        );
    }

    #[test]
    fn diff_risk_flags_transport_derp_enabled() {
        let zone = ZoneId::work();
        let before_policy = test_zone_policy(zone.clone());
        let mut after_policy = test_zone_policy(zone.clone());
        after_policy.transport_policy.allow_derp = true;

        let before_bundle = policy_bundle(
            "b1",
            zone.clone(),
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );
        let after_bundle = policy_bundle(
            "b2",
            zone,
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );

        let mut before_objs = BTreeMap::new();
        before_objs.insert(
            "p-1".to_string(),
            PolicyBundleObject::ZonePolicy(before_policy),
        );
        let mut after_objs = BTreeMap::new();
        after_objs.insert(
            "p-1".to_string(),
            PolicyBundleObject::ZonePolicy(after_policy),
        );

        let br = PolicyBundleResolved::new(before_bundle, before_objs);
        let ar = PolicyBundleResolved::new(after_bundle, after_objs);

        let diff = diff_policy_bundles(&br, &ar).expect("diff");
        assert!(
            diff.risk
                .flags
                .iter()
                .map(|flag| flag.code)
                .any(|code| code == PolicyRiskCode::TransportDerpEnabled)
        );
    }

    #[test]
    fn diff_risk_summary_is_deterministic() {
        let zone = ZoneId::work();
        let before_policy = test_zone_policy(zone.clone());
        let mut after_policy = test_zone_policy(zone.clone());
        after_policy.transport_policy.allow_derp = true;
        after_policy.transport_policy.allow_funnel = true;
        after_policy.capability_allow.push(PolicyPattern {
            pattern: "cap.read".to_string(),
        });

        let make_resolved = |bundle_id: &str, policy: ZonePolicyObject| {
            let bundle = policy_bundle(
                bundle_id,
                zone.clone(),
                vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
            );
            let mut objs = BTreeMap::new();
            objs.insert("p-1".to_string(), PolicyBundleObject::ZonePolicy(policy));
            PolicyBundleResolved::new(bundle, objs)
        };

        let br1 = make_resolved("b1", before_policy.clone());
        let ar1 = make_resolved("b2", after_policy.clone());
        let diff1 = diff_policy_bundles(&br1, &ar1).expect("d1");

        let br2 = make_resolved("b1", before_policy);
        let ar2 = make_resolved("b2", after_policy);
        let diff2 = diff_policy_bundles(&br2, &ar2).expect("d2");

        // Risk flags should be identical and in the same order
        assert_eq!(diff1.risk.flags.len(), diff2.risk.flags.len());
        for (f1, f2) in diff1.risk.flags.iter().zip(diff2.risk.flags.iter()) {
            assert_eq!(f1.code, f2.code);
            assert_eq!(f1.severity, f2.severity);
        }
    }

    #[test]
    fn diff_no_change_produces_empty_risk_flags() {
        let zone = ZoneId::work();
        let policy = test_zone_policy(zone.clone());

        let bundle = policy_bundle(
            "b-same",
            zone,
            vec![policy_ref("p-1", "fcp.core:ZonePolicy@1.0")],
        );

        let mut objs = BTreeMap::new();
        objs.insert("p-1".to_string(), PolicyBundleObject::ZonePolicy(policy));

        let r = PolicyBundleResolved::new(bundle, objs);
        let diff = diff_policy_bundles(&r, &r).expect("diff");

        assert!(
            diff.risk.flags.is_empty(),
            "identical policies should produce no risk flags"
        );
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert!(diff.changed.is_empty());
    }

    #[test]
    fn diff_rejects_zone_mismatch() {
        let zone_a = ZoneId::work();
        let zone_b = ZoneId::community();

        let ba = policy_bundle(
            "ba",
            zone_a.clone(),
            vec![policy_ref("p", "fcp.core:ZonePolicy@1.0")],
        );
        let bb = policy_bundle(
            "bb",
            zone_b,
            vec![policy_ref("p", "fcp.core:ZonePolicy@1.0")],
        );

        let mut objs = BTreeMap::new();
        objs.insert(
            "p".to_string(),
            PolicyBundleObject::ZonePolicy(test_zone_policy(zone_a)),
        );

        let ra = PolicyBundleResolved::new(ba, objs.clone());
        let rb = PolicyBundleResolved::new(bb, objs);

        assert!(matches!(
            diff_policy_bundles(&ra, &rb),
            Err(PolicyDiffError::ZoneMismatch { .. })
        ));
    }

    // ── Enforcement + Rollback Integration Tests (bead 2ady) ─────────────

    #[test]
    fn apply_bundle_changes_enforcement_decisions() {
        let zone = ZoneId::work();
        // Step 1: Baseline allows everything
        let baseline_policy = test_zone_policy(zone.clone());
        let baseline_engine = PolicyEngine {
            zone_policy: baseline_policy,
        };

        let input = minimal_decision_input();
        let d1 = baseline_engine.evaluate_invoke(&input);
        assert_eq!(d1.decision, Decision::Allow);

        // Step 2: "Apply" new policy that denies the capability
        let mut new_policy = test_zone_policy(zone);
        new_policy.capability_deny.push(PolicyPattern {
            pattern: "cap.*".to_string(),
        });
        let new_engine = PolicyEngine {
            zone_policy: new_policy,
        };

        let d2 = new_engine.evaluate_invoke(&input);
        assert_eq!(d2.decision, Decision::Deny);
        assert_eq!(
            d2.reason_code,
            DecisionReasonCode::ZonePolicyCapabilityDenied
        );
    }

    #[test]
    fn rollback_restores_prior_enforcement_behavior() {
        let zone = ZoneId::work();
        // Step 1: Baseline allows
        let baseline_policy = test_zone_policy(zone.clone());

        // Step 2: Changed policy denies
        let mut changed_policy = test_zone_policy(zone);
        changed_policy.principal_deny.push(PolicyPattern {
            pattern: "user:*".to_string(),
        });

        let input = minimal_decision_input();

        let baseline_engine = PolicyEngine {
            zone_policy: baseline_policy.clone(),
        };
        let changed_engine = PolicyEngine {
            zone_policy: changed_policy,
        };

        let d_before = baseline_engine.evaluate_invoke(&input);
        assert_eq!(d_before.decision, Decision::Allow);

        let d_changed = changed_engine.evaluate_invoke(&input);
        assert_eq!(d_changed.decision, Decision::Deny);

        // Step 3: Rollback to baseline
        let rollback_engine = PolicyEngine {
            zone_policy: baseline_policy,
        };
        let d_rollback = rollback_engine.evaluate_invoke(&input);
        assert_eq!(d_rollback.decision, Decision::Allow);
        assert_eq!(d_rollback.reason_code, d_before.reason_code);
    }

    #[test]
    fn enforcement_change_with_transport_restriction() {
        let zone = ZoneId::work();
        let mut policy = test_zone_policy(zone);
        // Deny DERP transport
        policy.transport_policy.allow_derp = false;

        let engine = PolicyEngine {
            zone_policy: policy,
        };

        let mut input = minimal_decision_input();
        // LAN should still be allowed
        input.transport = TransportMode::Lan;
        assert_eq!(engine.evaluate_invoke(&input).decision, Decision::Allow);

        // DERP should be denied
        input.transport = TransportMode::Derp;
        let d = engine.evaluate_invoke(&input);
        assert_eq!(d.decision, Decision::Deny);
        assert_eq!(d.reason_code, DecisionReasonCode::TransportDerpForbidden);
    }

    #[test]
    fn diff_serde_roundtrip() {
        let zone = ZoneId::work();
        let before_policy = test_zone_policy(zone.clone());
        let mut after_policy = test_zone_policy(zone.clone());
        after_policy.capability_allow.push(PolicyPattern {
            pattern: "cap.read".to_string(),
        });

        let make_resolved = |bundle_id: &str, policy: ZonePolicyObject| {
            let bundle = policy_bundle(
                bundle_id,
                zone.clone(),
                vec![policy_ref("p", "fcp.core:ZonePolicy@1.0")],
            );
            let mut objs = BTreeMap::new();
            objs.insert("p".to_string(), PolicyBundleObject::ZonePolicy(policy));
            PolicyBundleResolved::new(bundle, objs)
        };

        let br = make_resolved("b1", before_policy);
        let ar = make_resolved("b2", after_policy);
        let diff = diff_policy_bundles(&br, &ar).expect("diff");

        let json = serde_json::to_string(&diff).expect("serialize");
        let back: PolicyBundleDiff = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.zone_id, diff.zone_id);
        assert_eq!(back.risk.flags.len(), diff.risk.flags.len());
    }

    #[test]
    fn risk_severity_ordering() {
        assert!(PolicyRiskSeverity::Low < PolicyRiskSeverity::Medium);
        assert!(PolicyRiskSeverity::Medium < PolicyRiskSeverity::High);
        assert!(PolicyRiskSeverity::High < PolicyRiskSeverity::Critical);
    }

    #[test]
    fn risk_code_serde_roundtrip() {
        let code = PolicyRiskCode::TransportDerpEnabled;
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, "\"transport_derp_enabled\"");
        let back: PolicyRiskCode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, code);
    }

    // ── Batch 12: BudgetStatus ────────────────────────────────────────────

    #[test]
    fn budget_status_ok_serde_roundtrip() {
        let s = BudgetStatus::Ok;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"ok\"");
        let back: BudgetStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn budget_status_exceeded_serde_roundtrip() {
        let s = BudgetStatus::Exceeded;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"exceeded\"");
        let back: BudgetStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn budget_status_copy_clone() {
        let s = BudgetStatus::Ok;
        let copied = s;
        let cloned = Clone::clone(&s);
        assert_eq!(copied, cloned);
        assert_eq!(s, BudgetStatus::Ok);
    }

    #[test]
    fn budget_status_eq() {
        assert_eq!(BudgetStatus::Ok, BudgetStatus::Ok);
        assert_eq!(BudgetStatus::Exceeded, BudgetStatus::Exceeded);
        assert_ne!(BudgetStatus::Ok, BudgetStatus::Exceeded);
    }

    // ── Batch 12: UsageBudgetUsage ────────────────────────────────────────

    #[test]
    fn usage_budget_usage_serde_roundtrip() {
        let u = UsageBudgetUsage {
            metric: crate::UsageMetricKind::ApiCredits,
            used: 500,
            limit: 1000,
            remaining: 500,
            window_started_at: 1_700_000_000,
            window_resets_at: 1_700_003_600,
            status: BudgetStatus::Ok,
        };
        let json = serde_json::to_string(&u).unwrap();
        let back: UsageBudgetUsage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.used, 500);
        assert_eq!(back.limit, 1000);
        assert_eq!(back.remaining, 500);
        assert_eq!(back.status, BudgetStatus::Ok);
    }

    #[test]
    fn usage_budget_usage_clone() {
        let u = UsageBudgetUsage {
            metric: crate::UsageMetricKind::Tokens,
            used: 100,
            limit: 200,
            remaining: 100,
            window_started_at: 1_000,
            window_resets_at: 2_000,
            status: BudgetStatus::Exceeded,
        };
        let cloned = Clone::clone(&u);
        assert_eq!(cloned.used, u.used);
        assert_eq!(cloned.limit, u.limit);
        assert_eq!(cloned.status, u.status);
    }

    #[test]
    fn usage_budget_usage_exceeded_status() {
        let u = UsageBudgetUsage {
            metric: crate::UsageMetricKind::Bytes,
            used: 2000,
            limit: 1000,
            remaining: 0,
            window_started_at: 1_000,
            window_resets_at: 2_000,
            status: BudgetStatus::Exceeded,
        };
        assert_eq!(u.status, BudgetStatus::Exceeded);
        assert_eq!(u.remaining, 0);
    }

    // ── Batch 12: UsageBudgetSnapshot ─────────────────────────────────────

    #[test]
    fn usage_budget_snapshot_serde_roundtrip() {
        let snap = UsageBudgetSnapshot {
            zone_id: ZoneId::work(),
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetUsage {
                metric: crate::UsageMetricKind::Requests,
                used: 50,
                limit: 100,
                remaining: 50,
                window_started_at: 1_000,
                window_resets_at: 2_000,
                status: BudgetStatus::Ok,
            }],
            updated_at: 1_500,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: UsageBudgetSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.zone_id, ZoneId::work());
        assert_eq!(back.budgets.len(), 1);
        assert_eq!(back.updated_at, 1_500);
    }

    #[test]
    fn usage_budget_snapshot_clone() {
        let snap = UsageBudgetSnapshot {
            zone_id: ZoneId::owner(),
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![],
            updated_at: 9_000,
        };
        let cloned = Clone::clone(&snap);
        assert_eq!(cloned.zone_id, snap.zone_id);
        assert_eq!(cloned.updated_at, snap.updated_at);
        assert!(cloned.budgets.is_empty());
    }

    #[test]
    fn budget_enforcement_serde_roundtrip() {
        let w = BudgetEnforcement::Warn;
        let json = serde_json::to_string(&w).unwrap();
        let back: BudgetEnforcement = serde_json::from_str(&json).unwrap();
        assert_eq!(back, w);

        let d = BudgetEnforcement::Deny;
        let json2 = serde_json::to_string(&d).unwrap();
        let back2: BudgetEnforcement = serde_json::from_str(&json2).unwrap();
        assert_eq!(back2, d);
    }

    // ── Batch 12: PolicySimulationError ───────────────────────────────────

    #[test]
    fn policy_simulation_error_missing_claim_display() {
        let e = PolicySimulationError::MissingClaim { claim: "iss" };
        assert_eq!(e.to_string(), "missing required claim: iss");
    }

    #[test]
    fn policy_simulation_error_invalid_principal_display() {
        let e = PolicySimulationError::InvalidPrincipal {
            value: "bad".into(),
            message: "not a principal".into(),
        };
        assert_eq!(e.to_string(), "invalid principal id 'bad': not a principal");
    }

    #[test]
    fn policy_simulation_error_invalid_capability_display() {
        let e = PolicySimulationError::InvalidCapability {
            value: "cap-x".into(),
            message: "unknown".into(),
        };
        assert_eq!(e.to_string(), "invalid capability id 'cap-x': unknown");
    }

    #[test]
    fn policy_simulation_error_token_claims_display() {
        let e = PolicySimulationError::TokenClaims {
            message: "bad claims".into(),
        };
        assert_eq!(e.to_string(), "failed to parse token claims: bad claims");
    }

    #[test]
    fn policy_simulation_error_zone_mismatch_display() {
        let e = PolicySimulationError::ZoneMismatch {
            request_zone: "z:work".into(),
            policy_zone: "z:owner".into(),
        };
        assert_eq!(
            e.to_string(),
            "zone mismatch: request zone 'z:work' vs policy zone 'z:owner'"
        );
    }

    #[test]
    fn policy_simulation_error_is_std_error() {
        let e = PolicySimulationError::MissingClaim { claim: "sub" };
        let _: &dyn std::error::Error = &e;
    }

    // ── Batch 12: PreviewSummary ──────────────────────────────────────────

    #[test]
    fn preview_summary_default() {
        let s = PreviewSummary::default();
        assert_eq!(s.total_samples, 0);
        assert_eq!(s.changed_count, 0);
        assert_eq!(s.newly_allowed, 0);
        assert_eq!(s.newly_denied, 0);
        assert_eq!(s.unchanged, 0);
    }

    #[test]
    fn preview_summary_clone() {
        let s = PreviewSummary {
            total_samples: 10,
            changed_count: 3,
            newly_allowed: 2,
            newly_denied: 1,
            unchanged: 7,
        };
        let cloned = Clone::clone(&s);
        assert_eq!(cloned.total_samples, 10);
        assert_eq!(cloned.changed_count, 3);
        assert_eq!(cloned.unchanged, 7);
    }

    #[test]
    fn preview_summary_serde_roundtrip() {
        let s = PreviewSummary {
            total_samples: 5,
            changed_count: 2,
            newly_allowed: 1,
            newly_denied: 1,
            unchanged: 3,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: PreviewSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total_samples, s.total_samples);
        assert_eq!(back.newly_allowed, s.newly_allowed);
    }

    // ── Batch 12: PreviewOutcome ──────────────────────────────────────────

    #[test]
    fn preview_outcome_from_decision_allow() {
        let o: PreviewOutcome = Decision::Allow.into();
        assert_eq!(o, PreviewOutcome::Allow);
    }

    #[test]
    fn preview_outcome_from_decision_deny() {
        let o: PreviewOutcome = Decision::Deny.into();
        assert_eq!(o, PreviewOutcome::Deny);
    }

    #[test]
    fn preview_outcome_clone_eq() {
        let a = PreviewOutcome::Allow;
        let b = Clone::clone(&a);
        assert_eq!(a, b);
        assert_ne!(PreviewOutcome::Allow, PreviewOutcome::Deny);
    }

    // ── Batch 12: PreviewDeltaEntry ───────────────────────────────────────

    #[test]
    fn preview_delta_entry_clone() {
        let entry = PreviewDeltaEntry {
            sample_index: 0,
            baseline_outcome: PreviewOutcome::Allow,
            baseline_reason: "allowed".into(),
            proposed_outcome: PreviewOutcome::Deny,
            proposed_reason: "denied".into(),
            changed: true,
        };
        let cloned = Clone::clone(&entry);
        assert_eq!(cloned.sample_index, 0);
        assert!(cloned.changed);
        assert_eq!(cloned.proposed_outcome, PreviewOutcome::Deny);
    }

    // ── Batch 12: PreviewResult ───────────────────────────────────────────

    #[test]
    fn preview_result_clone() {
        let result = PreviewResult {
            deltas: vec![PreviewDeltaEntry {
                sample_index: 0,
                baseline_outcome: PreviewOutcome::Allow,
                baseline_reason: "ok".into(),
                proposed_outcome: PreviewOutcome::Allow,
                proposed_reason: "ok".into(),
                changed: false,
            }],
            summary: PreviewSummary {
                total_samples: 1,
                changed_count: 0,
                newly_allowed: 0,
                newly_denied: 0,
                unchanged: 1,
            },
        };
        let cloned = Clone::clone(&result);
        assert_eq!(cloned.deltas.len(), 1);
        assert_eq!(cloned.summary.unchanged, 1);
    }
}
