//! Security enforcement pipeline for validating every request before routing.
//!
//! Implements a staged pipeline of checks that each request must pass before
//! being forwarded to a connector. The pipeline runs checks in order and
//! short-circuits at the first denial.
//!
//! # Architecture
//!
//! The pipeline comprises concrete checks executed in the sequence declared by
//! `fcp_core::EnforcementCheckOrder`:
//! 1. Canonical decode — validates request has required non-empty fields
//! 2. Zone membership — validates principal is allowed in the zone
//! 3. Capability verify — validates capability claims include the operation's required capability
//! 4. Revocation cascade — validates token and issuer-chain revocation before use
//! 5. Deployment tier — validates request tier is admissible under host posture
//! 6. Holder proof — validates holder-bound tokens present a verified holder proof
//! 7. Checkpoint freshness — validates checkpoint age is within window
//! 8. Revocation freshness — validates revocation list age is within window
//! 9. Taint approval — validates critical taints have approval tokens
//! 10. Policy ceiling — validates zone policy permits connector/operation
//! 11. Capability constraints — validates token constraints against request details
//! 12. Connector manifest — validates manifest includes the operation
//! 13. Budget — validates request is within the current usage budget
//! 14. Rate limit — validates request is within rate quota

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use fcp_crypto::kid::KeyId;
use fcp_evidence::{
    AttestationChain, CascadeConfig, CascadeHop, CascadeReceipt, CascadeRejection,
    RevocationRecord, check_revocation_chain,
};
use fcp_kernel::{ConnectorId, OperationId};
use fcp_mesh::PeerProtocolCapabilities;
use fcp_policy::{
    CapabilityConstraintEnforcer, ConstraintDenialKind, DefaultConstraintEnforcer,
    LatticeDelegationError, LatticeDelegationVerifier, LatticeDelegationVerifierImpl,
    LatticeSubToken, RequestDescriptor, ZoneId,
};
use fcp_prelude::{
    CapabilityConstraints, EnforcementCheckId, EnforcementCheckOrder, IdValidationError, ObjectId,
    PrincipalId, RevocationRegistry, SafetyTier, ZoneIdError,
};

use crate::deployment_mode::{DeploymentClassification, DeploymentTierRefusal, admit_safety_tier};
use serde::Serialize;

// ─────────────────────────────────────────────────────────────────────────────
// Enforcement configuration
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnforcementConfigError {
    #[error("invalid zone id: {0}")]
    InvalidZoneId(ZoneIdError),
    #[error("invalid connector id: {0}")]
    InvalidConnectorId(IdValidationError),
    #[error("invalid operation id: {0}")]
    InvalidOperationId(IdValidationError),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AllowedConnector {
    Any,
    Connector(ConnectorId),
}

impl AllowedConnector {
    fn parse(value: &str) -> Result<Self, IdValidationError> {
        if value == "*" {
            Ok(Self::Any)
        } else {
            Ok(Self::Connector(value.parse()?))
        }
    }

    fn matches(&self, connector_id: &ConnectorId) -> bool {
        matches!(self, Self::Any) || matches!(self, Self::Connector(id) if id == connector_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AllowedOperation {
    Any,
    Operation(OperationId),
}

impl AllowedOperation {
    fn parse(value: &str) -> Result<Self, IdValidationError> {
        if value == "*" {
            Ok(Self::Any)
        } else {
            Ok(Self::Operation(value.parse()?))
        }
    }

    fn matches(&self, operation_id: &OperationId) -> bool {
        matches!(self, Self::Any) || matches!(self, Self::Operation(id) if id == operation_id)
    }
}

/// Configurable thresholds for enforcement checks.
#[derive(Debug, Clone)]
pub struct EnforcementConfig {
    /// Maximum age in milliseconds before a checkpoint is considered stale.
    pub checkpoint_max_age_ms: u64,
    /// Maximum age in milliseconds before the revocation list is stale.
    pub revocation_max_age_ms: u64,
    /// Taint flags that require an explicit approval token.
    pub critical_taint_flags: Vec<String>,
    /// Per-principal allowed zone IDs. Principal → set of zone IDs.
    pub zone_memberships: HashMap<String, HashSet<ZoneId>>,
    /// Per-zone allowed connector IDs.
    pub zone_allowed_connectors: HashMap<ZoneId, HashSet<AllowedConnector>>,
    /// Per-zone allowed operation IDs.
    pub zone_allowed_operations: HashMap<ZoneId, HashSet<AllowedOperation>>,
    /// Current revocation registry (optional).
    pub revocation_registry: Option<Arc<RevocationRegistry>>,
    /// Revocation-cascade verifier for token and issuer-chain checks.
    pub revocation_cascade: Option<Arc<RevocationCascadeVerifier>>,
    /// V4 lattice-delegation verifier for post-quantum capability tokens.
    pub lattice_delegation_verifier: Option<Arc<LatticeDelegationVerifierImpl>>,
}

impl Default for EnforcementConfig {
    fn default() -> Self {
        Self {
            checkpoint_max_age_ms: 300_000, // 5 minutes
            revocation_max_age_ms: 600_000, // 10 minutes
            critical_taint_flags: vec![
                "pii".into(),
                "phi".into(),
                "classified".into(),
                "financial".into(),
            ],
            zone_memberships: HashMap::new(),
            zone_allowed_connectors: HashMap::new(),
            zone_allowed_operations: HashMap::new(),
            revocation_registry: None,
            revocation_cascade: None,
            lattice_delegation_verifier: None,
        }
    }
}

impl EnforcementConfig {
    /// Create a new config with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the checkpoint maximum age.
    #[must_use]
    pub const fn with_checkpoint_max_age_ms(mut self, ms: u64) -> Self {
        self.checkpoint_max_age_ms = ms;
        self
    }

    /// Set the revocation list maximum age.
    #[must_use]
    pub const fn with_revocation_max_age_ms(mut self, ms: u64) -> Self {
        self.revocation_max_age_ms = ms;
        self
    }

    /// Set the critical taint flags.
    #[must_use]
    pub fn with_critical_taint_flags(mut self, flags: Vec<String>) -> Self {
        self.critical_taint_flags = flags;
        self
    }

    /// Set the revocation registry.
    #[must_use]
    pub fn with_revocation_registry(mut self, registry: Arc<RevocationRegistry>) -> Self {
        self.revocation_registry = Some(registry);
        self
    }

    /// Set the revocation-cascade verifier.
    #[must_use]
    pub fn with_revocation_cascade(mut self, verifier: Arc<RevocationCascadeVerifier>) -> Self {
        self.revocation_cascade = Some(verifier);
        self
    }

    /// Set the V4 lattice-delegation verifier.
    #[must_use]
    pub fn with_lattice_delegation_verifier(
        mut self,
        verifier: Arc<LatticeDelegationVerifierImpl>,
    ) -> Self {
        self.lattice_delegation_verifier = Some(verifier);
        self
    }

    /// Add a zone membership for a principal.
    ///
    /// # Errors
    /// Returns an error if the zone string is not a valid zone ID.
    pub fn add_zone_membership(
        &mut self,
        principal: &str,
        zone: &str,
    ) -> Result<(), EnforcementConfigError> {
        let zone_id = zone
            .parse()
            .map_err(EnforcementConfigError::InvalidZoneId)?;
        self.zone_memberships
            .entry(principal.to_string())
            .or_default()
            .insert(zone_id);
        Ok(())
    }

    /// Add an allowed connector to a zone.
    ///
    /// # Errors
    /// Returns an error if the zone or connector string is invalid.
    pub fn add_zone_connector(
        &mut self,
        zone: &str,
        connector: &str,
    ) -> Result<(), EnforcementConfigError> {
        let zone_id = zone
            .parse()
            .map_err(EnforcementConfigError::InvalidZoneId)?;
        let connector = AllowedConnector::parse(connector)
            .map_err(EnforcementConfigError::InvalidConnectorId)?;
        self.zone_allowed_connectors
            .entry(zone_id)
            .or_default()
            .insert(connector);
        Ok(())
    }

    /// Add an allowed operation to a zone.
    ///
    /// # Errors
    /// Returns an error if the zone or operation string is invalid.
    pub fn add_zone_operation(
        &mut self,
        zone: &str,
        operation: &str,
    ) -> Result<(), EnforcementConfigError> {
        let zone_id = zone
            .parse()
            .map_err(EnforcementConfigError::InvalidZoneId)?;
        let operation = AllowedOperation::parse(operation)
            .map_err(EnforcementConfigError::InvalidOperationId)?;
        self.zone_allowed_operations
            .entry(zone_id)
            .or_default()
            .insert(operation);
        Ok(())
    }
}

/// Host-side adapter around the bounded fcp-evidence revocation cascade walker.
///
/// The walker itself is intentionally storage-agnostic; this verifier provides
/// the concrete lookup tables and chain selection shape used by fcp-host. When
/// no explicit chain is registered for an issuer KID, the verifier uses a
/// single-key root chain for that KID. That keeps the production live path
/// running the same bounded walker even before mesh attestation edges are
/// available, while still enforcing direct and per-hop revocations whenever the
/// host has populated them.
#[derive(Debug, Clone)]
pub struct RevocationCascadeVerifier {
    config: CascadeConfig,
    registry_age_secs: u64,
    chains: Vec<(KeyId, AttestationChain)>,
    direct_revocations: Vec<(ObjectId, RevocationRecord)>,
    hop_revocations: Vec<(KeyId, CascadeHop, RevocationRecord)>,
}

impl Default for RevocationCascadeVerifier {
    fn default() -> Self {
        Self::new(CascadeConfig::default())
    }
}

impl RevocationCascadeVerifier {
    /// Create a verifier with the supplied cascade-walk policy.
    #[must_use]
    pub const fn new(config: CascadeConfig) -> Self {
        Self {
            config,
            registry_age_secs: 0,
            chains: Vec::new(),
            direct_revocations: Vec::new(),
            hop_revocations: Vec::new(),
        }
    }

    /// Override the age of the revocation snapshot used by lookups.
    #[must_use]
    pub const fn with_registry_age_secs(mut self, age_secs: u64) -> Self {
        self.registry_age_secs = age_secs;
        self
    }

    /// Register the attestation chain to use for a specific issuer KID.
    ///
    /// # Errors
    ///
    /// Returns a [`CascadeRejection`] when the chain violates the walker's
    /// bounded-chain invariants.
    pub fn with_chain_for_issuer(
        mut self,
        issuer_kid: KeyId,
        chain: AttestationChain,
    ) -> Result<Self, CascadeRejection> {
        chain.validate()?;
        self.chains.push((issuer_kid, chain));
        Ok(self)
    }

    /// Add a direct token revocation record to the verifier's lookup table.
    #[must_use]
    pub fn with_direct_revocation(mut self, token_id: ObjectId, record: RevocationRecord) -> Self {
        self.direct_revocations.push((token_id, record));
        self
    }

    /// Add a KID-scoped revocation record to the verifier's lookup table.
    #[must_use]
    pub fn with_hop_revocation(
        mut self,
        kid: KeyId,
        hop: CascadeHop,
        record: RevocationRecord,
    ) -> Self {
        self.hop_revocations.push((kid, hop, record));
        self
    }

    /// Verify that the token and every issuer-chain hop remain unrevoked.
    ///
    /// # Errors
    ///
    /// Returns the concrete cascade rejection reason emitted by the bounded
    /// walker.
    pub fn verify(
        &self,
        token_id: ObjectId,
        issuer_kid: KeyId,
    ) -> Result<CascadeReceipt, CascadeRejection> {
        if let Some((_, chain)) = self
            .chains
            .iter()
            .find(|(configured_issuer, _)| configured_issuer == &issuer_kid)
        {
            return self.verify_with_chain(token_id, issuer_kid, chain);
        }

        let implicit_chain = AttestationChain::rooted_at(issuer_kid.clone());
        self.verify_with_chain(token_id, issuer_kid, &implicit_chain)
    }

    fn verify_with_chain(
        &self,
        token_id: ObjectId,
        issuer_kid: KeyId,
        chain: &AttestationChain,
    ) -> Result<CascadeReceipt, CascadeRejection> {
        check_revocation_chain(
            token_id,
            issuer_kid,
            chain,
            &self.config,
            self.registry_age_secs,
            |probe_token| self.direct_revocation(probe_token),
            |probe_kid, hop| self.hop_revocation(probe_kid, hop),
        )
    }

    fn direct_revocation(&self, token_id: &ObjectId) -> Option<RevocationRecord> {
        self.direct_revocations
            .iter()
            .find(|(revoked_id, _)| revoked_id == token_id)
            .map(|(_, record)| *record)
    }

    fn hop_revocation(&self, kid: &KeyId, hop: CascadeHop) -> Option<RevocationRecord> {
        self.hop_revocations
            .iter()
            .find(|(revoked_kid, revoked_hop, _)| revoked_kid == kid && *revoked_hop == hop)
            .map(|(_, _, record)| *record)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Enforcement context
// ─────────────────────────────────────────────────────────────────────────────

/// Context for enforcement checks — carries the request plus resolver state.
///
/// Built via [`EnforcementContextBuilder`] for ergonomic construction.
#[derive(Debug, Clone)]
pub struct EnforcementContext {
    /// Unique identifier for this request.
    pub request_id: String,
    /// Target connector identifier.
    pub connector_id: String,
    /// Target operation name.
    pub operation: String,
    /// Zone under which the request executes.
    pub zone_id: String,
    /// Principal (agent/user) making the request.
    pub principal: String,
    /// Capability IDs from the presented token.
    pub capability_claims: Vec<String>,
    /// Capability ID required by the requested operation, if resolved.
    pub required_capability: Option<String>,
    /// V4 lattice sub-token presented by the request, when the capability
    /// envelope is a post-quantum lattice token instead of legacy string claims.
    pub lattice_sub_token: Option<LatticeSubToken>,
    /// Parsed constraints from the presented capability token.
    pub capability_constraints: Option<CapabilityConstraints>,
    /// Content-addressed object targeted by the request, when constraint checks need it.
    pub constraint_object_id: Option<ObjectId>,
    /// Egress host targeted by the request, when constraint checks need it.
    pub constraint_host: Option<String>,
    /// Resource URI targeted by the request, when constraint checks need it.
    pub constraint_resource_uri: Option<String>,
    /// Cumulative invocations observed against this capability so far.
    pub constraint_observed_calls: u32,
    /// Cumulative bytes transferred against this capability so far.
    pub constraint_observed_bytes: u64,
    /// Active taint flags on the request.
    pub taint_flags: Vec<String>,
    /// Approval scopes presented with the request.
    pub approval_scopes: Vec<String>,
    /// Request timestamp in milliseconds since epoch.
    pub timestamp_ms: u64,
    /// ID of the presented capability token (if any).
    pub token_id: Option<ObjectId>,
    /// COSE protected-header KID of the issuer key that signed the token.
    pub issuer_kid: Option<KeyId>,
    /// ID of the node attestation for the presenting node.
    pub node_attestation_id: Option<ObjectId>,
    /// ID of the issuer key that signed the token.
    pub issuer_key_id: Option<ObjectId>,
    /// ID of the connector binary artifact being invoked.
    pub binary_artifact_id: Option<ObjectId>,
    /// Whether the presented capability token requires holder-proof binding.
    pub holder_proof_required: bool,
    /// Whether the capability holder proof has been verified.
    pub holder_verified: bool,
    /// Age of the latest checkpoint in milliseconds (None if unavailable).
    pub checkpoint_age_ms: Option<u64>,
    /// Age of the revocation list in milliseconds (None if unavailable).
    pub revocation_list_age_ms: Option<u64>,
    /// Budget used so far in the current window.
    pub budget_used: Option<u64>,
    /// Budget limit for the current window.
    pub budget_limit: Option<u64>,
    /// Number of requests in the current rate-limit window.
    pub rate_count: Option<u32>,
    /// Maximum requests allowed in the rate-limit window.
    pub rate_limit: Option<u32>,
    /// Operations the connector manifest declares as supported.
    pub manifest_allowed_operations: Vec<String>,
    /// Safety tier for this request (br-nsrx3). Drives the
    /// `DeploymentTier` admission check via
    /// [`admit_safety_tier`]. `None` means tier-based admission is
    /// skipped (back-compat: pre-nsrx3 callers leave this field
    /// unset).
    pub safety_tier: Option<SafetyTier>,
    /// Current deployment classification (br-nsrx3). Held by the host
    /// and shared across requests so the `DeploymentTier` check can
    /// admit/refuse without re-classifying. `None` means tier-based
    /// admission is skipped (back-compat).
    pub deployment_classification: Option<Arc<DeploymentClassification>>,
    /// Remote mesh peer identifier, when this request arrived over mesh gossip.
    pub remote_peer_id: Option<String>,
    /// Remote peer's advertised V3/V4 protocol capability set.
    pub remote_peer_capabilities: Option<PeerProtocolCapabilities>,
}

/// Builder for constructing an [`EnforcementContext`].
#[derive(Debug, Clone, Default)]
pub struct EnforcementContextBuilder {
    request_id: Option<String>,
    connector_id: Option<String>,
    operation: Option<String>,
    zone_id: Option<String>,
    principal: Option<String>,
    capability_claims: Vec<String>,
    required_capability: Option<String>,
    lattice_sub_token: Option<LatticeSubToken>,
    capability_constraints: Option<CapabilityConstraints>,
    constraint_object_id: Option<ObjectId>,
    constraint_host: Option<String>,
    constraint_resource_uri: Option<String>,
    constraint_observed_calls: u32,
    constraint_observed_bytes: u64,
    taint_flags: Vec<String>,
    approval_scopes: Vec<String>,
    timestamp_ms: u64,
    token_id: Option<ObjectId>,
    issuer_kid: Option<KeyId>,
    node_attestation_id: Option<ObjectId>,
    issuer_key_id: Option<ObjectId>,
    binary_artifact_id: Option<ObjectId>,
    holder_proof_required: bool,
    holder_verified: bool,
    checkpoint_age_ms: Option<u64>,
    revocation_list_age_ms: Option<u64>,
    budget_used: Option<u64>,
    budget_limit: Option<u64>,
    rate_count: Option<u32>,
    rate_limit: Option<u32>,
    manifest_allowed_operations: Vec<String>,
    safety_tier: Option<SafetyTier>,
    deployment_classification: Option<Arc<DeploymentClassification>>,
    remote_peer_id: Option<String>,
    remote_peer_capabilities: Option<PeerProtocolCapabilities>,
}

impl EnforcementContextBuilder {
    /// Create a new builder with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the request ID.
    #[must_use]
    pub fn request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Set the connector ID.
    #[must_use]
    pub fn connector_id(mut self, id: impl Into<String>) -> Self {
        self.connector_id = Some(id.into());
        self
    }

    /// Set the operation name.
    #[must_use]
    pub fn operation(mut self, op: impl Into<String>) -> Self {
        self.operation = Some(op.into());
        self
    }

    /// Set the zone ID.
    #[must_use]
    pub fn zone_id(mut self, zone: impl Into<String>) -> Self {
        self.zone_id = Some(zone.into());
        self
    }

    /// Set the principal.
    #[must_use]
    pub fn principal(mut self, p: impl Into<String>) -> Self {
        self.principal = Some(p.into());
        self
    }

    /// Set the capability claims.
    #[must_use]
    pub fn capability_claims(mut self, claims: Vec<String>) -> Self {
        self.capability_claims = claims;
        self
    }

    /// Set the capability required by the operation.
    #[must_use]
    pub fn required_capability(mut self, capability: impl Into<String>) -> Self {
        self.required_capability = Some(capability.into());
        self
    }

    /// Set the V4 lattice sub-token presented by the request.
    #[must_use]
    pub fn lattice_sub_token(mut self, sub_token: LatticeSubToken) -> Self {
        self.lattice_sub_token = Some(sub_token);
        self
    }

    /// Set the parsed capability-token constraints.
    #[must_use]
    pub fn capability_constraints(mut self, constraints: CapabilityConstraints) -> Self {
        self.capability_constraints = Some(constraints);
        self
    }

    /// Set the request object id used by capability-constraint checks.
    #[must_use]
    pub const fn constraint_object_id(mut self, object_id: ObjectId) -> Self {
        self.constraint_object_id = Some(object_id);
        self
    }

    /// Set the request egress host used by capability-constraint checks.
    #[must_use]
    pub fn constraint_host(mut self, host: impl Into<String>) -> Self {
        self.constraint_host = Some(host.into());
        self
    }

    /// Set the resource URI used by capability-constraint checks.
    #[must_use]
    pub fn constraint_resource_uri(mut self, resource_uri: impl Into<String>) -> Self {
        self.constraint_resource_uri = Some(resource_uri.into());
        self
    }

    /// Set cumulative usage counters used by capability-constraint checks.
    #[must_use]
    pub const fn constraint_usage(mut self, observed_calls: u32, observed_bytes: u64) -> Self {
        self.constraint_observed_calls = observed_calls;
        self.constraint_observed_bytes = observed_bytes;
        self
    }

    /// Set the taint flags.
    #[must_use]
    pub fn taint_flags(mut self, flags: Vec<String>) -> Self {
        self.taint_flags = flags;
        self
    }

    /// Set the approval scopes.
    #[must_use]
    pub fn approval_scopes(mut self, scopes: Vec<String>) -> Self {
        self.approval_scopes = scopes;
        self
    }

    /// Set the request timestamp.
    #[must_use]
    pub const fn timestamp_ms(mut self, ts: u64) -> Self {
        self.timestamp_ms = ts;
        self
    }

    /// Set the presented capability token's object ID and issuer KID.
    #[must_use]
    pub fn revocation_cascade_inputs(mut self, token_id: ObjectId, issuer_kid: KeyId) -> Self {
        self.token_id = Some(token_id);
        self.issuer_kid = Some(issuer_kid);
        self
    }

    /// Set whether the token requires a verified holder proof.
    #[must_use]
    pub const fn holder_proof_required(mut self, required: bool) -> Self {
        self.holder_proof_required = required;
        self
    }

    /// Set whether the holder proof is verified.
    #[must_use]
    pub const fn holder_verified(mut self, verified: bool) -> Self {
        self.holder_verified = verified;
        self
    }

    /// Set the checkpoint age.
    #[must_use]
    pub const fn checkpoint_age_ms(mut self, age: u64) -> Self {
        self.checkpoint_age_ms = Some(age);
        self
    }

    /// Set the revocation list age.
    #[must_use]
    pub const fn revocation_list_age_ms(mut self, age: u64) -> Self {
        self.revocation_list_age_ms = Some(age);
        self
    }

    /// Set the budget used.
    #[must_use]
    pub const fn budget_used(mut self, used: u64) -> Self {
        self.budget_used = Some(used);
        self
    }

    /// Set the budget limit.
    #[must_use]
    pub const fn budget_limit(mut self, limit: u64) -> Self {
        self.budget_limit = Some(limit);
        self
    }

    /// Set the rate count.
    #[must_use]
    pub const fn rate_count(mut self, count: u32) -> Self {
        self.rate_count = Some(count);
        self
    }

    /// Set the rate limit.
    #[must_use]
    pub const fn rate_limit(mut self, limit: u32) -> Self {
        self.rate_limit = Some(limit);
        self
    }

    /// Set the manifest allowed operations.
    #[must_use]
    pub fn manifest_allowed_operations(mut self, ops: Vec<String>) -> Self {
        self.manifest_allowed_operations = ops;
        self
    }

    /// Set the request's safety tier (br-nsrx3). Drives the
    /// `DeploymentTier` admission check via [`admit_safety_tier`].
    /// Without this, `DeploymentTier` is skipped (back-compat for
    /// pre-nsrx3 callers).
    #[must_use]
    pub const fn safety_tier(mut self, tier: SafetyTier) -> Self {
        self.safety_tier = Some(tier);
        self
    }

    /// Set the active deployment classification (br-nsrx3). Held by
    /// the host and shared across requests so the `DeploymentTier`
    /// check can admit/refuse without re-classifying. Without this,
    /// `DeploymentTier` is skipped.
    #[must_use]
    pub fn deployment_classification(
        mut self,
        classification: Arc<DeploymentClassification>,
    ) -> Self {
        self.deployment_classification = Some(classification);
        self
    }

    /// Set the remote mesh peer identifier for peer-capability checks.
    #[must_use]
    pub fn remote_peer_id(mut self, peer_id: impl Into<String>) -> Self {
        self.remote_peer_id = Some(peer_id.into());
        self
    }

    /// Set the remote peer's advertised V3/V4 protocol capabilities.
    #[must_use]
    pub fn remote_peer_capabilities(mut self, capabilities: PeerProtocolCapabilities) -> Self {
        self.remote_peer_capabilities = Some(capabilities);
        self
    }

    /// Build the enforcement context.
    ///
    /// Returns `None` if any of the required fields (`request_id`, `connector_id`,
    /// `operation`, `zone_id`, `principal`) are missing.
    #[must_use]
    pub fn build(self) -> Option<EnforcementContext> {
        Some(EnforcementContext {
            request_id: self.request_id?,
            connector_id: self.connector_id?,
            operation: self.operation?,
            zone_id: self.zone_id?,
            principal: self.principal?,
            capability_claims: self.capability_claims,
            required_capability: self.required_capability,
            lattice_sub_token: self.lattice_sub_token,
            capability_constraints: self.capability_constraints,
            constraint_object_id: self.constraint_object_id,
            constraint_host: self.constraint_host,
            constraint_resource_uri: self.constraint_resource_uri,
            constraint_observed_calls: self.constraint_observed_calls,
            constraint_observed_bytes: self.constraint_observed_bytes,
            taint_flags: self.taint_flags,
            approval_scopes: self.approval_scopes,
            timestamp_ms: self.timestamp_ms,
            token_id: self.token_id,
            issuer_kid: self.issuer_kid,
            node_attestation_id: self.node_attestation_id,
            issuer_key_id: self.issuer_key_id,
            binary_artifact_id: self.binary_artifact_id,
            holder_proof_required: self.holder_proof_required,
            holder_verified: self.holder_verified,
            checkpoint_age_ms: self.checkpoint_age_ms,
            revocation_list_age_ms: self.revocation_list_age_ms,
            budget_used: self.budget_used,
            budget_limit: self.budget_limit,
            rate_count: self.rate_count,
            rate_limit: self.rate_limit,
            manifest_allowed_operations: self.manifest_allowed_operations,
            safety_tier: self.safety_tier,
            deployment_classification: self.deployment_classification,
            remote_peer_id: self.remote_peer_id,
            remote_peer_capabilities: self.remote_peer_capabilities,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Check outcome types
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of a single enforcement check.
#[must_use]
#[derive(Debug, Clone)]
pub enum CheckOutcome {
    /// The check passed.
    Allow,
    /// The check failed with a reason and explanation.
    Deny {
        /// Machine-readable reason code.
        reason_code: String,
        /// Human-readable explanation.
        explanation: String,
    },
    /// The check was not applicable.
    Skip {
        /// Why the check was skipped.
        reason: String,
    },
}

impl CheckOutcome {
    /// Whether this outcome is an `Allow`.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Whether this outcome is a `Deny`.
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Whether this outcome is a `Skip`.
    #[must_use]
    pub const fn is_skip(&self) -> bool {
        matches!(self, Self::Skip { .. })
    }
}

/// Record of a single check execution within the pipeline.
#[derive(Debug, Clone)]
pub struct CheckRecord {
    /// Name of the check.
    pub name: String,
    /// Outcome of the check.
    pub outcome: CheckOutcome,
    /// Wall-clock time in milliseconds for this check.
    pub elapsed_ms: f64,
}

/// Overall outcome of the enforcement pipeline.
#[must_use]
#[derive(Debug, Clone)]
pub enum PipelineOutcome {
    /// All checks passed (or were skipped).
    Allow,
    /// A check denied the request.
    Deny {
        /// Name of the check that denied.
        check_name: String,
        /// Machine-readable reason code.
        reason_code: String,
        /// Human-readable explanation.
        explanation: String,
    },
}

impl PipelineOutcome {
    /// Whether the pipeline allowed the request.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Whether the pipeline denied the request.
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

/// Result of the full enforcement pipeline evaluation.
#[derive(Debug, Clone)]
pub struct EnforcementDecision {
    /// Overall outcome of the pipeline.
    pub outcome: PipelineOutcome,
    /// Records of each check that was executed.
    pub checks_run: Vec<CheckRecord>,
    /// Total wall-clock time in milliseconds for the pipeline.
    pub elapsed_ms: f64,
}

impl EnforcementDecision {
    /// Whether the decision allows the request.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        self.outcome.is_allow()
    }

    /// Number of checks that were executed.
    #[must_use]
    pub const fn checks_executed(&self) -> usize {
        self.checks_run.len()
    }

    /// Number of checks that returned `Allow`.
    #[must_use]
    pub fn allow_count(&self) -> usize {
        self.checks_run
            .iter()
            .filter(|c| c.outcome.is_allow())
            .count()
    }

    /// Number of checks that were skipped.
    #[must_use]
    pub fn skip_count(&self) -> usize {
        self.checks_run
            .iter()
            .filter(|c| c.outcome.is_skip())
            .count()
    }

    /// Wall-clock time for the first executed check with the given name.
    #[must_use]
    pub fn check_elapsed_ms(&self, name: &str) -> Option<f64> {
        self.checks_run
            .iter()
            .find(|record| record.name == name)
            .map(|record| record.elapsed_ms)
    }

    /// Sum of the recorded per-check wall-clock times.
    #[must_use]
    pub fn check_elapsed_total_ms(&self) -> f64 {
        self.checks_run.iter().map(|record| record.elapsed_ms).sum()
    }

    /// Pipeline wall-clock time not attributed to an individual check record.
    #[must_use]
    pub fn non_check_overhead_ms(&self) -> f64 {
        (self.elapsed_ms - self.check_elapsed_total_ms()).max(0.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Enforcement check trait
// ─────────────────────────────────────────────────────────────────────────────

/// Trait for individual enforcement checks.
///
/// Each check inspects the [`EnforcementContext`] and returns a
/// [`CheckOutcome`]. Checks may also use a shared [`EnforcementConfig`].
pub trait EnforcementCheck: Send + Sync {
    /// Human-readable name for this check.
    fn name(&self) -> &'static str;

    /// Evaluate the check against the given context and config.
    fn check(&self, ctx: &EnforcementContext, config: &EnforcementConfig) -> CheckOutcome;
}

fn parse_zone_id_for_check(zone_id: &str) -> Result<ZoneId, CheckOutcome> {
    zone_id
        .parse()
        .map_err(|err: ZoneIdError| CheckOutcome::Deny {
            reason_code: "INVALID_ZONE_ID".into(),
            explanation: format!("zone_id '{zone_id}' is not canonical: {err}"),
        })
}

fn parse_connector_id_for_check(connector_id: &str) -> Result<ConnectorId, CheckOutcome> {
    connector_id
        .parse()
        .map_err(|err: IdValidationError| CheckOutcome::Deny {
            reason_code: "INVALID_CONNECTOR_ID".into(),
            explanation: format!("connector_id '{connector_id}' is not canonical: {err}"),
        })
}

fn parse_operation_id_for_check(operation: &str) -> Result<OperationId, CheckOutcome> {
    operation
        .parse()
        .map_err(|err: IdValidationError| CheckOutcome::Deny {
            reason_code: "INVALID_OPERATION_ID".into(),
            explanation: format!("operation '{operation}' is not canonical: {err}"),
        })
}

fn parse_principal_id_for_check(principal: &str) -> Result<PrincipalId, CheckOutcome> {
    PrincipalId::new(principal).map_err(|err: IdValidationError| CheckOutcome::Deny {
        reason_code: "INVALID_PRINCIPAL_ID".into(),
        explanation: format!("principal is not canonical: {err}"),
    })
}

const fn lattice_delegation_reason_code(error: &LatticeDelegationError) -> &'static str {
    match error {
        LatticeDelegationError::NotImplemented => "LATTICE_NOT_IMPLEMENTED",
        LatticeDelegationError::UnknownCertificate { .. } => "LATTICE_UNKNOWN_CERTIFICATE",
        LatticeDelegationError::OutsidePeriod { .. } => "LATTICE_OUTSIDE_PERIOD",
        LatticeDelegationError::VerificationEquationFailed { .. } => {
            "LATTICE_VERIFICATION_EQUATION_FAILED"
        }
        LatticeDelegationError::PreimageTooLong { .. } => "LATTICE_PREIMAGE_TOO_LONG",
        LatticeDelegationError::ZoneMismatch { .. } => "LATTICE_ZONE_MISMATCH",
        LatticeDelegationError::IncompleteDelegationChain { .. } => {
            "LATTICE_INCOMPLETE_DELEGATION_CHAIN"
        }
        LatticeDelegationError::ChainTooDeep { .. } => "LATTICE_CHAIN_TOO_DEEP",
        LatticeDelegationError::PreimageEncodingMismatch { .. } => {
            "LATTICE_PREIMAGE_ENCODING_MISMATCH"
        }
        LatticeDelegationError::ParameterMismatch { .. } => "LATTICE_PARAMETER_MISMATCH",
        LatticeDelegationError::OperationMismatch { .. } => "LATTICE_OPERATION_MISMATCH",
        LatticeDelegationError::PrincipalMismatch { .. } => "LATTICE_PRINCIPAL_MISMATCH",
        LatticeDelegationError::CertificatePublicKeyMismatch { .. } => {
            "LATTICE_CERTIFICATE_PUBLIC_KEY_MISMATCH"
        }
        LatticeDelegationError::RequestBindingMismatch { .. } => "LATTICE_REQUEST_BINDING_MISMATCH",
    }
}

/// Audit event type emitted when capability constraints deny a request.
pub const CAPABILITY_CONSTRAINT_DENIED_AUDIT_EVENT_TYPE: &str = "capability.constraint_denied";
const CAPABILITY_CONSTRAINT_DESCRIPTOR_HASH_DOMAIN: &[u8] =
    b"FCP2-CAPABILITY-CONSTRAINT-DESCRIPTOR-V1";

/// Redacted descriptor used to hash capability-constraint denial context.
#[derive(Debug, Clone, Serialize)]
pub struct ConstraintDenialAuditDescriptor<'a> {
    request_id: &'a str,
    connector_id: &'a str,
    operation: &'a str,
    zone_id: &'a str,
    principal: &'a str,
    object_id: String,
    host: &'a str,
    resource_uri: &'a str,
    requested_at_unix_ms: u64,
    observed_calls: u32,
    observed_bytes: u64,
}

impl ConstraintDenialAuditDescriptor<'_> {
    const fn timestamp_unix_seconds(&self) -> u64 {
        self.requested_at_unix_ms / 1_000
    }
}

/// Build the redacted request descriptor used by constraint-denial audit events.
#[must_use]
pub fn capability_constraint_audit_descriptor<'a>(
    request_id: &'a str,
    connector_id: &'a str,
    operation: &'a str,
    zone_id: &'a str,
    descriptor: &'a RequestDescriptor,
) -> ConstraintDenialAuditDescriptor<'a> {
    ConstraintDenialAuditDescriptor {
        request_id,
        connector_id,
        operation,
        zone_id,
        principal: descriptor.principal.as_str(),
        object_id: descriptor.object_id.to_string(),
        host: descriptor.host.as_str(),
        resource_uri: descriptor.resource_uri.as_str(),
        requested_at_unix_ms: descriptor.requested_at_unix_ms,
        observed_calls: descriptor.observed_calls,
        observed_bytes: descriptor.observed_bytes,
    }
}

/// Hash a redacted constraint-denial descriptor with the audit domain separator.
///
/// # Errors
///
/// Returns an error string if canonical CBOR encoding fails.
pub fn capability_constraint_descriptor_hash(
    descriptor: &ConstraintDenialAuditDescriptor<'_>,
) -> Result<String, String> {
    let canonical = fcp_cbor::to_canonical_cbor(descriptor)
        .map_err(|err| format!("failed to canonicalize audit descriptor: {err}"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(CAPABILITY_CONSTRAINT_DESCRIPTOR_HASH_DOMAIN);
    hasher.update(&canonical);
    Ok(hex::encode(hasher.finalize().as_bytes()))
}

/// Emit structured audit fields for a capability-constraint denial.
///
/// The event contains `request_descriptor_hash`, never the raw request payload.
pub fn emit_capability_constraint_denial_audit_event(
    descriptor: &ConstraintDenialAuditDescriptor<'_>,
    denial_kind: &ConstraintDenialKind,
    denying_node: &str,
) {
    match capability_constraint_descriptor_hash(descriptor) {
        Ok(request_descriptor_hash) => {
            tracing::warn!(
                audit_event_type = CAPABILITY_CONSTRAINT_DENIED_AUDIT_EVENT_TYPE,
                constraint_kind = denial_kind.as_str(),
                observed_value = %denial_kind.observed_value(),
                request_descriptor_hash = %request_descriptor_hash,
                denying_node = denying_node,
                timestamp = descriptor.timestamp_unix_seconds(),
                request_id = descriptor.request_id,
                connector_id = descriptor.connector_id,
                operation = descriptor.operation,
                zone_id = descriptor.zone_id,
                "capability_constraint_denied_audit_event"
            );
        }
        Err(error) => {
            tracing::warn!(
                audit_event_type = CAPABILITY_CONSTRAINT_DENIED_AUDIT_EVENT_TYPE,
                constraint_kind = denial_kind.as_str(),
                observed_value = %denial_kind.observed_value(),
                denying_node = denying_node,
                timestamp = descriptor.timestamp_unix_seconds(),
                request_id = descriptor.request_id,
                connector_id = descriptor.connector_id,
                operation = descriptor.operation,
                zone_id = descriptor.zone_id,
                request_descriptor_hash_error = %error,
                "capability_constraint_denied_audit_event_hash_failed"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Concrete checks
// ─────────────────────────────────────────────────────────────────────────────

/// Validates that required request fields are present and non-empty.
pub struct CanonicalDecodeCheck;

impl EnforcementCheck for CanonicalDecodeCheck {
    fn name(&self) -> &'static str {
        "canonical_decode"
    }

    fn check(&self, ctx: &EnforcementContext, _config: &EnforcementConfig) -> CheckOutcome {
        if ctx.connector_id.trim().is_empty() {
            return CheckOutcome::Deny {
                reason_code: "MISSING_CONNECTOR_ID".into(),
                explanation: "connector_id is required and must be non-empty".into(),
            };
        }
        if ctx.operation.trim().is_empty() {
            return CheckOutcome::Deny {
                reason_code: "MISSING_OPERATION".into(),
                explanation: "operation is required and must be non-empty".into(),
            };
        }
        if ctx.zone_id.trim().is_empty() {
            return CheckOutcome::Deny {
                reason_code: "MISSING_ZONE_ID".into(),
                explanation: "zone_id is required and must be non-empty".into(),
            };
        }
        if ctx.principal.trim().is_empty() {
            return CheckOutcome::Deny {
                reason_code: "MISSING_PRINCIPAL".into(),
                explanation: "principal is required and must be non-empty".into(),
            };
        }
        if ctx.request_id.trim().is_empty() {
            return CheckOutcome::Deny {
                reason_code: "MISSING_REQUEST_ID".into(),
                explanation: "request_id is required and must be non-empty".into(),
            };
        }
        if let Err(outcome) = parse_connector_id_for_check(&ctx.connector_id) {
            return outcome;
        }
        if let Err(outcome) = parse_operation_id_for_check(&ctx.operation) {
            return outcome;
        }
        if let Err(outcome) = parse_zone_id_for_check(&ctx.zone_id) {
            return outcome;
        }
        CheckOutcome::Allow
    }
}

/// Validates that the principal is a member of the requested zone.
pub struct ZoneMembershipCheck;

impl EnforcementCheck for ZoneMembershipCheck {
    fn name(&self) -> &'static str {
        "zone_membership"
    }

    fn check(&self, ctx: &EnforcementContext, config: &EnforcementConfig) -> CheckOutcome {
        // If no zone memberships are configured, skip (open policy).
        if config.zone_memberships.is_empty() {
            return CheckOutcome::Skip {
                reason: "no zone membership rules configured".into(),
            };
        }

        let zone_id = match parse_zone_id_for_check(&ctx.zone_id) {
            Ok(zone_id) => zone_id,
            Err(outcome) => return outcome,
        };

        match config.zone_memberships.get(&ctx.principal) {
            Some(zones) if zones.contains(&zone_id) => CheckOutcome::Allow,
            Some(_) => CheckOutcome::Deny {
                reason_code: "ZONE_MEMBERSHIP_DENIED".into(),
                explanation: format!(
                    "principal '{}' is not a member of zone '{}'",
                    ctx.principal, ctx.zone_id
                ),
            },
            None => CheckOutcome::Deny {
                reason_code: "PRINCIPAL_NOT_REGISTERED".into(),
                explanation: format!(
                    "principal '{}' has no zone memberships configured",
                    ctx.principal
                ),
            },
        }
    }
}

/// Validates that capability claims include the required capability.
pub struct CapabilityVerifyCheck;

impl EnforcementCheck for CapabilityVerifyCheck {
    fn name(&self) -> &'static str {
        "capability_verify"
    }

    fn check(&self, ctx: &EnforcementContext, config: &EnforcementConfig) -> CheckOutcome {
        if let Some(sub_token) = ctx.lattice_sub_token.as_ref() {
            let Some(verifier) = config.lattice_delegation_verifier.as_deref() else {
                return CheckOutcome::Deny {
                    reason_code: "LATTICE_VERIFIER_NOT_CONFIGURED".into(),
                    explanation: "request presented a lattice capability token, but no lattice delegation verifier is configured".into(),
                };
            };
            let request_zone = match parse_zone_id_for_check(&ctx.zone_id) {
                Ok(zone) => zone,
                Err(outcome) => return outcome,
            };
            let request_operation = match parse_operation_id_for_check(&ctx.operation) {
                Ok(operation) => operation,
                Err(outcome) => return outcome,
            };
            let request_principal = match parse_principal_id_for_check(&ctx.principal) {
                Ok(principal) => principal,
                Err(outcome) => return outcome,
            };

            return match verifier.verify_sub_token(
                sub_token,
                &request_zone,
                &request_operation,
                &request_principal,
                ctx.timestamp_ms,
            ) {
                Ok(_) => CheckOutcome::Allow,
                Err(error) => CheckOutcome::Deny {
                    reason_code: lattice_delegation_reason_code(&error).into(),
                    explanation: format!("lattice delegation rejected request: {error}"),
                },
            };
        }

        if ctx.capability_claims.is_empty() {
            return CheckOutcome::Deny {
                reason_code: "NO_CAPABILITY_CLAIMS".into(),
                explanation: "request has no capability claims".into(),
            };
        }

        let Some(required_capability) = ctx
            .required_capability
            .as_deref()
            .filter(|capability| !capability.trim().is_empty())
        else {
            return CheckOutcome::Deny {
                reason_code: "MISSING_REQUIRED_CAPABILITY".into(),
                explanation: format!(
                    "required capability is missing for operation '{}'",
                    ctx.operation
                ),
            };
        };

        let has_matching_claim = ctx
            .capability_claims
            .iter()
            .any(|claim| claim == "*" || claim == required_capability);

        if has_matching_claim {
            CheckOutcome::Allow
        } else {
            CheckOutcome::Deny {
                reason_code: "CAPABILITY_NOT_GRANTED".into(),
                explanation: format!(
                    "no capability claim grants required capability '{}' for operation '{}'",
                    required_capability, ctx.operation
                ),
            }
        }
    }
}

/// Validates that the presented token and issuer chain are not revoked.
pub struct CascadeRevocationCheck;

impl EnforcementCheck for CascadeRevocationCheck {
    fn name(&self) -> &'static str {
        "revocation_cascade"
    }

    fn check(&self, ctx: &EnforcementContext, config: &EnforcementConfig) -> CheckOutcome {
        let Some(verifier) = config.revocation_cascade.as_deref() else {
            return CheckOutcome::Skip {
                reason: "revocation cascade verifier is not configured".into(),
            };
        };
        let Some(token_id) = ctx.token_id else {
            return CheckOutcome::Deny {
                reason_code: "REVOCATION_CASCADE_TOKEN_ID_MISSING".into(),
                explanation: "revocation cascade cannot run without the capability token id".into(),
            };
        };
        let Some(issuer_kid) = ctx.issuer_kid.clone() else {
            return CheckOutcome::Deny {
                reason_code: "REVOCATION_CASCADE_ISSUER_KID_MISSING".into(),
                explanation: "revocation cascade cannot run without the token issuer KID".into(),
            };
        };

        match verifier.verify(token_id, issuer_kid) {
            Ok(_) => CheckOutcome::Allow,
            Err(err) => CheckOutcome::Deny {
                reason_code: "REVOCATION_CASCADE_REJECTED".into(),
                explanation: format!("revocation cascade rejected token: {err}"),
            },
        }
    }
}

/// Behavior when [`DeploymentTierCheck`] encounters an
/// [`EnforcementContext`] that is missing required fields
/// (`safety_tier` or `deployment_classification`).
///
/// Production default is [`MissingFieldPolicy::Deny`] (fail-closed)
/// per the br-298px review finding: a security gate that silently
/// skips when its inputs aren't populated is a fail-OPEN landmine
/// that gets hit the moment a future caller forgets the
/// `.safety_tier(t).deployment_classification(c)` builder calls.
/// The legacy back-compat behavior is preserved as
/// [`MissingFieldPolicy::Skip`] for callers that explicitly opt in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MissingFieldPolicy {
    /// Missing `safety_tier` OR `deployment_classification` →
    /// `CheckOutcome::Deny` with `reason_code`
    /// `"TIER_ADMISSION_NOT_CONFIGURED"`. This is the fail-CLOSED
    /// default: a request whose tier admission cannot be evaluated
    /// MUST NOT proceed.
    #[default]
    Deny,
    /// Missing fields → `CheckOutcome::Skip` with explanatory
    /// reason. Use only for explicit back-compat with pre-nsrx3
    /// callers that haven't wired the new context fields. NOT
    /// recommended for production hosts that target hr0rr.1's
    /// security guarantees.
    Skip,
}

/// Validates the request's [`SafetyTier`] is admissible under the
/// host's current [`DeploymentClassification`] (br-nsrx3 / hr0rr.A,
/// hardened by br-298px).
///
/// Composes the [`admit_safety_tier`] predicate hr0rr.1 (`CrimsonWolf`,
/// commit 26d7919dd). Refuses `Risky` and `Dangerous` tiers when
/// the host is in `DeploymentMode::Evaluation` (insufficient mesh
/// quorum). Always refuses `Forbidden`. Always allows `Safe` and
/// `Critical` (Critical's own quorum/elevation gating handles it).
///
/// ## Missing-field policy
///
/// When `ctx.safety_tier` OR `ctx.deployment_classification` is
/// missing, the check honors [`Self::on_missing`]:
///
/// * [`MissingFieldPolicy::Deny`] (production default) — returns
///   `CheckOutcome::Deny` with `reason_code`
///   `"TIER_ADMISSION_NOT_CONFIGURED"`. A security gate whose
///   inputs aren't populated MUST NOT silently skip — that is the
///   br-298px review finding's argument.
/// * [`MissingFieldPolicy::Skip`] — returns `CheckOutcome::Skip`
///   with an explanatory reason. Construct via
///   [`Self::back_compat`] for callers that explicitly need the
///   legacy fail-OPEN behavior.
pub struct DeploymentTierCheck {
    on_missing: MissingFieldPolicy,
}

impl DeploymentTierCheck {
    /// Strict (fail-CLOSED) constructor — missing context fields
    /// produce [`CheckOutcome::Deny`] with `reason_code`
    /// `"TIER_ADMISSION_NOT_CONFIGURED"`. This is the production
    /// default per br-298px.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            on_missing: MissingFieldPolicy::Deny,
        }
    }

    /// Back-compat (fail-OPEN) constructor — missing context fields
    /// produce [`CheckOutcome::Skip`] with an explanatory reason.
    /// Use only for explicit back-compat with pre-nsrx3 callers
    /// that haven't yet wired `safety_tier` +
    /// `deployment_classification` on every
    /// `EnforcementContextBuilder`. NOT recommended for production.
    #[must_use]
    pub const fn back_compat() -> Self {
        Self {
            on_missing: MissingFieldPolicy::Skip,
        }
    }

    /// Whether this check fails closed (Deny) on missing fields.
    #[must_use]
    pub const fn fails_closed(&self) -> bool {
        matches!(self.on_missing, MissingFieldPolicy::Deny)
    }
}

impl Default for DeploymentTierCheck {
    fn default() -> Self {
        Self::new()
    }
}

/// Stable reason code for missing-field denials. Operator dashboards
/// and alerting may key off this string.
pub const TIER_ADMISSION_NOT_CONFIGURED: &str = "TIER_ADMISSION_NOT_CONFIGURED";

impl EnforcementCheck for DeploymentTierCheck {
    fn name(&self) -> &'static str {
        "deployment_tier"
    }

    fn check(&self, ctx: &EnforcementContext, _config: &EnforcementConfig) -> CheckOutcome {
        let Some(tier) = ctx.safety_tier else {
            return self.handle_missing(
                "safety_tier",
                "request has no safety_tier — pre-nsrx3 caller; tier admission deferred",
            );
        };
        let Some(classification) = ctx.deployment_classification.as_deref() else {
            return self.handle_missing(
                "deployment_classification",
                "host has no deployment_classification on context — admission deferred",
            );
        };

        match admit_safety_tier(classification, tier) {
            Ok(()) => CheckOutcome::Allow,
            Err(refusal) => match refusal {
                DeploymentTierRefusal::TierRequiresMeshActive { tier, mode, reason } => {
                    CheckOutcome::Deny {
                        reason_code: "TIER_REQUIRES_MESH_ACTIVE".into(),
                        explanation: format!(
                            "safety tier {tier:?} not admissible in deployment mode {mode:?}: {reason:?}"
                        ),
                    }
                }
                DeploymentTierRefusal::TierForbidden { tier } => CheckOutcome::Deny {
                    reason_code: "TIER_FORBIDDEN".into(),
                    explanation: format!(
                        "safety tier {tier:?} is never admissible in any deployment mode"
                    ),
                },
            },
        }
    }
}

/// Stable reason code when a V4-required request lacks peer capability input.
pub const PEER_CAPABILITY_NOT_ADVERTISED: &str = "PEER_CAPABILITY_NOT_ADVERTISED";

/// Stable reason code when a remote peer advertises only V3 but policy requires V4.
pub const PEER_CAPABILITY_REQUIRES_V4: &str = "PEER_CAPABILITY_REQUIRES_V4";

/// Validates remote mesh peer V3/V4 capability before high-risk operations proceed.
///
/// Safe requests may continue over V3 during migration. Risky, Dangerous, and
/// Critical requests require a V4-capable remote advertisement so a receiver
/// cannot silently fall back to classical-only peer state.
pub struct PeerCapabilityCheck {
    on_missing: MissingFieldPolicy,
}

impl PeerCapabilityCheck {
    /// Strict (fail-CLOSED) constructor for production receivers.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            on_missing: MissingFieldPolicy::Deny,
        }
    }

    /// Back-compat constructor for callers that have not yet threaded peer
    /// capability advertisements into their enforcement context.
    #[must_use]
    pub const fn back_compat() -> Self {
        Self {
            on_missing: MissingFieldPolicy::Skip,
        }
    }

    /// Whether this check fails closed on missing safety/capability inputs.
    #[must_use]
    pub const fn fails_closed(&self) -> bool {
        matches!(self.on_missing, MissingFieldPolicy::Deny)
    }

    fn handle_missing(&self, field: &str, skip_reason: &'static str) -> CheckOutcome {
        match self.on_missing {
            MissingFieldPolicy::Deny => CheckOutcome::Deny {
                reason_code: PEER_CAPABILITY_NOT_ADVERTISED.into(),
                explanation: format!(
                    "peer-capability enforcement cannot be evaluated: required EnforcementContext field `{field}` is missing"
                ),
            },
            MissingFieldPolicy::Skip => CheckOutcome::Skip {
                reason: skip_reason.into(),
            },
        }
    }
}

impl Default for PeerCapabilityCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl EnforcementCheck for PeerCapabilityCheck {
    fn name(&self) -> &'static str {
        "peer_capability"
    }

    fn check(&self, ctx: &EnforcementContext, _config: &EnforcementConfig) -> CheckOutcome {
        let Some(tier) = ctx.safety_tier else {
            return self.handle_missing(
                "safety_tier",
                "request has no safety_tier; peer-capability enforcement deferred",
            );
        };
        if !safety_tier_requires_v4_peer(tier) {
            return CheckOutcome::Allow;
        }

        let Some(capabilities) = ctx.remote_peer_capabilities.as_ref() else {
            return self.handle_missing(
                "remote_peer_capabilities",
                "request has no remote peer capability advertisement; peer-capability enforcement deferred",
            );
        };
        if capabilities.supports_v4() {
            return CheckOutcome::Allow;
        }

        let peer = ctx.remote_peer_id.as_deref().unwrap_or("<unknown-peer>");
        let claim = if capabilities.is_v3_only() {
            "claims V3-only"
        } else {
            "does not advertise V4"
        };
        CheckOutcome::Deny {
            reason_code: PEER_CAPABILITY_REQUIRES_V4.into(),
            explanation: format!(
                "remote peer {peer} {claim}, but safety tier {tier:?} requires V4-capable mesh protocol negotiation"
            ),
        }
    }
}

#[must_use]
const fn safety_tier_requires_v4_peer(tier: SafetyTier) -> bool {
    matches!(
        tier,
        SafetyTier::Risky | SafetyTier::Dangerous | SafetyTier::Critical | SafetyTier::Forbidden
    )
}

impl DeploymentTierCheck {
    /// Translate a missing-field condition into the configured
    /// outcome. Centralizes the policy so the two missing-field
    /// branches in `check()` share identical message structure.
    fn handle_missing(&self, field: &str, skip_reason: &'static str) -> CheckOutcome {
        match self.on_missing {
            MissingFieldPolicy::Deny => CheckOutcome::Deny {
                reason_code: TIER_ADMISSION_NOT_CONFIGURED.into(),
                explanation: format!(
                    "deployment-tier admission cannot be evaluated: required EnforcementContext field `{field}` is missing. \
                    Populate via EnforcementContextBuilder.{field}(...) or use DeploymentTierCheck::back_compat() to opt into legacy fail-OPEN behavior."
                ),
            },
            MissingFieldPolicy::Skip => CheckOutcome::Skip {
                reason: skip_reason.into(),
            },
        }
    }
}

/// Validates that holder-bound tokens present a verified holder proof.
pub struct HolderProofCheck;

impl EnforcementCheck for HolderProofCheck {
    fn name(&self) -> &'static str {
        "holder_proof"
    }

    fn check(&self, ctx: &EnforcementContext, _config: &EnforcementConfig) -> CheckOutcome {
        if !ctx.holder_proof_required {
            return CheckOutcome::Skip {
                reason: "capability token is not holder-bound".into(),
            };
        }

        if ctx.holder_verified {
            CheckOutcome::Allow
        } else {
            CheckOutcome::Deny {
                reason_code: "HOLDER_PROOF_NOT_VERIFIED".into(),
                explanation:
                    "capability token is holder-bound but request did not include a verified holder proof"
                        .into(),
            }
        }
    }
}

/// Validates that the checkpoint is fresh enough.
pub struct CheckpointFreshnessCheck;

impl EnforcementCheck for CheckpointFreshnessCheck {
    fn name(&self) -> &'static str {
        "checkpoint_freshness"
    }

    fn check(&self, ctx: &EnforcementContext, config: &EnforcementConfig) -> CheckOutcome {
        match ctx.checkpoint_age_ms {
            None => CheckOutcome::Skip {
                reason: "checkpoint age not available".into(),
            },
            Some(age) if age <= config.checkpoint_max_age_ms => CheckOutcome::Allow,
            Some(age) => CheckOutcome::Deny {
                reason_code: "CHECKPOINT_STALE".into(),
                explanation: format!(
                    "checkpoint age {age}ms exceeds maximum {}ms",
                    config.checkpoint_max_age_ms
                ),
            },
        }
    }
}

/// Validates that critical taint flags have matching approval tokens.
pub struct TaintApprovalCheck;

impl EnforcementCheck for TaintApprovalCheck {
    fn name(&self) -> &'static str {
        "taint_approval"
    }

    fn check(&self, ctx: &EnforcementContext, config: &EnforcementConfig) -> CheckOutcome {
        if ctx.taint_flags.is_empty() {
            return CheckOutcome::Skip {
                reason: "no taint flags on request".into(),
            };
        }

        let approval_set: HashSet<&str> = ctx.approval_scopes.iter().map(String::as_str).collect();

        for flag in &ctx.taint_flags {
            if config.critical_taint_flags.contains(flag) && !approval_set.contains(flag.as_str()) {
                return CheckOutcome::Deny {
                    reason_code: "TAINT_APPROVAL_MISSING".into(),
                    explanation: format!("critical taint flag '{flag}' requires an approval token"),
                };
            }
        }

        CheckOutcome::Allow
    }
}

/// Validates that zone policy permits the connector and operation.
pub struct PolicyCeilingCheck;

impl EnforcementCheck for PolicyCeilingCheck {
    fn name(&self) -> &'static str {
        "policy_ceiling"
    }

    fn check(&self, ctx: &EnforcementContext, config: &EnforcementConfig) -> CheckOutcome {
        let zone_id = match parse_zone_id_for_check(&ctx.zone_id) {
            Ok(zone_id) => zone_id,
            Err(outcome) => return outcome,
        };
        let connector_id = match parse_connector_id_for_check(&ctx.connector_id) {
            Ok(connector_id) => connector_id,
            Err(outcome) => return outcome,
        };
        let operation_id = match parse_operation_id_for_check(&ctx.operation) {
            Ok(operation_id) => operation_id,
            Err(outcome) => return outcome,
        };

        // Check connector allow list for this zone.
        if let Some(allowed_connectors) = config.zone_allowed_connectors.get(&zone_id)
            && !allowed_connectors
                .iter()
                .any(|allowed| allowed.matches(&connector_id))
        {
            return CheckOutcome::Deny {
                reason_code: "CONNECTOR_NOT_IN_ZONE_POLICY".into(),
                explanation: format!(
                    "connector '{}' is not allowed in zone '{}'",
                    ctx.connector_id, ctx.zone_id
                ),
            };
        }

        // Check operation allow list for this zone.
        if let Some(allowed_ops) = config.zone_allowed_operations.get(&zone_id)
            && !allowed_ops
                .iter()
                .any(|allowed| allowed.matches(&operation_id))
        {
            return CheckOutcome::Deny {
                reason_code: "OPERATION_NOT_IN_ZONE_POLICY".into(),
                explanation: format!(
                    "operation '{}' is not allowed in zone '{}'",
                    ctx.operation, ctx.zone_id
                ),
            };
        }

        // No restrictions or all checks passed.
        CheckOutcome::Allow
    }
}

/// Validates capability-token constraints against request details.
pub struct CapabilityConstraintsCheck;

impl EnforcementCheck for CapabilityConstraintsCheck {
    fn name(&self) -> &'static str {
        "capability_constraints"
    }

    fn check(&self, ctx: &EnforcementContext, _config: &EnforcementConfig) -> CheckOutcome {
        let Some(constraints) = &ctx.capability_constraints else {
            return CheckOutcome::Skip {
                reason: "capability constraints not provided".into(),
            };
        };

        let Some(object_id) = ctx.constraint_object_id else {
            return CheckOutcome::Deny {
                reason_code: "CONSTRAINT_REQUEST_DESCRIPTOR_INCOMPLETE".into(),
                explanation:
                    "capability constraints were provided but request object_id is missing".into(),
            };
        };

        let operation = match parse_operation_id_for_check(&ctx.operation) {
            Ok(operation) => operation,
            Err(outcome) => return outcome,
        };
        let principal = match PrincipalId::new(ctx.principal.as_str()) {
            Ok(principal) => principal,
            Err(err) => {
                return CheckOutcome::Deny {
                    reason_code: "INVALID_PRINCIPAL_ID".into(),
                    explanation: format!("principal '{}' is not canonical: {err}", ctx.principal),
                };
            }
        };

        let descriptor = RequestDescriptor {
            object_id,
            operation,
            principal,
            host: ctx.constraint_host.clone().unwrap_or_default(),
            resource_uri: ctx.constraint_resource_uri.clone().unwrap_or_default(),
            requested_at_unix_ms: ctx.timestamp_ms,
            observed_calls: ctx.constraint_observed_calls,
            observed_bytes: ctx.constraint_observed_bytes,
        };

        match DefaultConstraintEnforcer::new().evaluate(constraints, &descriptor) {
            fcp_policy::ConstraintEvaluation::Allow => CheckOutcome::Allow,
            fcp_policy::ConstraintEvaluation::Deny(reason) => {
                let fcp_policy::ConstraintDenialReason { kind, explanation } = reason;
                let audit_descriptor = capability_constraint_audit_descriptor(
                    ctx.request_id.as_str(),
                    ctx.connector_id.as_str(),
                    ctx.operation.as_str(),
                    ctx.zone_id.as_str(),
                    &descriptor,
                );
                emit_capability_constraint_denial_audit_event(
                    &audit_descriptor,
                    &kind,
                    "fcp-host.enforcement_pipeline",
                );
                CheckOutcome::Deny {
                    reason_code: "CAPABILITY_CONSTRAINT_DENIED".into(),
                    explanation,
                }
            }
        }
    }
}

/// Validates that the connector manifest allows the requested operation.
pub struct ConnectorManifestCheck;

impl EnforcementCheck for ConnectorManifestCheck {
    fn name(&self) -> &'static str {
        "connector_manifest"
    }

    fn check(&self, ctx: &EnforcementContext, _config: &EnforcementConfig) -> CheckOutcome {
        if ctx.manifest_allowed_operations.is_empty() {
            return CheckOutcome::Skip {
                reason: "no manifest operations provided".into(),
            };
        }

        if ctx.manifest_allowed_operations.contains(&ctx.operation) {
            CheckOutcome::Allow
        } else {
            CheckOutcome::Deny {
                reason_code: "OPERATION_NOT_IN_MANIFEST".into(),
                explanation: format!(
                    "operation '{}' is not declared in the connector manifest",
                    ctx.operation
                ),
            }
        }
    }
}

/// Validates that the request is within the rate-limit quota.
pub struct RateLimitCheck;

impl EnforcementCheck for RateLimitCheck {
    fn name(&self) -> &'static str {
        "rate_limit"
    }

    fn check(&self, ctx: &EnforcementContext, _config: &EnforcementConfig) -> CheckOutcome {
        match (ctx.rate_count, ctx.rate_limit) {
            (None, _) | (_, None) => CheckOutcome::Skip {
                reason: "rate limit data not available".into(),
            },
            (Some(count), Some(limit)) if count < limit => CheckOutcome::Allow,
            (Some(count), Some(limit)) => CheckOutcome::Deny {
                reason_code: "RATE_LIMIT_EXCEEDED".into(),
                explanation: format!("rate count {count} has reached limit {limit}"),
            },
        }
    }
}

/// Validates that the request is within the current usage budget.
pub struct BudgetCheck;

impl EnforcementCheck for BudgetCheck {
    fn name(&self) -> &'static str {
        "budget"
    }

    fn check(&self, ctx: &EnforcementContext, _config: &EnforcementConfig) -> CheckOutcome {
        match (ctx.budget_used, ctx.budget_limit) {
            (None, _) | (_, None) => CheckOutcome::Skip {
                reason: "budget data not available".into(),
            },
            (Some(used), Some(limit)) if used <= limit => CheckOutcome::Allow,
            (Some(used), Some(limit)) => CheckOutcome::Deny {
                reason_code: "BUDGET_EXCEEDED".into(),
                explanation: format!("budget used {used} has reached limit {limit}"),
            },
        }
    }
}

/// Validates that none of the request's security artifacts have been revoked.
/// Also validates that the revocation list is fresh enough.
pub struct RevocationCheck;

impl EnforcementCheck for RevocationCheck {
    fn name(&self) -> &'static str {
        "revocation_freshness"
    }

    fn check(&self, ctx: &EnforcementContext, config: &EnforcementConfig) -> CheckOutcome {
        // 1. Exact-membership revocation is authoritative and INDEPENDENT of
        //    list freshness: a known revocation in a configured registry must
        //    deny even when the list's age is unknown. Freshness only needs the
        //    age; membership needs only the registry + ids, so coupling them
        //    (as the old `age.is_none() => Skip` short-circuit did) would let a
        //    revoked artifact through whenever `revocation_list_age_ms` was
        //    absent. Run membership first so it can never be bypassed.
        if let Some(registry) = &config.revocation_registry {
            // Check capability token revocation
            if let Some(token_id) = &ctx.token_id
                && registry.is_revoked(token_id)
            {
                return CheckOutcome::Deny {
                    reason_code: "CAPABILITY_REVOKED".into(),
                    explanation: format!("capability token '{token_id}' has been revoked"),
                };
            }

            // Check node attestation revocation
            if let Some(att_id) = &ctx.node_attestation_id
                && registry.is_revoked(att_id)
            {
                return CheckOutcome::Deny {
                    reason_code: "NODE_ATTESTATION_REVOKED".into(),
                    explanation: format!("node attestation '{att_id}' has been revoked"),
                };
            }

            // Check issuer key revocation
            if let Some(key_id) = &ctx.issuer_key_id
                && registry.is_revoked(key_id)
            {
                return CheckOutcome::Deny {
                    reason_code: "ISSUER_KEY_REVOKED".into(),
                    explanation: format!("issuer key '{key_id}' has been revoked"),
                };
            }

            // Check binary artifact revocation
            if let Some(bin_id) = &ctx.binary_artifact_id
                && registry.is_revoked(bin_id)
            {
                return CheckOutcome::Deny {
                    reason_code: "BINARY_ARTIFACT_REVOKED".into(),
                    explanation: format!("connector binary artifact '{bin_id}' has been revoked"),
                };
            }
        }

        // 2. Validate freshness of the revocation list (a separate concern: a
        //    stale list may be MISSING recent revocations). Membership above
        //    already honored every revocation the local registry knows about.
        match ctx.revocation_list_age_ms {
            None => CheckOutcome::Skip {
                reason: "revocation list age not available".into(),
            },
            Some(age) if age > config.revocation_max_age_ms => CheckOutcome::Deny {
                reason_code: "REVOCATION_LIST_STALE".into(),
                explanation: format!(
                    "revocation list age {age}ms exceeds maximum {}ms",
                    config.revocation_max_age_ms
                ),
            },
            _ => CheckOutcome::Allow,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Enforcement pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Ordered pipeline of enforcement checks.
///
/// Runs each check in sequence and short-circuits on the first denial.
/// Skipped checks are recorded but do not block.
///
/// # Production usage
///
/// **This pipeline is not currently wired into the production invoke
/// path.** The canonical enforcement flow runs as ad-hoc gates
/// inside `crates/fcp-host/src/bin/fcp-host.rs::verify_live_request`
/// and `evaluate_live_preflight`:
///
/// - Zone binding: `allowed_zones` check (`verify_live_request` line ~1735).
/// - Operation allow-list: `allowed_operations` check
///   (`verify_live_request` line ~1747, br-ike8x).
/// - Capability token: `CapabilityVerifier::verify_unbound` at
///   gateway vantage (line ~1785).
/// - Holder proof: explicit `holder_node` + `holder_proof` match
///   (line ~1800), fail-closed pending live signature verification.
/// - Persisted lifecycle verify: `state.lifecycle.verify_capability_token`.
///
/// The pipeline + its canonical checks remain useful as a structural
/// reference for the canonical check ordering and for callers that
/// want to run a check in isolation (e.g.,
/// `ConnectorManifestCheck.check(&ctx, &config)` directly). The
/// architectural decision of whether to migrate the production path
/// to the pipeline OR retire the pipeline entirely is tracked
/// separately; both options are valid resolutions of br-ike8x.
pub struct EnforcementPipeline {
    checks: Vec<Box<dyn EnforcementCheck>>,
    config: EnforcementConfig,
}

impl EnforcementPipeline {
    /// Create a pipeline with the default canonical checks and default config.
    #[must_use]
    pub fn new() -> Self {
        Self {
            checks: Self::default_checks(),
            config: EnforcementConfig::default(),
        }
    }

    /// Create a pipeline with custom checks and default config.
    #[must_use]
    pub fn with_checks(checks: Vec<Box<dyn EnforcementCheck>>) -> Self {
        Self {
            checks,
            config: EnforcementConfig::default(),
        }
    }

    /// Create a pipeline with default checks and a custom config.
    #[must_use]
    pub fn with_config(config: EnforcementConfig) -> Self {
        Self {
            checks: Self::default_checks(),
            config,
        }
    }

    /// Create a pipeline with custom checks and config.
    #[must_use]
    pub fn with_checks_and_config(
        checks: Vec<Box<dyn EnforcementCheck>>,
        config: EnforcementConfig,
    ) -> Self {
        Self { checks, config }
    }

    /// Number of checks in the pipeline.
    #[must_use]
    pub fn check_count(&self) -> usize {
        self.checks.len()
    }

    /// Reference to the pipeline's config.
    #[must_use]
    pub const fn config(&self) -> &EnforcementConfig {
        &self.config
    }

    /// Names of all checks in order.
    #[must_use]
    pub fn check_names(&self) -> Vec<&str> {
        self.checks.iter().map(|c| c.name()).collect()
    }

    /// Evaluate all checks against the given context, stopping at first denial.
    #[must_use]
    pub fn evaluate(&self, ctx: &EnforcementContext) -> EnforcementDecision {
        let pipeline_start = Instant::now();
        let mut records = Vec::with_capacity(self.checks.len());

        for check in &self.checks {
            let check_start = Instant::now();
            let outcome = check.check(ctx, &self.config);
            let elapsed_ms = check_start.elapsed().as_secs_f64() * 1000.0;
            let check_name = check.name();

            if let CheckOutcome::Deny {
                ref reason_code,
                ref explanation,
            } = outcome
            {
                let deny_outcome = PipelineOutcome::Deny {
                    check_name: check_name.to_string(),
                    reason_code: reason_code.clone(),
                    explanation: explanation.clone(),
                };
                records.push(CheckRecord {
                    name: check_name.to_string(),
                    outcome,
                    elapsed_ms,
                });
                return EnforcementDecision {
                    outcome: deny_outcome,
                    checks_run: records,
                    elapsed_ms: pipeline_start.elapsed().as_secs_f64() * 1000.0,
                };
            }

            records.push(CheckRecord {
                name: check_name.to_string(),
                outcome,
                elapsed_ms,
            });
        }

        EnforcementDecision {
            outcome: PipelineOutcome::Allow,
            checks_run: records,
            elapsed_ms: pipeline_start.elapsed().as_secs_f64() * 1000.0,
        }
    }

    /// The default checks in canonical order.
    fn default_checks() -> Vec<Box<dyn EnforcementCheck>> {
        EnforcementCheckOrder::canonical_order()
            .into_iter()
            .map(Self::check_for_id)
            .collect()
    }

    fn check_for_id(check: EnforcementCheckId) -> Box<dyn EnforcementCheck> {
        match check {
            EnforcementCheckId::CanonicalDecode => Box::new(CanonicalDecodeCheck),
            EnforcementCheckId::ZoneMembership => Box::new(ZoneMembershipCheck),
            EnforcementCheckId::CapabilityVerify => Box::new(CapabilityVerifyCheck),
            EnforcementCheckId::RevocationCascade => Box::new(CascadeRevocationCheck),
            EnforcementCheckId::DeploymentTier => Box::new(DeploymentTierCheck::new()),
            EnforcementCheckId::HolderProof => Box::new(HolderProofCheck),
            EnforcementCheckId::CheckpointFreshness => Box::new(CheckpointFreshnessCheck),
            EnforcementCheckId::RevocationFreshness => Box::new(RevocationCheck),
            EnforcementCheckId::TaintApproval => Box::new(TaintApprovalCheck),
            EnforcementCheckId::PolicyCeiling => Box::new(PolicyCeilingCheck),
            EnforcementCheckId::CapabilityConstraints => Box::new(CapabilityConstraintsCheck),
            EnforcementCheckId::ConnectorManifest => Box::new(ConnectorManifestCheck),
            EnforcementCheckId::Budget => Box::new(BudgetCheck),
            EnforcementCheckId::RateLimit => Box::new(RateLimitCheck),
        }
    }
}

impl Default for EnforcementPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for EnforcementPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnforcementPipeline")
            .field("check_count", &self.checks.len())
            .field("check_names", &self.check_names())
            .field("config", &self.config)
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: build a valid context for testing
// ─────────────────────────────────────────────────────────────────────────────

/// Convenience function to create a minimal valid context for testing.
#[cfg(test)]
fn test_context() -> EnforcementContext {
    EnforcementContext {
        request_id: "req-001".into(),
        connector_id: "slack:utility:1.0.0".into(),
        operation: "send_message".into(),
        zone_id: "z:prod".into(),
        principal: "agent-alpha".into(),
        capability_claims: vec!["messages.write".into()],
        required_capability: Some("messages.write".into()),
        lattice_sub_token: None,
        capability_constraints: None,
        constraint_object_id: None,
        constraint_host: None,
        constraint_resource_uri: None,
        constraint_observed_calls: 0,
        constraint_observed_bytes: 0,
        taint_flags: Vec::new(),
        approval_scopes: Vec::new(),
        timestamp_ms: 1_700_000_000_000,
        token_id: None,
        issuer_kid: None,
        node_attestation_id: None,
        issuer_key_id: None,
        binary_artifact_id: None,
        holder_proof_required: true,
        holder_verified: true,
        checkpoint_age_ms: Some(10_000),
        revocation_list_age_ms: Some(20_000),
        budget_used: Some(50),
        budget_limit: Some(1000),
        rate_count: Some(5),
        rate_limit: Some(100),
        manifest_allowed_operations: vec!["send_message".into(), "list_channels".into()],
        // br-298px: the test_context fixture populates both
        // DeploymentTier inputs with admissible defaults (Safe +
        // MeshActive) so the strict fail-CLOSED DeploymentTierCheck
        // (which now Denies on missing fields) does not short-circuit
        // every legacy pipeline test before the test's intended
        // assertion runs. Tests that exercise the missing-field
        // behavior override these to None explicitly (see
        // deployment_tier_check_default_denies_when_*_missing).
        safety_tier: Some(SafetyTier::Safe),
        deployment_classification: Some(test_mesh_active_classification()),
        remote_peer_id: None,
        remote_peer_capabilities: None,
    }
}

/// Test fixture: a `DeploymentClassification` for a fully-active
/// mesh deployment. Used by [`test_context`] so the strict
/// `DeploymentTierCheck` admits the request and downstream pipeline
/// checks run (br-298px).
#[cfg(test)]
fn test_mesh_active_classification() -> std::sync::Arc<DeploymentClassification> {
    use crate::deployment_mode::{MeshQuorumSignals, classify_deployment_mode};
    std::sync::Arc::new(classify_deployment_mode(MeshQuorumSignals::fully_active(3)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_cbor::SchemaId;
    use fcp_crypto_pq as pq;
    use fcp_policy::{DelegationCertificate, DelegationCertificateId, DelegationPeriod};

    fn constraint_object_id() -> ObjectId {
        ObjectId::from_unscoped_bytes(b"constraint-object")
    }

    fn lattice_cert_id(byte: u8) -> DelegationCertificateId {
        DelegationCertificateId::from_bytes([byte; 32])
    }

    const fn lattice_period() -> DelegationPeriod {
        DelegationPeriod {
            start_unix_ms: 1_700_000_000_000,
            end_unix_ms: 1_700_003_600_000,
        }
    }

    fn lattice_unit_fixture(
        params: pq::LatticeParams,
    ) -> (
        Arc<LatticeDelegationVerifierImpl>,
        LatticeSubToken,
        ZoneId,
        OperationId,
        PrincipalId,
        u64,
    ) {
        let zone = "z:prod".parse::<ZoneId>().unwrap();
        let operation = OperationId::new("send_message").unwrap();
        let principal = PrincipalId::new("agent-alpha").unwrap();
        let policy_period = lattice_period();
        let crypto_zone = LatticeDelegationVerifierImpl::zone_to_crypto(&zone);
        let crypto_period = LatticeDelegationVerifierImpl::period_to_crypto(policy_period);
        let entropy = pq::TrapGenEntropy::from_fixture_seed(
            b"fcp-host/lattice-dispatcher-unit-v1",
            [0x5A; 32],
        );
        let (master_public, master_trapdoor) = pq::trap_gen_with_entropy(params, &entropy).unwrap();
        let (public_key, trapdoor) = pq::delegate(
            &master_public,
            &master_trapdoor,
            crypto_zone,
            crypto_period,
            params,
        )
        .unwrap();
        let h = pq::operation_hash(
            &crypto_zone,
            crypto_period,
            operation.as_str().as_bytes(),
            principal.as_str().as_bytes(),
        );
        let preimage = pq::sample_pre(&public_key, &trapdoor, h, params).unwrap();
        let certificate = DelegationCertificate {
            cert_id: lattice_cert_id(0xA1),
            zone_id: zone.clone(),
            period: policy_period,
            parent_cert_id: None,
            public_key,
        };
        let verifier =
            LatticeDelegationVerifierImpl::with_certificates(params, [certificate.clone()]);
        let request_descriptor_hash = LatticeDelegationVerifierImpl::request_descriptor_hash(
            &certificate.cert_id,
            &zone,
            certificate.period,
            &operation,
            &principal,
            &certificate.public_key.hash,
            &verifier.trust_set_id(),
        );
        let sub_token = LatticeSubToken {
            cert_id: certificate.cert_id,
            op_id: operation.clone(),
            principal_id: principal.clone(),
            request_descriptor_hash,
            preimage_bytes: preimage.as_bytes().to_vec(),
        };
        (
            Arc::new(verifier),
            sub_token,
            zone,
            operation,
            principal,
            policy_period.start_unix_ms,
        )
    }

    fn denial_reason_code(outcome: CheckOutcome) -> Option<String> {
        match outcome {
            CheckOutcome::Deny { reason_code, .. } => Some(reason_code),
            CheckOutcome::Allow | CheckOutcome::Skip { .. } => None,
        }
    }

    // ── EnforcementConfig ──

    #[test]
    fn config_default_has_reasonable_values() {
        let config = EnforcementConfig::default();
        assert_eq!(config.checkpoint_max_age_ms, 300_000);
        assert_eq!(config.revocation_max_age_ms, 600_000);
        assert!(!config.critical_taint_flags.is_empty());
        assert!(config.critical_taint_flags.contains(&"pii".to_string()));
        assert!(config.critical_taint_flags.contains(&"phi".to_string()));
    }

    #[test]
    fn config_new_equals_default() {
        let a = EnforcementConfig::new();
        let b = EnforcementConfig::default();
        assert_eq!(a.checkpoint_max_age_ms, b.checkpoint_max_age_ms);
        assert_eq!(a.revocation_max_age_ms, b.revocation_max_age_ms);
        assert_eq!(a.critical_taint_flags.len(), b.critical_taint_flags.len());
    }

    #[test]
    fn config_builder_checkpoint_age() {
        let config = EnforcementConfig::new().with_checkpoint_max_age_ms(1000);
        assert_eq!(config.checkpoint_max_age_ms, 1000);
    }

    #[test]
    fn config_builder_revocation_age() {
        let config = EnforcementConfig::new().with_revocation_max_age_ms(2000);
        assert_eq!(config.revocation_max_age_ms, 2000);
    }

    #[test]
    fn config_builder_critical_taints() {
        let config = EnforcementConfig::new().with_critical_taint_flags(vec!["custom".into()]);
        assert_eq!(config.critical_taint_flags, vec!["custom"]);
    }

    #[test]
    fn config_builder_lattice_delegation_verifier() {
        let (verifier, _, _, _, _, _) = lattice_unit_fixture(pq::LatticeParams::SMALL_TEST);
        let config = EnforcementConfig::new().with_lattice_delegation_verifier(verifier);
        assert!(
            config.lattice_delegation_verifier.is_some(),
            "lattice verifier should be available to CapabilityVerifyCheck"
        );
    }

    #[test]
    fn config_add_zone_membership() {
        let mut config = EnforcementConfig::new();
        config.add_zone_membership("alice", "z:zone-a").unwrap();
        config.add_zone_membership("alice", "z:zone-b").unwrap();
        config.add_zone_membership("bob", "z:zone-a").unwrap();

        let alice_zones = config.zone_memberships.get("alice").unwrap();
        assert!(alice_zones.contains(&"z:zone-a".parse::<ZoneId>().unwrap()));
        assert!(alice_zones.contains(&"z:zone-b".parse::<ZoneId>().unwrap()));
        assert_eq!(alice_zones.len(), 2);

        let bob_zones = config.zone_memberships.get("bob").unwrap();
        assert_eq!(bob_zones.len(), 1);
    }

    #[test]
    fn config_add_zone_connector() {
        let mut config = EnforcementConfig::new();
        config
            .add_zone_connector("z:zone-a", "slack:utility:1.0.0")
            .unwrap();
        config
            .add_zone_connector("z:zone-a", "github:utility:1.0.0")
            .unwrap();

        let connectors = config
            .zone_allowed_connectors
            .get(&"z:zone-a".parse::<ZoneId>().unwrap())
            .unwrap();
        assert!(
            connectors.contains(&AllowedConnector::Connector(ConnectorId::from_static(
                "slack:utility:1.0.0"
            )))
        );
        assert!(
            connectors.contains(&AllowedConnector::Connector(ConnectorId::from_static(
                "github:utility:1.0.0"
            )))
        );
    }

    #[test]
    fn config_add_zone_operation() {
        let mut config = EnforcementConfig::new();
        config.add_zone_operation("z:zone-a", "read").unwrap();
        config.add_zone_operation("z:zone-a", "write").unwrap();

        let ops = config
            .zone_allowed_operations
            .get(&"z:zone-a".parse::<ZoneId>().unwrap())
            .unwrap();
        assert!(
            ops.contains(&AllowedOperation::Operation(OperationId::from_static(
                "read"
            )))
        );
        assert!(
            ops.contains(&AllowedOperation::Operation(OperationId::from_static(
                "write"
            )))
        );
    }

    #[test]
    fn config_clone() {
        let mut original = EnforcementConfig::new();
        original.add_zone_membership("alice", "z:zone-a").unwrap();
        let cloned = original.clone();
        assert_eq!(
            cloned.zone_memberships.get("alice").unwrap().len(),
            original.zone_memberships.get("alice").unwrap().len()
        );
    }

    #[test]
    fn config_debug_format() {
        let config = EnforcementConfig::new();
        let debug = format!("{config:?}");
        assert!(debug.contains("EnforcementConfig"));
    }

    #[test]
    fn config_add_zone_membership_rejects_invalid_zone_id() {
        let mut config = EnforcementConfig::new();
        assert!(matches!(
            config.add_zone_membership("alice", "zone-a"),
            Err(EnforcementConfigError::InvalidZoneId(
                ZoneIdError::MissingPrefix
            ))
        ));
        assert!(!config.zone_memberships.contains_key("alice"));
    }

    #[test]
    fn config_add_zone_connector_rejects_invalid_connector_id() {
        let mut config = EnforcementConfig::new();
        assert!(matches!(
            config.add_zone_connector("z:zone-a", "Slack:utility:1.0.0"),
            Err(EnforcementConfigError::InvalidConnectorId(
                IdValidationError::UppercaseNotAllowed
            ))
        ));
        assert!(config.zone_allowed_connectors.is_empty());
    }

    #[test]
    fn config_add_zone_operation_rejects_invalid_operation_id() {
        let mut config = EnforcementConfig::new();
        assert!(matches!(
            config.add_zone_operation("z:zone-a", "send message"),
            Err(EnforcementConfigError::InvalidOperationId(
                IdValidationError::InvalidChar { .. }
            ))
        ));
        assert!(config.zone_allowed_operations.is_empty());
    }

    // ── EnforcementContextBuilder ──

    #[test]
    fn builder_complete_builds_context() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .build();
        assert!(ctx.is_some());
        let ctx = ctx.unwrap();
        assert_eq!(ctx.request_id, "r1");
        assert_eq!(ctx.connector_id, "c1");
        assert_eq!(ctx.operation, "op1");
        assert_eq!(ctx.zone_id, "z1");
        assert_eq!(ctx.principal, "p1");
    }

    #[test]
    fn builder_missing_request_id_returns_none() {
        let ctx = EnforcementContextBuilder::new()
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .build();
        assert!(ctx.is_none());
    }

    #[test]
    fn builder_missing_connector_id_returns_none() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .build();
        assert!(ctx.is_none());
    }

    #[test]
    fn builder_missing_operation_returns_none() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .zone_id("z1")
            .principal("p1")
            .build();
        assert!(ctx.is_none());
    }

    #[test]
    fn builder_missing_zone_id_returns_none() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .principal("p1")
            .build();
        assert!(ctx.is_none());
    }

    #[test]
    fn builder_missing_principal_returns_none() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .build();
        assert!(ctx.is_none());
    }

    #[test]
    fn builder_with_capability_claims() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .capability_claims(vec!["cap1".into(), "cap2".into()])
            .build()
            .unwrap();
        assert_eq!(ctx.capability_claims.len(), 2);
    }

    #[test]
    fn builder_with_required_capability() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .required_capability("messages.write")
            .build()
            .unwrap();
        assert_eq!(ctx.required_capability.as_deref(), Some("messages.write"));
    }

    #[test]
    fn builder_with_capability_constraints_descriptor() {
        let constraints = CapabilityConstraints {
            resource_allow: vec!["/messages/*".into()],
            ..CapabilityConstraints::default()
        };
        let object_id = constraint_object_id();
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("slack:utility:1.0.0")
            .operation("messages.write")
            .zone_id("z:prod")
            .principal("agent-alpha")
            .capability_constraints(constraints)
            .constraint_object_id(object_id)
            .constraint_host("api.example.com")
            .constraint_resource_uri("/messages/1")
            .constraint_usage(3, 512)
            .build()
            .unwrap();
        assert!(ctx.capability_constraints.is_some());
        assert_eq!(ctx.constraint_object_id, Some(object_id));
        assert_eq!(ctx.constraint_host.as_deref(), Some("api.example.com"));
        assert_eq!(ctx.constraint_resource_uri.as_deref(), Some("/messages/1"));
        assert_eq!(ctx.constraint_observed_calls, 3);
        assert_eq!(ctx.constraint_observed_bytes, 512);
    }

    #[test]
    fn builder_with_taint_flags() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .taint_flags(vec!["pii".into()])
            .build()
            .unwrap();
        assert_eq!(ctx.taint_flags, vec!["pii"]);
    }

    #[test]
    fn builder_with_approval_scopes() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .approval_scopes(vec!["pii".into()])
            .build()
            .unwrap();
        assert_eq!(ctx.approval_scopes, vec!["pii"]);
    }

    #[test]
    fn builder_with_timestamp() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .timestamp_ms(42)
            .build()
            .unwrap();
        assert_eq!(ctx.timestamp_ms, 42);
    }

    #[test]
    fn builder_with_holder_proof_required() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .holder_proof_required(true)
            .build()
            .unwrap();
        assert!(ctx.holder_proof_required);
    }

    #[test]
    fn builder_with_holder_verified() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .holder_verified(true)
            .build()
            .unwrap();
        assert!(ctx.holder_verified);
    }

    #[test]
    fn builder_with_checkpoint_age() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .checkpoint_age_ms(5000)
            .build()
            .unwrap();
        assert_eq!(ctx.checkpoint_age_ms, Some(5000));
    }

    #[test]
    fn builder_with_revocation_list_age() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .revocation_list_age_ms(10_000)
            .build()
            .unwrap();
        assert_eq!(ctx.revocation_list_age_ms, Some(10_000));
    }

    #[test]
    fn builder_with_budget() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .budget_used(100)
            .budget_limit(1000)
            .build()
            .unwrap();
        assert_eq!(ctx.budget_used, Some(100));
        assert_eq!(ctx.budget_limit, Some(1000));
    }

    #[test]
    fn builder_with_rate_limit() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .rate_count(10)
            .rate_limit(100)
            .build()
            .unwrap();
        assert_eq!(ctx.rate_count, Some(10));
        assert_eq!(ctx.rate_limit, Some(100));
    }

    #[test]
    fn builder_with_manifest_ops() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .manifest_allowed_operations(vec!["op1".into(), "op2".into()])
            .build()
            .unwrap();
        assert_eq!(ctx.manifest_allowed_operations.len(), 2);
    }

    #[test]
    fn builder_default_values() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .build()
            .unwrap();
        assert_eq!(ctx.timestamp_ms, 0);
        assert!(!ctx.holder_proof_required);
        assert!(!ctx.holder_verified);
        assert!(ctx.checkpoint_age_ms.is_none());
        assert!(ctx.revocation_list_age_ms.is_none());
        assert!(ctx.budget_used.is_none());
        assert!(ctx.budget_limit.is_none());
        assert!(ctx.rate_count.is_none());
        assert!(ctx.rate_limit.is_none());
        assert!(ctx.manifest_allowed_operations.is_empty());
        assert!(ctx.capability_claims.is_empty());
        assert!(ctx.required_capability.is_none());
        assert!(ctx.capability_constraints.is_none());
        assert!(ctx.constraint_object_id.is_none());
        assert!(ctx.constraint_host.is_none());
        assert!(ctx.constraint_resource_uri.is_none());
        assert_eq!(ctx.constraint_observed_calls, 0);
        assert_eq!(ctx.constraint_observed_bytes, 0);
        assert!(ctx.taint_flags.is_empty());
        assert!(ctx.approval_scopes.is_empty());
    }

    #[test]
    fn builder_clone() {
        let builder = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1");
        let cloned = builder.clone();
        // Use original after clone to prove both are valid.
        let ctx_original = builder.build().unwrap();
        let ctx_cloned = cloned.build().unwrap();
        assert_eq!(ctx_original.request_id, "r1");
        assert_eq!(ctx_cloned.request_id, "r1");
    }

    // ── CheckOutcome ──

    #[test]
    fn check_outcome_allow_predicates() {
        let o = CheckOutcome::Allow;
        assert!(o.is_allow());
        assert!(!o.is_deny());
        assert!(!o.is_skip());
    }

    #[test]
    fn check_outcome_deny_predicates() {
        let o = CheckOutcome::Deny {
            reason_code: "X".into(),
            explanation: "Y".into(),
        };
        assert!(!o.is_allow());
        assert!(o.is_deny());
        assert!(!o.is_skip());
    }

    #[test]
    fn check_outcome_skip_predicates() {
        let o = CheckOutcome::Skip {
            reason: "N/A".into(),
        };
        assert!(!o.is_allow());
        assert!(!o.is_deny());
        assert!(o.is_skip());
    }

    #[test]
    fn check_outcome_debug_format() {
        let o = CheckOutcome::Allow;
        assert!(format!("{o:?}").contains("Allow"));
    }

    #[test]
    fn check_outcome_deny_debug() {
        let o = CheckOutcome::Deny {
            reason_code: "CODE".into(),
            explanation: "explain".into(),
        };
        let debug = format!("{o:?}");
        assert!(debug.contains("CODE"));
        assert!(debug.contains("explain"));
    }

    #[test]
    fn check_outcome_clone() {
        let original = CheckOutcome::Deny {
            reason_code: "A".into(),
            explanation: "B".into(),
        };
        let cloned = original.clone();
        assert!(original.is_deny());
        assert!(cloned.is_deny());
    }

    // ── PipelineOutcome ──

    #[test]
    fn pipeline_outcome_allow_predicates() {
        let o = PipelineOutcome::Allow;
        assert!(o.is_allow());
        assert!(!o.is_deny());
    }

    #[test]
    fn pipeline_outcome_deny_predicates() {
        let o = PipelineOutcome::Deny {
            check_name: "c".into(),
            reason_code: "r".into(),
            explanation: "e".into(),
        };
        assert!(!o.is_allow());
        assert!(o.is_deny());
    }

    #[test]
    fn pipeline_outcome_debug() {
        let o = PipelineOutcome::Allow;
        assert!(format!("{o:?}").contains("Allow"));
    }

    // ── CanonicalDecodeCheck ──

    #[test]
    fn canonical_decode_name() {
        assert_eq!(CanonicalDecodeCheck.name(), "canonical_decode");
    }

    #[test]
    fn canonical_decode_allow_valid() {
        let ctx = test_context();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn canonical_decode_deny_empty_connector_id() {
        let mut ctx = test_context();
        ctx.connector_id = String::new();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_CONNECTOR_ID");
        }
    }

    #[test]
    fn canonical_decode_deny_whitespace_connector_id() {
        let mut ctx = test_context();
        ctx.connector_id = "   ".into();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_CONNECTOR_ID");
        }
    }

    #[test]
    fn canonical_decode_deny_empty_operation() {
        let mut ctx = test_context();
        ctx.operation = String::new();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_OPERATION");
        }
    }

    #[test]
    fn canonical_decode_deny_whitespace_operation() {
        let mut ctx = test_context();
        ctx.operation = "\t\n ".into();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn canonical_decode_deny_empty_zone_id() {
        let mut ctx = test_context();
        ctx.zone_id = String::new();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_ZONE_ID");
        }
    }

    #[test]
    fn canonical_decode_deny_empty_principal() {
        let mut ctx = test_context();
        ctx.principal = String::new();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_PRINCIPAL");
        }
    }

    #[test]
    fn canonical_decode_deny_empty_request_id() {
        let mut ctx = test_context();
        ctx.request_id = String::new();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_REQUEST_ID");
        }
    }

    #[test]
    fn canonical_decode_deny_whitespace_principal() {
        let mut ctx = test_context();
        ctx.principal = "  ".into();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn canonical_decode_deny_whitespace_zone_id() {
        let mut ctx = test_context();
        ctx.zone_id = " ".into();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn canonical_decode_deny_invalid_connector_id() {
        let mut ctx = test_context();
        // Use an actually invalid ID (uppercase is rejected by canonical ID validation)
        ctx.connector_id = "INVALID_UPPERCASE".into();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "INVALID_CONNECTOR_ID");
        }
    }

    #[test]
    fn canonical_decode_deny_invalid_operation_id() {
        let mut ctx = test_context();
        ctx.operation = "send message".into();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "INVALID_OPERATION_ID");
        }
    }

    #[test]
    fn canonical_decode_deny_invalid_zone_id() {
        let mut ctx = test_context();
        ctx.zone_id = "zone-prod".into();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "INVALID_ZONE_ID");
        }
    }

    // ── ZoneMembershipCheck ──

    #[test]
    fn zone_membership_name() {
        assert_eq!(ZoneMembershipCheck.name(), "zone_membership");
    }

    #[test]
    fn zone_membership_skip_no_rules() {
        let ctx = test_context();
        let config = EnforcementConfig::default();
        let outcome = ZoneMembershipCheck.check(&ctx, &config);
        assert!(outcome.is_skip());
    }

    #[test]
    fn zone_membership_allow_member() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config.add_zone_membership("agent-alpha", "z:prod").unwrap();
        let outcome = ZoneMembershipCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn zone_membership_deny_not_member() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config
            .add_zone_membership("agent-alpha", "z:staging")
            .unwrap();
        let outcome = ZoneMembershipCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny {
            reason_code,
            explanation,
        } = &outcome
        {
            assert_eq!(reason_code, "ZONE_MEMBERSHIP_DENIED");
            assert!(explanation.contains("agent-alpha"));
            assert!(explanation.contains("z:prod"));
        }
    }

    #[test]
    fn zone_membership_deny_unknown_principal() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config.add_zone_membership("agent-beta", "z:prod").unwrap();
        let outcome = ZoneMembershipCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "PRINCIPAL_NOT_REGISTERED");
        }
    }

    #[test]
    fn zone_membership_allow_multiple_zones() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config
            .add_zone_membership("agent-alpha", "z:staging")
            .unwrap();
        config.add_zone_membership("agent-alpha", "z:prod").unwrap();
        let outcome = ZoneMembershipCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    // ── CapabilityVerifyCheck ──

    #[test]
    fn capability_verify_name() {
        assert_eq!(CapabilityVerifyCheck.name(), "capability_verify");
    }

    #[test]
    fn capability_verify_allow_exact_match() {
        let ctx = test_context();
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn capability_verify_allow_wildcard() {
        let mut ctx = test_context();
        ctx.capability_claims = vec!["*".into()];
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn holder_proof_skip_when_not_required() {
        let mut ctx = test_context();
        ctx.holder_proof_required = false;
        ctx.holder_verified = false;
        let config = EnforcementConfig::default();
        let outcome = HolderProofCheck.check(&ctx, &config);
        assert!(outcome.is_skip());
    }

    #[test]
    fn holder_proof_allow_when_verified() {
        let mut ctx = test_context();
        ctx.holder_proof_required = true;
        ctx.holder_verified = true;
        let config = EnforcementConfig::default();
        let outcome = HolderProofCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn holder_proof_deny_when_required_but_not_verified() {
        let mut ctx = test_context();
        ctx.holder_proof_required = true;
        ctx.holder_verified = false;
        let config = EnforcementConfig::default();
        let outcome = HolderProofCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "HOLDER_PROOF_NOT_VERIFIED");
        }
    }

    #[test]
    fn capability_verify_deny_operation_named_claim() {
        let mut ctx = test_context();
        ctx.capability_claims = vec!["send_message".into()];
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn capability_verify_deny_wrong_claim() {
        let mut ctx = test_context();
        ctx.capability_claims = vec!["list_channels".into()];
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny {
            reason_code,
            explanation,
        } = &outcome
        {
            assert_eq!(reason_code, "CAPABILITY_NOT_GRANTED");
            assert!(explanation.contains("messages.write"));
            assert!(explanation.contains("send_message"));
        }
    }

    #[test]
    fn capability_verify_deny_no_claims() {
        let mut ctx = test_context();
        ctx.capability_claims = Vec::new();
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "NO_CAPABILITY_CLAIMS");
        }
    }

    #[test]
    fn capability_verify_deny_missing_required_capability() {
        let mut ctx = test_context();
        ctx.required_capability = None;
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny {
            reason_code,
            explanation,
        } = &outcome
        {
            assert_eq!(reason_code, "MISSING_REQUIRED_CAPABILITY");
            assert!(explanation.contains("send_message"));
        }
    }

    #[test]
    fn capability_verify_allows_valid_lattice_sub_token() {
        let (verifier, sub_token, _, _, _, now) =
            lattice_unit_fixture(pq::LatticeParams::SMALL_TEST);
        let mut ctx = test_context();
        ctx.timestamp_ms = now;
        ctx.lattice_sub_token = Some(sub_token);
        ctx.capability_claims = Vec::new();
        ctx.required_capability = None;
        let config = EnforcementConfig::new().with_lattice_delegation_verifier(verifier);

        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn capability_verify_denies_lattice_token_without_configured_verifier() {
        let (_, sub_token, _, _, _, now) = lattice_unit_fixture(pq::LatticeParams::SMALL_TEST);
        let mut ctx = test_context();
        ctx.timestamp_ms = now;
        ctx.lattice_sub_token = Some(sub_token);
        ctx.capability_claims = vec!["*".into()];
        let outcome = CapabilityVerifyCheck.check(&ctx, &EnforcementConfig::default());

        assert_eq!(
            denial_reason_code(outcome).as_deref(),
            Some("LATTICE_VERIFIER_NOT_CONFIGURED")
        );
    }

    #[test]
    fn capability_verify_denies_forged_lattice_token_even_with_legacy_claim() {
        let (verifier, mut sub_token, _, _, _, now) =
            lattice_unit_fixture(pq::LatticeParams::SMALL_TEST);
        *sub_token
            .preimage_bytes
            .first_mut()
            .expect("fixture preimage must not be empty") ^= 0x01;
        let mut ctx = test_context();
        ctx.timestamp_ms = now;
        ctx.lattice_sub_token = Some(sub_token);
        ctx.capability_claims = vec!["*".into(), "messages.write".into()];
        let config = EnforcementConfig::new().with_lattice_delegation_verifier(verifier);

        assert_eq!(
            denial_reason_code(CapabilityVerifyCheck.check(&ctx, &config)).as_deref(),
            Some("LATTICE_VERIFICATION_EQUATION_FAILED")
        );
    }

    #[test]
    fn capability_verify_maps_lattice_operation_mismatch() {
        let (verifier, sub_token, _, _, _, now) =
            lattice_unit_fixture(pq::LatticeParams::SMALL_TEST);
        let mut ctx = test_context();
        ctx.timestamp_ms = now;
        ctx.operation = "list_channels".into();
        ctx.lattice_sub_token = Some(sub_token);
        let config = EnforcementConfig::new().with_lattice_delegation_verifier(verifier);

        assert_eq!(
            denial_reason_code(CapabilityVerifyCheck.check(&ctx, &config)).as_deref(),
            Some("LATTICE_OPERATION_MISMATCH")
        );
    }

    #[test]
    fn capability_verify_maps_lattice_principal_mismatch() {
        let (verifier, sub_token, _, _, _, now) =
            lattice_unit_fixture(pq::LatticeParams::SMALL_TEST);
        let mut ctx = test_context();
        ctx.timestamp_ms = now;
        ctx.principal = "agent-beta".into();
        ctx.lattice_sub_token = Some(sub_token);
        let config = EnforcementConfig::new().with_lattice_delegation_verifier(verifier);

        assert_eq!(
            denial_reason_code(CapabilityVerifyCheck.check(&ctx, &config)).as_deref(),
            Some("LATTICE_PRINCIPAL_MISMATCH")
        );
    }

    #[test]
    fn capability_verify_multiple_claims_one_match() {
        let mut ctx = test_context();
        ctx.capability_claims = vec!["unrelated".into(), "messages.write".into()];
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn capability_verify_exact_claim_does_not_authorize_other_capability() {
        let mut ctx = test_context();
        ctx.required_capability = Some("messages.read".into());
        ctx.capability_claims = vec!["messages.write".into()];
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    // ── CheckpointFreshnessCheck ──

    #[test]
    fn checkpoint_freshness_name() {
        assert_eq!(CheckpointFreshnessCheck.name(), "checkpoint_freshness");
    }

    #[test]
    fn checkpoint_freshness_allow_within_window() {
        let ctx = test_context();
        let config = EnforcementConfig::default();
        let outcome = CheckpointFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn checkpoint_freshness_skip_no_data() {
        let mut ctx = test_context();
        ctx.checkpoint_age_ms = None;
        let config = EnforcementConfig::default();
        let outcome = CheckpointFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_skip());
    }

    #[test]
    fn checkpoint_freshness_deny_stale() {
        let mut ctx = test_context();
        ctx.checkpoint_age_ms = Some(500_000);
        let config = EnforcementConfig::default();
        let outcome = CheckpointFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny {
            reason_code,
            explanation,
        } = &outcome
        {
            assert_eq!(reason_code, "CHECKPOINT_STALE");
            assert!(explanation.contains("500000"));
            assert!(explanation.contains("300000"));
        }
    }

    #[test]
    fn checkpoint_freshness_allow_at_boundary() {
        let mut ctx = test_context();
        ctx.checkpoint_age_ms = Some(300_000);
        let config = EnforcementConfig::default();
        let outcome = CheckpointFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn checkpoint_freshness_deny_just_over() {
        let mut ctx = test_context();
        ctx.checkpoint_age_ms = Some(300_001);
        let config = EnforcementConfig::default();
        let outcome = CheckpointFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn checkpoint_freshness_custom_threshold() {
        let mut ctx = test_context();
        ctx.checkpoint_age_ms = Some(50);
        let config = EnforcementConfig::new().with_checkpoint_max_age_ms(100);
        let outcome = CheckpointFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn checkpoint_freshness_zero_age() {
        let mut ctx = test_context();
        ctx.checkpoint_age_ms = Some(0);
        let config = EnforcementConfig::default();
        let outcome = CheckpointFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    // ── RevocationCheck freshness behavior ──

    #[test]
    fn revocation_freshness_name() {
        assert_eq!(RevocationCheck.name(), "revocation_freshness");
    }

    #[test]
    fn revocation_freshness_allow_within_window() {
        let ctx = test_context();
        let config = EnforcementConfig::default();
        let outcome = RevocationCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn revocation_freshness_skip_no_data() {
        let mut ctx = test_context();
        ctx.revocation_list_age_ms = None;
        let config = EnforcementConfig::default();
        let outcome = RevocationCheck.check(&ctx, &config);
        assert!(outcome.is_skip());
    }

    #[test]
    fn revocation_freshness_deny_stale() {
        let mut ctx = test_context();
        ctx.revocation_list_age_ms = Some(700_000);
        let config = EnforcementConfig::default();
        let outcome = RevocationCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "REVOCATION_LIST_STALE");
        }
    }

    #[test]
    fn revocation_freshness_allow_at_boundary() {
        let mut ctx = test_context();
        ctx.revocation_list_age_ms = Some(600_000);
        let config = EnforcementConfig::default();
        let outcome = RevocationCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn revocation_freshness_deny_just_over() {
        let mut ctx = test_context();
        ctx.revocation_list_age_ms = Some(600_001);
        let config = EnforcementConfig::default();
        let outcome = RevocationCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn revocation_freshness_custom_threshold() {
        let mut ctx = test_context();
        ctx.revocation_list_age_ms = Some(200);
        let config = EnforcementConfig::new().with_revocation_max_age_ms(500);
        let outcome = RevocationCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    // ── TaintApprovalCheck ──

    #[test]
    fn taint_approval_name() {
        assert_eq!(TaintApprovalCheck.name(), "taint_approval");
    }

    #[test]
    fn taint_approval_skip_no_flags() {
        let ctx = test_context();
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_skip());
    }

    #[test]
    fn taint_approval_allow_non_critical() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["public".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn taint_approval_allow_with_approval() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["pii".into()];
        ctx.approval_scopes = vec!["pii".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn taint_approval_deny_missing_approval() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["pii".into()];
        ctx.approval_scopes = Vec::new();
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny {
            reason_code,
            explanation,
        } = &outcome
        {
            assert_eq!(reason_code, "TAINT_APPROVAL_MISSING");
            assert!(explanation.contains("pii"));
        }
    }

    #[test]
    fn taint_approval_deny_wrong_approval() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["pii".into()];
        ctx.approval_scopes = vec!["phi".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn taint_approval_allow_multiple_flags_all_approved() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["pii".into(), "phi".into(), "financial".into()];
        ctx.approval_scopes = vec!["pii".into(), "phi".into(), "financial".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn taint_approval_deny_multiple_flags_one_missing() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["pii".into(), "phi".into()];
        ctx.approval_scopes = vec!["pii".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { explanation, .. } = &outcome {
            assert!(explanation.contains("phi"));
        }
    }

    #[test]
    fn taint_approval_custom_critical_flags() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["custom".into()];
        let config = EnforcementConfig::new().with_critical_taint_flags(vec!["custom".into()]);
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn taint_approval_mixed_critical_and_non_critical() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["public".into(), "pii".into()];
        ctx.approval_scopes = vec!["pii".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    // ── PolicyCeilingCheck ──

    #[test]
    fn policy_ceiling_name() {
        assert_eq!(PolicyCeilingCheck.name(), "policy_ceiling");
    }

    #[test]
    fn policy_ceiling_allow_no_restrictions() {
        let ctx = test_context();
        let config = EnforcementConfig::default();
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn policy_ceiling_allow_connector_permitted() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config
            .add_zone_connector("z:prod", "slack:utility:1.0.0")
            .unwrap();
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn policy_ceiling_deny_connector_not_allowed() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config
            .add_zone_connector("z:prod", "github:utility:1.0.0")
            .unwrap();
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "CONNECTOR_NOT_IN_ZONE_POLICY");
        }
    }

    #[test]
    fn policy_ceiling_allow_operation_permitted() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config.add_zone_operation("z:prod", "send_message").unwrap();
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn policy_ceiling_allow_connector_wildcard() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config.add_zone_connector("z:prod", "*").unwrap();
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn policy_ceiling_allow_operation_wildcard() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config
            .add_zone_connector("z:prod", "slack:utility:1.0.0")
            .unwrap();
        config.add_zone_operation("z:prod", "*").unwrap();
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn policy_ceiling_deny_operation_not_allowed() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config
            .add_zone_operation("z:prod", "list_channels")
            .unwrap();
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "OPERATION_NOT_IN_ZONE_POLICY");
        }
    }

    #[test]
    fn policy_ceiling_allow_both_permitted() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config
            .add_zone_connector("z:prod", "slack:utility:1.0.0")
            .unwrap();
        config.add_zone_operation("z:prod", "send_message").unwrap();
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn policy_ceiling_deny_connector_blocks_before_operation() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config
            .add_zone_connector("z:prod", "github:utility:1.0.0")
            .unwrap();
        config.add_zone_operation("z:prod", "send_message").unwrap();
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "CONNECTOR_NOT_IN_ZONE_POLICY");
        }
    }

    #[test]
    fn policy_ceiling_other_zone_rules_dont_affect() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config
            .add_zone_connector("z:staging", "github:utility:1.0.0")
            .unwrap();
        // z:prod has no rules, so allow.
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    // ── CapabilityConstraintsCheck ──

    #[test]
    fn capability_constraints_name() {
        assert_eq!(CapabilityConstraintsCheck.name(), "capability_constraints");
    }

    #[test]
    fn capability_constraints_skip_when_not_provided() {
        let ctx = test_context();
        let config = EnforcementConfig::default();
        let outcome = CapabilityConstraintsCheck.check(&ctx, &config);
        assert!(outcome.is_skip());
    }

    #[test]
    fn capability_constraints_deny_empty_constraint_set() {
        let mut ctx = test_context();
        ctx.capability_constraints = Some(CapabilityConstraints::default());
        ctx.constraint_object_id = Some(constraint_object_id());
        let config = EnforcementConfig::default();
        let outcome = CapabilityConstraintsCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny {
            reason_code,
            explanation,
        } = &outcome
        {
            assert_eq!(reason_code, "CAPABILITY_CONSTRAINT_DENIED");
            assert!(explanation.contains("default-deny"));
        }
    }

    #[test]
    fn capability_constraints_allow_matching_resource() {
        let mut ctx = test_context();
        ctx.capability_constraints = Some(CapabilityConstraints {
            resource_allow: vec!["/messages/*".into()],
            ..CapabilityConstraints::default()
        });
        ctx.constraint_object_id = Some(constraint_object_id());
        ctx.constraint_resource_uri = Some("/messages/123".into());
        let config = EnforcementConfig::default();
        let outcome = CapabilityConstraintsCheck.check(&ctx, &config);
        assert!(outcome.is_allow(), "got {outcome:?}");
    }

    #[test]
    fn capability_constraints_deny_resource_mismatch() {
        let mut ctx = test_context();
        ctx.capability_constraints = Some(CapabilityConstraints {
            resource_allow: vec!["/messages/*".into()],
            ..CapabilityConstraints::default()
        });
        ctx.constraint_object_id = Some(constraint_object_id());
        ctx.constraint_resource_uri = Some("/admin/keys".into());
        let config = EnforcementConfig::default();
        let outcome = CapabilityConstraintsCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "CAPABILITY_CONSTRAINT_DENIED");
        }
    }

    #[test]
    fn capability_constraint_denial_audit_descriptor_hash_is_redacted_and_stable()
    -> Result<(), String> {
        let mut ctx = test_context();
        let resource_uri = "/messages/secret-thread".to_string();
        let host = "api.example.com".to_string();
        ctx.constraint_resource_uri = Some(resource_uri.clone());
        ctx.constraint_host = Some(host.clone());
        ctx.constraint_observed_calls = 1;
        ctx.constraint_observed_bytes = 256;

        let descriptor = RequestDescriptor {
            object_id: constraint_object_id(),
            operation: parse_operation_id_for_check(&ctx.operation)
                .map_err(|outcome| format!("operation parse failed: {outcome:?}"))?,
            principal: PrincipalId::new(ctx.principal.as_str())
                .map_err(|err| format!("principal parse failed: {err}"))?,
            host,
            resource_uri,
            requested_at_unix_ms: ctx.timestamp_ms,
            observed_calls: ctx.constraint_observed_calls,
            observed_bytes: ctx.constraint_observed_bytes,
        };
        let audit_descriptor = capability_constraint_audit_descriptor(
            ctx.request_id.as_str(),
            ctx.connector_id.as_str(),
            ctx.operation.as_str(),
            ctx.zone_id.as_str(),
            &descriptor,
        );

        let first = capability_constraint_descriptor_hash(&audit_descriptor)?;
        let second = capability_constraint_descriptor_hash(&audit_descriptor)?;
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(first.chars().all(|ch| ch.is_ascii_hexdigit()));

        let serialized = serde_json::to_string(&audit_descriptor).map_err(|err| err.to_string())?;
        assert!(!serialized.contains("raw_payload"));
        assert!(!serialized.contains("secret payload body"));
        Ok(())
    }

    #[test]
    fn capability_constraints_deny_missing_request_descriptor() {
        let mut ctx = test_context();
        ctx.capability_constraints = Some(CapabilityConstraints {
            resource_allow: vec!["/messages/*".into()],
            ..CapabilityConstraints::default()
        });
        let config = EnforcementConfig::default();
        let outcome = CapabilityConstraintsCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "CONSTRAINT_REQUEST_DESCRIPTOR_INCOMPLETE");
        }
    }

    // ── ConnectorManifestCheck ──

    #[test]
    fn connector_manifest_name() {
        assert_eq!(ConnectorManifestCheck.name(), "connector_manifest");
    }

    #[test]
    fn connector_manifest_allow_in_list() {
        let ctx = test_context();
        let config = EnforcementConfig::default();
        let outcome = ConnectorManifestCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn connector_manifest_skip_no_manifest() {
        let mut ctx = test_context();
        ctx.manifest_allowed_operations = Vec::new();
        let config = EnforcementConfig::default();
        let outcome = ConnectorManifestCheck.check(&ctx, &config);
        assert!(outcome.is_skip());
    }

    #[test]
    fn connector_manifest_deny_not_in_list() {
        let mut ctx = test_context();
        ctx.operation = "delete_channel".into();
        let config = EnforcementConfig::default();
        let outcome = ConnectorManifestCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny {
            reason_code,
            explanation,
        } = &outcome
        {
            assert_eq!(reason_code, "OPERATION_NOT_IN_MANIFEST");
            assert!(explanation.contains("delete_channel"));
        }
    }

    #[test]
    fn connector_manifest_allow_second_op() {
        let mut ctx = test_context();
        ctx.operation = "list_channels".into();
        ctx.required_capability = Some("channels.read".into());
        ctx.capability_claims = vec!["channels.read".into()];
        let config = EnforcementConfig::default();
        // test_context has both send_message and list_channels.
        let outcome = ConnectorManifestCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    // ── BudgetCheck ──

    #[test]
    fn budget_name() {
        assert_eq!(BudgetCheck.name(), "budget");
    }

    #[test]
    fn budget_allow_under_limit() {
        let ctx = test_context();
        let config = EnforcementConfig::default();
        let outcome = BudgetCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn budget_skip_no_used() {
        let mut ctx = test_context();
        ctx.budget_used = None;
        let config = EnforcementConfig::default();
        let outcome = BudgetCheck.check(&ctx, &config);
        assert!(outcome.is_skip());
    }

    #[test]
    fn budget_skip_no_limit() {
        let mut ctx = test_context();
        ctx.budget_limit = None;
        let config = EnforcementConfig::default();
        let outcome = BudgetCheck.check(&ctx, &config);
        assert!(outcome.is_skip());
    }

    #[test]
    fn budget_allow_at_limit() {
        let mut ctx = test_context();
        ctx.budget_used = Some(1000);
        ctx.budget_limit = Some(1000);
        let config = EnforcementConfig::default();
        let outcome = BudgetCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn budget_deny_over_limit() {
        let mut ctx = test_context();
        ctx.budget_used = Some(1500);
        ctx.budget_limit = Some(1000);
        let config = EnforcementConfig::default();
        let outcome = BudgetCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn budget_allow_zero_used() {
        let mut ctx = test_context();
        ctx.budget_used = Some(0);
        ctx.budget_limit = Some(1000);
        let config = EnforcementConfig::default();
        let outcome = BudgetCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn budget_deny_explanation_includes_numbers() {
        let mut ctx = test_context();
        ctx.budget_used = Some(51);
        ctx.budget_limit = Some(50);
        let config = EnforcementConfig::default();
        let outcome = BudgetCheck.check(&ctx, &config);
        if let CheckOutcome::Deny { explanation, .. } = &outcome {
            assert!(explanation.contains("50"));
        }
    }

    #[test]
    fn budget_check_matches_budget_tracker_at_limit_semantics() {
        let zone = fcp_policy::ZoneId::work();
        let policy = fcp_kernel::UsageBudgetPolicy {
            enforcement: fcp_kernel::BudgetEnforcement::Deny,
            budgets: vec![fcp_kernel::UsageBudgetLimit {
                metric: fcp_kernel::UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };
        let mut tracker = crate::budget::BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[fcp_kernel::UsageMetric::tokens(100)]);
        assert_eq!(eval.action, crate::budget::BudgetAction::Allow);

        let mut ctx = test_context();
        ctx.budget_used = Some(eval.snapshot.budgets[0].used);
        ctx.budget_limit = Some(eval.snapshot.budgets[0].limit);
        let outcome = BudgetCheck.check(&ctx, &EnforcementConfig::default());
        assert!(
            outcome.is_allow(),
            "budget enforcement must agree with budget tracker exact-limit semantics"
        );
    }

    // ── RateLimitCheck ──

    #[test]
    fn rate_limit_name() {
        assert_eq!(RateLimitCheck.name(), "rate_limit");
    }

    #[test]
    fn rate_limit_allow_under_limit() {
        let ctx = test_context();
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn rate_limit_skip_no_count() {
        let mut ctx = test_context();
        ctx.rate_count = None;
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_skip());
    }

    #[test]
    fn rate_limit_skip_no_limit() {
        let mut ctx = test_context();
        ctx.rate_limit = None;
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_skip());
    }

    #[test]
    fn rate_limit_deny_at_limit() {
        let mut ctx = test_context();
        ctx.rate_count = Some(100);
        ctx.rate_limit = Some(100);
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "RATE_LIMIT_EXCEEDED");
        }
    }

    #[test]
    fn rate_limit_deny_over_limit() {
        let mut ctx = test_context();
        ctx.rate_count = Some(150);
        ctx.rate_limit = Some(100);
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn rate_limit_allow_just_under() {
        let mut ctx = test_context();
        ctx.rate_count = Some(99);
        ctx.rate_limit = Some(100);
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn rate_limit_allow_zero_count() {
        let mut ctx = test_context();
        ctx.rate_count = Some(0);
        ctx.rate_limit = Some(100);
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn rate_limit_deny_explanation_includes_numbers() {
        let mut ctx = test_context();
        ctx.rate_count = Some(50);
        ctx.rate_limit = Some(50);
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        if let CheckOutcome::Deny { explanation, .. } = &outcome {
            assert!(explanation.contains("50"));
        }
    }

    // ── EnforcementPipeline ──

    #[test]
    fn pipeline_default_has_canonical_checks() {
        let pipeline = EnforcementPipeline::new();
        assert_eq!(pipeline.check_count(), EnforcementCheckOrder::COUNT);
    }

    #[test]
    fn pipeline_default_check_order() {
        let pipeline = EnforcementPipeline::new();
        let names = pipeline.check_names();
        let canonical: Vec<&str> = EnforcementCheckOrder::canonical_order()
            .iter()
            .map(EnforcementCheckId::as_str)
            .collect();
        assert_eq!(names, canonical);
    }

    #[test]
    fn pipeline_with_checks_custom_count() {
        let pipeline = EnforcementPipeline::with_checks(vec![
            Box::new(CanonicalDecodeCheck),
            Box::new(RateLimitCheck),
        ]);
        assert_eq!(pipeline.check_count(), 2);
    }

    #[test]
    fn pipeline_empty() {
        let pipeline = EnforcementPipeline::with_checks(vec![]);
        assert_eq!(pipeline.check_count(), 0);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.is_allowed());
        assert_eq!(decision.checks_executed(), 0);
    }

    #[test]
    fn pipeline_evaluate_full_allow() {
        let pipeline = EnforcementPipeline::new();
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.is_allowed());
        assert!(decision.elapsed_ms >= 0.0);
        assert_eq!(decision.checks_executed(), EnforcementCheckOrder::COUNT);
    }

    #[test]
    fn pipeline_evaluate_deny_at_canonical_decode() {
        let pipeline = EnforcementPipeline::new();
        let mut ctx = test_context();
        ctx.connector_id = String::new();
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        assert_eq!(decision.checks_executed(), 1);
        if let PipelineOutcome::Deny {
            check_name,
            reason_code,
            ..
        } = &decision.outcome
        {
            assert_eq!(check_name, "canonical_decode");
            assert_eq!(reason_code, "MISSING_CONNECTOR_ID");
        }
    }

    #[test]
    fn pipeline_evaluate_deny_at_capability_verify() {
        let config = EnforcementConfig::default();
        let pipeline = EnforcementPipeline::with_config(config);
        let mut ctx = test_context();
        ctx.capability_claims = Vec::new();
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        if let PipelineOutcome::Deny { check_name, .. } = &decision.outcome {
            assert_eq!(check_name, "capability_verify");
        }
    }

    #[test]
    fn pipeline_evaluate_deny_when_required_capability_missing() {
        let pipeline = EnforcementPipeline::new();
        let mut ctx = test_context();
        ctx.required_capability = None;
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        if let PipelineOutcome::Deny {
            check_name,
            reason_code,
            ..
        } = &decision.outcome
        {
            assert_eq!(check_name, "capability_verify");
            assert_eq!(reason_code, "MISSING_REQUIRED_CAPABILITY");
        }
    }

    #[test]
    fn pipeline_evaluate_deny_at_holder_proof() {
        let pipeline = EnforcementPipeline::new();
        let mut ctx = test_context();
        ctx.holder_verified = false;
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        if let PipelineOutcome::Deny {
            check_name,
            reason_code,
            ..
        } = &decision.outcome
        {
            assert_eq!(check_name, "holder_proof");
            assert_eq!(reason_code, "HOLDER_PROOF_NOT_VERIFIED");
        }
    }

    #[test]
    fn pipeline_evaluate_deny_at_checkpoint_freshness() {
        let pipeline = EnforcementPipeline::new();
        let mut ctx = test_context();
        ctx.checkpoint_age_ms = Some(999_999);
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        if let PipelineOutcome::Deny { check_name, .. } = &decision.outcome {
            assert_eq!(check_name, "checkpoint_freshness");
        }
    }

    #[test]
    fn pipeline_evaluate_deny_at_revocation_freshness() {
        let pipeline = EnforcementPipeline::new();
        let mut ctx = test_context();
        ctx.revocation_list_age_ms = Some(999_999);
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        if let PipelineOutcome::Deny { check_name, .. } = &decision.outcome {
            assert_eq!(check_name, "revocation_freshness");
        }
    }

    #[test]
    fn pipeline_evaluate_deny_at_taint_approval() {
        let pipeline = EnforcementPipeline::new();
        let mut ctx = test_context();
        ctx.taint_flags = vec!["pii".into()];
        // no approval scopes.
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        if let PipelineOutcome::Deny { check_name, .. } = &decision.outcome {
            assert_eq!(check_name, "taint_approval");
        }
    }

    #[test]
    fn pipeline_evaluate_deny_at_policy_ceiling() {
        let mut config = EnforcementConfig::default();
        config
            .add_zone_connector("z:prod", "github:utility:1.0.0")
            .unwrap();
        let pipeline = EnforcementPipeline::with_config(config);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        if let PipelineOutcome::Deny { check_name, .. } = &decision.outcome {
            assert_eq!(check_name, "policy_ceiling");
        }
    }

    #[test]
    fn pipeline_evaluate_deny_at_capability_constraints() {
        let pipeline = EnforcementPipeline::new();
        let mut ctx = test_context();
        ctx.capability_constraints = Some(CapabilityConstraints::default());
        ctx.constraint_object_id = Some(constraint_object_id());
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        if let PipelineOutcome::Deny {
            check_name,
            reason_code,
            ..
        } = &decision.outcome
        {
            assert_eq!(check_name, "capability_constraints");
            assert_eq!(reason_code, "CAPABILITY_CONSTRAINT_DENIED");
        }
    }

    #[test]
    fn pipeline_evaluate_deny_at_connector_manifest() {
        let pipeline = EnforcementPipeline::new();
        let mut ctx = test_context();
        ctx.operation = "nonexistent_op".into();
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        if let PipelineOutcome::Deny { check_name, .. } = &decision.outcome {
            assert_eq!(check_name, "connector_manifest");
        }
    }

    #[test]
    fn pipeline_evaluate_deny_at_budget() {
        let pipeline = EnforcementPipeline::new();
        let mut ctx = test_context();
        // Commit 53323189 changed BudgetCheck to Allow at exact equality
        // (used == limit is the closing request, matching BudgetTracker).
        // Use used > limit so this test keeps exercising the Deny branch.
        ctx.budget_used = Some(1001);
        ctx.budget_limit = Some(1000);
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        if let PipelineOutcome::Deny { check_name, .. } = &decision.outcome {
            assert_eq!(check_name, "budget");
        }
    }

    #[test]
    fn pipeline_evaluate_deny_at_rate_limit() {
        let pipeline = EnforcementPipeline::new();
        let mut ctx = test_context();
        ctx.rate_count = Some(200);
        ctx.rate_limit = Some(100);
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        if let PipelineOutcome::Deny { check_name, .. } = &decision.outcome {
            assert_eq!(check_name, "rate_limit");
        }
    }

    #[test]
    fn pipeline_deny_budget_before_rate_limit() {
        let pipeline = EnforcementPipeline::new();
        let mut ctx = test_context();
        // Both checks must be in the Deny branch to validate ordering.
        // Budget at exact equality is now Allow (commit 53323189), so push
        // both budget and rate strictly over their limits.
        ctx.budget_used = Some(1001);
        ctx.budget_limit = Some(1000);
        ctx.rate_count = Some(101);
        ctx.rate_limit = Some(100);
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        assert_eq!(
            decision.checks_executed(),
            EnforcementCheckOrder::index_of(EnforcementCheckId::Budget) + 1
        );
        if let PipelineOutcome::Deny {
            check_name,
            reason_code,
            ..
        } = &decision.outcome
        {
            assert_eq!(check_name, "budget");
            assert_eq!(reason_code, "BUDGET_EXCEEDED");
        }
    }

    #[test]
    fn pipeline_constraints_run_after_policy_before_manifest_and_budget() {
        let pipeline = EnforcementPipeline::new();
        let names = pipeline.check_names();
        let constraints = names
            .iter()
            .position(|name| *name == "capability_constraints")
            .expect("constraints check present");
        let policy = names
            .iter()
            .position(|name| *name == "policy_ceiling")
            .expect("policy check present");
        let manifest = names
            .iter()
            .position(|name| *name == "connector_manifest")
            .expect("manifest check present");
        let budget = names
            .iter()
            .position(|name| *name == "budget")
            .expect("budget check present");
        assert!(policy < constraints);
        assert!(constraints < manifest);
        assert!(constraints < budget);
    }

    #[test]
    fn pipeline_skips_are_tracked() {
        let pipeline = EnforcementPipeline::new();
        let ctx = test_context();
        // zone_membership and taint_approval will skip with default config.
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.skip_count() >= 2);
    }

    #[test]
    fn pipeline_allow_count() {
        let pipeline = EnforcementPipeline::new();
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.allow_count() > 0);
        assert_eq!(
            decision.allow_count() + decision.skip_count(),
            decision.checks_executed()
        );
    }

    #[test]
    fn pipeline_elapsed_non_negative() {
        let pipeline = EnforcementPipeline::new();
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.elapsed_ms >= 0.0);
        for record in &decision.checks_run {
            assert!(record.elapsed_ms >= 0.0);
        }
    }

    #[test]
    fn pipeline_check_records_have_names() {
        let pipeline = EnforcementPipeline::new();
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        for record in &decision.checks_run {
            assert!(!record.name.is_empty());
        }
    }

    #[test]
    fn pipeline_with_config() {
        let config = EnforcementConfig::new().with_checkpoint_max_age_ms(100);
        let pipeline = EnforcementPipeline::with_config(config);
        assert_eq!(pipeline.config().checkpoint_max_age_ms, 100);
        assert_eq!(pipeline.check_count(), EnforcementCheckOrder::COUNT);
    }

    #[test]
    fn pipeline_with_checks_and_config() {
        let config = EnforcementConfig::new().with_checkpoint_max_age_ms(50);
        let pipeline = EnforcementPipeline::with_checks_and_config(
            vec![Box::new(CanonicalDecodeCheck)],
            config,
        );
        assert_eq!(pipeline.check_count(), 1);
        assert_eq!(pipeline.config().checkpoint_max_age_ms, 50);
    }

    #[test]
    fn pipeline_debug_format() {
        let pipeline = EnforcementPipeline::new();
        let debug = format!("{pipeline:?}");
        assert!(debug.contains("EnforcementPipeline"));
        assert!(debug.contains("check_count"));
    }

    #[test]
    fn pipeline_default_trait() {
        let pipeline = EnforcementPipeline::default();
        assert_eq!(pipeline.check_count(), EnforcementCheckOrder::COUNT);
    }

    // ── Custom check implementation ──

    struct AlwaysAllowCheck;
    impl EnforcementCheck for AlwaysAllowCheck {
        fn name(&self) -> &'static str {
            "always_allow"
        }
        fn check(&self, _ctx: &EnforcementContext, _config: &EnforcementConfig) -> CheckOutcome {
            CheckOutcome::Allow
        }
    }

    struct AlwaysDenyCheck {
        code: String,
    }
    impl EnforcementCheck for AlwaysDenyCheck {
        fn name(&self) -> &'static str {
            "always_deny"
        }
        fn check(&self, _ctx: &EnforcementContext, _config: &EnforcementConfig) -> CheckOutcome {
            CheckOutcome::Deny {
                reason_code: self.code.clone(),
                explanation: "always denied".into(),
            }
        }
    }

    struct AlwaysSkipCheck;
    impl EnforcementCheck for AlwaysSkipCheck {
        fn name(&self) -> &'static str {
            "always_skip"
        }
        fn check(&self, _ctx: &EnforcementContext, _config: &EnforcementConfig) -> CheckOutcome {
            CheckOutcome::Skip {
                reason: "always skipped".into(),
            }
        }
    }

    #[test]
    fn custom_check_all_allow() {
        let pipeline = EnforcementPipeline::with_checks(vec![
            Box::new(AlwaysAllowCheck),
            Box::new(AlwaysAllowCheck),
        ]);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.is_allowed());
        assert_eq!(decision.checks_executed(), 2);
    }

    #[test]
    fn custom_check_deny_stops_pipeline() {
        let pipeline = EnforcementPipeline::with_checks(vec![
            Box::new(AlwaysAllowCheck),
            Box::new(AlwaysDenyCheck {
                code: "CUSTOM".into(),
            }),
            Box::new(AlwaysAllowCheck),
        ]);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        assert_eq!(decision.checks_executed(), 2);
        if let PipelineOutcome::Deny {
            check_name,
            reason_code,
            ..
        } = &decision.outcome
        {
            assert_eq!(check_name, "always_deny");
            assert_eq!(reason_code, "CUSTOM");
        }
    }

    #[test]
    fn custom_check_skip_does_not_block() {
        let pipeline = EnforcementPipeline::with_checks(vec![
            Box::new(AlwaysSkipCheck),
            Box::new(AlwaysAllowCheck),
        ]);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.is_allowed());
        assert_eq!(decision.skip_count(), 1);
        assert_eq!(decision.allow_count(), 1);
    }

    #[test]
    fn custom_check_all_skip() {
        let pipeline = EnforcementPipeline::with_checks(vec![
            Box::new(AlwaysSkipCheck),
            Box::new(AlwaysSkipCheck),
            Box::new(AlwaysSkipCheck),
        ]);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.is_allowed());
        assert_eq!(decision.skip_count(), 3);
        assert_eq!(decision.allow_count(), 0);
    }

    #[test]
    fn custom_check_first_deny_recorded() {
        let pipeline = EnforcementPipeline::with_checks(vec![
            Box::new(AlwaysDenyCheck {
                code: "FIRST".into(),
            }),
            Box::new(AlwaysDenyCheck {
                code: "SECOND".into(),
            }),
        ]);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert_eq!(decision.checks_executed(), 1);
        if let PipelineOutcome::Deny { reason_code, .. } = &decision.outcome {
            assert_eq!(reason_code, "FIRST");
        }
    }

    // ── EnforcementDecision ──

    #[test]
    fn decision_is_allowed_true() {
        let decision = EnforcementDecision {
            outcome: PipelineOutcome::Allow,
            checks_run: vec![],
            elapsed_ms: 0.0,
        };
        assert!(decision.is_allowed());
    }

    #[test]
    fn decision_is_allowed_false() {
        let decision = EnforcementDecision {
            outcome: PipelineOutcome::Deny {
                check_name: "x".into(),
                reason_code: "y".into(),
                explanation: "z".into(),
            },
            checks_run: vec![],
            elapsed_ms: 0.0,
        };
        assert!(!decision.is_allowed());
    }

    #[test]
    fn decision_checks_executed_count() {
        let decision = EnforcementDecision {
            outcome: PipelineOutcome::Allow,
            checks_run: vec![
                CheckRecord {
                    name: "a".into(),
                    outcome: CheckOutcome::Allow,
                    elapsed_ms: 0.1,
                },
                CheckRecord {
                    name: "b".into(),
                    outcome: CheckOutcome::Allow,
                    elapsed_ms: 0.2,
                },
            ],
            elapsed_ms: 0.3,
        };
        assert_eq!(decision.checks_executed(), 2);
    }

    #[test]
    fn decision_allow_and_skip_counts() {
        let decision = EnforcementDecision {
            outcome: PipelineOutcome::Allow,
            checks_run: vec![
                CheckRecord {
                    name: "a".into(),
                    outcome: CheckOutcome::Allow,
                    elapsed_ms: 0.0,
                },
                CheckRecord {
                    name: "b".into(),
                    outcome: CheckOutcome::Skip {
                        reason: "n/a".into(),
                    },
                    elapsed_ms: 0.0,
                },
                CheckRecord {
                    name: "c".into(),
                    outcome: CheckOutcome::Allow,
                    elapsed_ms: 0.0,
                },
            ],
            elapsed_ms: 0.0,
        };
        assert_eq!(decision.allow_count(), 2);
        assert_eq!(decision.skip_count(), 1);
    }

    #[test]
    fn decision_reports_named_check_and_overhead_timings() {
        let decision = EnforcementDecision {
            outcome: PipelineOutcome::Allow,
            checks_run: vec![
                CheckRecord {
                    name: "canonical_decode".into(),
                    outcome: CheckOutcome::Allow,
                    elapsed_ms: 0.25,
                },
                CheckRecord {
                    name: "capability_verify".into(),
                    outcome: CheckOutcome::Allow,
                    elapsed_ms: 2.5,
                },
            ],
            elapsed_ms: 3.0,
        };

        assert_eq!(decision.check_elapsed_ms("capability_verify"), Some(2.5));
        assert_eq!(decision.check_elapsed_ms("missing_check"), None);
        assert!((decision.check_elapsed_total_ms() - 2.75).abs() < f64::EPSILON);
        assert!((decision.non_check_overhead_ms() - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn decision_overhead_never_goes_negative_when_clocks_round() {
        let decision = EnforcementDecision {
            outcome: PipelineOutcome::Allow,
            checks_run: vec![CheckRecord {
                name: "capability_verify".into(),
                outcome: CheckOutcome::Allow,
                elapsed_ms: 1.1,
            }],
            elapsed_ms: 1.0,
        };

        assert!(decision.non_check_overhead_ms() <= f64::EPSILON);
    }

    #[test]
    fn decision_debug_format() {
        let decision = EnforcementDecision {
            outcome: PipelineOutcome::Allow,
            checks_run: vec![],
            elapsed_ms: 1.5,
        };
        let debug = format!("{decision:?}");
        assert!(debug.contains("Allow"));
        assert!(debug.contains("1.5"));
    }

    // ── Context clone and debug ──

    #[test]
    fn context_clone() {
        let ctx = test_context();
        let cloned = ctx.clone();
        assert_eq!(ctx.request_id, cloned.request_id);
        assert_eq!(ctx.connector_id, cloned.connector_id);
        assert_eq!(ctx.operation, cloned.operation);
    }

    #[test]
    fn context_debug() {
        let ctx = test_context();
        let debug = format!("{ctx:?}");
        assert!(debug.contains("EnforcementContext"));
        assert!(debug.contains("req-001"));
    }

    // ── Edge cases ──

    #[test]
    fn zone_membership_check_with_many_zones() {
        let mut ctx = test_context();
        ctx.zone_id = "z:zone-99".into();
        let mut config = EnforcementConfig::default();
        for i in 0..100 {
            config
                .add_zone_membership("agent-alpha", &format!("z:zone-{i}"))
                .unwrap();
        }
        let outcome = ZoneMembershipCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn capability_verify_many_claims() {
        let mut ctx = test_context();
        ctx.capability_claims = (0..50).map(|i| format!("cap_{i}")).collect();
        ctx.required_capability = Some("cap_25".into());
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn rate_limit_zero_limit() {
        let mut ctx = test_context();
        ctx.rate_count = Some(0);
        ctx.rate_limit = Some(0);
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn taint_approval_empty_critical_flags_config() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["pii".into()];
        let config = EnforcementConfig::new().with_critical_taint_flags(vec![]);
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        // No critical flags configured, so all taints are non-critical → allow.
        assert!(outcome.is_allow());
    }

    #[test]
    fn policy_ceiling_multiple_connectors_in_zone() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config
            .add_zone_connector("z:prod", "github:utility:1.0.0")
            .unwrap();
        config
            .add_zone_connector("z:prod", "slack:utility:1.0.0")
            .unwrap();
        config
            .add_zone_connector("z:prod", "jira:utility:1.0.0")
            .unwrap();
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn connector_manifest_single_op_match() {
        let mut ctx = test_context();
        ctx.manifest_allowed_operations = vec!["send_message".into()];
        let config = EnforcementConfig::default();
        let outcome = ConnectorManifestCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn connector_manifest_single_op_no_match() {
        let mut ctx = test_context();
        ctx.manifest_allowed_operations = vec!["other_op".into()];
        let config = EnforcementConfig::default();
        let outcome = ConnectorManifestCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn pipeline_short_circuits_preserves_timing() {
        let pipeline = EnforcementPipeline::new();
        let mut ctx = test_context();
        ctx.connector_id = String::new();
        let decision = pipeline.evaluate(&ctx);
        // Only ran one check.
        assert_eq!(decision.checks_executed(), 1);
        assert!(decision.checks_run[0].elapsed_ms >= 0.0);
        assert!(decision.elapsed_ms >= 0.0);
    }

    #[test]
    fn check_record_debug() {
        let record = CheckRecord {
            name: "test_check".into(),
            outcome: CheckOutcome::Allow,
            elapsed_ms: 0.42,
        };
        let debug = format!("{record:?}");
        assert!(debug.contains("test_check"));
        assert!(debug.contains("0.42"));
    }

    #[test]
    fn canonical_decode_checks_order_connector_first() {
        // When multiple fields are empty, connector_id is checked first.
        let mut ctx = test_context();
        ctx.connector_id = String::new();
        ctx.operation = String::new();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_CONNECTOR_ID");
        }
    }

    #[test]
    fn pipeline_zone_membership_configured_allow_passes_through() {
        let mut config = EnforcementConfig::default();
        config.add_zone_membership("agent-alpha", "z:prod").unwrap();
        config
            .add_zone_connector("z:prod", "slack:utility:1.0.0")
            .unwrap();
        config.add_zone_operation("z:prod", "send_message").unwrap();
        let pipeline = EnforcementPipeline::with_config(config);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.is_allowed());
    }

    #[test]
    fn pipeline_fully_configured_deny_zone_membership() {
        let mut config = EnforcementConfig::default();
        config
            .add_zone_membership("agent-alpha", "z:staging")
            .unwrap();
        let pipeline = EnforcementPipeline::with_config(config);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        if let PipelineOutcome::Deny { check_name, .. } = &decision.outcome {
            assert_eq!(check_name, "zone_membership");
        }
    }

    #[test]
    fn check_names_returns_correct_order() {
        let pipeline = EnforcementPipeline::with_checks(vec![
            Box::new(RateLimitCheck),
            Box::new(CanonicalDecodeCheck),
        ]);
        let names = pipeline.check_names();
        assert_eq!(names, vec!["rate_limit", "canonical_decode"]);
    }

    #[test]
    fn enforcement_decision_clone() {
        let decision = EnforcementDecision {
            outcome: PipelineOutcome::Allow,
            checks_run: vec![CheckRecord {
                name: "a".into(),
                outcome: CheckOutcome::Allow,
                elapsed_ms: 0.1,
            }],
            elapsed_ms: 0.1,
        };
        let cloned = decision.clone();
        assert!(decision.is_allowed());
        assert!(cloned.is_allowed());
        assert_eq!(cloned.checks_executed(), 1);
    }

    #[test]
    fn capability_verify_wildcard_with_other_claims() {
        let mut ctx = test_context();
        ctx.capability_claims = vec!["unrelated".into(), "*".into()];
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn taint_approval_duplicate_flags() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["pii".into(), "pii".into()];
        ctx.approval_scopes = vec!["pii".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    // ── Additional edge-case and boundary tests ──

    // ── Config builder chaining ──

    #[test]
    fn config_builder_chained_all_setters() {
        let config = EnforcementConfig::new()
            .with_checkpoint_max_age_ms(111)
            .with_revocation_max_age_ms(222)
            .with_critical_taint_flags(vec!["secret".into()]);
        assert_eq!(config.checkpoint_max_age_ms, 111);
        assert_eq!(config.revocation_max_age_ms, 222);
        assert_eq!(config.critical_taint_flags, vec!["secret"]);
    }

    #[test]
    fn config_zero_thresholds() {
        let config = EnforcementConfig::new()
            .with_checkpoint_max_age_ms(0)
            .with_revocation_max_age_ms(0);
        assert_eq!(config.checkpoint_max_age_ms, 0);
        assert_eq!(config.revocation_max_age_ms, 0);
    }

    #[test]
    fn config_max_u64_thresholds() {
        let config = EnforcementConfig::new()
            .with_checkpoint_max_age_ms(u64::MAX)
            .with_revocation_max_age_ms(u64::MAX);
        assert_eq!(config.checkpoint_max_age_ms, u64::MAX);
        assert_eq!(config.revocation_max_age_ms, u64::MAX);
    }

    #[test]
    fn config_add_duplicate_zone_membership_is_idempotent() {
        let mut config = EnforcementConfig::new();
        config.add_zone_membership("alice", "z:zone-a").unwrap();
        config.add_zone_membership("alice", "z:zone-a").unwrap();
        let zones = config.zone_memberships.get("alice").unwrap();
        assert_eq!(zones.len(), 1);
    }

    #[test]
    fn config_add_duplicate_zone_connector_is_idempotent() {
        let mut config = EnforcementConfig::new();
        config
            .add_zone_connector("z:zone-a", "slack:utility:1.0.0")
            .unwrap();
        config
            .add_zone_connector("z:zone-a", "slack:utility:1.0.0")
            .unwrap();
        let connectors = config
            .zone_allowed_connectors
            .get(&"z:zone-a".parse::<ZoneId>().unwrap())
            .unwrap();
        assert_eq!(connectors.len(), 1);
    }

    #[test]
    fn config_add_duplicate_zone_operation_is_idempotent() {
        let mut config = EnforcementConfig::new();
        config.add_zone_operation("z:zone-a", "read").unwrap();
        config.add_zone_operation("z:zone-a", "read").unwrap();
        let ops = config
            .zone_allowed_operations
            .get(&"z:zone-a".parse::<ZoneId>().unwrap())
            .unwrap();
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn config_default_has_all_four_critical_flags() {
        let config = EnforcementConfig::default();
        assert!(config.critical_taint_flags.contains(&"pii".to_string()));
        assert!(config.critical_taint_flags.contains(&"phi".to_string()));
        assert!(
            config
                .critical_taint_flags
                .contains(&"classified".to_string())
        );
        assert!(
            config
                .critical_taint_flags
                .contains(&"financial".to_string())
        );
        assert_eq!(config.critical_taint_flags.len(), 4);
    }

    // ── Builder edge cases ──

    #[test]
    fn builder_empty_build_returns_none() {
        let ctx = EnforcementContextBuilder::new().build();
        assert!(ctx.is_none());
    }

    #[test]
    fn builder_debug_format() {
        let builder = EnforcementContextBuilder::new().request_id("r1");
        let debug = format!("{builder:?}");
        assert!(debug.contains("EnforcementContextBuilder"));
        assert!(debug.contains("r1"));
    }

    #[test]
    fn builder_empty_strings_still_build() {
        // Builder accepts empty strings — canonical_decode catches them later
        let ctx = EnforcementContextBuilder::new()
            .request_id("")
            .connector_id("")
            .operation("")
            .zone_id("")
            .principal("")
            .build();
        assert!(ctx.is_some());
        let ctx = ctx.unwrap();
        assert!(ctx.request_id.is_empty());
    }

    #[test]
    fn revocation_check_denies_revoked_token() {
        let mut registry = RevocationRegistry::new();
        let token_id = ObjectId::from_bytes([0xAA; 32]);
        let revocation = fcp_core::RevocationObject {
            header: fcp_core::ObjectHeader {
                zone_id: ZoneId::work(),
                schema: SchemaId::new(
                    "fcp.core",
                    "RevocationObject",
                    semver::Version::new(1, 0, 0),
                ),
                created_at: 1_700_000_000,
                provenance: fcp_core::Provenance::new(ZoneId::work()),
                refs: Vec::new(),
                foreign_refs: Vec::new(),
                ttl_secs: None,
                placement: None,
            },
            scope: fcp_core::RevocationScope::Capability,
            revoked: vec![token_id],
            effective_at: 1000,
            expires_at: None,
            reason: "test".into(),
            signature: [0u8; 64],
        };
        registry.add_revocation(&revocation);

        let config = EnforcementConfig::default().with_revocation_registry(Arc::new(registry));

        let mut ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .revocation_list_age_ms(100)
            .build()
            .unwrap();
        ctx.token_id = Some(token_id);

        let check = RevocationCheck;
        let outcome = check.check(&ctx, &config);

        if let CheckOutcome::Deny { reason_code, .. } = outcome {
            assert_eq!(reason_code, "CAPABILITY_REVOKED");
        } else {
            panic!("Expected denial for revoked token, got {outcome:?}");
        }
    }

    #[test]
    fn revocation_check_denies_revoked_token_even_when_freshness_unknown() {
        // Regression: a revoked token in a configured registry must be denied
        // even when `revocation_list_age_ms` is absent. The old code
        // short-circuited to Skip on missing freshness BEFORE consulting
        // is_revoked, silently bypassing exact-membership revocation.
        let mut registry = RevocationRegistry::new();
        let token_id = ObjectId::from_bytes([0xAA; 32]);
        let revocation = fcp_core::RevocationObject {
            header: fcp_core::ObjectHeader {
                zone_id: ZoneId::work(),
                schema: SchemaId::new(
                    "fcp.core",
                    "RevocationObject",
                    semver::Version::new(1, 0, 0),
                ),
                created_at: 1_700_000_000,
                provenance: fcp_core::Provenance::new(ZoneId::work()),
                refs: Vec::new(),
                foreign_refs: Vec::new(),
                ttl_secs: None,
                placement: None,
            },
            scope: fcp_core::RevocationScope::Capability,
            revoked: vec![token_id],
            effective_at: 1000,
            expires_at: None,
            reason: "test".into(),
            signature: [0u8; 64],
        };
        registry.add_revocation(&revocation);

        let config = EnforcementConfig::default().with_revocation_registry(Arc::new(registry));

        // No revocation_list_age_ms → freshness unknown.
        let mut ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .build()
            .unwrap();
        assert!(ctx.revocation_list_age_ms.is_none());
        ctx.token_id = Some(token_id);

        let outcome = RevocationCheck.check(&ctx, &config);
        assert!(
            outcome.is_deny(),
            "revoked token must be denied regardless of freshness availability, got {outcome:?}"
        );
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "CAPABILITY_REVOKED");
        }
    }

    #[test]
    fn revocation_check_allows_fresh_unrevoked() {
        let registry = RevocationRegistry::new();
        let config = EnforcementConfig::default().with_revocation_registry(Arc::new(registry));

        let mut ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .revocation_list_age_ms(100)
            .build()
            .unwrap();
        ctx.token_id = Some(ObjectId::from_bytes([0xBB; 32]));

        let check = RevocationCheck;
        let outcome = check.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn builder_all_optional_fields_set() {
        let ctx = EnforcementContextBuilder::new()
            .request_id("r1")
            .connector_id("c1")
            .operation("op1")
            .zone_id("z1")
            .principal("p1")
            .capability_claims(vec!["cap".into()])
            .required_capability("cap")
            .taint_flags(vec!["pii".into()])
            .approval_scopes(vec!["pii".into()])
            .timestamp_ms(12345)
            .holder_proof_required(true)
            .holder_verified(true)
            .checkpoint_age_ms(100)
            .revocation_list_age_ms(200)
            .budget_used(50)
            .budget_limit(500)
            .rate_count(3)
            .rate_limit(10)
            .manifest_allowed_operations(vec!["op1".into()])
            .build()
            .unwrap();
        assert_eq!(ctx.timestamp_ms, 12345);
        assert!(ctx.holder_proof_required);
        assert!(ctx.holder_verified);
        assert_eq!(ctx.checkpoint_age_ms, Some(100));
        assert_eq!(ctx.revocation_list_age_ms, Some(200));
        assert_eq!(ctx.budget_used, Some(50));
        assert_eq!(ctx.budget_limit, Some(500));
        assert_eq!(ctx.rate_count, Some(3));
        assert_eq!(ctx.rate_limit, Some(10));
        assert_eq!(ctx.required_capability.as_deref(), Some("cap"));
    }

    // ── CanonicalDecodeCheck ordering ──

    #[test]
    fn canonical_decode_checks_operation_before_zone() {
        let mut ctx = test_context();
        ctx.operation = String::new();
        ctx.zone_id = String::new();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_OPERATION");
        }
    }

    #[test]
    fn canonical_decode_checks_zone_before_principal() {
        let mut ctx = test_context();
        ctx.zone_id = String::new();
        ctx.principal = String::new();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_ZONE_ID");
        }
    }

    #[test]
    fn canonical_decode_checks_principal_before_request_id() {
        let mut ctx = test_context();
        ctx.principal = String::new();
        ctx.request_id = String::new();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_PRINCIPAL");
        }
    }

    #[test]
    fn canonical_decode_deny_whitespace_request_id() {
        let mut ctx = test_context();
        ctx.request_id = " \t ".into();
        let config = EnforcementConfig::default();
        let outcome = CanonicalDecodeCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "MISSING_REQUEST_ID");
        }
    }

    // ── CapabilityVerifyCheck edge cases ──

    #[test]
    fn capability_verify_nested_operation_prefix_does_not_authorize_capability() {
        let mut ctx = test_context();
        ctx.operation = "messages.channels.send".into();
        ctx.capability_claims = vec!["messages.channels".into()];
        ctx.required_capability = Some("messages.channels.write".into());
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn capability_verify_slash_operation_prefix_does_not_authorize_capability() {
        let mut ctx = test_context();
        ctx.operation = "api/v2/list".into();
        ctx.capability_claims = vec!["api/v2".into()];
        ctx.required_capability = Some("api.v2.read".into());
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn capability_verify_blank_required_capability_denied() {
        let mut ctx = test_context();
        ctx.required_capability = Some("   ".into());
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn capability_verify_exact_match_with_dots() {
        let mut ctx = test_context();
        ctx.required_capability = Some("a.b.c".into());
        ctx.capability_claims = vec!["a.b.c".into()];
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn capability_verify_wildcard_alone() {
        let mut ctx = test_context();
        ctx.capability_claims = vec!["*".into()];
        ctx.operation = "any.random.operation".into();
        ctx.required_capability = Some("any.random.capability".into());
        let config = EnforcementConfig::default();
        let outcome = CapabilityVerifyCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    // ── CheckpointFreshnessCheck boundary ──

    #[test]
    fn checkpoint_freshness_deny_at_max_u64() {
        let mut ctx = test_context();
        ctx.checkpoint_age_ms = Some(u64::MAX);
        let config = EnforcementConfig::default();
        let outcome = CheckpointFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn checkpoint_freshness_allow_zero_threshold() {
        let mut ctx = test_context();
        ctx.checkpoint_age_ms = Some(0);
        let config = EnforcementConfig::new().with_checkpoint_max_age_ms(0);
        let outcome = CheckpointFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn checkpoint_freshness_deny_one_over_zero_threshold() {
        let mut ctx = test_context();
        ctx.checkpoint_age_ms = Some(1);
        let config = EnforcementConfig::new().with_checkpoint_max_age_ms(0);
        let outcome = CheckpointFreshnessCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    // ── RevocationCheck freshness boundary ──

    #[test]
    fn revocation_freshness_deny_at_max_u64() {
        let mut ctx = test_context();
        ctx.revocation_list_age_ms = Some(u64::MAX);
        let config = EnforcementConfig::default();
        let outcome = RevocationCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn revocation_freshness_allow_zero_threshold() {
        let mut ctx = test_context();
        ctx.revocation_list_age_ms = Some(0);
        let config = EnforcementConfig::new().with_revocation_max_age_ms(0);
        let outcome = RevocationCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn revocation_freshness_zero_age() {
        let mut ctx = test_context();
        ctx.revocation_list_age_ms = Some(0);
        let config = EnforcementConfig::default();
        let outcome = RevocationCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    // ── TaintApprovalCheck edge cases ──

    #[test]
    fn taint_approval_deny_classified_without_approval() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["classified".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { explanation, .. } = &outcome {
            assert!(explanation.contains("classified"));
        }
    }

    #[test]
    fn taint_approval_deny_financial_without_approval() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["financial".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { explanation, .. } = &outcome {
            assert!(explanation.contains("financial"));
        }
    }

    #[test]
    fn taint_approval_superset_approvals_ok() {
        let mut ctx = test_context();
        ctx.taint_flags = vec!["pii".into()];
        ctx.approval_scopes = vec!["pii".into(), "phi".into(), "classified".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn taint_approval_all_four_defaults_approved() {
        let mut ctx = test_context();
        ctx.taint_flags = vec![
            "pii".into(),
            "phi".into(),
            "classified".into(),
            "financial".into(),
        ];
        ctx.approval_scopes = vec![
            "pii".into(),
            "phi".into(),
            "classified".into(),
            "financial".into(),
        ];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn taint_approval_all_four_defaults_one_missing() {
        let mut ctx = test_context();
        ctx.taint_flags = vec![
            "pii".into(),
            "phi".into(),
            "classified".into(),
            "financial".into(),
        ];
        ctx.approval_scopes = vec!["pii".into(), "phi".into(), "financial".into()];
        let config = EnforcementConfig::default();
        let outcome = TaintApprovalCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { explanation, .. } = &outcome {
            assert!(explanation.contains("classified"));
        }
    }

    // ── PolicyCeilingCheck edge cases ──

    #[test]
    fn policy_ceiling_connector_allowed_operation_denied() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config
            .add_zone_connector("z:prod", "slack:utility:1.0.0")
            .unwrap();
        config
            .add_zone_operation("z:prod", "list_channels")
            .unwrap();
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "OPERATION_NOT_IN_ZONE_POLICY");
        }
    }

    #[test]
    fn policy_ceiling_no_connector_rules_but_operation_rules_deny() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        // No connector rules for z:prod, but operation rules exist
        config
            .add_zone_operation("z:prod", "list_channels")
            .unwrap();
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
        if let CheckOutcome::Deny { reason_code, .. } = &outcome {
            assert_eq!(reason_code, "OPERATION_NOT_IN_ZONE_POLICY");
        }
    }

    #[test]
    fn policy_ceiling_rules_for_other_zone_only() {
        let ctx = test_context();
        let mut config = EnforcementConfig::default();
        config
            .add_zone_connector("z:dev", "slack:utility:1.0.0")
            .unwrap();
        config.add_zone_operation("z:dev", "send_message").unwrap();
        // z:prod has no rules → allow
        let outcome = PolicyCeilingCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    // ── RateLimitCheck edge cases ──

    #[test]
    fn rate_limit_both_none() {
        let mut ctx = test_context();
        ctx.rate_count = None;
        ctx.rate_limit = None;
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_skip());
    }

    #[test]
    fn rate_limit_max_u32_under_limit() {
        let mut ctx = test_context();
        ctx.rate_count = Some(u32::MAX - 1);
        ctx.rate_limit = Some(u32::MAX);
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn rate_limit_max_u32_at_limit() {
        let mut ctx = test_context();
        ctx.rate_count = Some(u32::MAX);
        ctx.rate_limit = Some(u32::MAX);
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    #[test]
    fn rate_limit_one_of_one() {
        let mut ctx = test_context();
        ctx.rate_count = Some(1);
        ctx.rate_limit = Some(1);
        let config = EnforcementConfig::default();
        let outcome = RateLimitCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    // ── ConnectorManifestCheck edge cases ──

    #[test]
    fn connector_manifest_many_ops_last_matches() {
        let mut ctx = test_context();
        let mut ops: Vec<String> = (0..99).map(|i| format!("op_{i}")).collect();
        ops.push("send_message".into());
        ctx.manifest_allowed_operations = ops;
        let config = EnforcementConfig::default();
        let outcome = ConnectorManifestCheck.check(&ctx, &config);
        assert!(outcome.is_allow());
    }

    #[test]
    fn connector_manifest_many_ops_none_match() {
        let mut ctx = test_context();
        ctx.manifest_allowed_operations = (0..100).map(|i| format!("op_{i}")).collect();
        let config = EnforcementConfig::default();
        let outcome = ConnectorManifestCheck.check(&ctx, &config);
        assert!(outcome.is_deny());
    }

    // ── Pipeline integration edge cases ──

    #[test]
    fn pipeline_single_allow_check() {
        let pipeline = EnforcementPipeline::with_checks(vec![Box::new(AlwaysAllowCheck)]);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.is_allowed());
        assert_eq!(decision.checks_executed(), 1);
        assert_eq!(decision.allow_count(), 1);
        assert_eq!(decision.skip_count(), 0);
    }

    #[test]
    fn pipeline_single_deny_check() {
        let pipeline = EnforcementPipeline::with_checks(vec![Box::new(AlwaysDenyCheck {
            code: "SOLO".into(),
        })]);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        assert_eq!(decision.checks_executed(), 1);
        if let PipelineOutcome::Deny { reason_code, .. } = &decision.outcome {
            assert_eq!(reason_code, "SOLO");
        }
    }

    #[test]
    fn pipeline_single_skip_check() {
        let pipeline = EnforcementPipeline::with_checks(vec![Box::new(AlwaysSkipCheck)]);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.is_allowed());
        assert_eq!(decision.skip_count(), 1);
        assert_eq!(decision.allow_count(), 0);
    }

    #[test]
    fn pipeline_deny_after_many_skips() {
        let pipeline = EnforcementPipeline::with_checks(vec![
            Box::new(AlwaysSkipCheck),
            Box::new(AlwaysSkipCheck),
            Box::new(AlwaysSkipCheck),
            Box::new(AlwaysDenyCheck {
                code: "LATE".into(),
            }),
            Box::new(AlwaysAllowCheck),
        ]);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(!decision.is_allowed());
        assert_eq!(decision.checks_executed(), 4);
        assert_eq!(decision.skip_count(), 3);
    }

    #[test]
    fn pipeline_check_names_empty() {
        let pipeline = EnforcementPipeline::with_checks(vec![]);
        assert!(pipeline.check_names().is_empty());
    }

    // ── PipelineOutcome clone ──

    #[test]
    fn pipeline_outcome_clone_allow() {
        let o = PipelineOutcome::Allow;
        let cloned = o.clone();
        assert!(o.is_allow());
        assert!(cloned.is_allow());
    }

    #[test]
    fn pipeline_outcome_clone_deny() {
        let o = PipelineOutcome::Deny {
            check_name: "check".into(),
            reason_code: "code".into(),
            explanation: "detail".into(),
        };
        let cloned = o.clone();
        assert!(o.is_deny());
        assert!(cloned.is_deny());
        if let PipelineOutcome::Deny {
            check_name,
            reason_code,
            explanation,
        } = &cloned
        {
            assert_eq!(check_name, "check");
            assert_eq!(reason_code, "code");
            assert_eq!(explanation, "detail");
        }
    }

    #[test]
    fn pipeline_outcome_deny_debug_contains_fields() {
        let o = PipelineOutcome::Deny {
            check_name: "mycheck".into(),
            reason_code: "MYCODE".into(),
            explanation: "mydetail".into(),
        };
        let debug = format!("{o:?}");
        assert!(debug.contains("mycheck"));
        assert!(debug.contains("MYCODE"));
        assert!(debug.contains("mydetail"));
    }

    // ── CheckOutcome skip debug ──

    #[test]
    fn check_outcome_skip_debug_contains_reason() {
        let o = CheckOutcome::Skip {
            reason: "not applicable".into(),
        };
        let debug = format!("{o:?}");
        assert!(debug.contains("not applicable"));
    }

    // ── CheckRecord clone ──

    #[test]
    fn check_record_clone() {
        let record = CheckRecord {
            name: "test".into(),
            outcome: CheckOutcome::Allow,
            elapsed_ms: 1.5,
        };
        let cloned = record.clone();
        assert_eq!(record.name, cloned.name);
        assert!(cloned.outcome.is_allow());
        assert!((cloned.elapsed_ms - 1.5).abs() < f64::EPSILON);
    }

    // ── Decision with deny outcome ──

    #[test]
    fn enforcement_decision_clone_deny() {
        let decision = EnforcementDecision {
            outcome: PipelineOutcome::Deny {
                check_name: "x".into(),
                reason_code: "y".into(),
                explanation: "z".into(),
            },
            checks_run: vec![CheckRecord {
                name: "x".into(),
                outcome: CheckOutcome::Deny {
                    reason_code: "y".into(),
                    explanation: "z".into(),
                },
                elapsed_ms: 0.5,
            }],
            elapsed_ms: 0.5,
        };
        let cloned = decision.clone();
        assert!(!decision.is_allowed());
        assert!(!cloned.is_allowed());
        assert_eq!(cloned.checks_executed(), 1);
    }

    #[test]
    fn enforcement_decision_debug_deny() {
        let decision = EnforcementDecision {
            outcome: PipelineOutcome::Deny {
                check_name: "check_abc".into(),
                reason_code: "CODE_XYZ".into(),
                explanation: "details here".into(),
            },
            checks_run: vec![],
            elapsed_ms: 2.0,
        };
        let debug = format!("{decision:?}");
        assert!(debug.contains("check_abc"));
        assert!(debug.contains("CODE_XYZ"));
    }

    // ── Context field verification ──

    #[test]
    fn context_clone_preserves_all_fields() {
        let ctx = test_context();
        let cloned = ctx.clone();
        assert_eq!(ctx.request_id, cloned.request_id);
        assert_eq!(ctx.connector_id, cloned.connector_id);
        assert_eq!(ctx.operation, cloned.operation);
        assert_eq!(ctx.zone_id, cloned.zone_id);
        assert_eq!(ctx.principal, cloned.principal);
        assert_eq!(ctx.capability_claims, cloned.capability_claims);
        assert_eq!(ctx.required_capability, cloned.required_capability);
        assert_eq!(ctx.taint_flags, cloned.taint_flags);
        assert_eq!(ctx.approval_scopes, cloned.approval_scopes);
        assert_eq!(ctx.timestamp_ms, cloned.timestamp_ms);
        assert_eq!(ctx.holder_proof_required, cloned.holder_proof_required);
        assert_eq!(ctx.holder_verified, cloned.holder_verified);
        assert_eq!(ctx.checkpoint_age_ms, cloned.checkpoint_age_ms);
        assert_eq!(ctx.revocation_list_age_ms, cloned.revocation_list_age_ms);
        assert_eq!(ctx.budget_used, cloned.budget_used);
        assert_eq!(ctx.budget_limit, cloned.budget_limit);
        assert_eq!(ctx.rate_count, cloned.rate_count);
        assert_eq!(ctx.rate_limit, cloned.rate_limit);
        assert_eq!(
            ctx.manifest_allowed_operations,
            cloned.manifest_allowed_operations
        );
    }

    // ── Pipeline with fully configured config passes all checks ──

    #[test]
    fn pipeline_fully_configured_all_allow() {
        let mut config = EnforcementConfig::new()
            .with_checkpoint_max_age_ms(100_000)
            .with_revocation_max_age_ms(200_000);
        config.add_zone_membership("agent-alpha", "z:prod").unwrap();
        config
            .add_zone_connector("z:prod", "slack:utility:1.0.0")
            .unwrap();
        config.add_zone_operation("z:prod", "send_message").unwrap();

        let pipeline = EnforcementPipeline::with_config(config);
        let ctx = test_context();
        let decision = pipeline.evaluate(&ctx);
        assert!(decision.is_allowed());
        assert_eq!(decision.checks_executed(), EnforcementCheckOrder::COUNT);
        // With zone membership configured, it should be allow not skip
        let zone_check = &decision.checks_run[1];
        assert_eq!(zone_check.name, "zone_membership");
        assert!(zone_check.outcome.is_allow());
    }

    #[test]
    fn pipeline_deny_zone_membership_before_capability() {
        let mut config = EnforcementConfig::default();
        config
            .add_zone_membership("agent-alpha", "z:staging")
            .unwrap();
        let pipeline = EnforcementPipeline::with_config(config);
        let mut ctx = test_context();
        ctx.capability_claims = Vec::new(); // would also fail
        let decision = pipeline.evaluate(&ctx);
        // zone_membership is checked before capability_verify
        if let PipelineOutcome::Deny { check_name, .. } = &decision.outcome {
            assert_eq!(check_name, "zone_membership");
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // br-nsrx3 — DeploymentTier admission gate wired into pipeline
    //
    // Pin the per-(mode × tier) admission matrix at the pipeline-check
    // boundary. CrimsonWolf's hr0rr.1 (commit 26d7919dd) shipped the
    // admit_safety_tier predicate; nsrx3 wires it in as
    // EnforcementCheckId::DeploymentTier so a Risky/Dangerous request
    // arriving while the host is in Evaluation mode is REFUSED before
    // dispatch. Slot is canonical: right after CapabilityVerify.
    //
    // Back-compat: contexts with safety_tier=None or
    // deployment_classification=None Skip the check (pre-nsrx3 callers
    // unaffected).
    // ─────────────────────────────────────────────────────────────────

    use crate::deployment_mode::{
        DeploymentClassification, DeploymentClassificationReason, DeploymentMode, MeshQuorumSignals,
    };

    fn evaluation_classification() -> Arc<DeploymentClassification> {
        Arc::new(DeploymentClassification {
            mode: DeploymentMode::Evaluation,
            signals: MeshQuorumSignals::single_host_evaluation(),
            reason: DeploymentClassificationReason::InsufficientMeshQuorum {
                observed: 0,
                required: 2,
            },
        })
    }

    fn mesh_active_classification() -> Arc<DeploymentClassification> {
        Arc::new(DeploymentClassification {
            mode: DeploymentMode::MeshActive,
            signals: MeshQuorumSignals::fully_active(3),
            reason: DeploymentClassificationReason::MeshQuorumActive,
        })
    }

    fn ctx_with_tier_and_mode(
        tier: SafetyTier,
        classification: Arc<DeploymentClassification>,
    ) -> EnforcementContext {
        let mut ctx = test_context();
        ctx.safety_tier = Some(tier);
        ctx.deployment_classification = Some(classification);
        ctx
    }

    #[test]
    fn peer_capability_check_allows_safe_v3_only_during_migration() {
        let check = PeerCapabilityCheck::new();
        let mut ctx = test_context();
        ctx.safety_tier = Some(SafetyTier::Safe);
        ctx.remote_peer_id = Some("peer-v3".into());
        ctx.remote_peer_capabilities = Some(PeerProtocolCapabilities::v3_only());

        let outcome = check.check(&ctx, &EnforcementConfig::default());
        assert!(matches!(outcome, CheckOutcome::Allow));
    }

    #[test]
    fn peer_capability_check_refuses_v3_only_when_policy_requires_v4() {
        let check = PeerCapabilityCheck::new();
        let mut ctx = test_context();
        ctx.safety_tier = Some(SafetyTier::Risky);
        ctx.remote_peer_id = Some("peer-v3".into());
        ctx.remote_peer_capabilities = Some(PeerProtocolCapabilities::v3_only());

        let outcome = check.check(&ctx, &EnforcementConfig::default());
        match outcome {
            CheckOutcome::Deny {
                reason_code,
                explanation,
            } => {
                assert_eq!(reason_code, PEER_CAPABILITY_REQUIRES_V4);
                assert!(explanation.contains("peer-v3"));
                assert!(explanation.contains("V3-only"));
            }
            other => panic!("expected V3-only peer to be denied, got {other:?}"),
        }
    }

    #[test]
    fn peer_capability_check_allows_v4_when_policy_requires_v4() {
        let check = PeerCapabilityCheck::new();
        let mut ctx = test_context();
        ctx.safety_tier = Some(SafetyTier::Dangerous);
        ctx.remote_peer_id = Some("peer-v4".into());
        ctx.remote_peer_capabilities = Some(PeerProtocolCapabilities::v3_v4());

        let outcome = check.check(&ctx, &EnforcementConfig::default());
        assert!(matches!(outcome, CheckOutcome::Allow));
    }

    #[test]
    fn peer_capability_check_denies_missing_capability_when_policy_requires_v4() {
        let check = PeerCapabilityCheck::new();
        let mut ctx = test_context();
        ctx.safety_tier = Some(SafetyTier::Critical);
        ctx.remote_peer_id = Some("peer-missing".into());
        ctx.remote_peer_capabilities = None;

        let outcome = check.check(&ctx, &EnforcementConfig::default());
        assert!(matches!(
            outcome,
            CheckOutcome::Deny {
                reason_code,
                ..
            } if reason_code == PEER_CAPABILITY_NOT_ADVERTISED
        ));
    }

    // ── Per-tier admission in Evaluation mode ──

    #[test]
    fn deployment_tier_check_allows_safe_in_evaluation() {
        let check = DeploymentTierCheck::new();
        let ctx = ctx_with_tier_and_mode(SafetyTier::Safe, evaluation_classification());
        let outcome = check.check(&ctx, &EnforcementConfig::default());
        assert!(matches!(outcome, CheckOutcome::Allow));
    }

    #[test]
    fn deployment_tier_check_refuses_risky_in_evaluation() {
        let check = DeploymentTierCheck::new();
        let ctx = ctx_with_tier_and_mode(SafetyTier::Risky, evaluation_classification());
        let outcome = check.check(&ctx, &EnforcementConfig::default());
        match outcome {
            CheckOutcome::Deny { reason_code, .. } => {
                assert_eq!(reason_code, "TIER_REQUIRES_MESH_ACTIVE");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn deployment_tier_check_refuses_dangerous_in_evaluation() {
        let check = DeploymentTierCheck::new();
        let ctx = ctx_with_tier_and_mode(SafetyTier::Dangerous, evaluation_classification());
        let outcome = check.check(&ctx, &EnforcementConfig::default());
        match outcome {
            CheckOutcome::Deny { reason_code, .. } => {
                assert_eq!(reason_code, "TIER_REQUIRES_MESH_ACTIVE");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn deployment_tier_check_allows_critical_in_evaluation() {
        // Critical carries its own quorum/elevation gating downstream;
        // DeploymentTier MUST NOT block it.
        let check = DeploymentTierCheck::new();
        let ctx = ctx_with_tier_and_mode(SafetyTier::Critical, evaluation_classification());
        let outcome = check.check(&ctx, &EnforcementConfig::default());
        assert!(matches!(outcome, CheckOutcome::Allow));
    }

    #[test]
    fn deployment_tier_check_refuses_forbidden_in_any_mode() {
        let check = DeploymentTierCheck::new();
        for classification in [evaluation_classification(), mesh_active_classification()] {
            let ctx = ctx_with_tier_and_mode(SafetyTier::Forbidden, classification);
            let outcome = check.check(&ctx, &EnforcementConfig::default());
            match outcome {
                CheckOutcome::Deny { reason_code, .. } => {
                    assert_eq!(reason_code, "TIER_FORBIDDEN");
                }
                other => panic!("expected Deny, got {other:?}"),
            }
        }
    }

    // ── Per-tier admission in MeshActive mode ──

    #[test]
    fn deployment_tier_check_allows_all_non_forbidden_tiers_in_mesh_active() {
        let check = DeploymentTierCheck::new();
        for tier in [
            SafetyTier::Safe,
            SafetyTier::Risky,
            SafetyTier::Dangerous,
            SafetyTier::Critical,
        ] {
            let ctx = ctx_with_tier_and_mode(tier, mesh_active_classification());
            let outcome = check.check(&ctx, &EnforcementConfig::default());
            assert!(
                matches!(outcome, CheckOutcome::Allow),
                "tier {tier:?} MUST be admitted in MeshActive mode (got {outcome:?})"
            );
        }
    }

    // ── br-298px: production default fails CLOSED on missing fields ──

    #[test]
    fn deployment_tier_check_default_denies_when_safety_tier_missing() {
        // The production constructor (DeploymentTierCheck::new() /
        // ::default()) MUST refuse a request that lacks safety_tier
        // — silently skipping is fail-OPEN on a security gate.
        let check = DeploymentTierCheck::new();
        assert!(check.fails_closed(), "default constructor must fail closed");
        let mut ctx = test_context();
        ctx.deployment_classification = Some(evaluation_classification());
        ctx.safety_tier = None;
        let outcome = check.check(&ctx, &EnforcementConfig::default());
        match outcome {
            CheckOutcome::Deny {
                reason_code,
                explanation,
            } => {
                assert_eq!(reason_code, TIER_ADMISSION_NOT_CONFIGURED);
                assert!(
                    explanation.contains("safety_tier"),
                    "explanation must name the missing field: {explanation}"
                );
                assert!(
                    explanation.contains("EnforcementContextBuilder"),
                    "explanation must point operators at the fix: {explanation}"
                );
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn deployment_tier_check_default_denies_when_classification_missing() {
        let check = DeploymentTierCheck::default();
        let mut ctx = test_context();
        ctx.safety_tier = Some(SafetyTier::Risky);
        ctx.deployment_classification = None;
        let outcome = check.check(&ctx, &EnforcementConfig::default());
        match outcome {
            CheckOutcome::Deny {
                reason_code,
                explanation,
            } => {
                assert_eq!(reason_code, TIER_ADMISSION_NOT_CONFIGURED);
                assert!(
                    explanation.contains("deployment_classification"),
                    "explanation must name the missing field: {explanation}"
                );
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn deployment_tier_check_default_denies_when_both_fields_missing() {
        // Both fields missing — Deny on the first one checked
        // (safety_tier per current impl ordering). The exact field
        // named in the explanation is fine as long as ONE is named.
        let check = DeploymentTierCheck::default();
        let mut ctx = test_context();
        ctx.safety_tier = None;
        ctx.deployment_classification = None;
        let outcome = check.check(&ctx, &EnforcementConfig::default());
        assert!(
            matches!(
                &outcome,
                CheckOutcome::Deny { reason_code, .. } if reason_code == TIER_ADMISSION_NOT_CONFIGURED
            ),
            "both-missing must Deny with TIER_ADMISSION_NOT_CONFIGURED; got {outcome:?}"
        );
    }

    #[test]
    fn deployment_tier_check_default_constructor_returns_strict_mode() {
        // Invariant: DeploymentTierCheck::new() and
        // DeploymentTierCheck::default() are equivalent (both
        // return MissingFieldPolicy::Deny).
        let new_check = DeploymentTierCheck::new();
        let default_check = DeploymentTierCheck::default();
        assert!(new_check.fails_closed());
        assert!(default_check.fails_closed());
    }

    // ── Back-compat opt-in: explicit ::back_compat() preserves Skip ──

    #[test]
    fn deployment_tier_check_back_compat_skips_when_safety_tier_missing() {
        // The back_compat constructor preserves the legacy
        // fail-OPEN behavior for callers that explicitly opt in.
        let check = DeploymentTierCheck::back_compat();
        assert!(
            !check.fails_closed(),
            "back_compat constructor must NOT fail closed"
        );
        let mut ctx = test_context();
        ctx.deployment_classification = Some(evaluation_classification());
        ctx.safety_tier = None;
        let outcome = check.check(&ctx, &EnforcementConfig::default());
        assert!(
            matches!(outcome, CheckOutcome::Skip { .. }),
            "back_compat with missing safety_tier must Skip; got {outcome:?}"
        );
    }

    #[test]
    fn deployment_tier_check_back_compat_skips_when_classification_missing() {
        let check = DeploymentTierCheck::back_compat();
        let mut ctx = test_context();
        ctx.safety_tier = Some(SafetyTier::Risky);
        ctx.deployment_classification = None;
        let outcome = check.check(&ctx, &EnforcementConfig::default());
        assert!(
            matches!(outcome, CheckOutcome::Skip { .. }),
            "back_compat with missing classification must Skip; got {outcome:?}"
        );
    }

    #[test]
    fn deployment_tier_check_back_compat_still_admits_when_fields_present() {
        // back_compat affects ONLY the missing-field path. When both
        // fields are present, behavior must be identical to the
        // strict default — a real Risky-in-Evaluation request must
        // still Deny.
        let check = DeploymentTierCheck::back_compat();
        let mut ctx = test_context();
        ctx.safety_tier = Some(SafetyTier::Risky);
        ctx.deployment_classification = Some(evaluation_classification());
        let outcome = check.check(&ctx, &EnforcementConfig::default());
        assert!(
            matches!(
                &outcome,
                CheckOutcome::Deny { reason_code, .. } if reason_code == "TIER_REQUIRES_MESH_ACTIVE"
            ),
            "back_compat must NOT weaken the present-fields admission path; got {outcome:?}"
        );
    }

    #[test]
    fn missing_field_policy_default_is_deny_per_br_298px() {
        // Explicit invariant: the default MissingFieldPolicy is
        // Deny (fail-CLOSED). Any future change that flips this
        // default flips the security gate to fail-OPEN — that
        // change MUST be deliberate, not accidental.
        let policy = MissingFieldPolicy::default();
        assert_eq!(policy, MissingFieldPolicy::Deny);
    }

    // ── Wired into the canonical EnforcementPipeline ──

    #[test]
    fn pipeline_includes_deployment_tier_check_in_canonical_position() {
        // br-yowdy inserts RevocationCascade right after CapabilityVerify;
        // DeploymentTier remains immediately after that cascade gate and
        // before HolderProof. Pin the count and all three adjacent slots.
        let pipeline = EnforcementPipeline::default();
        let names = pipeline.check_names();
        assert_eq!(names.len(), EnforcementCheckOrder::COUNT);
        let cascade_pos = names.iter().position(|n| *n == "revocation_cascade");
        assert_eq!(
            cascade_pos,
            Some(3),
            "revocation_cascade MUST be at canonical index 3 (right after capability_verify); got {cascade_pos:?}"
        );
        let pos = names.iter().position(|n| *n == "deployment_tier");
        assert_eq!(
            pos,
            Some(4),
            "deployment_tier MUST be at canonical index 4 (after revocation_cascade); got {pos:?}"
        );
        // Sanity: capability_verify is index 2, holder_proof is 5.
        assert_eq!(names[2], "capability_verify");
        assert_eq!(names[5], "holder_proof");
    }

    #[test]
    fn pipeline_denies_risky_request_in_evaluation_mode_via_deployment_tier() {
        // End-to-end through the pipeline: a Risky request with a
        // valid capability claim arriving while the host is in
        // Evaluation mode MUST be denied at the deployment_tier check
        // (not at any earlier check). This is the bead's marquee
        // assertion.
        let pipeline = EnforcementPipeline::default();
        let ctx = ctx_with_tier_and_mode(SafetyTier::Risky, evaluation_classification());
        let decision = pipeline.evaluate(&ctx);
        match decision.outcome {
            PipelineOutcome::Deny {
                check_name,
                reason_code,
                ..
            } => {
                assert_eq!(check_name, "deployment_tier");
                assert_eq!(reason_code, "TIER_REQUIRES_MESH_ACTIVE");
            }
            other @ PipelineOutcome::Allow => {
                panic!("expected Deny at deployment_tier for Risky-in-Evaluation, got {other:?}")
            }
        }
    }

    #[test]
    fn pipeline_admits_risky_request_in_mesh_active_mode() {
        // The same Risky request MUST proceed past deployment_tier
        // when the host is in MeshActive mode. Other downstream checks
        // may still deny (holder_proof, budget, etc.), but the
        // deployment_tier check itself MUST allow.
        let pipeline = EnforcementPipeline::default();
        let ctx = ctx_with_tier_and_mode(SafetyTier::Risky, mesh_active_classification());
        let decision = pipeline.evaluate(&ctx);
        // Find the deployment_tier check record specifically.
        let record = decision
            .checks_run
            .iter()
            .find(|r| r.name == "deployment_tier")
            .expect("deployment_tier check ran");
        assert!(
            matches!(record.outcome, CheckOutcome::Allow),
            "deployment_tier MUST allow Risky in MeshActive (got {:?})",
            record.outcome
        );
    }
}
