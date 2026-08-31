//! Connector state management for mesh-persisted state objects (NORMATIVE).
//!
//! Based on FCP Specification V2 §10 and docs §2.2.
//!
//! # Overview
//!
//! Implements the connector state model so polling/cursors/dedup are safe under
//! failover and migration. Authoritative state lives in mesh objects; local
//! `$CONNECTOR_STATE` is a cache only.
//!
//! # State Models
//!
//! - **Stateless**: No mesh-persisted state required
//! - **`SingletonWriter`**: Exactly one writer enforced via Lease
//! - **Crdt**: Multi-writer state using CRDT deltas + periodic snapshots
//!
//! # Key Invariants
//!
//! - State writes for `SingletonWriter` MUST be fenced by a Lease with
//!   `LeasePurpose::ConnectorStateWrite`
//! - Fork detection MUST pause connector execution and require resolution
//! - Snapshots enable compaction of older state objects

use fcp_cbor::{SerializationError, to_canonical_cbor};
use fcp_crypto::{
    Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey, canonical_signing_bytes,
};
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use std::{fmt, pin::Pin};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    BoundVerified, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    CheckpointTransferEncoding, ComputationCheckpoint, ConnectorId, InstanceId, Lease,
    LeaseHandoff, LeaseId, LeasePurpose, LeaseTransferValidationError, LeaseValidationError,
    MigrationCapabilityContext, ObjectHeader, ObjectId, OperationId, TailscaleNodeId, ZoneId,
    validate_lease, validate_lease_handoff,
};

/// Maximum accepted size for a canonical CBOR blob decoded by
/// [`CursorState::from_cbor`].
///
/// `CursorState` is a small three-field struct (i64 + optional String + u64);
/// a realistic encoding is well under 256 bytes. The cap is set to 64 KiB —
/// several orders of magnitude above any legitimate cursor state — so that a
/// malicious or corrupted `ConnectorStateObject::state_cbor` cannot force
/// unbounded allocation inside `ciborium::de::from_reader` before the
/// downstream canonical re-encode check would catch the drift.
pub const MAX_CURSOR_STATE_BYTES: usize = 64 * 1024;

/// Maximum accepted size for either CRDT branch state fed into
/// [`merge_crdt_states`].
///
/// CRDT states legitimately grow with the number of logical keys/entries,
/// so the cap is larger than [`MAX_CURSOR_STATE_BYTES`]. 4 MiB accommodates
/// realistic multi-thousand-entry `LwwMap`/`OrSet` states while still
/// rejecting pathological branches crafted to force unbounded allocation
/// during `ciborium::from_reader` — each merge deserializes both branches,
/// so unbounded branches are a two-sided `DoS` surface.
pub const MAX_CRDT_STATE_BYTES: usize = 4 * 1024 * 1024;

/// Capability required to write canonical connector state.
pub const CONNECTOR_STATE_WRITE_CAPABILITY_ID: &str = "fcp.connector-state.write";

/// Operation required to append canonical connector-state objects.
pub const CONNECTOR_STATE_APPEND_OPERATION_ID: &str = "fcp.connector-state.append";

/// Domain-separated schema identifier for `ConnectorStateObject` signatures.
///
/// The signed payload intentionally excludes the `signature` field so the
/// signature is not self-referential.
pub const CONNECTOR_STATE_OBJECT_SIGNING_SCHEMA_ID: &str =
    "fcp.connector-state.state-object-signing.v1";

/// Canonical connector-state write capability identifier.
#[must_use]
pub fn connector_state_write_capability_id() -> CapabilityId {
    CapabilityId::from_static(CONNECTOR_STATE_WRITE_CAPABILITY_ID)
}

/// Canonical connector-state append operation identifier.
#[must_use]
pub fn connector_state_append_operation_id() -> OperationId {
    OperationId::from_static(CONNECTOR_STATE_APPEND_OPERATION_ID)
}

/// Resource URI used for connector-scoped state-write constraints.
#[must_use]
pub fn connector_state_resource_uri(connector_id: &ConnectorId) -> String {
    format!("fcp://connector-state/{}", connector_id.as_str())
}

/// Verified authorization witness for appending canonical connector state.
///
/// The only public constructor verifies a bound capability token against the
/// canonical connector-state write capability, append operation, target zone,
/// and connector-scoped resource URI. Holding this witness means the append
/// caller has crossed the capability boundary before reaching storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorStateWriteAuthorization {
    connector_id: ConnectorId,
    zone_id: ZoneId,
    writer_public_key: [u8; 32],
}

impl ConnectorStateWriteAuthorization {
    /// Verify a capability token and construct an append authorization witness.
    ///
    /// # Errors
    /// Returns [`ConnectorStateError::AuthorizationDenied`] when the token does
    /// not grant connector-state append for the supplied connector and zone.
    pub fn verify_append_token<T>(
        verifier: &CapabilityVerifier,
        token: T,
        connector_id: &ConnectorId,
        zone_id: &ZoneId,
    ) -> Result<Self, ConnectorStateError>
    where
        T: Into<CapabilityToken>,
    {
        let resource_uris = [connector_state_resource_uri(connector_id)];
        let bound = verifier
            .verify_bound(
                token,
                &connector_state_write_capability_id(),
                &connector_state_append_operation_id(),
                &resource_uris,
            )
            .map_err(|error| {
                connector_state_authorization_denied(
                    connector_id,
                    format!("capability token rejected: {error}"),
                )
            })?;

        Self::from_bound_append_token(&bound, connector_id, zone_id, verifier.host_public_key)
    }

    /// Connector authorized by this witness.
    #[must_use]
    pub const fn connector_id(&self) -> &ConnectorId {
        &self.connector_id
    }

    /// Zone authorized by this witness.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.zone_id
    }

    /// Public key that verified the append capability token.
    ///
    /// The connector-state append boundary uses this key as the writer key for
    /// `ConnectorStateObject` signature verification.
    #[must_use]
    pub const fn writer_public_key(&self) -> [u8; 32] {
        self.writer_public_key
    }

    fn from_bound_append_token(
        token: &CapabilityToken<BoundVerified>,
        connector_id: &ConnectorId,
        zone_id: &ZoneId,
        writer_public_key: [u8; 32],
    ) -> Result<Self, ConnectorStateError> {
        let claims = token.claims();
        let token_zone = claims.get_zone_id().ok_or_else(|| {
            connector_state_authorization_denied(
                connector_id,
                "capability token is missing zone binding".to_string(),
            )
        })?;
        if token_zone != zone_id.as_str() {
            return Err(connector_state_authorization_denied(
                connector_id,
                format!(
                    "capability token zone {token_zone} does not match connector state zone {}",
                    zone_id.as_str()
                ),
            ));
        }

        if let Some(claim_capability) = claims.get_capability_id()
            && claim_capability != CONNECTOR_STATE_WRITE_CAPABILITY_ID
        {
            return Err(connector_state_authorization_denied(
                connector_id,
                format!(
                    "capability token claim {claim_capability} does not match required {CONNECTOR_STATE_WRITE_CAPABILITY_ID}"
                ),
            ));
        }

        let grants_value = claims
            .get(fcp_crypto::cose::fcp2_claims::GRANTS)
            .ok_or_else(|| {
                connector_state_authorization_denied(
                    connector_id,
                    "capability token is missing canonical grants".to_string(),
                )
            })?;
        let grants: Vec<CapabilityGrant> = decode_connector_state_grants(
            connector_id,
            grants_value,
            "capability token grants are malformed",
        )?;
        let required_capability = connector_state_write_capability_id();
        let required_operation = connector_state_append_operation_id();
        let grants_append = grants.iter().any(|grant| {
            grant.capability == required_capability
                && grant
                    .operation
                    .as_ref()
                    .is_none_or(|operation| operation == &required_operation)
        });

        if !grants_append {
            return Err(connector_state_authorization_denied(
                connector_id,
                format!(
                    "capability token does not grant {CONNECTOR_STATE_WRITE_CAPABILITY_ID}:{CONNECTOR_STATE_APPEND_OPERATION_ID}"
                ),
            ));
        }

        Ok(Self {
            connector_id: connector_id.clone(),
            zone_id: zone_id.clone(),
            writer_public_key,
        })
    }
}

fn decode_connector_state_grants(
    connector_id: &ConnectorId,
    value: &ciborium::Value,
    context: &'static str,
) -> Result<Vec<CapabilityGrant>, ConnectorStateError> {
    let mut cbor = Vec::new();
    ciborium::into_writer(value, &mut cbor).map_err(|error| {
        connector_state_authorization_denied(connector_id, format!("{context}: {error}"))
    })?;
    ciborium::from_reader(cbor.as_slice()).map_err(|error| {
        connector_state_authorization_denied(connector_id, format!("{context}: {error}"))
    })
}

fn connector_state_authorization_denied(
    connector_id: &ConnectorId,
    reason: String,
) -> ConnectorStateError {
    ConnectorStateError::AuthorizationDenied {
        connector_id: connector_id.clone(),
        reason,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Signature Type
// ─────────────────────────────────────────────────────────────────────────────

/// Ed25519 signature (64 bytes) (NORMATIVE).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(#[serde(with = "crate::util::hex_or_bytes")] pub [u8; 64]);

impl Signature {
    /// Create a signature from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Get the raw signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Create a zero signature (for testing).
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 64])
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Signature")
            .field(&format!("{}...", hex::encode(&self.0[..8])))
            .finish()
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}...", hex::encode(&self.0[..8]))
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self::zero()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CRDT Types (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// CRDT type discriminant (NORMATIVE).
///
/// Defines the merge semantics for multi-writer connector state.
/// The actual CRDT implementations are in the `crate::crdt` module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrdtType {
    /// Last-write-wins map (key-value with timestamps).
    ///
    /// Merge: Take entry with latest timestamp per key.
    /// Implementation: `crate::LwwMap`
    LwwMap,

    /// Observed-remove set (add/remove operations).
    ///
    /// Merge: Via observed-remove set algebra.
    /// Implementation: `crate::OrSet`
    OrSet,

    /// Grow-only counter (only increments).
    ///
    /// Merge: Take max per actor.
    /// Implementation: `crate::GCounter`
    GCounter,

    /// Positive-negative counter (increments and decrements).
    ///
    /// Merge: Merge positive and negative counters separately.
    /// Implementation: `crate::PnCounter`
    PnCounter,
}

impl CrdtType {
    /// Get the human-readable name for this CRDT type.
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

impl fmt::Display for CrdtType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State Model (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Connector state model discriminant (NORMATIVE).
///
/// Defines how connector state is persisted and synchronized in the mesh.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConnectorStateModel {
    /// No mesh-persisted state required.
    ///
    /// The connector maintains no durable state across restarts.
    #[default]
    Stateless,

    /// Exactly one writer enforced via Lease (`ConnectorStateWrite` purpose).
    ///
    /// - State writes MUST be fenced by a Lease
    /// - Higher `lease_seq` wins deterministically
    /// - Fork detection triggers safety incident
    SingletonWriter,

    /// Multi-writer state using CRDT deltas + periodic snapshots.
    ///
    /// - Multiple nodes can write concurrently
    /// - Deltas are merged according to `crdt_type` semantics
    /// - Snapshots compact the delta chain
    Crdt {
        /// The CRDT type determining merge semantics.
        crdt_type: CrdtType,
    },
}

impl ConnectorStateModel {
    /// Check if this model is stateless.
    #[must_use]
    pub const fn is_stateless(&self) -> bool {
        matches!(self, Self::Stateless)
    }

    /// Check if this model requires singleton writer semantics.
    #[must_use]
    pub const fn is_singleton_writer(&self) -> bool {
        matches!(self, Self::SingletonWriter)
    }

    /// Check if this model uses CRDT semantics.
    #[must_use]
    pub const fn is_crdt(&self) -> bool {
        matches!(self, Self::Crdt { .. })
    }

    /// Get the CRDT type if this is a CRDT model.
    #[must_use]
    pub const fn crdt_type(&self) -> Option<CrdtType> {
        match self {
            Self::Crdt { crdt_type } => Some(*crdt_type),
            _ => None,
        }
    }
}

impl fmt::Display for ConnectorStateModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stateless => write!(f, "stateless"),
            Self::SingletonWriter => write!(f, "singleton_writer"),
            Self::Crdt { crdt_type } => write!(f, "crdt({crdt_type})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State Root (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Root object for connector state (NORMATIVE).
///
/// This object defines the state model and points to the current head of the
/// state chain. It is the entry point for state resolution during failover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorStateRoot {
    /// Object header (includes zone, schema, etc).
    pub header: ObjectHeader,

    /// Connector identifier.
    pub connector_id: ConnectorId,

    /// Optional instance identifier (for multi-instance connectors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,

    /// Zone in which this state resides.
    pub zone_id: ZoneId,

    /// State model governing this connector's state.
    pub model: ConnectorStateModel,

    /// Latest `ConnectorStateObject` (or `None` if no state yet).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<ObjectId>,

    /// Schema version for safe upgrades (NORMATIVE).
    #[serde(default = "default_schema_version")]
    pub state_schema_version: u32,
}

const fn default_schema_version() -> u32 {
    1
}

impl ConnectorStateRoot {
    /// Create a new state root for a stateless connector.
    #[must_use]
    pub const fn stateless(
        header: ObjectHeader,
        connector_id: ConnectorId,
        zone_id: ZoneId,
    ) -> Self {
        Self {
            header,
            connector_id,
            instance_id: None,
            zone_id,
            model: ConnectorStateModel::Stateless,
            head: None,
            state_schema_version: 1,
        }
    }

    /// Create a new state root for a singleton-writer connector.
    #[must_use]
    pub const fn singleton_writer(
        header: ObjectHeader,
        connector_id: ConnectorId,
        zone_id: ZoneId,
    ) -> Self {
        Self {
            header,
            connector_id,
            instance_id: None,
            zone_id,
            model: ConnectorStateModel::SingletonWriter,
            head: None,
            state_schema_version: 1,
        }
    }

    /// Create a new state root for a CRDT connector.
    #[must_use]
    pub const fn crdt(
        header: ObjectHeader,
        connector_id: ConnectorId,
        zone_id: ZoneId,
        crdt_type: CrdtType,
    ) -> Self {
        Self {
            header,
            connector_id,
            instance_id: None,
            zone_id,
            model: ConnectorStateModel::Crdt { crdt_type },
            head: None,
            state_schema_version: 1,
        }
    }

    /// Set the instance ID.
    #[must_use]
    pub fn with_instance_id(mut self, instance_id: InstanceId) -> Self {
        self.instance_id = Some(instance_id);
        self
    }

    /// Set the head object ID.
    #[must_use]
    pub const fn with_head(mut self, head: ObjectId) -> Self {
        self.head = Some(head);
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State Object (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// State object in the state chain (NORMATIVE).
///
/// For `SingletonWriter` connectors, each state object represents an atomic
/// state transition. The chain is linked via `prev` references.
///
/// # Singleton Writer Fencing
///
/// For `SingletonWriter` model:
/// - `lease_seq` MUST be included (fencing token)
/// - `lease_object_id` MUST reference the authorizing Lease
/// - Verifiers MUST reject updates with stale `lease_seq`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorStateObject {
    /// Object header (includes zone, schema, etc).
    pub header: ObjectHeader,

    /// Connector identifier.
    pub connector_id: ConnectorId,

    /// Optional instance identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,

    /// Zone in which this state resides.
    pub zone_id: ZoneId,

    /// Previous state object in the chain (`None` for genesis).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<ObjectId>,

    /// Monotonic sequence number.
    ///
    /// MUST increase for each state object. Used for ordering and fork detection.
    pub seq: u64,

    /// Canonical state blob (CBOR-encoded).
    ///
    /// The structure depends on the connector's state schema.
    pub state_cbor: Vec<u8>,

    /// Timestamp when this state was created (UNIX seconds).
    pub updated_at: u64,

    /// Fencing token (NORMATIVE for `SingletonWriter`).
    ///
    /// The `lease_seq` from the authorizing Lease. Verifiers MUST reject
    /// updates with stale fencing tokens.
    pub lease_seq: u64,

    /// The Lease object granting write authority (NORMATIVE for `SingletonWriter`).
    ///
    /// This MUST be included in `header.refs` for reference tracking.
    pub lease_object_id: ObjectId,

    /// Ed25519 public key of the writer that signed this state object.
    ///
    /// Append authorization verifies this key against the capability-token
    /// verifier key. Read paths use the embedded key to verify persisted state
    /// objects without needing the original append witness in memory.
    #[serde(with = "crate::util::hex_or_bytes")]
    pub writer_public_key: [u8; 32],

    /// Ed25519 signature over the canonical state object.
    pub signature: Signature,
}

#[derive(Serialize)]
struct ConnectorStateObjectSigningPayload<'a> {
    header: &'a ObjectHeader,
    connector_id: &'a ConnectorId,
    #[serde(skip_serializing_if = "Option::is_none")]
    instance_id: &'a Option<InstanceId>,
    zone_id: &'a ZoneId,
    #[serde(skip_serializing_if = "Option::is_none")]
    prev: &'a Option<ObjectId>,
    seq: u64,
    state_cbor: &'a [u8],
    updated_at: u64,
    lease_seq: u64,
    lease_object_id: &'a ObjectId,
    #[serde(with = "crate::util::hex_or_bytes")]
    writer_public_key: &'a [u8; 32],
}

/// Error returned while signing or verifying connector state objects.
#[derive(Debug, Error)]
pub enum ConnectorStateSignatureError {
    /// Canonical signing transcript construction failed.
    #[error("connector state signing transcript error: {0}")]
    Serialization(#[from] SerializationError),

    /// Ed25519 signature verification failed.
    #[error("connector state signature verification failed: {0}")]
    Crypto(#[from] fcp_crypto::CryptoError),
}

impl ConnectorStateObject {
    /// Check if this is a genesis state object.
    #[must_use]
    pub const fn is_genesis(&self) -> bool {
        self.prev.is_none()
    }

    /// Build the domain-separated signing bytes for this state object.
    ///
    /// The signed payload includes every state-object field except
    /// [`Self::signature`], which avoids a self-referential signature.
    ///
    /// # Errors
    /// Returns a [`SerializationError`] if canonical CBOR encoding fails.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let payload = ConnectorStateObjectSigningPayload {
            header: &self.header,
            connector_id: &self.connector_id,
            instance_id: &self.instance_id,
            zone_id: &self.zone_id,
            prev: &self.prev,
            seq: self.seq,
            state_cbor: &self.state_cbor,
            updated_at: self.updated_at,
            lease_seq: self.lease_seq,
            lease_object_id: &self.lease_object_id,
            writer_public_key: &self.writer_public_key,
        };
        let cbor = to_canonical_cbor(&payload)?;
        Ok(canonical_signing_bytes(
            CONNECTOR_STATE_OBJECT_SIGNING_SCHEMA_ID,
            &cbor,
        ))
    }

    /// Sign this state object with the supplied Ed25519 key.
    ///
    /// # Errors
    /// Returns a [`SerializationError`] if canonical signing bytes cannot be
    /// constructed.
    pub fn sign_with(&mut self, signing_key: &Ed25519SigningKey) -> Result<(), SerializationError> {
        self.writer_public_key = signing_key.verifying_key().to_bytes();
        let signature = signing_key.sign(&self.signing_bytes()?);
        self.signature = Signature::from_bytes(signature.to_bytes());
        Ok(())
    }

    /// Verify this state object's signature with its embedded writer key.
    ///
    /// # Errors
    /// Returns [`ConnectorStateSignatureError`] when the embedded writer key is
    /// malformed, the signing transcript cannot be constructed, or the
    /// signature does not verify.
    pub fn verify_signature(&self) -> Result<(), ConnectorStateSignatureError> {
        let verifying_key = Ed25519VerifyingKey::from_bytes(&self.writer_public_key)?;
        self.verify_signature_with(&verifying_key)
    }

    /// Verify this state object signature with the supplied Ed25519 key.
    ///
    /// # Errors
    /// Returns [`ConnectorStateSignatureError`] when transcript construction
    /// fails or the signature does not verify.
    pub fn verify_signature_with(
        &self,
        verifying_key: &Ed25519VerifyingKey,
    ) -> Result<(), ConnectorStateSignatureError> {
        let signature = Ed25519Signature::from_bytes(self.signature.as_bytes());
        verifying_key.verify(&self.signing_bytes()?, &signature)?;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State Delta (NORMATIVE for CRDT models)
// ─────────────────────────────────────────────────────────────────────────────

/// Delta object for CRDT state models (NORMATIVE).
///
/// For `Crdt` connectors, deltas represent incremental changes that can be
/// merged according to CRDT semantics. Periodic snapshots compact the delta chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorStateDelta {
    /// Object header (includes zone, schema, etc).
    pub header: ObjectHeader,

    /// Connector identifier.
    pub connector_id: ConnectorId,

    /// Optional instance identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,

    /// Zone in which this state resides.
    pub zone_id: ZoneId,

    /// CRDT type for this delta.
    pub crdt_type: CrdtType,

    /// Delta payload (CBOR-encoded).
    ///
    /// The structure depends on `crdt_type`:
    /// - `LwwMap`: `[(key, value, timestamp, actor)]`
    /// - `OrSet`: `[(element, add/remove, unique_tag)]`
    /// - `GCounter`: `[(actor_id, count)]`
    /// - `PnCounter`: `[(actor_id, pos_count, neg_count)]`
    pub delta_cbor: Vec<u8>,

    /// Timestamp when this delta was applied (UNIX seconds).
    pub applied_at: u64,

    /// Node that produced this delta.
    pub applied_by: TailscaleNodeId,

    /// Ed25519 signature over the canonical delta.
    pub signature: Signature,
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State Snapshot (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Snapshot for state compaction (NORMATIVE).
///
/// Snapshots capture the full state at a point in time, enabling:
/// - Efficient state recovery without replaying entire chain
/// - Garbage collection of older state objects/deltas
/// - Bounded storage consumption
///
/// # Compaction Rules
///
/// - `MeshNode` SHOULD create a snapshot every N updates or M bytes
/// - After snapshot is replicated, older objects MAY be GC'd
/// - Audit/policy pins may preserve older objects
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorStateSnapshot {
    /// Object header (includes zone, schema, etc).
    pub header: ObjectHeader,

    /// Connector identifier.
    pub connector_id: ConnectorId,

    /// Optional instance identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,

    /// Zone in which this state resides.
    pub zone_id: ZoneId,

    /// Latest state object included in this snapshot.
    pub covers_head: ObjectId,

    /// Sequence number of the covered head.
    pub covers_seq: u64,

    /// Full canonical state at `covers_head` (CBOR-encoded).
    pub state_cbor: Vec<u8>,

    /// Timestamp when this snapshot was created (UNIX seconds).
    pub snapshotted_at: u64,

    /// Ed25519 signature over the canonical snapshot.
    pub signature: Signature,
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State Store (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Result of appending a connector state object to canonical storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ConnectorStateAppendOutcome {
    /// The object became the canonical chain head.
    Committed {
        /// Stored state-object id.
        object_id: ObjectId,
        /// Stored root-object id pointing at `object_id`.
        root_object_id: ObjectId,
        /// Committed sequence number.
        seq: u64,
        /// Snapshot emitted by this append, when interval policy requested one.
        #[serde(skip_serializing_if = "Option::is_none")]
        snapshot_object_id: Option<ObjectId>,
    },
    /// The append did not match the canonical head and was not stored.
    Conflict {
        /// Current canonical head, if any.
        #[serde(skip_serializing_if = "Option::is_none")]
        canonical_head: Option<ObjectId>,
        /// Current canonical sequence number, if the head object resolves.
        #[serde(skip_serializing_if = "Option::is_none")]
        canonical_seq: Option<u64>,
    },
}

/// Connector-state change kind emitted by canonical storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorStateChangeKind {
    /// A root was created or advanced.
    RootUpdated,
    /// A chain object was appended.
    ObjectAppended,
    /// A snapshot was emitted.
    SnapshotEmitted,
    /// Older objects were compacted or marked eligible for collection.
    Compacted,
}

/// Connector-state change notification for cache invalidation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorStateChange {
    /// Connector whose state changed.
    pub connector_id: ConnectorId,
    /// Optional connector instance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,
    /// Zone containing the changed state.
    pub zone_id: ZoneId,
    /// Change kind.
    pub kind: ConnectorStateChangeKind,
    /// Object associated with the change, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_id: Option<ObjectId>,
    /// Sequence associated with the change, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// Observation timestamp in UNIX seconds.
    pub observed_at: u64,
}

/// Stream of connector-state change notifications.
pub type ConnectorStateChangeStream =
    Pin<Box<dyn Stream<Item = Result<ConnectorStateChange, ConnectorStateError>> + Send + 'static>>;

/// Errors surfaced by canonical connector-state storage.
#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum ConnectorStateError {
    /// Canonical state could not be read or written.
    #[error("connector state storage unavailable for {connector_id}: {reason}")]
    StorageUnavailable {
        /// Connector whose state operation failed.
        connector_id: ConnectorId,
        /// Redaction-safe failure detail.
        reason: String,
    },
    /// The append lost a prev-pointer race against the canonical head.
    #[error("connector state conflict; canonical head is {canonical_head:?}")]
    Conflict {
        /// Canonical head at the time of conflict.
        canonical_head: Option<ObjectId>,
    },
    /// The state payload or object envelope was malformed.
    #[error("malformed connector state for {connector_id}: {reason}")]
    MalformedState {
        /// Connector whose state failed validation.
        connector_id: ConnectorId,
        /// Redaction-safe validation detail.
        reason: String,
    },
    /// A caller lacked authority to mutate or read connector state.
    #[error("connector state authorization denied for {connector_id}: {reason}")]
    AuthorizationDenied {
        /// Connector whose state operation was denied.
        connector_id: ConnectorId,
        /// Redaction-safe denial detail.
        reason: String,
    },
    /// No snapshot can be emitted or read for the requested connector.
    #[error("connector state snapshot unavailable for {connector_id}: {reason}")]
    SnapshotUnavailable {
        /// Connector whose snapshot was requested.
        connector_id: ConnectorId,
        /// Redaction-safe failure detail.
        reason: String,
    },
    /// Change subscription is unavailable.
    #[error("connector state subscription unavailable for {connector_id}: {reason}")]
    SubscribeUnavailable {
        /// Connector whose change stream was requested.
        connector_id: ConnectorId,
        /// Redaction-safe failure detail.
        reason: String,
    },
    /// A chain-read limit was invalid.
    #[error("invalid connector state read limit {limit}")]
    InvalidLimit {
        /// Supplied limit.
        limit: usize,
    },
}

/// Storage-backed summary of the current canonical connector-state chain.
///
/// This is the payload shape host/operator explain routes can expose when
/// they are wired to canonical fcp-store state instead of cache markers alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorStateCanonicalStatus {
    /// Connector represented by this status record.
    pub connector_id: ConnectorId,
    /// Optional connector instance represented by the root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,
    /// Zone that owns the canonical root, if one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<ZoneId>,
    /// State model declared by the canonical root, if one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<ConnectorStateModel>,
    /// Whether a canonical root currently exists.
    pub root_present: bool,
    /// Content-addressed root object id when the store can expose it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_object_id: Option<ObjectId>,
    /// Current canonical state-object head.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_object_id: Option<ObjectId>,
    /// Last committed canonical sequence number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_canonical_seq: Option<u64>,
    /// Root schema version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_schema_version: Option<u32>,
    /// Proven count of mesh replicas for the root object, when symbol
    /// distribution metadata was supplied by the backing store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mesh_replica_count: Option<usize>,
}

impl ConnectorStateCanonicalStatus {
    /// Build a missing-root status for a connector.
    #[must_use]
    pub const fn missing(connector_id: ConnectorId) -> Self {
        Self {
            connector_id,
            instance_id: None,
            zone_id: None,
            model: None,
            root_present: false,
            root_object_id: None,
            head_object_id: None,
            last_canonical_seq: None,
            state_schema_version: None,
            mesh_replica_count: None,
        }
    }

    /// Build a status from a canonical root and optional storage evidence.
    #[must_use]
    pub fn from_root(
        root_object_id: Option<ObjectId>,
        root: &ConnectorStateRoot,
        last_canonical_seq: Option<u64>,
        mesh_replica_count: Option<usize>,
    ) -> Self {
        Self {
            connector_id: root.connector_id.clone(),
            instance_id: root.instance_id.clone(),
            zone_id: Some(root.zone_id.clone()),
            model: Some(root.model.clone()),
            root_present: true,
            root_object_id,
            head_object_id: root.head,
            last_canonical_seq,
            state_schema_version: Some(root.state_schema_version),
            mesh_replica_count,
        }
    }
}

/// Canonical connector-state storage contract.
#[async_trait::async_trait]
pub trait ConnectorStateStore: Send + Sync + 'static {
    /// Read the current root for a connector.
    ///
    /// # Errors
    /// Returns [`ConnectorStateError`] if canonical storage cannot be queried.
    async fn read_root(
        &self,
        connector_id: &ConnectorId,
    ) -> Result<Option<ConnectorStateRoot>, ConnectorStateError>;

    /// Append a state-chain object with a verified write authorization witness.
    ///
    /// # Errors
    /// Returns [`ConnectorStateError`] if the object is malformed, unauthorized,
    /// or canonical storage cannot persist it.
    async fn append_object(
        &self,
        connector_id: &ConnectorId,
        authorization: &ConnectorStateWriteAuthorization,
        object: ConnectorStateObject,
    ) -> Result<ConnectorStateAppendOutcome, ConnectorStateError>;

    /// Read chain objects after `after_seq`, up to `limit`.
    ///
    /// # Errors
    /// Returns [`ConnectorStateError`] if canonical storage cannot read the chain.
    async fn read_chain(
        &self,
        connector_id: &ConnectorId,
        after_seq: Option<u64>,
        limit: usize,
    ) -> Result<Vec<ConnectorStateObject>, ConnectorStateError>;

    /// Return a storage-backed summary of the current canonical chain.
    ///
    /// Store implementations that know root object ids or mesh replica counts
    /// should override this default. The fallback is intentionally conservative:
    /// it reports root/head/schema/seq only from the trait read APIs and leaves
    /// storage-specific fields unset.
    ///
    /// # Errors
    /// Returns [`ConnectorStateError`] if canonical storage cannot be queried.
    async fn canonical_status(
        &self,
        connector_id: &ConnectorId,
    ) -> Result<ConnectorStateCanonicalStatus, ConnectorStateError> {
        let Some(root) = self.read_root(connector_id).await? else {
            return Ok(ConnectorStateCanonicalStatus::missing(connector_id.clone()));
        };
        let last_canonical_seq = if root.head.is_some() {
            self.read_chain(connector_id, None, usize::MAX)
                .await?
                .last()
                .map(|state| state.seq)
        } else {
            None
        };
        Ok(ConnectorStateCanonicalStatus::from_root(
            None,
            &root,
            last_canonical_seq,
            None,
        ))
    }

    /// Emit and return a snapshot for the connector's current head.
    ///
    /// # Errors
    /// Returns [`ConnectorStateError`] if the connector has no snapshot-able
    /// state or canonical storage cannot persist the snapshot.
    async fn snapshot(
        &self,
        connector_id: &ConnectorId,
    ) -> Result<ConnectorStateSnapshot, ConnectorStateError>;

    /// Compact chain objects before `before_seq`.
    ///
    /// # Errors
    /// Returns [`ConnectorStateError`] if canonical storage cannot compact state.
    async fn compact(
        &self,
        connector_id: &ConnectorId,
        before_seq: u64,
    ) -> Result<usize, ConnectorStateError>;

    /// Subscribe to canonical-state changes for cross-host cache invalidation.
    ///
    /// # Errors
    /// Returns [`ConnectorStateError`] if the mesh-gossip backed stream is unavailable.
    async fn subscribe_changes(
        &self,
        connector_id: &ConnectorId,
    ) -> Result<ConnectorStateChangeStream, ConnectorStateError>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Cursor State Schema (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical cursor state payload for polling connectors (NORMATIVE).
///
/// This struct defines the canonical schema stored inside
/// [`ConnectorStateObject::state_cbor`] for cursor/offset-based polling.
///
/// # Monotonicity Rules
/// - `offset` MUST be monotonic (non-decreasing).
/// - `watermark` MUST be monotonic if used (typically a Unix timestamp).
/// - `last_seen_id` SHOULD only advance forward (connector-specific ordering).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorState {
    /// Numeric offset (e.g., `update_id` + 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,

    /// Last seen identifier (e.g., message id, history id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_id: Option<String>,

    /// Watermark timestamp (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watermark: Option<u64>,
}

impl CursorState {
    /// Encode this cursor state as canonical CBOR (no schema hash prefix).
    ///
    /// # Errors
    /// Returns a [`SerializationError`] if canonical CBOR encoding fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, SerializationError> {
        to_canonical_cbor(self)
    }

    /// Decode cursor state from canonical CBOR.
    ///
    /// # Errors
    /// Returns a [`SerializationError`] if decoding fails, if trailing bytes are
    /// present, if the encoding is not canonical, or if the input exceeds
    /// [`MAX_CURSOR_STATE_BYTES`].
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, SerializationError> {
        if bytes.len() > MAX_CURSOR_STATE_BYTES {
            return Err(SerializationError::PayloadTooLarge {
                len: bytes.len(),
                max: MAX_CURSOR_STATE_BYTES,
            });
        }
        let mut reader = bytes;
        let decoded: Self = ciborium::de::from_reader(&mut reader)?;
        if !reader.is_empty() {
            return Err(SerializationError::TrailingBytes);
        }

        let canonical = to_canonical_cbor(&decoded)?;
        if canonical != bytes {
            return Err(SerializationError::NonCanonicalEncoding);
        }

        Ok(decoded)
    }
}

/// Decode a cursor state from a connector state object.
///
/// # Errors
/// Returns a [`SerializationError`] if the embedded `state_cbor` is invalid.
pub fn cursor_state_from_object(
    state_obj: &ConnectorStateObject,
) -> Result<CursorState, SerializationError> {
    CursorState::from_cbor(&state_obj.state_cbor)
}

// ─────────────────────────────────────────────────────────────────────────────
// Computation Migration (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Explicit migration state machine for movable computations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum MigratableComputationState {
    /// Computation is actively executing on the current holder.
    Running,
    /// Computation is quiesced at a checkpoint and may resume locally.
    Suspended,
    /// Lease ownership has been transferred but the target has not resumed yet.
    Transferring {
        target_holder: TailscaleNodeId,
        next_lease_id: LeaseId,
        next_fencing_token: u64,
    },
    /// Computation finished successfully.
    Completed,
    /// Computation terminated with an unrecoverable failure.
    Failed,
}

impl MigratableComputationState {
    /// Returns true when the computation can no longer resume.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

/// Canonical migration state tracked across suspend, handoff, and resume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigratableComputation {
    /// Stable object identity for the computation itself.
    pub computation_id: ObjectId,
    /// Zone boundary the computation is constrained to.
    pub zone_id: ZoneId,
    /// Holder that most recently executed the computation.
    pub current_holder: TailscaleNodeId,
    /// Explicit migration state machine.
    pub state: MigratableComputationState,
    /// Last durable checkpoint object, if one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_object_id: Option<ObjectId>,
    /// Lease authorizing the current holder.
    pub execution_lease_id: LeaseId,
    /// Fencing token tied to the current lease/checkpoint.
    pub lease_fencing_token: u64,
    /// Minimal authority binding for safe resumption.
    pub capability_context: MigrationCapabilityContext,
}

impl MigratableComputation {
    /// Create a new running computation with an active execution lease.
    #[must_use]
    pub const fn new(
        computation_id: ObjectId,
        zone_id: ZoneId,
        current_holder: TailscaleNodeId,
        execution_lease_id: LeaseId,
        lease_fencing_token: u64,
        capability_context: MigrationCapabilityContext,
    ) -> Self {
        Self {
            computation_id,
            zone_id,
            current_holder,
            state: MigratableComputationState::Running,
            checkpoint_object_id: None,
            execution_lease_id,
            lease_fencing_token,
            capability_context,
        }
    }

    fn validate_checkpoint_binding(
        &self,
        checkpoint: &ComputationCheckpoint,
        checkpoint_object_id: ObjectId,
    ) -> Result<(), ComputationMigrationError> {
        let derived_checkpoint_object_id = checkpoint.object_id()?;
        if derived_checkpoint_object_id != checkpoint_object_id {
            return Err(ComputationMigrationError::CheckpointObjectMismatch {
                expected: Some(derived_checkpoint_object_id),
                got: checkpoint_object_id,
            });
        }

        if checkpoint.computation_id != self.computation_id {
            return Err(ComputationMigrationError::CheckpointComputationMismatch {
                expected: self.computation_id,
                got: checkpoint.computation_id,
            });
        }

        if checkpoint.zone_id() != &self.zone_id {
            return Err(ComputationMigrationError::CheckpointZoneMismatch {
                expected: self.zone_id.clone(),
                got: checkpoint.zone_id().clone(),
            });
        }

        if checkpoint.current_holder != self.current_holder {
            return Err(ComputationMigrationError::CheckpointHolderMismatch {
                expected: self.current_holder.clone(),
                got: checkpoint.current_holder.clone(),
            });
        }

        if checkpoint.lease_id != self.execution_lease_id {
            return Err(ComputationMigrationError::CheckpointLeaseIdMismatch {
                expected: self.execution_lease_id,
                got: checkpoint.lease_id,
            });
        }

        if checkpoint.lease_fencing_token != self.lease_fencing_token {
            return Err(ComputationMigrationError::CheckpointFenceMismatch {
                expected: self.lease_fencing_token,
                got: checkpoint.lease_fencing_token,
            });
        }

        if checkpoint.capability_context.capability_token_jti
            != self.capability_context.capability_token_jti
        {
            return Err(ComputationMigrationError::CapabilityTokenMismatch {
                expected: self.capability_context.capability_token_jti,
                got: checkpoint.capability_context.capability_token_jti,
            });
        }

        if self
            .checkpoint_object_id
            .is_some_and(|expected| expected != checkpoint_object_id)
        {
            return Err(ComputationMigrationError::CheckpointObjectMismatch {
                expected: self.checkpoint_object_id,
                got: checkpoint_object_id,
            });
        }

        Ok(())
    }

    /// Suspend a running computation onto a durable checkpoint.
    ///
    /// # Errors
    /// Returns a [`ComputationMigrationError`] if the state transition is invalid or the
    /// checkpoint does not bind to the current computation/lease.
    pub fn suspend(
        &mut self,
        checkpoint: &ComputationCheckpoint,
        checkpoint_object_id: ObjectId,
    ) -> Result<(), ComputationMigrationError> {
        if self.state != MigratableComputationState::Running {
            return Err(ComputationMigrationError::InvalidStateTransition {
                state: self.state.clone(),
                action: "suspend",
            });
        }

        self.validate_checkpoint_binding(checkpoint, checkpoint_object_id)?;
        self.state = MigratableComputationState::Suspended;
        self.checkpoint_object_id = Some(checkpoint_object_id);
        self.capability_context = checkpoint.capability_context.clone();
        self.capability_context.checkpoint_id = Some(checkpoint_object_id);
        self.capability_context.checkpoint_seq = checkpoint.checkpoint_seq;
        Ok(())
    }

    /// Begin a migration handoff after a computation has been suspended.
    ///
    /// # Errors
    /// Returns a [`ComputationMigrationError`] if the computation is not suspended,
    /// the handoff references the wrong prior lease, or lease handoff validation fails.
    pub fn begin_transfer(
        &mut self,
        active_lease: &Lease,
        handoff: &LeaseHandoff,
        now: u64,
    ) -> Result<(), ComputationMigrationError> {
        if self.state != MigratableComputationState::Suspended {
            return Err(ComputationMigrationError::InvalidStateTransition {
                state: self.state.clone(),
                action: "begin_transfer",
            });
        }

        if handoff.previous_lease_id != self.execution_lease_id {
            return Err(ComputationMigrationError::UnexpectedPriorLeaseId {
                expected: self.execution_lease_id,
                got: handoff.previous_lease_id,
            });
        }

        validate_lease_handoff(active_lease, handoff, now)?;
        self.state = MigratableComputationState::Transferring {
            target_holder: handoff.to_holder.clone(),
            next_lease_id: handoff.next_lease_id,
            next_fencing_token: handoff.next_fencing_token,
        };
        Ok(())
    }

    /// Resume a suspended or transferred computation using a validated lease.
    ///
    /// # Errors
    /// Returns a [`ComputationMigrationError`] if checkpoint bindings fail, the
    /// computation is in the wrong state, or the lease/holder does not match the
    /// expected resumption authority.
    pub fn resume(
        &mut self,
        checkpoint: &ComputationCheckpoint,
        checkpoint_object_id: ObjectId,
        resumed_lease_id: LeaseId,
        resumed_lease: &Lease,
        now: u64,
    ) -> Result<(), ComputationMigrationError> {
        self.validate_checkpoint_binding(checkpoint, checkpoint_object_id)?;

        match &self.state {
            MigratableComputationState::Suspended => {
                validate_lease(
                    resumed_lease,
                    &self.computation_id,
                    &self.zone_id,
                    LeasePurpose::ComputationMigration,
                    self.lease_fencing_token,
                    now,
                    0,
                )?;

                if resumed_lease_id != self.execution_lease_id {
                    return Err(ComputationMigrationError::ResumeLeaseIdMismatch {
                        expected: self.execution_lease_id,
                        got: resumed_lease_id,
                    });
                }

                if resumed_lease.holder != self.current_holder {
                    return Err(ComputationMigrationError::ResumeHolderMismatch {
                        expected: self.current_holder.clone(),
                        got: resumed_lease.holder.clone(),
                    });
                }

                if resumed_lease.fencing_token() != self.lease_fencing_token {
                    return Err(ComputationMigrationError::ResumeFenceMismatch {
                        expected: self.lease_fencing_token,
                        got: resumed_lease.fencing_token(),
                    });
                }
            }
            MigratableComputationState::Transferring {
                target_holder,
                next_lease_id,
                next_fencing_token,
            } => {
                validate_lease(
                    resumed_lease,
                    &self.computation_id,
                    &self.zone_id,
                    LeasePurpose::ComputationMigration,
                    *next_fencing_token,
                    now,
                    0,
                )?;

                if resumed_lease_id != *next_lease_id {
                    return Err(ComputationMigrationError::ResumeLeaseIdMismatch {
                        expected: *next_lease_id,
                        got: resumed_lease_id,
                    });
                }

                if resumed_lease.holder != *target_holder {
                    return Err(ComputationMigrationError::ResumeHolderMismatch {
                        expected: target_holder.clone(),
                        got: resumed_lease.holder.clone(),
                    });
                }

                if resumed_lease.fencing_token() != *next_fencing_token {
                    return Err(ComputationMigrationError::ResumeFenceMismatch {
                        expected: *next_fencing_token,
                        got: resumed_lease.fencing_token(),
                    });
                }

                self.current_holder = target_holder.clone();
                self.execution_lease_id = *next_lease_id;
                self.lease_fencing_token = *next_fencing_token;
            }
            _ => {
                return Err(ComputationMigrationError::InvalidStateTransition {
                    state: self.state.clone(),
                    action: "resume",
                });
            }
        }

        self.state = MigratableComputationState::Running;
        self.checkpoint_object_id = Some(checkpoint_object_id);
        self.capability_context = checkpoint.capability_context.clone();
        self.capability_context.checkpoint_id = Some(checkpoint_object_id);
        self.capability_context.checkpoint_seq = checkpoint.checkpoint_seq;
        Ok(())
    }
}

/// Durable boundary that a target must validate before resuming a computation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeBoundary {
    /// Subject being resumed.
    pub subject_id: ObjectId,
    /// Canonical checkpoint object that anchors the resume attempt.
    pub checkpoint_object_id: ObjectId,
    /// Monotonic checkpoint sequence used for rollback detection.
    pub checkpoint_seq: u64,
    /// Durable state object referenced by the checkpoint, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_object_id: Option<ObjectId>,
    /// Receipt lineage head referenced by the checkpoint, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_head: Option<ObjectId>,
    /// Lease object bound to the checkpoint.
    pub lease_object_id: LeaseId,
    /// Lease fencing token bound to the checkpoint.
    pub lease_fencing_token: u64,
    /// Capability token JTI proving the authority context under which the checkpoint was taken.
    pub capability_token_jti: Uuid,
}

impl ResumeBoundary {
    /// Build a durable resume boundary from a canonical checkpoint.
    ///
    /// # Errors
    /// Returns a [`ComputationMigrationError`] when the provided object id does not match the
    /// checkpoint's canonical bytes.
    pub fn from_checkpoint(
        checkpoint: &ComputationCheckpoint,
        checkpoint_object_id: ObjectId,
        state_object_id: Option<ObjectId>,
        receipt_head: Option<ObjectId>,
    ) -> Result<Self, ComputationMigrationError> {
        let derived_object_id = checkpoint.object_id()?;
        if derived_object_id != checkpoint_object_id {
            return Err(ComputationMigrationError::CheckpointObjectMismatch {
                expected: Some(derived_object_id),
                got: checkpoint_object_id,
            });
        }

        Ok(Self {
            subject_id: checkpoint.computation_id,
            checkpoint_object_id,
            checkpoint_seq: checkpoint.checkpoint_seq,
            state_object_id,
            receipt_head,
            lease_object_id: checkpoint.lease_id,
            lease_fencing_token: checkpoint.lease_fencing_token,
            capability_token_jti: checkpoint.capability_context.capability_token_jti,
        })
    }

    /// Assess whether this boundary is stale relative to the current durable lineage.
    #[must_use]
    pub fn assess_freshness(
        &self,
        current_checkpoint_seq: u64,
        current_lease_id: LeaseId,
        current_lease_fencing_token: u64,
    ) -> CheckpointFreshness {
        if self.checkpoint_seq < current_checkpoint_seq {
            return CheckpointFreshness::StaleCheckpoint {
                candidate_checkpoint_seq: self.checkpoint_seq,
                current_checkpoint_seq,
            };
        }

        if self.lease_fencing_token < current_lease_fencing_token {
            return CheckpointFreshness::StaleLease {
                candidate_lease_id: self.lease_object_id,
                current_lease_id,
                candidate_fencing_token: self.lease_fencing_token,
                current_fencing_token: current_lease_fencing_token,
            };
        }

        if self.lease_fencing_token == current_lease_fencing_token
            && self.lease_object_id != current_lease_id
        {
            return CheckpointFreshness::EvidenceConflict {
                checkpoint_lease_id: self.lease_object_id,
                current_lease_id,
                checkpoint_fencing_token: self.lease_fencing_token,
                current_fencing_token: current_lease_fencing_token,
            };
        }

        CheckpointFreshness::Fresh
    }
}

/// Freshness classification for a checkpoint boundary before resume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CheckpointFreshness {
    /// The checkpoint is current enough to participate in resume.
    Fresh,
    /// A newer checkpoint sequence exists and this checkpoint would roll progress back.
    StaleCheckpoint {
        /// Candidate checkpoint sequence.
        candidate_checkpoint_seq: u64,
        /// Current durable checkpoint sequence.
        current_checkpoint_seq: u64,
    },
    /// The checkpoint was taken under a superseded lease lineage.
    StaleLease {
        /// Lease bound to the candidate checkpoint.
        candidate_lease_id: LeaseId,
        /// Lease currently considered authoritative.
        current_lease_id: LeaseId,
        /// Fencing token bound to the candidate checkpoint.
        candidate_fencing_token: u64,
        /// Current authoritative fencing token.
        current_fencing_token: u64,
    },
    /// The checkpoint and current lease lineage disagree in a way that cannot be ordered safely.
    EvidenceConflict {
        /// Lease bound to the candidate checkpoint.
        checkpoint_lease_id: LeaseId,
        /// Lease currently considered authoritative.
        current_lease_id: LeaseId,
        /// Fencing token bound to the candidate checkpoint.
        checkpoint_fencing_token: u64,
        /// Current authoritative fencing token.
        current_fencing_token: u64,
    },
}

impl CheckpointFreshness {
    /// Whether this freshness result allows resume to proceed.
    #[must_use]
    pub const fn allows_resume(&self) -> bool {
        matches!(self, Self::Fresh)
    }

    /// Human-readable explanation of this freshness result.
    #[must_use]
    pub fn explanation(&self) -> String {
        match self {
            Self::Fresh => {
                "checkpoint boundary is fresh relative to the current lineage".to_string()
            }
            Self::StaleCheckpoint {
                candidate_checkpoint_seq,
                current_checkpoint_seq,
            } => format!(
                "checkpoint sequence {candidate_checkpoint_seq} is stale; current sequence is {current_checkpoint_seq}"
            ),
            Self::StaleLease {
                candidate_lease_id,
                current_lease_id,
                candidate_fencing_token,
                current_fencing_token,
            } => format!(
                "checkpoint lease {candidate_lease_id} fence {candidate_fencing_token} is stale; current lease {current_lease_id} fence {current_fencing_token}"
            ),
            Self::EvidenceConflict {
                checkpoint_lease_id,
                current_lease_id,
                checkpoint_fencing_token,
                current_fencing_token,
            } => format!(
                "checkpoint lease {checkpoint_lease_id} fence {checkpoint_fencing_token} conflicts with current lease {current_lease_id} fence {current_fencing_token}"
            ),
        }
    }
}

/// Why a computation is being resumed on the current node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeCause {
    /// Source node intentionally drained and handed control to the target.
    PlannedHandoff,
    /// Another node is taking over after a failure or placement change.
    Failover,
    /// The same node is recovering after a local crash or restart.
    CrashRecovery,
    /// An operator forced a repair or resume attempt.
    OperatorRepair,
}

impl ResumeCause {
    /// Stable label for logs and evidence.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::PlannedHandoff => "planned_handoff",
            Self::Failover => "failover",
            Self::CrashRecovery => "crash_recovery",
            Self::OperatorRepair => "operator_repair",
        }
    }
}

/// Duplicate-delivery classification that constrains replay behavior after resume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DuplicateDeliveryClass {
    /// No conflicting prior effect has been observed.
    Fresh,
    /// Prior work already committed and resume must attach to it.
    DuplicateCommitted,
    /// Retry is safe because prior work did not commit.
    ReplaySafeRetry,
    /// External state may have advanced without enough proof to replay safely.
    AmbiguousExternal,
    /// Durable evidence objects disagree and require operator attention.
    EvidenceConflict,
}

impl DuplicateDeliveryClass {
    /// Stable label for logs and evidence.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::DuplicateCommitted => "duplicate_committed",
            Self::ReplaySafeRetry => "replay_safe_retry",
            Self::AmbiguousExternal => "ambiguous_external",
            Self::EvidenceConflict => "evidence_conflict",
        }
    }
}

/// Recommended connector-state recovery action when observed state drifts from intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorRecoveryAction {
    /// Restart the connector runtime.
    RestartConnector,
    /// Repair configuration or health before retrying.
    RepairConnector,
    /// Reinstall or restore connector artifacts.
    ReinstallConnector,
    /// Finish an in-flight rollout decision.
    CompleteRollout,
    /// Disable or uninstall the connector to match policy.
    DisableConnector,
    /// Manual operator investigation is required.
    Investigate,
}

impl ConnectorRecoveryAction {
    /// Stable label for logs, evidence, and operator surfaces.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RestartConnector => "restart_connector",
            Self::RepairConnector => "repair_connector",
            Self::ReinstallConnector => "reinstall_connector",
            Self::CompleteRollout => "complete_rollout",
            Self::DisableConnector => "disable_connector",
            Self::Investigate => "investigate",
        }
    }
}

impl std::fmt::Display for ConnectorRecoveryAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Chosen disposition once prior work has been classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeDisposition {
    /// Attach to an already-committed result.
    Attach,
    /// Retry execution safely.
    Retry,
    /// Deny automatic continuation.
    Deny,
    /// Perform a repair or reconciliation flow first.
    Reconcile,
}

impl ResumeDisposition {
    /// Stable label for logs and evidence.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Attach => "attach",
            Self::Retry => "retry",
            Self::Deny => "deny",
            Self::Reconcile => "reconcile",
        }
    }
}

/// Final outcome of a resume attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeOutcome {
    /// Resume completed and execution may continue.
    Accepted,
    /// Resume was rejected and execution must remain stopped.
    Denied,
}

/// Export mode used to carry a checkpoint between nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointExportEncoding {
    /// Checkpoint bytes are carried inline.
    Inline,
    /// Checkpoint bytes are carried as ordered chunks.
    Chunked,
}

impl CheckpointExportEncoding {
    /// Stable label for logs and evidence.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::Chunked => "chunked",
        }
    }
}

/// Lease lineage spanning the source and resumed execution sites.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeLeaseLineage {
    /// Holder that produced the checkpoint.
    pub prior_holder: TailscaleNodeId,
    /// Holder that attempted or completed the resume.
    pub resumed_holder: TailscaleNodeId,
    /// Lease that authorized the checkpoint.
    pub prior_lease_id: LeaseId,
    /// Lease under which the target attempted or completed resume.
    pub resumed_lease_id: LeaseId,
    /// Fencing token bound to the checkpoint.
    pub prior_fencing_token: u64,
    /// Fencing token under which the target attempted or completed resume.
    pub resumed_fencing_token: u64,
}

/// Reason code for timeline events emitted during checkpoint export, handoff, and resume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeReasonCode {
    /// Checkpoint bytes were exported into a transfer encoding.
    CheckpointExported,
    /// A lease handoff was authorized for the exported checkpoint.
    HandoffAuthorized,
    /// The checkpoint boundary is current enough for resume.
    CheckpointFresh,
    /// The checkpoint boundary is stale and cannot be trusted as-is.
    CheckpointStale,
    /// Prior work classification completed.
    DuplicateClassified,
    /// Resume completed successfully.
    ResumeAccepted,
    /// Resume was denied due to lease or state validation.
    ResumeDenied,
    /// Durable evidence objects disagree and require reconciliation.
    EvidenceConflict,
}

/// Deterministic timeline event emitted for handoff and resume artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeTimelineEvent {
    /// Observation timestamp in milliseconds since epoch.
    pub observed_at_ms: u64,
    /// Event operation label.
    pub operation: String,
    /// Explanation category.
    pub reason_code: ResumeReasonCode,
    /// Canonical checkpoint object under discussion.
    pub checkpoint_object_id: ObjectId,
    /// Checkpoint sequence under discussion.
    pub checkpoint_seq: u64,
    /// Holder associated with the event when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<TailscaleNodeId>,
    /// Lease associated with the event when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_object_id: Option<LeaseId>,
    /// Fencing token associated with the event when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_fencing_token: Option<u64>,
    /// Human-readable explanation.
    pub explanation: String,
}

/// Canonical metadata for a checkpoint that has been prepared for transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointExportArtifact {
    /// Boundary that the target must validate before resuming.
    pub boundary: ResumeBoundary,
    /// Holder that produced the exported checkpoint.
    pub current_holder: TailscaleNodeId,
    /// Transfer encoding used to carry the checkpoint.
    pub encoding: CheckpointExportEncoding,
    /// Canonical payload length in bytes.
    pub total_bytes: u64,
    /// Number of payload chunks represented by the export.
    pub chunk_count: usize,
    /// Audit lineage bound to the checkpoint when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_event_id: Option<ObjectId>,
}

impl CheckpointExportArtifact {
    /// Capture canonical export metadata from a checkpoint and transfer encoding.
    ///
    /// # Errors
    /// Returns a [`ComputationMigrationError`] when the checkpoint object id or transfer encoding
    /// disagree with the canonical checkpoint bytes.
    pub fn from_transfer_encoding(
        checkpoint: &ComputationCheckpoint,
        checkpoint_object_id: ObjectId,
        transfer_encoding: &CheckpointTransferEncoding,
        state_object_id: Option<ObjectId>,
        receipt_head: Option<ObjectId>,
    ) -> Result<Self, ComputationMigrationError> {
        let boundary = ResumeBoundary::from_checkpoint(
            checkpoint,
            checkpoint_object_id,
            state_object_id,
            receipt_head,
        )?;
        if transfer_encoding.object_id() != checkpoint_object_id {
            return Err(ComputationMigrationError::CheckpointObjectMismatch {
                expected: Some(transfer_encoding.object_id()),
                got: checkpoint_object_id,
            });
        }

        let (encoding, total_bytes, chunk_count) = match transfer_encoding {
            CheckpointTransferEncoding::Inline {
                canonical_bytes, ..
            } => (
                CheckpointExportEncoding::Inline,
                u64::try_from(canonical_bytes.len()).unwrap_or(u64::MAX),
                1,
            ),
            CheckpointTransferEncoding::Chunked(chunked) => (
                CheckpointExportEncoding::Chunked,
                chunked.manifest.total_bytes,
                chunked.manifest.chunk_count(),
            ),
        };

        Ok(Self {
            boundary,
            current_holder: checkpoint.current_holder.clone(),
            encoding,
            total_bytes,
            chunk_count,
            audit_event_id: checkpoint.capability_context.audit_event_id,
        })
    }
}

/// Inputs required to capture a handoff artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffArtifactInputs {
    /// Durable state object referenced by the checkpoint, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_object_id: Option<ObjectId>,
    /// Receipt lineage head referenced by the checkpoint, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_head: Option<ObjectId>,
    /// Why the target will be resuming this computation.
    pub resume_cause: ResumeCause,
    /// Timestamp in milliseconds used for deterministic timeline emission.
    pub observed_at_ms: u64,
}

/// Canonical artifact emitted once a checkpoint is exported and paired with a lease handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointHandoffArtifact {
    /// Zone in which the handoff is valid.
    pub zone_id: ZoneId,
    /// Subject being migrated.
    pub subject_id: ObjectId,
    /// Exported checkpoint metadata.
    pub export: CheckpointExportArtifact,
    /// Lease lineage from source holder to target holder.
    pub lease_lineage: ResumeLeaseLineage,
    /// Why the target is expected to resume this computation.
    pub resume_cause: ResumeCause,
    /// Unix timestamp when the handoff was authorized.
    pub transferred_at: u64,
    /// Deterministic event timeline for later assertions.
    pub timeline: Vec<ResumeTimelineEvent>,
}

impl CheckpointHandoffArtifact {
    /// Capture a canonical handoff artifact after a computation enters the transferring state.
    ///
    /// # Errors
    /// Returns a [`ComputationMigrationError`] when the checkpoint binding, transfer encoding, or
    /// handoff lineage do not match the current migration state.
    #[allow(clippy::too_many_lines)]
    pub fn capture(
        computation: &MigratableComputation,
        checkpoint: &ComputationCheckpoint,
        checkpoint_object_id: ObjectId,
        transfer_encoding: &CheckpointTransferEncoding,
        handoff: &LeaseHandoff,
        inputs: &HandoffArtifactInputs,
    ) -> Result<Self, ComputationMigrationError> {
        computation.validate_checkpoint_binding(checkpoint, checkpoint_object_id)?;
        let export = CheckpointExportArtifact::from_transfer_encoding(
            checkpoint,
            checkpoint_object_id,
            transfer_encoding,
            inputs.state_object_id,
            inputs.receipt_head,
        )?;

        if handoff.previous_lease_id != computation.execution_lease_id {
            return Err(ComputationMigrationError::UnexpectedPriorLeaseId {
                expected: computation.execution_lease_id,
                got: handoff.previous_lease_id,
            });
        }
        if handoff.checkpoint_object_id != Some(checkpoint_object_id) {
            return Err(ComputationMigrationError::HandoffCheckpointMismatch {
                expected: checkpoint_object_id,
                got: handoff.checkpoint_object_id,
            });
        }

        let (target_holder, next_lease_id, next_fencing_token) = match &computation.state {
            MigratableComputationState::Transferring {
                target_holder,
                next_lease_id,
                next_fencing_token,
            } => (target_holder, next_lease_id, next_fencing_token),
            state => {
                return Err(ComputationMigrationError::InvalidStateTransition {
                    state: state.clone(),
                    action: "capture_handoff_artifact",
                });
            }
        };

        if handoff.to_holder != *target_holder {
            return Err(ComputationMigrationError::HandoffTargetMismatch {
                expected: target_holder.clone(),
                got: handoff.to_holder.clone(),
            });
        }
        if handoff.next_lease_id != *next_lease_id {
            return Err(ComputationMigrationError::HandoffNextLeaseMismatch {
                expected: *next_lease_id,
                got: handoff.next_lease_id,
            });
        }
        if handoff.next_fencing_token != *next_fencing_token {
            return Err(ComputationMigrationError::HandoffNextFenceMismatch {
                expected: *next_fencing_token,
                got: handoff.next_fencing_token,
            });
        }

        let timeline = vec![
            ResumeTimelineEvent {
                observed_at_ms: inputs.observed_at_ms,
                operation: "checkpoint.exported".to_string(),
                reason_code: ResumeReasonCode::CheckpointExported,
                checkpoint_object_id,
                checkpoint_seq: checkpoint.checkpoint_seq,
                holder: Some(computation.current_holder.clone()),
                lease_object_id: Some(computation.execution_lease_id),
                lease_fencing_token: Some(computation.lease_fencing_token),
                explanation: format!(
                    "checkpoint exported as {} payload ({} bytes across {} chunk(s))",
                    export.encoding.label(),
                    export.total_bytes,
                    export.chunk_count,
                ),
            },
            ResumeTimelineEvent {
                observed_at_ms: inputs.observed_at_ms,
                operation: "handoff.authorized".to_string(),
                reason_code: ResumeReasonCode::HandoffAuthorized,
                checkpoint_object_id,
                checkpoint_seq: checkpoint.checkpoint_seq,
                holder: Some(handoff.to_holder.clone()),
                lease_object_id: Some(handoff.next_lease_id),
                lease_fencing_token: Some(handoff.next_fencing_token),
                explanation: format!(
                    "handoff authorized from {} to {} for resume cause {}",
                    handoff.from_holder.as_str(),
                    handoff.to_holder.as_str(),
                    inputs.resume_cause.label(),
                ),
            },
        ];

        Ok(Self {
            zone_id: computation.zone_id.clone(),
            subject_id: computation.computation_id,
            export,
            lease_lineage: ResumeLeaseLineage {
                prior_holder: computation.current_holder.clone(),
                resumed_holder: handoff.to_holder.clone(),
                prior_lease_id: computation.execution_lease_id,
                resumed_lease_id: handoff.next_lease_id,
                prior_fencing_token: computation.lease_fencing_token,
                resumed_fencing_token: handoff.next_fencing_token,
            },
            resume_cause: inputs.resume_cause,
            transferred_at: handoff.transferred_at,
            timeline,
        })
    }
}

/// Inputs required to evaluate a resume attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeEvidenceInputs {
    /// Durable state object referenced by the checkpoint, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_object_id: Option<ObjectId>,
    /// Receipt lineage head referenced by the checkpoint, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_head: Option<ObjectId>,
    /// Why this resume attempt is happening.
    pub resume_cause: ResumeCause,
    /// Duplicate-delivery classification consulted before reissuing work.
    pub duplicate_delivery_class: DuplicateDeliveryClass,
    /// Intended disposition if resume succeeds.
    pub disposition: ResumeDisposition,
    /// Timestamp in milliseconds used for deterministic timeline emission.
    pub observed_at_ms: u64,
}

/// Durable evidence emitted for a resume decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeEvidence {
    /// Zone in which the resume was attempted.
    pub zone_id: ZoneId,
    /// Subject being resumed.
    pub subject_id: ObjectId,
    /// Boundary that anchored the resume decision.
    pub boundary: ResumeBoundary,
    /// Lease lineage from the checkpoint producer to the attempted or successful resume site.
    pub lease_lineage: ResumeLeaseLineage,
    /// Why the resume attempt was performed.
    pub resume_cause: ResumeCause,
    /// Freshness assessment for the checkpoint boundary.
    pub freshness: CheckpointFreshness,
    /// Duplicate-delivery classification consulted before reissuing work.
    pub duplicate_delivery_class: DuplicateDeliveryClass,
    /// Final disposition selected for this attempt.
    pub disposition: ResumeDisposition,
    /// Whether the resume was accepted or denied.
    pub outcome: ResumeOutcome,
    /// Audit lineage bound to the checkpoint when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_event_id: Option<ObjectId>,
    /// Validation error captured when resume is denied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_error: Option<String>,
    /// Deterministic event timeline for later assertions.
    pub timeline: Vec<ResumeTimelineEvent>,
}

impl ResumeEvidence {
    /// Evaluate a resume attempt and emit durable evidence for the outcome.
    ///
    /// # Errors
    /// Returns a [`ComputationMigrationError`] when the checkpoint does not bind to the current
    /// computation state at all. Lease validation failures are encoded into the returned evidence.
    #[allow(clippy::too_many_lines)]
    pub fn evaluate(
        computation: &MigratableComputation,
        checkpoint: &ComputationCheckpoint,
        checkpoint_object_id: ObjectId,
        resumed_lease_id: LeaseId,
        resumed_lease: &Lease,
        now: u64,
        inputs: &ResumeEvidenceInputs,
    ) -> Result<Self, ComputationMigrationError> {
        computation.validate_checkpoint_binding(checkpoint, checkpoint_object_id)?;
        let boundary = ResumeBoundary::from_checkpoint(
            checkpoint,
            checkpoint_object_id,
            inputs.state_object_id,
            inputs.receipt_head,
        )?;
        let freshness = boundary.assess_freshness(
            computation.capability_context.checkpoint_seq,
            computation.execution_lease_id,
            computation.lease_fencing_token,
        );

        let mut attempt = computation.clone();
        let resume_result = attempt.resume(
            checkpoint,
            checkpoint_object_id,
            resumed_lease_id,
            resumed_lease,
            now,
        );

        let (outcome, disposition, validation_error, outcome_reason_code, outcome_explanation) =
            match resume_result {
                Ok(()) => (
                    ResumeOutcome::Accepted,
                    inputs.disposition,
                    None,
                    ResumeReasonCode::ResumeAccepted,
                    format!(
                        "resume accepted for holder {} under disposition {}",
                        attempt.current_holder.as_str(),
                        inputs.disposition.label(),
                    ),
                ),
                Err(err) => {
                    let reason_code =
                        if matches!(freshness, CheckpointFreshness::EvidenceConflict { .. }) {
                            ResumeReasonCode::EvidenceConflict
                        } else {
                            ResumeReasonCode::ResumeDenied
                        };
                    (
                        ResumeOutcome::Denied,
                        ResumeDisposition::Deny,
                        Some(err.to_string()),
                        reason_code,
                        err.to_string(),
                    )
                }
            };

        let freshness_reason_code = match freshness {
            CheckpointFreshness::Fresh => ResumeReasonCode::CheckpointFresh,
            CheckpointFreshness::EvidenceConflict { .. } => ResumeReasonCode::EvidenceConflict,
            CheckpointFreshness::StaleCheckpoint { .. }
            | CheckpointFreshness::StaleLease { .. } => ResumeReasonCode::CheckpointStale,
        };

        let timeline = vec![
            ResumeTimelineEvent {
                observed_at_ms: inputs.observed_at_ms,
                operation: "checkpoint.freshness_checked".to_string(),
                reason_code: freshness_reason_code,
                checkpoint_object_id,
                checkpoint_seq: checkpoint.checkpoint_seq,
                holder: Some(computation.current_holder.clone()),
                lease_object_id: Some(computation.execution_lease_id),
                lease_fencing_token: Some(computation.lease_fencing_token),
                explanation: freshness.explanation(),
            },
            ResumeTimelineEvent {
                observed_at_ms: inputs.observed_at_ms,
                operation: "resume.classified".to_string(),
                reason_code: ResumeReasonCode::DuplicateClassified,
                checkpoint_object_id,
                checkpoint_seq: checkpoint.checkpoint_seq,
                holder: Some(resumed_lease.holder.clone()),
                lease_object_id: Some(resumed_lease_id),
                lease_fencing_token: Some(resumed_lease.fencing_token()),
                explanation: format!(
                    "duplicate classification {} with intended disposition {}",
                    inputs.duplicate_delivery_class.label(),
                    inputs.disposition.label(),
                ),
            },
            ResumeTimelineEvent {
                observed_at_ms: inputs.observed_at_ms,
                operation: match outcome {
                    ResumeOutcome::Accepted => "resume.accepted".to_string(),
                    ResumeOutcome::Denied => "resume.denied".to_string(),
                },
                reason_code: outcome_reason_code,
                checkpoint_object_id,
                checkpoint_seq: checkpoint.checkpoint_seq,
                holder: Some(resumed_lease.holder.clone()),
                lease_object_id: Some(resumed_lease_id),
                lease_fencing_token: Some(resumed_lease.fencing_token()),
                explanation: outcome_explanation,
            },
        ];

        Ok(Self {
            zone_id: computation.zone_id.clone(),
            subject_id: computation.computation_id,
            boundary,
            lease_lineage: ResumeLeaseLineage {
                prior_holder: computation.current_holder.clone(),
                resumed_holder: resumed_lease.holder.clone(),
                prior_lease_id: computation.execution_lease_id,
                resumed_lease_id,
                prior_fencing_token: computation.lease_fencing_token,
                resumed_fencing_token: resumed_lease.fencing_token(),
            },
            resume_cause: inputs.resume_cause,
            freshness,
            duplicate_delivery_class: inputs.duplicate_delivery_class,
            disposition,
            outcome,
            audit_event_id: checkpoint.capability_context.audit_event_id,
            validation_error,
            timeline,
        })
    }
}

/// Errors produced while advancing the computation migration state machine.
#[derive(Debug, Error)]
pub enum ComputationMigrationError {
    #[error("cannot {action} while computation is in state {state:?}")]
    InvalidStateTransition {
        state: MigratableComputationState,
        action: &'static str,
    },
    #[error("checkpoint computation mismatch: expected {expected}, got {got}")]
    CheckpointComputationMismatch { expected: ObjectId, got: ObjectId },
    #[error("checkpoint zone mismatch: expected {expected}, got {got}")]
    CheckpointZoneMismatch { expected: ZoneId, got: ZoneId },
    #[error("checkpoint holder mismatch: expected {expected:?}, got {got:?}")]
    CheckpointHolderMismatch {
        expected: TailscaleNodeId,
        got: TailscaleNodeId,
    },
    #[error("checkpoint lease id mismatch: expected {expected}, got {got}")]
    CheckpointLeaseIdMismatch { expected: LeaseId, got: LeaseId },
    #[error("checkpoint fencing token mismatch: expected {expected}, got {got}")]
    CheckpointFenceMismatch { expected: u64, got: u64 },
    #[error("capability token mismatch: expected {expected}, got {got}")]
    CapabilityTokenMismatch { expected: Uuid, got: Uuid },
    #[error("checkpoint object mismatch: expected {expected:?}, got {got}")]
    CheckpointObjectMismatch {
        expected: Option<ObjectId>,
        got: ObjectId,
    },
    #[error("handoff referenced prior lease {got}, expected {expected}")]
    UnexpectedPriorLeaseId { expected: LeaseId, got: LeaseId },
    #[error("handoff checkpoint mismatch: expected {expected}, got {got:?}")]
    HandoffCheckpointMismatch {
        expected: ObjectId,
        got: Option<ObjectId>,
    },
    #[error("handoff target holder mismatch: expected {expected:?}, got {got:?}")]
    HandoffTargetMismatch {
        expected: TailscaleNodeId,
        got: TailscaleNodeId,
    },
    #[error("handoff next lease mismatch: expected {expected}, got {got}")]
    HandoffNextLeaseMismatch { expected: LeaseId, got: LeaseId },
    #[error("handoff next fencing token mismatch: expected {expected}, got {got}")]
    HandoffNextFenceMismatch { expected: u64, got: u64 },
    #[error("resume holder mismatch: expected {expected:?}, got {got:?}")]
    ResumeHolderMismatch {
        expected: TailscaleNodeId,
        got: TailscaleNodeId,
    },
    #[error("resume lease id mismatch: expected {expected}, got {got}")]
    ResumeLeaseIdMismatch { expected: LeaseId, got: LeaseId },
    #[error("resume fencing token mismatch: expected {expected}, got {got}")]
    ResumeFenceMismatch { expected: u64, got: u64 },
    #[error(transparent)]
    CheckpointEncoding(#[from] SerializationError),
    #[error(transparent)]
    LeaseValidation(#[from] LeaseValidationError),
    #[error(transparent)]
    LeaseTransfer(#[from] LeaseTransferValidationError),
}

// ─────────────────────────────────────────────────────────────────────────────
// Fork Detection (NORMATIVE for SingletonWriter)
// ─────────────────────────────────────────────────────────────────────────────

/// Fork event indicating competing writes (NORMATIVE).
///
/// A fork occurs when two different `ConnectorStateObject` share the same `prev`
/// (competing sequence numbers). This indicates a lease violation or bug.
///
/// # Recovery Protocol
///
/// 1. Pause connector execution immediately
/// 2. Log the fork event for audit
/// 3. Require manual resolution OR automated "choose-by-lease" recovery
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkEvent {
    /// The common predecessor.
    pub common_prev: ObjectId,

    /// First competing state object.
    pub branch_a: ObjectId,

    /// Second competing state object.
    pub branch_b: ObjectId,

    /// Sequence number at which the fork occurred.
    pub fork_seq: u64,

    /// Timestamp when the fork was detected (UNIX seconds).
    pub detected_at: u64,

    /// Zone in which the fork occurred.
    pub zone_id: ZoneId,

    /// Connector that experienced the fork.
    pub connector_id: ConnectorId,
}

/// Fork resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkResolution {
    /// Choose the branch with the higher `lease_seq`.
    ChooseByLease,

    /// Require manual intervention.
    ManualResolution,

    /// Merge both branches (only valid for CRDT state).
    CrdtMerge,
}

impl fmt::Display for ForkResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ChooseByLease => "choose_by_lease",
            Self::ManualResolution => "manual_resolution",
            Self::CrdtMerge => "crdt_merge",
        };
        f.write_str(label)
    }
}

impl ForkResolution {
    /// Check if this resolution strategy is valid for the given state model.
    #[must_use]
    pub const fn is_valid_for(&self, model: &ConnectorStateModel) -> bool {
        match self {
            Self::ChooseByLease => model.is_singleton_writer(),
            Self::ManualResolution => true, // Always valid
            Self::CrdtMerge => model.is_crdt(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fork Detection and Resolution (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Result of fork detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateForkDetectionResult {
    /// No fork detected; single consistent head.
    NoFork {
        /// Current head object ID.
        head: ObjectId,
        /// Current sequence number.
        seq: u64,
    },
    /// Fork detected with competing heads.
    ForkDetected(ForkEvent),
}

impl StateForkDetectionResult {
    /// Returns true if a fork was detected.
    #[must_use]
    pub const fn is_fork(&self) -> bool {
        matches!(self, Self::ForkDetected(_))
    }

    /// Get fork event if one was detected.
    #[must_use]
    pub const fn fork_event(&self) -> Option<&ForkEvent> {
        match self {
            Self::ForkDetected(event) => Some(event),
            Self::NoFork { .. } => None,
        }
    }
}

impl ForkEvent {
    /// Create a new fork event.
    #[must_use]
    pub const fn new(
        common_prev: ObjectId,
        branch_a: ObjectId,
        branch_b: ObjectId,
        fork_seq: u64,
        detected_at: u64,
        zone_id: ZoneId,
        connector_id: ConnectorId,
    ) -> Self {
        Self {
            common_prev,
            branch_a,
            branch_b,
            fork_seq,
            detected_at,
            zone_id,
            connector_id,
        }
    }

    /// Determine the winning branch using lease-based resolution.
    ///
    /// Returns the object ID of the branch with the higher `lease_seq`.
    /// If `lease_seq` values are equal, returns `None` (requires manual resolution).
    #[must_use]
    pub fn resolve_by_lease(&self, lease_seq_a: u64, lease_seq_b: u64) -> Option<ObjectId> {
        use std::cmp::Ordering;
        match lease_seq_a.cmp(&lease_seq_b) {
            Ordering::Greater => Some(self.branch_a),
            Ordering::Less => Some(self.branch_b),
            Ordering::Equal => None, // Tie - requires manual resolution
        }
    }
}

/// Fork resolution outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkResolutionOutcome {
    /// The fork that was resolved.
    pub fork_event: ForkEvent,
    /// Resolution strategy used.
    pub strategy: ForkResolution,
    /// Winning branch object ID (if resolved).
    pub winning_head: Option<ObjectId>,
    /// Timestamp when resolution occurred.
    pub resolved_at: u64,
    /// Whether resolution succeeded.
    pub resolved: bool,
    /// Reason if resolution failed.
    pub failure_reason: Option<String>,
    /// Structured diagnostic explaining the resolution decision.
    pub decision_detail: Option<String>,
}

impl ForkResolutionOutcome {
    /// Create a successful resolution outcome.
    #[must_use]
    pub fn success(
        fork_event: ForkEvent,
        strategy: ForkResolution,
        winning_head: ObjectId,
        resolved_at: u64,
    ) -> Self {
        let detail = match strategy {
            ForkResolution::ChooseByLease => {
                "Winner determined by highest lease_seq among forked branches.".to_owned()
            }
            ForkResolution::CrdtMerge => {
                "Both branches merged via CRDT semantics; no data lost.".to_owned()
            }
            ForkResolution::ManualResolution => {
                "Resolution was manually selected by an operator.".to_owned()
            }
        };
        Self {
            fork_event,
            strategy,
            winning_head: Some(winning_head),
            resolved_at,
            resolved: true,
            failure_reason: None,
            decision_detail: Some(detail),
        }
    }

    /// Create a failed resolution outcome.
    #[must_use]
    pub fn failure(
        fork_event: ForkEvent,
        strategy: ForkResolution,
        resolved_at: u64,
        reason: impl Into<String>,
    ) -> Self {
        let reason_str = reason.into();
        let detail = format!("Resolution failed: {reason_str}");
        Self {
            fork_event,
            strategy,
            winning_head: None,
            resolved_at,
            resolved: false,
            failure_reason: Some(reason_str),
            decision_detail: Some(detail),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CRDT State Merge (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from CRDT state merge operations.
#[derive(Debug, Error)]
pub enum CrdtMergeError {
    /// Failed to deserialize CBOR state payload.
    #[error("CRDT deserialization error ({crdt_type}): {message}")]
    Deserialization {
        crdt_type: CrdtType,
        message: String,
    },

    /// Failed to serialize merged CBOR state payload.
    #[error("CRDT serialization error ({crdt_type}): {message}")]
    Serialization {
        crdt_type: CrdtType,
        message: String,
    },

    /// CRDT merge is not supported for this state model.
    #[error("CRDT merge is not valid for state model: {model}")]
    InvalidModel { model: String },
}

/// Merge two CBOR-encoded CRDT state payloads according to their `CrdtType`.
///
/// This is the delta-level merge used for fork resolution in CRDT-mode connectors.
/// Both payloads must represent the same CRDT type. The result is a new CBOR-encoded
/// state that is the deterministic merge of both inputs.
///
/// # Arguments
///
/// * `crdt_type` - The CRDT semantics to use for merging.
/// * `state_a` - CBOR-encoded state from branch A.
/// * `state_b` - CBOR-encoded state from branch B.
///
/// # Errors
///
/// Returns `CrdtMergeError` if deserialization or serialization fails.
pub fn merge_crdt_states(
    crdt_type: CrdtType,
    state_a: &[u8],
    state_b: &[u8],
) -> Result<Vec<u8>, CrdtMergeError> {
    if state_a.len() > MAX_CRDT_STATE_BYTES {
        return Err(CrdtMergeError::Deserialization {
            crdt_type,
            message: format!(
                "branch_a: payload {} bytes exceeds {}-byte cap",
                state_a.len(),
                MAX_CRDT_STATE_BYTES
            ),
        });
    }
    if state_b.len() > MAX_CRDT_STATE_BYTES {
        return Err(CrdtMergeError::Deserialization {
            crdt_type,
            message: format!(
                "branch_b: payload {} bytes exceeds {}-byte cap",
                state_b.len(),
                MAX_CRDT_STATE_BYTES
            ),
        });
    }

    match crdt_type {
        CrdtType::LwwMap => {
            let mut a: crate::LwwMap<String, serde_json::Value> = ciborium::from_reader(state_a)
                .map_err(|e| CrdtMergeError::Deserialization {
                    crdt_type,
                    message: format!("branch_a: {e}"),
                })?;
            let b: crate::LwwMap<String, serde_json::Value> = ciborium::from_reader(state_b)
                .map_err(|e| CrdtMergeError::Deserialization {
                    crdt_type,
                    message: format!("branch_b: {e}"),
                })?;
            a.merge(&b);
            to_canonical_cbor(&a).map_err(|e| CrdtMergeError::Serialization {
                crdt_type,
                message: e.to_string(),
            })
        }
        CrdtType::OrSet => {
            let mut a: crate::OrSet<String> =
                ciborium::from_reader(state_a).map_err(|e| CrdtMergeError::Deserialization {
                    crdt_type,
                    message: format!("branch_a: {e}"),
                })?;
            let b: crate::OrSet<String> =
                ciborium::from_reader(state_b).map_err(|e| CrdtMergeError::Deserialization {
                    crdt_type,
                    message: format!("branch_b: {e}"),
                })?;
            a.merge(&b);
            to_canonical_cbor(&a).map_err(|e| CrdtMergeError::Serialization {
                crdt_type,
                message: e.to_string(),
            })
        }
        CrdtType::GCounter => {
            let mut a: crate::GCounter =
                ciborium::from_reader(state_a).map_err(|e| CrdtMergeError::Deserialization {
                    crdt_type,
                    message: format!("branch_a: {e}"),
                })?;
            let b: crate::GCounter =
                ciborium::from_reader(state_b).map_err(|e| CrdtMergeError::Deserialization {
                    crdt_type,
                    message: format!("branch_b: {e}"),
                })?;
            a.merge(&b);
            to_canonical_cbor(&a).map_err(|e| CrdtMergeError::Serialization {
                crdt_type,
                message: e.to_string(),
            })
        }
        CrdtType::PnCounter => {
            let mut a: crate::PnCounter =
                ciborium::from_reader(state_a).map_err(|e| CrdtMergeError::Deserialization {
                    crdt_type,
                    message: format!("branch_a: {e}"),
                })?;
            let b: crate::PnCounter =
                ciborium::from_reader(state_b).map_err(|e| CrdtMergeError::Deserialization {
                    crdt_type,
                    message: format!("branch_b: {e}"),
                })?;
            a.merge(&b);
            to_canonical_cbor(&a).map_err(|e| CrdtMergeError::Serialization {
                crdt_type,
                message: e.to_string(),
            })
        }
    }
}

/// Structured diagnostic for a CRDT merge decision.
///
/// Captures why a particular merge outcome was reached so that audits
/// and operator flows can explain the decision without source-code
/// archaeology.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeDiagnostic {
    /// The CRDT strategy that governed this merge.
    pub strategy: String,
    /// Number of entries/elements in branch A before merge.
    pub branch_a_size: usize,
    /// Number of entries/elements in branch B before merge.
    pub branch_b_size: usize,
    /// Number of entries/elements in the merged result.
    pub merged_size: usize,
    /// Human-readable explanation of the merge outcome.
    pub explanation: String,
}

/// Outcome of a CRDT merge operation on forked connector state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrdtMergeOutcome {
    /// The fork that was resolved.
    pub fork_event: ForkEvent,
    /// Merged state (CBOR-encoded).
    pub merged_state_cbor: Vec<u8>,
    /// CRDT type used for the merge.
    pub crdt_type: CrdtType,
    /// Timestamp when the merge completed.
    pub merged_at: u64,
    /// Structured diagnostic explaining the merge decision.
    pub diagnostic: Option<MergeDiagnostic>,
}

/// Fork detector for connector state objects.
///
/// Tracks state objects indexed by their `prev` pointer to detect forks
/// (multiple objects with the same `prev`).
#[derive(Debug, Default)]
pub struct StateForkDetector {
    /// Map from `prev` object ID to list of state objects pointing to it.
    /// A fork exists when any `prev` has more than one child.
    children_by_prev: std::collections::HashMap<ObjectId, Vec<ObjectId>>,
    /// Map from object ID to its sequence number.
    seq_by_id: std::collections::HashMap<ObjectId, u64>,
    /// Map from object ID to its `lease_seq` (for resolution).
    lease_seq_by_id: std::collections::HashMap<ObjectId, u64>,
}

impl StateForkDetector {
    /// Create a new fork detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a state object for fork detection.
    ///
    /// Call this for each state object received. The detector will track
    /// parent-child relationships to detect forks.
    pub fn register(
        &mut self,
        object_id: ObjectId,
        prev: Option<ObjectId>,
        seq: u64,
        lease_seq: u64,
    ) {
        self.seq_by_id.insert(object_id, seq);
        self.lease_seq_by_id.insert(object_id, lease_seq);

        if let Some(prev_id) = prev {
            self.children_by_prev
                .entry(prev_id)
                .or_default()
                .push(object_id);
        }
    }

    /// Check for forks in the registered state objects.
    ///
    /// Returns the first detected fork, if any.
    #[must_use]
    pub fn detect_fork(
        &self,
        zone_id: ZoneId,
        connector_id: ConnectorId,
        now: u64,
    ) -> StateForkDetectionResult {
        // Find any prev with multiple children (fork point)
        for (prev_id, children) in &self.children_by_prev {
            if children.len() > 1 {
                // Fork detected: multiple objects share the same prev
                let branch_a = children[0];
                let branch_b = children[1];
                let fork_seq = self.seq_by_id.get(&branch_a).copied().unwrap_or(0);

                return StateForkDetectionResult::ForkDetected(ForkEvent::new(
                    *prev_id,
                    branch_a,
                    branch_b,
                    fork_seq,
                    now,
                    zone_id,
                    connector_id,
                ));
            }
        }

        // No fork - find the latest head
        let (head, seq) = self
            .seq_by_id
            .iter()
            .max_by_key(|(_, seq)| *seq)
            .map_or((ObjectId::from_bytes([0u8; 32]), 0), |(id, seq)| {
                (*id, *seq)
            });

        StateForkDetectionResult::NoFork { head, seq }
    }

    /// Get the `lease_seq` for a given object ID.
    #[must_use]
    pub fn lease_seq(&self, object_id: &ObjectId) -> Option<u64> {
        self.lease_seq_by_id.get(object_id).copied()
    }

    /// Resolve a fork using the specified strategy.
    ///
    /// # Arguments
    ///
    /// * `fork` - The fork event to resolve
    /// * `strategy` - Resolution strategy to use
    /// * `model` - State model (for validation)
    /// * `now` - Current timestamp
    ///
    /// # Errors
    ///
    /// Returns a failure outcome if the strategy is invalid for the model
    /// or if lease-based resolution results in a tie.
    #[must_use]
    pub fn resolve(
        &self,
        fork: &ForkEvent,
        strategy: ForkResolution,
        model: &ConnectorStateModel,
        now: u64,
    ) -> ForkResolutionOutcome {
        if !strategy.is_valid_for(model) {
            return ForkResolutionOutcome::failure(
                fork.clone(),
                strategy,
                now,
                format!("strategy {strategy:?} is not valid for state model {model}"),
            );
        }

        match strategy {
            ForkResolution::ChooseByLease => {
                let lease_seq_a = self.lease_seq(&fork.branch_a).unwrap_or(0);
                let lease_seq_b = self.lease_seq(&fork.branch_b).unwrap_or(0);

                fork.resolve_by_lease(lease_seq_a, lease_seq_b).map_or_else(
                    || {
                        ForkResolutionOutcome::failure(
                            fork.clone(),
                            strategy,
                            now,
                            format!("lease_seq tie ({lease_seq_a} == {lease_seq_b}); manual resolution required"),
                        )
                    },
                    |winner| ForkResolutionOutcome::success(fork.clone(), strategy, winner, now),
                )
            }
            ForkResolution::ManualResolution => ForkResolutionOutcome::failure(
                fork.clone(),
                strategy,
                now,
                "manual resolution requires explicit head selection",
            ),
            ForkResolution::CrdtMerge => {
                // The detector does not hold CBOR state payloads — it only
                // tracks object IDs for fork detection. To complete a CRDT
                // merge, the caller must:
                // 1. Retrieve both branch states (branch_a, branch_b)
                // 2. Call `merge_crdt_states(crdt_type, state_a, state_b)`
                // 3. Persist the merged result as a new state object
                //
                // We return a "success" outcome to signal that CrdtMerge is
                // the resolved strategy. The caller picks either branch as
                // the merge base (branch_a by convention) and merges into it.
                ForkResolutionOutcome::success(fork.clone(), strategy, fork.branch_a, now)
            }
        }
    }

    /// Resolve a fork by explicitly selecting a head.
    ///
    /// Used for manual resolution when an operator chooses the winning branch.
    #[must_use]
    pub fn resolve_manual(
        &self,
        fork: &ForkEvent,
        selected_head: ObjectId,
        now: u64,
    ) -> ForkResolutionOutcome {
        // Validate the selected head is one of the fork branches
        if selected_head != fork.branch_a && selected_head != fork.branch_b {
            return ForkResolutionOutcome::failure(
                fork.clone(),
                ForkResolution::ManualResolution,
                now,
                format!(
                    "selected head {} is not one of the fork branches ({} or {})",
                    selected_head, fork.branch_a, fork.branch_b
                ),
            );
        }

        ForkResolutionOutcome::success(
            fork.clone(),
            ForkResolution::ManualResolution,
            selected_head,
            now,
        )
    }

    /// Clear all tracked state (for testing or reset).
    pub fn clear(&mut self) {
        self.children_by_prev.clear();
        self.seq_by_id.clear();
        self.lease_seq_by_id.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Singleton Writer Fencing Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when fencing validation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FencingError {
    /// The lease has expired.
    LeaseExpired { expired_at: u64, now: u64 },

    /// The `lease_seq` is stale (superseded by a newer lease).
    StaleLeaseSeq { held_seq: u64, current_seq: u64 },

    /// The lease is for the wrong subject.
    SubjectMismatch { expected: ObjectId, got: ObjectId },

    /// The lease purpose is not `ConnectorStateWrite`.
    WrongPurpose,

    /// The state object references a non-existent lease.
    LeaseNotFound { lease_id: ObjectId },
}

impl fmt::Display for FencingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeaseExpired { expired_at, now } => {
                write!(f, "lease expired at {expired_at}, current time is {now}")
            }
            Self::StaleLeaseSeq {
                held_seq,
                current_seq,
            } => {
                write!(
                    f,
                    "stale lease_seq: held {held_seq}, current is {current_seq}"
                )
            }
            Self::SubjectMismatch { expected, got } => {
                write!(f, "lease subject mismatch: expected {expected}, got {got}")
            }
            Self::WrongPurpose => {
                write!(f, "lease purpose is not ConnectorStateWrite")
            }
            Self::LeaseNotFound { lease_id } => {
                write!(f, "lease not found: {lease_id}")
            }
        }
    }
}

impl std::error::Error for FencingError {}

/// Validate that a state object has valid fencing for singleton-writer semantics.
///
/// # Arguments
///
/// * `state_obj` - The state object to validate
/// * `current_known_seq` - The highest known `lease_seq` for this subject
/// * `now` - Current timestamp for expiry checking
/// * `lease_exp` - Expiration time of the referenced lease
///
/// # Errors
///
/// Returns an error if fencing validation fails.
pub fn validate_singleton_writer_fencing(
    state_obj: &ConnectorStateObject,
    current_known_seq: u64,
    now: u64,
    lease_exp: u64,
) -> Result<(), FencingError> {
    // Check lease expiry
    if now >= lease_exp {
        return Err(FencingError::LeaseExpired {
            expired_at: lease_exp,
            now,
        });
    }

    // Check fencing token is not stale
    if state_obj.lease_seq < current_known_seq {
        return Err(FencingError::StaleLeaseSeq {
            held_seq: state_obj.lease_seq,
            current_seq: current_known_seq,
        });
    }

    // Verify lease is in header refs
    if !state_obj.header.refs.contains(&state_obj.lease_object_id) {
        return Err(FencingError::LeaseNotFound {
            lease_id: state_obj.lease_object_id,
        });
    }

    // Note: Subject and purpose validation require the actual Lease object,
    // which should be done by the caller with access to the object store.

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for snapshot creation (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotConfig {
    /// Create snapshot every N updates.
    #[serde(default = "default_snapshot_every_updates")]
    pub snapshot_every_updates: u32,

    /// Create snapshot every N bytes of state.
    #[serde(default = "default_snapshot_every_bytes")]
    pub snapshot_every_bytes: u64,
}

const fn default_snapshot_every_updates() -> u32 {
    5000
}

const fn default_snapshot_every_bytes() -> u64 {
    1_048_576 // 1 MiB
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            snapshot_every_updates: default_snapshot_every_updates(),
            snapshot_every_bytes: default_snapshot_every_bytes(),
        }
    }
}

impl SnapshotConfig {
    /// Check if a snapshot should be created.
    #[must_use]
    pub const fn should_snapshot(&self, updates_since_last: u32, bytes_since_last: u64) -> bool {
        updates_since_last >= self.snapshot_every_updates
            || bytes_since_last >= self.snapshot_every_bytes
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapabilityConstraints, Provenance, TaintLevel};
    use chrono::Duration;
    use fcp_cbor::SchemaId;
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use semver::Version;
    use uuid::Uuid;

    fn capability_constraints_cbor(resource_allow: Vec<String>) -> Vec<u8> {
        let constraints = CapabilityConstraints {
            resource_allow,
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).unwrap();
        cbor
    }

    fn signed_connector_state_token(
        signing_key: &Ed25519SigningKey,
        zone_id: &ZoneId,
        instance_id: &InstanceId,
        capability_id: &str,
        operations: &[&str],
        resource_allow: Vec<String>,
    ) -> CapabilityToken {
        let now = crate::Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(capability_id)
            .zone_id(zone_id.as_str())
            .target_instance(instance_id.as_str())
            .principal("principal:test")
            .operations(operations)
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&capability_constraints_cbor(resource_allow))
            .unwrap()
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    #[test]
    fn connector_state_write_authorization_accepts_bound_append_token() {
        let connector_id = test_connector_id();
        let zone_id = ZoneId::work();
        let instance_id = InstanceId::new();
        let signing_key = Ed25519SigningKey::generate();
        let token = signed_connector_state_token(
            &signing_key,
            &zone_id,
            &instance_id,
            CONNECTOR_STATE_WRITE_CAPABILITY_ID,
            &[CONNECTOR_STATE_APPEND_OPERATION_ID],
            vec![connector_state_resource_uri(&connector_id)],
        );
        let verifier = CapabilityVerifier::new(
            signing_key.verifying_key().to_bytes(),
            zone_id.clone(),
            instance_id,
        );

        let authorization = ConnectorStateWriteAuthorization::verify_append_token(
            &verifier,
            token,
            &connector_id,
            &zone_id,
        )
        .expect("valid connector-state append token should authorize");

        assert_eq!(authorization.connector_id(), &connector_id);
        assert_eq!(authorization.zone_id(), &zone_id);
    }

    #[test]
    fn connector_state_write_authorization_rejects_wrong_operation() {
        let connector_id = test_connector_id();
        let zone_id = ZoneId::work();
        let instance_id = InstanceId::new();
        let signing_key = Ed25519SigningKey::generate();
        let token = signed_connector_state_token(
            &signing_key,
            &zone_id,
            &instance_id,
            CONNECTOR_STATE_WRITE_CAPABILITY_ID,
            &["fcp.connector-state.read"],
            vec![connector_state_resource_uri(&connector_id)],
        );
        let verifier = CapabilityVerifier::new(
            signing_key.verifying_key().to_bytes(),
            zone_id.clone(),
            instance_id,
        );

        let err = ConnectorStateWriteAuthorization::verify_append_token(
            &verifier,
            token,
            &connector_id,
            &zone_id,
        )
        .expect_err("read-only token must not authorize append");

        assert!(matches!(
            err,
            ConnectorStateError::AuthorizationDenied { .. }
        ));
    }

    #[test]
    fn connector_state_write_authorization_rejects_wrong_resource_scope() {
        let connector_id = test_connector_id();
        let zone_id = ZoneId::work();
        let instance_id = InstanceId::new();
        let signing_key = Ed25519SigningKey::generate();
        let other_connector_id = ConnectorId::from_static("github:issue:v1");
        let token = signed_connector_state_token(
            &signing_key,
            &zone_id,
            &instance_id,
            CONNECTOR_STATE_WRITE_CAPABILITY_ID,
            &[CONNECTOR_STATE_APPEND_OPERATION_ID],
            vec![connector_state_resource_uri(&other_connector_id)],
        );
        let verifier = CapabilityVerifier::new(
            signing_key.verifying_key().to_bytes(),
            zone_id.clone(),
            instance_id,
        );

        let err = ConnectorStateWriteAuthorization::verify_append_token(
            &verifier,
            token,
            &connector_id,
            &zone_id,
        )
        .expect_err("resource-scoped token for another connector must not authorize append");

        assert!(matches!(
            err,
            ConnectorStateError::AuthorizationDenied { .. }
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CrdtType Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn crdt_type_display() {
        assert_eq!(CrdtType::LwwMap.to_string(), "lww_map");
        assert_eq!(CrdtType::OrSet.to_string(), "or_set");
        assert_eq!(CrdtType::GCounter.to_string(), "g_counter");
        assert_eq!(CrdtType::PnCounter.to_string(), "pn_counter");
    }

    #[test]
    fn crdt_type_serde_roundtrip() {
        for crdt_type in [
            CrdtType::LwwMap,
            CrdtType::OrSet,
            CrdtType::GCounter,
            CrdtType::PnCounter,
        ] {
            let json = serde_json::to_string(&crdt_type).unwrap();
            let deserialized: CrdtType = serde_json::from_str(&json).unwrap();
            assert_eq!(crdt_type, deserialized);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ConnectorStateModel Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_state_model_stateless() {
        let model = ConnectorStateModel::Stateless;
        assert!(model.is_stateless());
        assert!(!model.is_singleton_writer());
        assert!(!model.is_crdt());
        assert!(model.crdt_type().is_none());
        assert_eq!(model.to_string(), "stateless");
    }

    #[test]
    fn connector_state_model_singleton_writer() {
        let model = ConnectorStateModel::SingletonWriter;
        assert!(!model.is_stateless());
        assert!(model.is_singleton_writer());
        assert!(!model.is_crdt());
        assert!(model.crdt_type().is_none());
        assert_eq!(model.to_string(), "singleton_writer");
    }

    #[test]
    fn connector_state_model_crdt() {
        let model = ConnectorStateModel::Crdt {
            crdt_type: CrdtType::LwwMap,
        };
        assert!(!model.is_stateless());
        assert!(!model.is_singleton_writer());
        assert!(model.is_crdt());
        assert_eq!(model.crdt_type(), Some(CrdtType::LwwMap));
        assert_eq!(model.to_string(), "crdt(lww_map)");
    }

    #[test]
    fn connector_state_model_default_is_stateless() {
        let model = ConnectorStateModel::default();
        assert!(model.is_stateless());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CursorState Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn cursor_state_from_cbor_rejects_oversized_payload() {
        // An oversized blob must fail at the size-cap check before ciborium
        // attempts to allocate for the decode, irrespective of well-formedness.
        let blob = vec![0u8; MAX_CURSOR_STATE_BYTES + 1];
        let err = CursorState::from_cbor(&blob).expect_err("oversized blob must be rejected");
        match err {
            SerializationError::PayloadTooLarge { len, max } => {
                assert_eq!(len, MAX_CURSOR_STATE_BYTES + 1);
                assert_eq!(max, MAX_CURSOR_STATE_BYTES);
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn cursor_state_from_cbor_accepts_at_cap_boundary() {
        // A blob exactly at the cap passes the size gate. Random bytes are
        // not valid CBOR so the decode will fail, but crucially NOT with the
        // size-cap error — proves the check is inclusive and off-by-one safe.
        let blob = vec![0u8; MAX_CURSOR_STATE_BYTES];
        let err = CursorState::from_cbor(&blob).expect_err("random bytes must not decode");
        assert!(
            !matches!(err, SerializationError::PayloadTooLarge { .. }),
            "at-cap input must bypass the size check and fail on CBOR parse: got {err:?}"
        );
    }

    #[test]
    fn cursor_state_cbor_roundtrip() {
        let state = CursorState {
            offset: Some(42),
            last_seen_id: Some("msg_123".to_string()),
            watermark: Some(1_700_000_000),
        };

        let encoded = state.to_cbor().unwrap();
        let decoded = CursorState::from_cbor(&encoded).unwrap();

        assert_eq!(state, decoded);
    }

    #[test]
    fn cursor_state_cbor_deterministic() {
        let state = CursorState {
            offset: Some(7),
            last_seen_id: Some("cursor_abc".to_string()),
            watermark: Some(1_700_000_111),
        };

        let encoded1 = state.to_cbor().unwrap();
        let encoded2 = state.to_cbor().unwrap();

        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn cursor_state_cbor_golden_vector() {
        let state = CursorState {
            offset: Some(1),
            last_seen_id: Some("a".to_string()),
            watermark: Some(2),
        };

        let encoded = state.to_cbor().unwrap();
        let expected =
            hex::decode("a3666f6666736574016977617465726d61726b026c6c6173745f7365656e5f69646161")
                .unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn cursor_state_from_cbor_rejects_trailing_bytes() {
        let state = CursorState {
            offset: Some(9),
            last_seen_id: Some("trail".to_string()),
            watermark: Some(3),
        };

        let mut encoded = state.to_cbor().unwrap();
        encoded.push(0x00);

        let err = CursorState::from_cbor(&encoded).unwrap_err();
        assert!(matches!(err, SerializationError::TrailingBytes));
    }

    #[test]
    fn cursor_state_from_object_uses_state_cbor() {
        let state = CursorState {
            offset: Some(100),
            last_seen_id: Some("last_id".to_string()),
            watermark: Some(1_700_000_222),
        };
        let state_cbor = state.to_cbor().unwrap();

        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "CursorState", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance {
                origin_zone: ZoneId::work(),
                chain: Vec::new(),
                taint: TaintLevel::Untainted,
                elevated: false,
                elevation_token: None,
            },
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        };

        let state_obj = ConnectorStateObject {
            header,
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: ZoneId::work(),
            prev: None,
            seq: 1,
            state_cbor,
            updated_at: 1_700_000_000,
            lease_seq: 1,
            lease_object_id: test_object_id("lease"),
            writer_public_key: [0u8; 32],
            signature: Signature::zero(),
        };

        let decoded = cursor_state_from_object(&state_obj).unwrap();
        assert_eq!(decoded, state);
    }

    #[test]
    fn connector_state_model_serde_roundtrip() {
        let models = [
            ConnectorStateModel::Stateless,
            ConnectorStateModel::SingletonWriter,
            ConnectorStateModel::Crdt {
                crdt_type: CrdtType::OrSet,
            },
        ];

        for model in models {
            let json = serde_json::to_string(&model).unwrap();
            let deserialized: ConnectorStateModel = serde_json::from_str(&json).unwrap();
            assert_eq!(model, deserialized);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ConnectorStateStore Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[derive(Default)]
    struct EmptyConnectorStateStore;

    #[async_trait::async_trait]
    impl ConnectorStateStore for EmptyConnectorStateStore {
        async fn read_root(
            &self,
            _connector_id: &ConnectorId,
        ) -> Result<Option<ConnectorStateRoot>, ConnectorStateError> {
            Ok(None)
        }

        async fn append_object(
            &self,
            _connector_id: &ConnectorId,
            _authorization: &ConnectorStateWriteAuthorization,
            object: ConnectorStateObject,
        ) -> Result<ConnectorStateAppendOutcome, ConnectorStateError> {
            Ok(ConnectorStateAppendOutcome::Committed {
                object_id: test_object_id("state"),
                root_object_id: test_object_id("root"),
                seq: object.seq,
                snapshot_object_id: None,
            })
        }

        async fn read_chain(
            &self,
            _connector_id: &ConnectorId,
            _after_seq: Option<u64>,
            limit: usize,
        ) -> Result<Vec<ConnectorStateObject>, ConnectorStateError> {
            if limit == 0 {
                return Err(ConnectorStateError::InvalidLimit { limit });
            }
            Ok(Vec::new())
        }

        async fn snapshot(
            &self,
            connector_id: &ConnectorId,
        ) -> Result<ConnectorStateSnapshot, ConnectorStateError> {
            Err(ConnectorStateError::SnapshotUnavailable {
                connector_id: connector_id.clone(),
                reason: "empty test store".to_string(),
            })
        }

        async fn compact(
            &self,
            _connector_id: &ConnectorId,
            _before_seq: u64,
        ) -> Result<usize, ConnectorStateError> {
            Ok(0)
        }

        async fn subscribe_changes(
            &self,
            _connector_id: &ConnectorId,
        ) -> Result<ConnectorStateChangeStream, ConnectorStateError> {
            Ok(Box::pin(futures_util::stream::empty()))
        }
    }

    #[test]
    fn connector_state_append_outcome_conflict_serde_roundtrip() -> Result<(), serde_json::Error> {
        let outcome = ConnectorStateAppendOutcome::Conflict {
            canonical_head: Some(test_object_id("head")),
            canonical_seq: Some(7),
        };
        let json = serde_json::to_string(&outcome)?;
        let back: ConnectorStateAppendOutcome = serde_json::from_str(&json)?;
        assert_eq!(back, outcome);
        Ok(())
    }

    #[test]
    fn connector_state_change_serde_roundtrip() -> Result<(), serde_json::Error> {
        let change = ConnectorStateChange {
            connector_id: test_connector_id(),
            instance_id: Some(InstanceId::new()),
            zone_id: ZoneId::work(),
            kind: ConnectorStateChangeKind::ObjectAppended,
            object_id: Some(test_object_id("state")),
            seq: Some(9),
            observed_at: 1_700_000_000,
        };

        let json = serde_json::to_string(&change)?;
        let back: ConnectorStateChange = serde_json::from_str(&json)?;
        assert_eq!(back, change);
        Ok(())
    }

    #[test]
    fn connector_state_error_display_is_redaction_safe() {
        let err = ConnectorStateError::StorageUnavailable {
            connector_id: test_connector_id(),
            reason: "object store timeout".to_string(),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("object store timeout"));
        assert!(rendered.contains(test_connector_id().as_str()));
    }

    #[test]
    fn connector_state_store_trait_is_object_safe() {
        let store: Box<dyn ConnectorStateStore> = Box::new(EmptyConnectorStateStore);
        let result = fcp_async_core::runtime::block_on_sync(store.read_root(&test_connector_id()));
        assert!(matches!(result, Ok(Ok(None))));
    }

    #[test]
    fn connector_state_store_default_canonical_status_reports_missing_root() {
        let store: Box<dyn ConnectorStateStore> = Box::new(EmptyConnectorStateStore);
        let result =
            fcp_async_core::runtime::block_on_sync(store.canonical_status(&test_connector_id()));
        let status = result.expect("runtime").expect("canonical status");

        assert_eq!(status.connector_id, test_connector_id());
        assert!(!status.root_present);
        assert!(status.root_object_id.is_none());
        assert!(status.head_object_id.is_none());
        assert!(status.last_canonical_seq.is_none());
        assert!(status.mesh_replica_count.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SnapshotConfig Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn snapshot_config_default() {
        let config = SnapshotConfig::default();
        assert_eq!(config.snapshot_every_updates, 5000);
        assert_eq!(config.snapshot_every_bytes, 1_048_576);
    }

    #[test]
    fn snapshot_config_should_snapshot() {
        let config = SnapshotConfig {
            snapshot_every_updates: 100,
            snapshot_every_bytes: 1000,
        };

        assert!(!config.should_snapshot(50, 500));
        assert!(config.should_snapshot(100, 500)); // Updates threshold
        assert!(config.should_snapshot(50, 1000)); // Bytes threshold
        assert!(config.should_snapshot(100, 1000)); // Both thresholds
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Signature Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn signature_zero() {
        let sig = Signature::zero();
        assert_eq!(sig.as_bytes(), &[0u8; 64]);
    }

    #[test]
    fn signature_from_bytes() {
        let bytes = [42u8; 64];
        let sig = Signature::from_bytes(bytes);
        assert_eq!(sig.as_bytes(), &bytes);
    }

    #[test]
    fn signature_display() {
        let sig = Signature::from_bytes([0xab; 64]);
        let display = sig.to_string();
        assert!(display.contains("abababab"));
        assert!(display.ends_with("..."));
    }

    #[test]
    fn connector_state_object_signature_uses_unsigned_payload() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let wrong_key = Ed25519SigningKey::generate().verifying_key();
        let lease_object_id = test_object_id("lease");
        let mut header = test_header();
        header.refs.push(lease_object_id);
        let mut state_obj = ConnectorStateObject {
            header,
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: ZoneId::work(),
            prev: None,
            seq: 0,
            state_cbor: vec![0xa1, 0x61, b'n', 0x00],
            updated_at: 1_700_000_000,
            lease_seq: 1,
            lease_object_id,
            writer_public_key: verifying_key.to_bytes(),
            signature: Signature::zero(),
        };

        let unsigned_signing_bytes = state_obj.signing_bytes().unwrap();
        state_obj.sign_with(&signing_key).unwrap();

        assert_ne!(state_obj.signature, Signature::zero());
        assert_eq!(state_obj.signing_bytes().unwrap(), unsigned_signing_bytes);
        state_obj.verify_signature().unwrap();
        state_obj.verify_signature_with(&verifying_key).unwrap();
        assert!(state_obj.verify_signature_with(&wrong_key).is_err());

        let mut tampered = state_obj.clone();
        tampered.seq += 1;
        assert!(tampered.verify_signature_with(&verifying_key).is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FencingError Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fencing_error_display() {
        let err = FencingError::LeaseExpired {
            expired_at: 1000,
            now: 2000,
        };
        assert!(err.to_string().contains("expired"));

        let err = FencingError::StaleLeaseSeq {
            held_seq: 5,
            current_seq: 10,
        };
        assert!(err.to_string().contains("stale"));

        let err = FencingError::WrongPurpose;
        assert!(err.to_string().contains("ConnectorStateWrite"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ForkResolution Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fork_resolution_serde() {
        let resolutions = [
            ForkResolution::ChooseByLease,
            ForkResolution::ManualResolution,
            ForkResolution::CrdtMerge,
        ];

        for resolution in resolutions {
            let json = serde_json::to_string(&resolution).unwrap();
            let deserialized: ForkResolution = serde_json::from_str(&json).unwrap();
            assert_eq!(resolution, deserialized);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Fork Detection Tests
    // ─────────────────────────────────────────────────────────────────────────

    fn test_object_id(label: &str) -> ObjectId {
        ObjectId::test_id(label)
    }

    fn test_connector_id() -> ConnectorId {
        ConnectorId::from_static("fcp.test:fork:v1")
    }

    fn test_header() -> ObjectHeader {
        ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_node_id(name: &str) -> TailscaleNodeId {
        TailscaleNodeId::new(name)
    }

    fn test_migration_context(checkpoint_seq: u64) -> MigrationCapabilityContext {
        MigrationCapabilityContext {
            capability_token_jti: Uuid::from_bytes([0xCD; 16]),
            checkpoint_id: None,
            checkpoint_seq,
            audit_event_id: Some(test_object_id("audit-event")),
        }
    }

    fn test_computation_checkpoint(
        holder: &str,
        lease_id: LeaseId,
        lease_fencing_token: u64,
        checkpoint_seq: u64,
    ) -> ComputationCheckpoint {
        let computation_id = test_object_id("computation");
        let mut header = test_header();
        header.schema = SchemaId::new("fcp.core", "ComputationCheckpoint", Version::new(1, 0, 0));
        header.refs = vec![computation_id, lease_id];

        ComputationCheckpoint {
            header,
            computation_id,
            current_holder: test_node_id(holder),
            checkpoint_seq,
            suspended_at: 1_700_000_050,
            lease_id,
            lease_fencing_token,
            capability_context: test_migration_context(checkpoint_seq),
            state_cbor: vec![0xAA; 128],
        }
    }

    fn test_migration_lease(holder: &str, lease_seq: u64, exp: u64) -> Lease {
        let computation_id = test_object_id("computation");
        let mut header = test_header();
        header.schema = SchemaId::new("fcp.lease", "lease", Version::new(1, 0, 0));
        header.created_at = 1_000;
        header.refs = vec![computation_id];

        Lease {
            header,
            holder: test_node_id(holder),
            lease_seq,
            exp,
            subject_object_id: computation_id,
            purpose: LeasePurpose::ComputationMigration,
            quorum_signatures: crate::SignatureSet::new(),
        }
    }

    fn test_migration_handoff(
        previous_lease_id: LeaseId,
        next_lease_id: LeaseId,
        from: &str,
        to: &str,
        previous_fencing_token: u64,
        next_fencing_token: u64,
    ) -> LeaseHandoff {
        test_migration_handoff_with_checkpoint(
            previous_lease_id,
            next_lease_id,
            from,
            to,
            previous_fencing_token,
            next_fencing_token,
            Some(test_object_id("checkpoint")),
        )
    }

    fn test_migration_handoff_with_checkpoint(
        previous_lease_id: LeaseId,
        next_lease_id: LeaseId,
        from: &str,
        to: &str,
        previous_fencing_token: u64,
        next_fencing_token: u64,
        checkpoint_object_id: Option<ObjectId>,
    ) -> LeaseHandoff {
        LeaseHandoff {
            previous_lease_id,
            next_lease_id,
            from_holder: test_node_id(from),
            to_holder: test_node_id(to),
            zone_id: ZoneId::work(),
            subject_object_id: test_object_id("computation"),
            purpose: LeasePurpose::ComputationMigration,
            previous_fencing_token,
            next_fencing_token,
            transferred_at: 1_500,
            checkpoint_object_id,
        }
    }

    #[test]
    fn fork_detector_no_fork_single_chain() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("genesis");
        let obj1 = test_object_id("obj1");
        let obj2 = test_object_id("obj2");

        // Linear chain: genesis -> obj1 -> obj2
        detector.register(genesis, None, 0, 100);
        detector.register(obj1, Some(genesis), 1, 100);
        detector.register(obj2, Some(obj1), 2, 100);

        let result = detector.detect_fork(ZoneId::work(), test_connector_id(), 1_700_000_000);

        assert!(!result.is_fork());
        if let StateForkDetectionResult::NoFork { head, seq } = result {
            assert_eq!(head, obj2);
            assert_eq!(seq, 2);
        }
    }

    #[test]
    fn fork_detector_detects_fork() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("genesis");
        let branch_a = test_object_id("branch_a");
        let branch_b = test_object_id("branch_b");

        // Fork: genesis -> branch_a AND genesis -> branch_b
        detector.register(genesis, None, 0, 100);
        detector.register(branch_a, Some(genesis), 1, 101);
        detector.register(branch_b, Some(genesis), 1, 102);

        let result = detector.detect_fork(ZoneId::work(), test_connector_id(), 1_700_000_000);

        assert!(result.is_fork());
        let fork = result.fork_event().unwrap();
        assert_eq!(fork.common_prev, genesis);
        assert_eq!(fork.fork_seq, 1);
        // branch_a and branch_b should be the two competing heads (order may vary)
        assert!(
            (fork.branch_a == branch_a && fork.branch_b == branch_b)
                || (fork.branch_a == branch_b && fork.branch_b == branch_a)
        );
    }

    #[test]
    fn fork_resolve_by_lease_higher_wins() {
        let genesis = test_object_id("genesis");
        let branch_a = test_object_id("branch_a");
        let branch_b = test_object_id("branch_b");

        let fork = ForkEvent::new(
            genesis,
            branch_a,
            branch_b,
            1,
            1_700_000_000,
            ZoneId::work(),
            test_connector_id(),
        );

        // branch_a has higher lease_seq
        let winner = fork.resolve_by_lease(200, 100);
        assert_eq!(winner, Some(branch_a));

        // branch_b has higher lease_seq
        let winner = fork.resolve_by_lease(100, 200);
        assert_eq!(winner, Some(branch_b));

        // Tie - no winner
        let winner = fork.resolve_by_lease(100, 100);
        assert!(winner.is_none());
    }

    #[test]
    fn fork_detector_resolve_by_lease_success() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("genesis");
        let branch_a = test_object_id("branch_a");
        let branch_b = test_object_id("branch_b");

        detector.register(genesis, None, 0, 100);
        detector.register(branch_a, Some(genesis), 1, 200); // Higher lease_seq
        detector.register(branch_b, Some(genesis), 1, 150);

        let result = detector.detect_fork(ZoneId::work(), test_connector_id(), 1_700_000_000);
        let fork = result.fork_event().unwrap();

        let outcome = detector.resolve(
            fork,
            ForkResolution::ChooseByLease,
            &ConnectorStateModel::SingletonWriter,
            1_700_000_001,
        );

        assert!(outcome.resolved);
        assert_eq!(outcome.winning_head, Some(branch_a));
    }

    #[test]
    fn fork_detector_resolve_invalid_strategy() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("genesis");
        let branch_a = test_object_id("branch_a");
        let branch_b = test_object_id("branch_b");
        let invalid_head = test_object_id("invalid");

        detector.register(genesis, None, 0, 100);
        detector.register(branch_a, Some(genesis), 1, 100);
        detector.register(branch_b, Some(genesis), 1, 100);

        let result = detector.detect_fork(ZoneId::work(), test_connector_id(), 1_700_000_000);
        let fork = result.fork_event().unwrap();

        // Try to select an invalid head
        let outcome = detector.resolve_manual(fork, invalid_head, 1_700_000_001);

        assert!(!outcome.resolved);
        assert!(
            outcome
                .failure_reason
                .unwrap()
                .contains("not one of the fork branches")
        );
    }

    #[test]
    fn fork_resolution_is_valid_for_model() {
        assert!(ForkResolution::ChooseByLease.is_valid_for(&ConnectorStateModel::SingletonWriter));
        assert!(!ForkResolution::ChooseByLease.is_valid_for(&ConnectorStateModel::Stateless));
        assert!(
            !ForkResolution::ChooseByLease.is_valid_for(&ConnectorStateModel::Crdt {
                crdt_type: CrdtType::LwwMap,
            })
        );

        assert!(
            ForkResolution::ManualResolution.is_valid_for(&ConnectorStateModel::SingletonWriter)
        );
        assert!(ForkResolution::ManualResolution.is_valid_for(&ConnectorStateModel::Stateless));
        assert!(
            ForkResolution::ManualResolution.is_valid_for(&ConnectorStateModel::Crdt {
                crdt_type: CrdtType::LwwMap,
            })
        );

        assert!(!ForkResolution::CrdtMerge.is_valid_for(&ConnectorStateModel::SingletonWriter));
        assert!(
            ForkResolution::CrdtMerge.is_valid_for(&ConnectorStateModel::Crdt {
                crdt_type: CrdtType::LwwMap,
            })
        );
    }

    #[test]
    fn fork_detector_clear() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("genesis");
        let obj1 = test_object_id("obj1");

        detector.register(genesis, None, 0, 100);
        detector.register(obj1, Some(genesis), 1, 100);

        assert!(detector.lease_seq(&genesis).is_some());

        detector.clear();

        assert!(detector.lease_seq(&genesis).is_none());
    }

    // ── CRDT merge tests ──

    #[test]
    fn merge_crdt_states_rejects_oversized_branch_a() {
        let oversized = vec![0u8; MAX_CRDT_STATE_BYTES + 1];
        let small = vec![0xA0]; // valid-ish single-byte CBOR (empty map)
        let err = merge_crdt_states(CrdtType::LwwMap, &oversized, &small)
            .expect_err("oversized branch_a must be rejected");
        match err {
            CrdtMergeError::Deserialization { message, .. } => {
                assert!(
                    message.contains("branch_a") && message.contains("exceeds"),
                    "expected branch_a size-cap error, got: {message}"
                );
            }
            other => panic!("expected Deserialization, got {other:?}"),
        }
    }

    #[test]
    fn merge_crdt_states_rejects_oversized_branch_b() {
        let small = vec![0xA0];
        let oversized = vec![0u8; MAX_CRDT_STATE_BYTES + 1];
        let err = merge_crdt_states(CrdtType::LwwMap, &small, &oversized)
            .expect_err("oversized branch_b must be rejected");
        match err {
            CrdtMergeError::Deserialization { message, .. } => {
                assert!(
                    message.contains("branch_b") && message.contains("exceeds"),
                    "expected branch_b size-cap error, got: {message}"
                );
            }
            other => panic!("expected Deserialization, got {other:?}"),
        }
    }

    #[test]
    fn merge_crdt_states_lww_map() {
        use crate::{CrdtActorId, LwwMap};

        let mut map_a = LwwMap::<String, serde_json::Value>::default();
        map_a.insert(
            "key1".into(),
            serde_json::json!("value_a"),
            100,
            CrdtActorId::new("node_a"),
        );
        map_a.insert(
            "key2".into(),
            serde_json::json!(42),
            100,
            CrdtActorId::new("node_a"),
        );

        let mut map_b = LwwMap::<String, serde_json::Value>::default();
        map_b.insert(
            "key1".into(),
            serde_json::json!("value_b"),
            200, // newer timestamp wins
            CrdtActorId::new("node_b"),
        );
        map_b.insert(
            "key3".into(),
            serde_json::json!("only_b"),
            100,
            CrdtActorId::new("node_b"),
        );

        let cbor_a = fcp_cbor::to_canonical_cbor(&map_a).unwrap();
        let cbor_b = fcp_cbor::to_canonical_cbor(&map_b).unwrap();

        let merged = merge_crdt_states(CrdtType::LwwMap, &cbor_a, &cbor_b).unwrap();

        let result: LwwMap<String, serde_json::Value> = ciborium::from_reader(&merged[..]).unwrap();
        // key1 should have value_b (timestamp 200 > 100)
        assert_eq!(
            result.get(&"key1".to_string()).unwrap().value,
            serde_json::json!("value_b")
        );
        // key2 should be preserved from A
        assert_eq!(
            result.get(&"key2".to_string()).unwrap().value,
            serde_json::json!(42)
        );
        // key3 should be added from B
        assert_eq!(
            result.get(&"key3".to_string()).unwrap().value,
            serde_json::json!("only_b")
        );
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn merge_crdt_states_gcounter() {
        use crate::{CrdtActorId, GCounter};

        let mut counter_a = GCounter::default();
        counter_a.increment(CrdtActorId::new("node_a"), 10);
        counter_a.increment(CrdtActorId::new("node_b"), 5);

        let mut counter_b = GCounter::default();
        counter_b.increment(CrdtActorId::new("node_a"), 7); // less than A's 10
        counter_b.increment(CrdtActorId::new("node_b"), 12); // more than A's 5
        counter_b.increment(CrdtActorId::new("node_c"), 3); // only in B

        let cbor_a = fcp_cbor::to_canonical_cbor(&counter_a).unwrap();
        let cbor_b = fcp_cbor::to_canonical_cbor(&counter_b).unwrap();

        let merged = merge_crdt_states(CrdtType::GCounter, &cbor_a, &cbor_b).unwrap();

        let result: GCounter = ciborium::from_reader(&merged[..]).unwrap();
        // max(10, 7) + max(5, 12) + 3 = 10 + 12 + 3 = 25
        assert_eq!(result.value(), 25);
    }

    #[test]
    fn merge_crdt_states_pn_counter() {
        use crate::{CrdtActorId, PnCounter};

        let mut pn_a = PnCounter::default();
        pn_a.increment(CrdtActorId::new("node_a"), 20);
        pn_a.decrement(CrdtActorId::new("node_a"), 5);

        let mut pn_b = PnCounter::default();
        pn_b.increment(CrdtActorId::new("node_b"), 10);
        pn_b.decrement(CrdtActorId::new("node_b"), 3);

        let cbor_a = fcp_cbor::to_canonical_cbor(&pn_a).unwrap();
        let cbor_b = fcp_cbor::to_canonical_cbor(&pn_b).unwrap();

        let merged = merge_crdt_states(CrdtType::PnCounter, &cbor_a, &cbor_b).unwrap();

        let result: PnCounter = ciborium::from_reader(&merged[..]).unwrap();
        // pos: max(20,0) + max(0,10) = 20 + 10 = 30
        // neg: max(5,0) + max(0,3) = 5 + 3 = 8
        // value = 30 - 8 = 22
        assert_eq!(result.value(), 22);
    }

    #[test]
    fn merge_crdt_states_or_set() {
        use crate::{CrdtActorId, OrSet, OrSetTag};

        let mut set_a = OrSet::<String>::default();
        set_a.add("item1".into(), OrSetTag::new(CrdtActorId::new("a"), 1));
        set_a.add("item2".into(), OrSetTag::new(CrdtActorId::new("a"), 2));

        let mut set_b = OrSet::<String>::default();
        set_b.add("item2".into(), OrSetTag::new(CrdtActorId::new("b"), 3));
        set_b.add("item3".into(), OrSetTag::new(CrdtActorId::new("b"), 4));

        let cbor_a = fcp_cbor::to_canonical_cbor(&set_a).unwrap();
        let cbor_b = fcp_cbor::to_canonical_cbor(&set_b).unwrap();

        let merged = merge_crdt_states(CrdtType::OrSet, &cbor_a, &cbor_b).unwrap();

        let result: OrSet<String> = ciborium::from_reader(&merged[..]).unwrap();
        assert!(result.contains(&"item1".to_string()));
        assert!(result.contains(&"item2".to_string()));
        assert!(result.contains(&"item3".to_string()));
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn merge_crdt_states_rejects_invalid_cbor() {
        let bad_cbor = b"not valid CBOR at all";
        let good_gcounter = {
            let c = crate::GCounter::default();
            fcp_cbor::to_canonical_cbor(&c).unwrap()
        };

        let err = merge_crdt_states(CrdtType::GCounter, bad_cbor, &good_gcounter);
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("deserialization"), "error: {msg}");
    }

    #[test]
    fn fork_detector_crdt_merge_returns_success() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("genesis");
        let obj1 = test_object_id("crdt_branch_a");
        let obj2 = test_object_id("crdt_branch_b");

        detector.register(genesis, None, 0, 0);
        detector.register(obj1, Some(genesis), 1, 0);
        detector.register(obj2, Some(genesis), 1, 0);

        let detection = detector.detect_fork(ZoneId::work(), test_connector_id(), 1_700_000_000);
        assert!(detection.is_fork());

        let model = ConnectorStateModel::Crdt {
            crdt_type: CrdtType::LwwMap,
        };
        let fork = detection.fork_event().unwrap();
        let outcome = detector.resolve(fork, ForkResolution::CrdtMerge, &model, 1_700_000_000);
        assert!(
            outcome.resolved,
            "CrdtMerge should succeed at detector level: {:?}",
            outcome.failure_reason
        );
        assert_eq!(outcome.strategy, ForkResolution::CrdtMerge);
        // The winning head is branch_a by convention (merge base)
        assert!(outcome.winning_head.is_some());
    }

    #[test]
    fn crdt_merge_outcome_serialization() {
        use crate::CrdtActorId;

        let mut counter = crate::GCounter::default();
        counter.increment(CrdtActorId::new("test"), 42);
        let state = fcp_cbor::to_canonical_cbor(&counter).unwrap();

        let outcome = CrdtMergeOutcome {
            fork_event: ForkEvent {
                common_prev: test_object_id("prev"),
                branch_a: test_object_id("a"),
                branch_b: test_object_id("b"),
                fork_seq: 5,
                detected_at: 1000,
                zone_id: crate::ZoneId::work(),
                connector_id: crate::ConnectorId::from_static("test.connector"),
            },
            merged_state_cbor: state,
            crdt_type: CrdtType::GCounter,
            merged_at: 2000,
            diagnostic: None,
        };

        let json = serde_json::to_string(&outcome).unwrap();
        let roundtrip: CrdtMergeOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.crdt_type, CrdtType::GCounter);
        assert_eq!(roundtrip.merged_at, 2000);
    }

    // ── Additional coverage ──

    #[test]
    fn crdt_type_as_str() {
        assert_eq!(CrdtType::LwwMap.as_str(), "lww_map");
        assert_eq!(CrdtType::OrSet.as_str(), "or_set");
        assert_eq!(CrdtType::GCounter.as_str(), "g_counter");
        assert_eq!(CrdtType::PnCounter.as_str(), "pn_counter");
    }

    #[test]
    fn signature_serde_roundtrip() {
        let sig = Signature::from_bytes([0xAB; 64]);
        let json = serde_json::to_string(&sig).unwrap();
        let back: Signature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, back);
    }

    #[test]
    fn signature_debug_is_truncated() {
        let sig = Signature::from_bytes([0xCD; 64]);
        let debug = format!("{sig:?}");
        assert!(debug.contains("Signature"));
        assert!(debug.contains("..."));
    }

    #[test]
    fn signature_default_is_zero() {
        let sig = Signature::default();
        assert_eq!(sig, Signature::zero());
    }

    #[test]
    fn connector_state_model_tagged_serde() {
        // Verify the internally tagged representation
        let json = serde_json::to_string(&ConnectorStateModel::Stateless).unwrap();
        assert!(json.contains("\"type\":\"stateless\""));

        let json = serde_json::to_string(&ConnectorStateModel::SingletonWriter).unwrap();
        assert!(json.contains("\"type\":\"singleton_writer\""));

        let json = serde_json::to_string(&ConnectorStateModel::Crdt {
            crdt_type: CrdtType::LwwMap,
        })
        .unwrap();
        assert!(json.contains("\"type\":\"crdt\""));
        assert!(json.contains("\"crdt_type\":\"lww_map\""));
    }

    #[test]
    fn connector_state_root_stateless_constructor() {
        let root =
            ConnectorStateRoot::stateless(test_header(), test_connector_id(), ZoneId::work());
        assert!(root.model.is_stateless());
        assert!(root.head.is_none());
        assert!(root.instance_id.is_none());
        assert_eq!(root.state_schema_version, 1);
    }

    #[test]
    fn connector_state_root_singleton_writer_constructor() {
        let root = ConnectorStateRoot::singleton_writer(
            test_header(),
            test_connector_id(),
            ZoneId::work(),
        );
        assert!(root.model.is_singleton_writer());
    }

    #[test]
    fn connector_state_root_crdt_constructor() {
        let root = ConnectorStateRoot::crdt(
            test_header(),
            test_connector_id(),
            ZoneId::work(),
            CrdtType::GCounter,
        );
        assert!(root.model.is_crdt());
        assert_eq!(root.model.crdt_type(), Some(CrdtType::GCounter));
    }

    #[test]
    fn connector_state_root_with_instance_id() {
        let root =
            ConnectorStateRoot::stateless(test_header(), test_connector_id(), ZoneId::work())
                .with_instance_id(InstanceId::new());
        assert!(root.instance_id.is_some());
    }

    #[test]
    fn connector_state_root_with_head() {
        let head = test_object_id("head");
        let root =
            ConnectorStateRoot::stateless(test_header(), test_connector_id(), ZoneId::work())
                .with_head(head);
        assert_eq!(root.head, Some(head));
    }

    #[test]
    fn connector_state_object_is_genesis() {
        let mut header = test_header();
        let lease_id = test_object_id("lease");
        header.refs.push(lease_id);

        let genesis = ConnectorStateObject {
            header: header.clone(),
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: ZoneId::work(),
            prev: None,
            seq: 0,
            state_cbor: vec![],
            updated_at: 1_700_000_000,
            lease_seq: 1,
            lease_object_id: lease_id,
            writer_public_key: [0u8; 32],
            signature: Signature::zero(),
        };
        assert!(genesis.is_genesis());

        let non_genesis = ConnectorStateObject {
            prev: Some(test_object_id("prev")),
            seq: 1,
            ..genesis
        };
        assert!(!non_genesis.is_genesis());
    }

    #[test]
    fn migratable_computation_suspend_resume_same_holder() {
        let lease_id = test_object_id("lease-source");
        let checkpoint = test_computation_checkpoint("node-source", lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut computation = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("node-source"),
            lease_id,
            7,
            test_migration_context(0),
        );

        computation
            .suspend(&checkpoint, checkpoint_object_id)
            .unwrap();
        assert_eq!(computation.state, MigratableComputationState::Suspended);

        let local_resume_lease = test_migration_lease("node-source", 7, 2_000);
        computation
            .resume(
                &checkpoint,
                checkpoint_object_id,
                lease_id,
                &local_resume_lease,
                1_500,
            )
            .unwrap();

        assert_eq!(computation.state, MigratableComputationState::Running);
        assert_eq!(computation.current_holder, test_node_id("node-source"));
    }

    #[test]
    fn migratable_computation_suspend_transfer_resume() {
        let source_lease_id = test_object_id("lease-source");
        let target_lease_id = test_object_id("lease-target");
        let checkpoint = test_computation_checkpoint("node-source", source_lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut computation = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("node-source"),
            source_lease_id,
            7,
            test_migration_context(0),
        );

        computation
            .suspend(&checkpoint, checkpoint_object_id)
            .unwrap();

        let active_lease = test_migration_lease("node-source", 7, 2_000);
        let handoff = test_migration_handoff(
            source_lease_id,
            target_lease_id,
            "node-source",
            "node-target",
            7,
            8,
        );
        computation
            .begin_transfer(&active_lease, &handoff, 1_500)
            .unwrap();
        assert!(matches!(
            computation.state,
            MigratableComputationState::Transferring {
                ref target_holder,
                next_lease_id,
                next_fencing_token
            } if target_holder == &test_node_id("node-target")
                && next_lease_id == target_lease_id
                && next_fencing_token == 8
        ));

        let target_lease = test_migration_lease("node-target", 8, 2_500);
        computation
            .resume(
                &checkpoint,
                checkpoint_object_id,
                target_lease_id,
                &target_lease,
                1_600,
            )
            .unwrap();

        assert_eq!(computation.state, MigratableComputationState::Running);
        assert_eq!(computation.current_holder, test_node_id("node-target"));
        assert_eq!(computation.execution_lease_id, target_lease_id);
        assert_eq!(computation.lease_fencing_token, 8);
    }

    #[test]
    fn migratable_computation_resume_rejects_non_holder() {
        let source_lease_id = test_object_id("lease-source");
        let target_lease_id = test_object_id("lease-target");
        let checkpoint = test_computation_checkpoint("node-source", source_lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut computation = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("node-source"),
            source_lease_id,
            7,
            test_migration_context(0),
        );

        computation
            .suspend(&checkpoint, checkpoint_object_id)
            .unwrap();
        let active_lease = test_migration_lease("node-source", 7, 2_000);
        let handoff = test_migration_handoff(
            source_lease_id,
            target_lease_id,
            "node-source",
            "node-target",
            7,
            8,
        );
        computation
            .begin_transfer(&active_lease, &handoff, 1_500)
            .unwrap();

        let wrong_holder_lease = test_migration_lease("node-wrong", 8, 2_500);
        let err = computation
            .resume(
                &checkpoint,
                checkpoint_object_id,
                target_lease_id,
                &wrong_holder_lease,
                1_600,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::ResumeHolderMismatch { .. }
        ));
    }

    #[test]
    fn migratable_computation_suspend_rejects_stale_checkpoint_fence() {
        let lease_id = test_object_id("lease-source");
        let checkpoint = test_computation_checkpoint("node-source", lease_id, 6, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut computation = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("node-source"),
            lease_id,
            7,
            test_migration_context(0),
        );

        let err = computation
            .suspend(&checkpoint, checkpoint_object_id)
            .unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::CheckpointFenceMismatch { .. }
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ConnectorStateDelta tests (zero coverage → new)
    // ─────────────────────────────────────────────────────────────────────────

    fn create_test_delta() -> ConnectorStateDelta {
        ConnectorStateDelta {
            header: test_header(),
            connector_id: test_connector_id(),
            instance_id: Some(InstanceId::new()),
            zone_id: ZoneId::work(),
            crdt_type: CrdtType::LwwMap,
            delta_cbor: vec![0xA0], // empty CBOR map
            applied_at: 1_700_000_000,
            applied_by: TailscaleNodeId::new("node-1"),
            signature: Signature::zero(),
        }
    }

    #[test]
    fn connector_state_delta_clone() {
        let delta = create_test_delta();
        let cloned = Clone::clone(&delta);
        assert_eq!(cloned.applied_at, 1_700_000_000);
        assert_eq!(cloned.crdt_type, CrdtType::LwwMap);
    }

    #[test]
    fn connector_state_delta_serde_roundtrip() {
        let delta = create_test_delta();
        let json = serde_json::to_string(&delta).unwrap();
        let back: ConnectorStateDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(back.applied_at, delta.applied_at);
        assert_eq!(back.crdt_type, delta.crdt_type);
        assert_eq!(back.delta_cbor, delta.delta_cbor);
    }

    #[test]
    fn connector_state_delta_serde_omits_none_instance() {
        let mut delta = create_test_delta();
        delta.instance_id = None;
        let json = serde_json::to_string(&delta).unwrap();
        assert!(!json.contains("instance_id"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ConnectorStateSnapshot tests (zero coverage → new)
    // ─────────────────────────────────────────────────────────────────────────

    fn create_test_snapshot() -> ConnectorStateSnapshot {
        ConnectorStateSnapshot {
            header: test_header(),
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: ZoneId::work(),
            covers_head: test_object_id("head-100"),
            covers_seq: 100,
            state_cbor: vec![0xA0],
            snapshotted_at: 1_700_000_000,
            signature: Signature::zero(),
        }
    }

    #[test]
    fn connector_state_snapshot_clone() {
        let snap = create_test_snapshot();
        let cloned = Clone::clone(&snap);
        assert_eq!(cloned.covers_seq, 100);
        assert_eq!(cloned.snapshotted_at, 1_700_000_000);
    }

    #[test]
    fn connector_state_snapshot_serde_roundtrip() {
        let snap = create_test_snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let back: ConnectorStateSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.covers_seq, snap.covers_seq);
        assert_eq!(back.state_cbor, snap.state_cbor);
        assert_eq!(back.snapshotted_at, snap.snapshotted_at);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ConnectorStateObject additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_state_object_clone() {
        let obj = ConnectorStateObject {
            header: test_header(),
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: ZoneId::work(),
            prev: None,
            seq: 0,
            state_cbor: vec![0xA0],
            updated_at: 1_700_000_000,
            lease_seq: 42,
            lease_object_id: test_object_id("lease-1"),
            writer_public_key: [0u8; 32],
            signature: Signature::zero(),
        };
        let cloned = Clone::clone(&obj);
        assert_eq!(cloned.seq, 0);
        assert!(cloned.is_genesis());
    }

    #[test]
    fn connector_state_object_serde_roundtrip() {
        let obj = ConnectorStateObject {
            header: test_header(),
            connector_id: test_connector_id(),
            instance_id: Some(InstanceId::new()),
            zone_id: ZoneId::work(),
            prev: Some(test_object_id("prev")),
            seq: 5,
            state_cbor: vec![0xBF, 0xFF],
            updated_at: 1_700_000_000,
            lease_seq: 10,
            lease_object_id: test_object_id("lease-2"),
            writer_public_key: [0u8; 32],
            signature: Signature::zero(),
        };
        let json = serde_json::to_string(&obj).unwrap();
        let back: ConnectorStateObject = serde_json::from_str(&json).unwrap();
        assert_eq!(back.seq, 5);
        assert!(!back.is_genesis());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FencingError trait coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fencing_error_clone() {
        let err = FencingError::StaleLeaseSeq {
            held_seq: 42,
            current_seq: 41,
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn fencing_error_equality() {
        let a = FencingError::WrongPurpose;
        let b = FencingError::WrongPurpose;
        assert_eq!(a, b);
    }

    #[test]
    fn fencing_error_inequality() {
        let a = FencingError::WrongPurpose;
        let b = FencingError::LeaseNotFound {
            lease_id: test_object_id("lease-1"),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn fencing_error_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(FencingError::WrongPurpose);
        assert!(!err.to_string().is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ForkEvent Clone
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fork_event_clone() {
        let event = ForkEvent::new(
            test_object_id("prev"),
            test_object_id("a"),
            test_object_id("b"),
            10,
            1_700_000_000,
            ZoneId::work(),
            test_connector_id(),
        );
        let cloned = event.clone();
        assert_eq!(event, cloned);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ForkResolutionOutcome Clone + serde
    // ─────────────────────────────────────────────────────────────────────────

    fn create_test_fork_event() -> ForkEvent {
        ForkEvent::new(
            test_object_id("prev"),
            test_object_id("a"),
            test_object_id("b"),
            10,
            1_700_000_000,
            ZoneId::work(),
            test_connector_id(),
        )
    }

    #[test]
    fn fork_resolution_outcome_success_clone() {
        let outcome = ForkResolutionOutcome::success(
            create_test_fork_event(),
            ForkResolution::ChooseByLease,
            test_object_id("winner"),
            1_700_000_100,
        );
        let cloned = Clone::clone(&outcome);
        assert!(cloned.resolved);
        assert!(cloned.failure_reason.is_none());
    }

    #[test]
    fn fork_resolution_outcome_serde_roundtrip() {
        let outcome = ForkResolutionOutcome::failure(
            create_test_fork_event(),
            ForkResolution::ManualResolution,
            1_700_000_100,
            "test failure",
        );
        let json = serde_json::to_string(&outcome).unwrap();
        let back: ForkResolutionOutcome = serde_json::from_str(&json).unwrap();
        assert!(!back.resolved);
        assert!(back.failure_reason.is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Bead 24llg.5.3.1: Merge and placement decision diagnostics
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fork_resolution_success_has_decision_detail() {
        let outcome = ForkResolutionOutcome::success(
            create_test_fork_event(),
            ForkResolution::ChooseByLease,
            test_object_id("winner"),
            1_700_000_100,
        );
        assert!(outcome.resolved);
        let detail = outcome
            .decision_detail
            .as_ref()
            .expect("should have decision_detail");
        assert!(
            detail.contains("lease_seq"),
            "ChooseByLease detail should mention lease_seq: {detail}"
        );
    }

    #[test]
    fn fork_resolution_crdt_merge_decision_detail() {
        let outcome = ForkResolutionOutcome::success(
            create_test_fork_event(),
            ForkResolution::CrdtMerge,
            test_object_id("merged"),
            1_700_000_100,
        );
        let detail = outcome
            .decision_detail
            .as_ref()
            .expect("should have decision_detail");
        assert!(
            detail.contains("CRDT"),
            "CrdtMerge detail should mention CRDT: {detail}"
        );
    }

    #[test]
    fn fork_resolution_failure_has_decision_detail() {
        let outcome = ForkResolutionOutcome::failure(
            create_test_fork_event(),
            ForkResolution::ManualResolution,
            1_700_000_100,
            "lease tie",
        );
        let detail = outcome
            .decision_detail
            .as_ref()
            .expect("should have decision_detail");
        assert!(
            detail.contains("lease tie"),
            "Failure detail should include the reason: {detail}"
        );
    }

    #[test]
    fn fork_resolution_decision_detail_serializes() {
        let outcome = ForkResolutionOutcome::success(
            create_test_fork_event(),
            ForkResolution::ChooseByLease,
            test_object_id("winner"),
            1_700_000_100,
        );
        let json = serde_json::to_value(&outcome).unwrap();
        assert!(
            json["decision_detail"].is_string(),
            "decision_detail should serialize as string"
        );
    }

    #[test]
    fn merge_diagnostic_serializes() {
        let diag = MergeDiagnostic {
            strategy: "lww-map".to_owned(),
            branch_a_size: 3,
            branch_b_size: 5,
            merged_size: 6,
            explanation: "LWW merge resolved 2 conflicting keys by timestamp.".to_owned(),
        };
        let json = serde_json::to_value(&diag).unwrap();
        assert_eq!(json["strategy"], "lww-map");
        assert_eq!(json["branch_a_size"], 3);
        assert_eq!(json["merged_size"], 6);
    }

    #[test]
    fn crdt_merge_outcome_with_diagnostic() {
        let mut counter = crate::GCounter::default();
        counter.increment(crate::CrdtActorId::new("test"), 10);
        let state = fcp_cbor::to_canonical_cbor(&counter).unwrap();

        let outcome = CrdtMergeOutcome {
            fork_event: create_test_fork_event(),
            merged_state_cbor: state,
            crdt_type: CrdtType::GCounter,
            merged_at: 2000,
            diagnostic: Some(MergeDiagnostic {
                strategy: "g-counter".to_owned(),
                branch_a_size: 1,
                branch_b_size: 1,
                merged_size: 1,
                explanation: "GCounter merge took max of each actor's count.".to_owned(),
            }),
        };
        let json = serde_json::to_value(&outcome).unwrap();
        assert!(json["diagnostic"].is_object());
        assert_eq!(json["diagnostic"]["strategy"], "g-counter");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ConnectorStateRoot Clone
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_state_root_clone() {
        let root = ConnectorStateRoot::singleton_writer(
            test_header(),
            test_connector_id(),
            ZoneId::work(),
        );
        let cloned = Clone::clone(&root);
        assert_eq!(cloned.model, ConnectorStateModel::SingletonWriter);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional CrdtType tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn crdt_type_copy_semantics() {
        let ct = CrdtType::OrSet;
        let copied = ct;
        assert_eq!(ct, copied);
    }

    #[test]
    fn crdt_type_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(CrdtType::LwwMap);
        set.insert(CrdtType::OrSet);
        set.insert(CrdtType::GCounter);
        set.insert(CrdtType::PnCounter);
        assert_eq!(set.len(), 4);
        assert!(set.contains(&CrdtType::LwwMap));
    }

    #[test]
    fn crdt_type_serde_snake_case_values() {
        let json = serde_json::to_string(&CrdtType::LwwMap).unwrap();
        assert_eq!(json, "\"lww_map\"");
        let json = serde_json::to_string(&CrdtType::OrSet).unwrap();
        assert_eq!(json, "\"or_set\"");
        let json = serde_json::to_string(&CrdtType::GCounter).unwrap();
        assert_eq!(json, "\"g_counter\"");
        let json = serde_json::to_string(&CrdtType::PnCounter).unwrap();
        assert_eq!(json, "\"pn_counter\"");
    }

    #[test]
    fn crdt_type_debug_format() {
        let debug = format!("{:?}", CrdtType::LwwMap);
        assert_eq!(debug, "LwwMap");
        let debug = format!("{:?}", CrdtType::PnCounter);
        assert_eq!(debug, "PnCounter");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional ConnectorStateModel tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_state_model_crdt_all_types() {
        for crdt_type in [
            CrdtType::LwwMap,
            CrdtType::OrSet,
            CrdtType::GCounter,
            CrdtType::PnCounter,
        ] {
            let model = ConnectorStateModel::Crdt { crdt_type };
            assert!(model.is_crdt());
            assert_eq!(model.crdt_type(), Some(crdt_type));
            let display = model.to_string();
            assert!(display.starts_with("crdt("));
            assert!(display.ends_with(')'));
        }
    }

    #[test]
    fn connector_state_model_display_crdt_or_set() {
        let model = ConnectorStateModel::Crdt {
            crdt_type: CrdtType::OrSet,
        };
        assert_eq!(model.to_string(), "crdt(or_set)");
    }

    #[test]
    fn connector_state_model_display_crdt_pn_counter() {
        let model = ConnectorStateModel::Crdt {
            crdt_type: CrdtType::PnCounter,
        };
        assert_eq!(model.to_string(), "crdt(pn_counter)");
    }

    #[test]
    fn connector_state_model_equality() {
        let a = ConnectorStateModel::Stateless;
        let b = ConnectorStateModel::Stateless;
        assert_eq!(a, b);
        let c = ConnectorStateModel::SingletonWriter;
        assert_ne!(a, c);
    }

    #[test]
    fn connector_state_model_crdt_equality_same() {
        let a = ConnectorStateModel::Crdt {
            crdt_type: CrdtType::GCounter,
        };
        let b = ConnectorStateModel::Crdt {
            crdt_type: CrdtType::GCounter,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn connector_state_model_crdt_equality_different() {
        let a = ConnectorStateModel::Crdt {
            crdt_type: CrdtType::GCounter,
        };
        let b = ConnectorStateModel::Crdt {
            crdt_type: CrdtType::PnCounter,
        };
        assert_ne!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional Signature tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn signature_equality() {
        let a = Signature::from_bytes([1u8; 64]);
        let b = Signature::from_bytes([1u8; 64]);
        assert_eq!(a, b);
    }

    #[test]
    fn signature_inequality() {
        let a = Signature::from_bytes([1u8; 64]);
        let b = Signature::from_bytes([2u8; 64]);
        assert_ne!(a, b);
    }

    #[test]
    fn signature_copy_semantics() {
        let sig = Signature::from_bytes([0xAA; 64]);
        let copied = sig;
        assert_eq!(sig, copied);
    }

    #[test]
    fn signature_display_shows_first_8_bytes() {
        let mut bytes = [0u8; 64];
        bytes[0] = 0xDE;
        bytes[1] = 0xAD;
        bytes[2] = 0xBE;
        bytes[3] = 0xEF;
        bytes[4] = 0xCA;
        bytes[5] = 0xFE;
        bytes[6] = 0xBA;
        bytes[7] = 0xBE;
        let sig = Signature::from_bytes(bytes);
        assert_eq!(sig.to_string(), "deadbeefcafebabe...");
    }

    #[test]
    fn signature_debug_truncated_format() {
        let sig = Signature::from_bytes([0xFF; 64]);
        let debug = format!("{sig:?}");
        assert!(debug.starts_with("Signature("));
        assert!(debug.contains("..."));
    }

    #[test]
    fn signature_json_roundtrip_all_zeros() {
        let sig = Signature::zero();
        let json = serde_json::to_string(&sig).unwrap();
        let back: Signature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, back);
        assert_eq!(back.as_bytes(), &[0u8; 64]);
    }

    #[test]
    fn signature_json_roundtrip_all_ones() {
        let sig = Signature::from_bytes([0xFF; 64]);
        let json = serde_json::to_string(&sig).unwrap();
        let back: Signature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, back);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional CursorState tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn cursor_state_all_none() {
        let state = CursorState {
            offset: None,
            last_seen_id: None,
            watermark: None,
        };
        let cbor = state.to_cbor().unwrap();
        let back = CursorState::from_cbor(&cbor).unwrap();
        assert_eq!(state, back);
    }

    #[test]
    fn cursor_state_only_offset() {
        let state = CursorState {
            offset: Some(999),
            last_seen_id: None,
            watermark: None,
        };
        let cbor = state.to_cbor().unwrap();
        let back = CursorState::from_cbor(&cbor).unwrap();
        assert_eq!(back.offset, Some(999));
        assert!(back.last_seen_id.is_none());
    }

    #[test]
    fn cursor_state_only_last_seen_id() {
        let state = CursorState {
            offset: None,
            last_seen_id: Some("msg_abc".to_string()),
            watermark: None,
        };
        let cbor = state.to_cbor().unwrap();
        let back = CursorState::from_cbor(&cbor).unwrap();
        assert_eq!(back.last_seen_id.as_deref(), Some("msg_abc"));
    }

    #[test]
    fn cursor_state_only_watermark() {
        let state = CursorState {
            offset: None,
            last_seen_id: None,
            watermark: Some(1_700_000_555),
        };
        let cbor = state.to_cbor().unwrap();
        let back = CursorState::from_cbor(&cbor).unwrap();
        assert_eq!(back.watermark, Some(1_700_000_555));
    }

    #[test]
    fn cursor_state_negative_offset() {
        let state = CursorState {
            offset: Some(-42),
            last_seen_id: None,
            watermark: None,
        };
        let cbor = state.to_cbor().unwrap();
        let back = CursorState::from_cbor(&cbor).unwrap();
        assert_eq!(back.offset, Some(-42));
    }

    #[test]
    fn cursor_state_zero_offset() {
        let state = CursorState {
            offset: Some(0),
            last_seen_id: None,
            watermark: None,
        };
        let cbor = state.to_cbor().unwrap();
        let back = CursorState::from_cbor(&cbor).unwrap();
        assert_eq!(back.offset, Some(0));
    }

    #[test]
    fn cursor_state_large_offset() {
        let state = CursorState {
            offset: Some(i64::MAX),
            last_seen_id: None,
            watermark: None,
        };
        let cbor = state.to_cbor().unwrap();
        let back = CursorState::from_cbor(&cbor).unwrap();
        assert_eq!(back.offset, Some(i64::MAX));
    }

    #[test]
    fn cursor_state_empty_last_seen_id() {
        let state = CursorState {
            offset: None,
            last_seen_id: Some(String::new()),
            watermark: None,
        };
        let cbor = state.to_cbor().unwrap();
        let back = CursorState::from_cbor(&cbor).unwrap();
        assert_eq!(back.last_seen_id.as_deref(), Some(""));
    }

    #[test]
    fn cursor_state_json_serde_roundtrip() {
        let state = CursorState {
            offset: Some(77),
            last_seen_id: Some("last-77".to_string()),
            watermark: Some(1_234_567),
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: CursorState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }

    #[test]
    fn cursor_state_json_omits_none_fields() {
        let state = CursorState {
            offset: None,
            last_seen_id: None,
            watermark: None,
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(!json.contains("offset"));
        assert!(!json.contains("last_seen_id"));
        assert!(!json.contains("watermark"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional SnapshotConfig tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn snapshot_config_below_both_thresholds() {
        let config = SnapshotConfig {
            snapshot_every_updates: 100,
            snapshot_every_bytes: 1000,
        };
        assert!(!config.should_snapshot(99, 999));
    }

    #[test]
    fn snapshot_config_zero_thresholds() {
        let config = SnapshotConfig {
            snapshot_every_updates: 0,
            snapshot_every_bytes: 0,
        };
        assert!(config.should_snapshot(0, 0));
    }

    #[test]
    fn snapshot_config_serde_roundtrip() {
        let config = SnapshotConfig {
            snapshot_every_updates: 2500,
            snapshot_every_bytes: 512_000,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: SnapshotConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.snapshot_every_updates, 2500);
        assert_eq!(back.snapshot_every_bytes, 512_000);
    }

    #[test]
    fn snapshot_config_serde_defaults_applied() {
        let json = "{}";
        let config: SnapshotConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.snapshot_every_updates, 5000);
        assert_eq!(config.snapshot_every_bytes, 1_048_576);
    }

    #[test]
    fn snapshot_config_clone() {
        let config = SnapshotConfig {
            snapshot_every_updates: 42,
            snapshot_every_bytes: 9999,
        };
        let cloned = Clone::clone(&config);
        assert_eq!(cloned.snapshot_every_updates, 42);
        assert_eq!(cloned.snapshot_every_bytes, 9999);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional FencingError Display coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fencing_error_display_subject_mismatch() {
        let err = FencingError::SubjectMismatch {
            expected: test_object_id("expected"),
            got: test_object_id("got"),
        };
        let display = err.to_string();
        assert!(display.contains("subject mismatch"));
    }

    #[test]
    fn fencing_error_display_lease_not_found() {
        let err = FencingError::LeaseNotFound {
            lease_id: test_object_id("missing"),
        };
        let display = err.to_string();
        assert!(display.contains("not found"));
    }

    #[test]
    fn fencing_error_display_lease_expired_values() {
        let err = FencingError::LeaseExpired {
            expired_at: 500,
            now: 700,
        };
        let display = err.to_string();
        assert!(display.contains("500"));
        assert!(display.contains("700"));
    }

    #[test]
    fn fencing_error_display_stale_lease_seq_values() {
        let err = FencingError::StaleLeaseSeq {
            held_seq: 3,
            current_seq: 10,
        };
        let display = err.to_string();
        assert!(display.contains('3'));
        assert!(display.contains("10"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // validate_singleton_writer_fencing tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fencing_valid_passes() {
        let lease_id = test_object_id("lease-fence");
        let mut header = test_header();
        header.refs.push(lease_id);
        let obj = ConnectorStateObject {
            header,
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: ZoneId::work(),
            prev: None,
            seq: 0,
            state_cbor: vec![],
            updated_at: 1_000,
            lease_seq: 10,
            lease_object_id: lease_id,
            writer_public_key: [0u8; 32],
            signature: Signature::zero(),
        };
        assert!(validate_singleton_writer_fencing(&obj, 10, 500, 1000).is_ok());
    }

    #[test]
    fn fencing_rejects_expired_lease() {
        let lease_id = test_object_id("lease-fence");
        let mut header = test_header();
        header.refs.push(lease_id);
        let obj = ConnectorStateObject {
            header,
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: ZoneId::work(),
            prev: None,
            seq: 0,
            state_cbor: vec![],
            updated_at: 1_000,
            lease_seq: 10,
            lease_object_id: lease_id,
            writer_public_key: [0u8; 32],
            signature: Signature::zero(),
        };
        let err = validate_singleton_writer_fencing(&obj, 10, 2000, 1000).unwrap_err();
        assert!(matches!(err, FencingError::LeaseExpired { .. }));
    }

    #[test]
    fn fencing_rejects_stale_seq() {
        let lease_id = test_object_id("lease-fence");
        let mut header = test_header();
        header.refs.push(lease_id);
        let obj = ConnectorStateObject {
            header,
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: ZoneId::work(),
            prev: None,
            seq: 0,
            state_cbor: vec![],
            updated_at: 1_000,
            lease_seq: 5,
            lease_object_id: lease_id,
            writer_public_key: [0u8; 32],
            signature: Signature::zero(),
        };
        let err = validate_singleton_writer_fencing(&obj, 10, 500, 1000).unwrap_err();
        assert!(matches!(err, FencingError::StaleLeaseSeq { .. }));
    }

    #[test]
    fn fencing_rejects_missing_lease_ref() {
        let lease_id = test_object_id("lease-fence");
        let header = test_header(); // refs is empty - lease_id not included
        let obj = ConnectorStateObject {
            header,
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: ZoneId::work(),
            prev: None,
            seq: 0,
            state_cbor: vec![],
            updated_at: 1_000,
            lease_seq: 10,
            lease_object_id: lease_id,
            writer_public_key: [0u8; 32],
            signature: Signature::zero(),
        };
        let err = validate_singleton_writer_fencing(&obj, 10, 500, 1000).unwrap_err();
        assert!(matches!(err, FencingError::LeaseNotFound { .. }));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional ForkDetector tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fork_detector_empty() {
        let detector = StateForkDetector::new();
        let result = detector.detect_fork(ZoneId::work(), test_connector_id(), 1_700_000_000);
        assert!(!result.is_fork());
    }

    #[test]
    fn fork_detector_single_genesis() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("gen");
        detector.register(genesis, None, 0, 50);
        let result = detector.detect_fork(ZoneId::work(), test_connector_id(), 1_700_000_000);
        assert!(!result.is_fork());
        if let StateForkDetectionResult::NoFork { head, seq } = result {
            assert_eq!(head, genesis);
            assert_eq!(seq, 0);
        } else {
            panic!("expected NoFork");
        }
    }

    #[test]
    fn fork_detector_lease_seq_lookup() {
        let mut detector = StateForkDetector::new();
        let obj = test_object_id("obj");
        detector.register(obj, None, 0, 42);
        assert_eq!(detector.lease_seq(&obj), Some(42));
    }

    #[test]
    fn fork_detector_lease_seq_unknown() {
        let detector = StateForkDetector::new();
        assert!(detector.lease_seq(&test_object_id("unknown")).is_none());
    }

    #[test]
    fn fork_resolve_crdt_strategy_for_singleton_fails() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("gen");
        let a = test_object_id("a");
        let b = test_object_id("b");
        detector.register(genesis, None, 0, 100);
        detector.register(a, Some(genesis), 1, 101);
        detector.register(b, Some(genesis), 1, 102);
        let result = detector.detect_fork(ZoneId::work(), test_connector_id(), 1_700_000_000);
        let fork = result.fork_event().unwrap();
        let outcome = detector.resolve(
            fork,
            ForkResolution::CrdtMerge,
            &ConnectorStateModel::SingletonWriter,
            1_700_000_001,
        );
        assert!(!outcome.resolved);
        assert!(outcome.failure_reason.unwrap().contains("not valid"));
    }

    #[test]
    fn fork_resolve_manual_always_fails_without_selection() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("gen");
        let a = test_object_id("a");
        let b = test_object_id("b");
        detector.register(genesis, None, 0, 100);
        detector.register(a, Some(genesis), 1, 100);
        detector.register(b, Some(genesis), 1, 100);
        let result = detector.detect_fork(ZoneId::work(), test_connector_id(), 1_700_000_000);
        let fork = result.fork_event().unwrap();
        let outcome = detector.resolve(
            fork,
            ForkResolution::ManualResolution,
            &ConnectorStateModel::SingletonWriter,
            1_700_000_001,
        );
        assert!(!outcome.resolved);
        assert!(
            outcome
                .failure_reason
                .unwrap()
                .contains("manual resolution")
        );
    }

    #[test]
    fn fork_resolve_manual_select_branch_a() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("gen");
        let a = test_object_id("a");
        let b = test_object_id("b");
        detector.register(genesis, None, 0, 100);
        detector.register(a, Some(genesis), 1, 100);
        detector.register(b, Some(genesis), 1, 100);
        let result = detector.detect_fork(ZoneId::work(), test_connector_id(), 1_700_000_000);
        let fork = result.fork_event().unwrap();
        let outcome = detector.resolve_manual(fork, a, 1_700_000_001);
        assert!(outcome.resolved);
        assert_eq!(outcome.winning_head, Some(a));
    }

    #[test]
    fn fork_resolve_manual_select_branch_b() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("gen");
        let a = test_object_id("a");
        let b = test_object_id("b");
        detector.register(genesis, None, 0, 100);
        detector.register(a, Some(genesis), 1, 100);
        detector.register(b, Some(genesis), 1, 100);
        let result = detector.detect_fork(ZoneId::work(), test_connector_id(), 1_700_000_000);
        let fork = result.fork_event().unwrap();
        let outcome = detector.resolve_manual(fork, b, 1_700_000_001);
        assert!(outcome.resolved);
        assert_eq!(outcome.winning_head, Some(b));
    }

    #[test]
    fn fork_resolve_by_lease_tie() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("gen");
        let a = test_object_id("a");
        let b = test_object_id("b");
        detector.register(genesis, None, 0, 100);
        detector.register(a, Some(genesis), 1, 50);
        detector.register(b, Some(genesis), 1, 50);
        let result = detector.detect_fork(ZoneId::work(), test_connector_id(), 1_700_000_000);
        let fork = result.fork_event().unwrap();
        let outcome = detector.resolve(
            fork,
            ForkResolution::ChooseByLease,
            &ConnectorStateModel::SingletonWriter,
            1_700_000_001,
        );
        assert!(!outcome.resolved);
        assert!(outcome.failure_reason.unwrap().contains("tie"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional ForkEvent tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fork_event_serde_roundtrip() {
        let event = create_test_fork_event();
        let json = serde_json::to_string(&event).unwrap();
        let back: ForkEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn fork_event_fields() {
        let prev = test_object_id("prev");
        let a = test_object_id("a");
        let b = test_object_id("b");
        let event = ForkEvent::new(prev, a, b, 5, 999, ZoneId::work(), test_connector_id());
        assert_eq!(event.common_prev, prev);
        assert_eq!(event.branch_a, a);
        assert_eq!(event.branch_b, b);
        assert_eq!(event.fork_seq, 5);
        assert_eq!(event.detected_at, 999);
    }

    #[test]
    fn fork_event_resolve_by_lease_zero_vs_zero() {
        let event = create_test_fork_event();
        assert!(event.resolve_by_lease(0, 0).is_none());
    }

    #[test]
    fn fork_event_resolve_by_lease_max_values() {
        let event = create_test_fork_event();
        let winner = event.resolve_by_lease(u64::MAX, u64::MAX - 1);
        assert_eq!(winner, Some(event.branch_a));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // StateForkDetectionResult tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn state_fork_detection_result_no_fork() {
        let result = StateForkDetectionResult::NoFork {
            head: test_object_id("head"),
            seq: 5,
        };
        assert!(!result.is_fork());
        assert!(result.fork_event().is_none());
    }

    #[test]
    fn state_fork_detection_result_serde_no_fork() {
        let result = StateForkDetectionResult::NoFork {
            head: test_object_id("head"),
            seq: 10,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: StateForkDetectionResult = serde_json::from_str(&json).unwrap();
        assert!(!back.is_fork());
    }

    #[test]
    fn state_fork_detection_result_serde_fork_detected() {
        let event = create_test_fork_event();
        let result = StateForkDetectionResult::ForkDetected(event.clone());
        let json = serde_json::to_string(&result).unwrap();
        let back: StateForkDetectionResult = serde_json::from_str(&json).unwrap();
        assert!(back.is_fork());
        let back_event = back.fork_event().unwrap();
        assert_eq!(back_event, &event);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MigratableComputationState tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn migratable_computation_state_terminal() {
        assert!(MigratableComputationState::Completed.is_terminal());
        assert!(MigratableComputationState::Failed.is_terminal());
        assert!(!MigratableComputationState::Running.is_terminal());
        assert!(!MigratableComputationState::Suspended.is_terminal());
    }

    #[test]
    fn migratable_computation_state_transferring_not_terminal() {
        let state = MigratableComputationState::Transferring {
            target_holder: test_node_id("node-x"),
            next_lease_id: test_object_id("lease-x"),
            next_fencing_token: 99,
        };
        assert!(!state.is_terminal());
    }

    #[test]
    fn migratable_computation_state_serde_roundtrip_all() {
        let states = vec![
            MigratableComputationState::Running,
            MigratableComputationState::Suspended,
            MigratableComputationState::Completed,
            MigratableComputationState::Failed,
            MigratableComputationState::Transferring {
                target_holder: test_node_id("n"),
                next_lease_id: test_object_id("l"),
                next_fencing_token: 7,
            },
        ];
        for state in &states {
            let json = serde_json::to_string(state).unwrap();
            let back: MigratableComputationState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, &back);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MigratableComputation invalid state transition tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn migratable_computation_suspend_rejects_suspended_state() {
        let lease_id = test_object_id("lease");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();
        let err = comp.suspend(&checkpoint, checkpoint_object_id).unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::InvalidStateTransition {
                action: "suspend",
                ..
            }
        ));
    }

    #[test]
    fn migratable_computation_begin_transfer_rejects_running() {
        let lease_id = test_object_id("lease");
        let target_lease_id = test_object_id("lease-target");
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        let active_lease = test_migration_lease("holder", 7, 2_000);
        let handoff = test_migration_handoff(lease_id, target_lease_id, "holder", "target", 7, 8);
        let err = comp
            .begin_transfer(&active_lease, &handoff, 1_500)
            .unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::InvalidStateTransition {
                action: "begin_transfer",
                ..
            }
        ));
    }

    #[test]
    fn migratable_computation_resume_rejects_completed() {
        let lease_id = test_object_id("lease");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        comp.state = MigratableComputationState::Completed;
        let resume_lease = test_migration_lease("holder", 7, 2_000);
        let err = comp
            .resume(
                &checkpoint,
                checkpoint_object_id,
                lease_id,
                &resume_lease,
                1_500,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::InvalidStateTransition {
                action: "resume",
                ..
            }
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ConnectorStateRoot serde + builder
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_state_root_serde_roundtrip_stateless() {
        let root =
            ConnectorStateRoot::stateless(test_header(), test_connector_id(), ZoneId::work());
        let json = serde_json::to_string(&root).unwrap();
        let back: ConnectorStateRoot = serde_json::from_str(&json).unwrap();
        assert!(back.model.is_stateless());
        assert!(back.head.is_none());
        assert_eq!(back.state_schema_version, 1);
    }

    #[test]
    fn connector_state_root_serde_roundtrip_with_head() {
        let head = test_object_id("head-obj");
        let root = ConnectorStateRoot::singleton_writer(
            test_header(),
            test_connector_id(),
            ZoneId::work(),
        )
        .with_head(head);
        let json = serde_json::to_string(&root).unwrap();
        let back: ConnectorStateRoot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.head, Some(head));
        assert!(back.model.is_singleton_writer());
    }

    #[test]
    fn connector_state_root_default_schema_version() {
        let json = r#"{
            "header": {
                "schema": {"namespace":"fcp.test","name":"T","version":"1.0.0"},
                "zone_id": "z:work",
                "created_at": 0,
                "provenance": {"origin_zone":"z:work"}
            },
            "connector_id": "fcp.test:fork:v1",
            "zone_id": "z:work",
            "model": {"type":"stateless"}
        }"#;
        let root: ConnectorStateRoot = serde_json::from_str(json).unwrap();
        assert_eq!(root.state_schema_version, 1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ComputationMigrationError Display coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn computation_migration_error_display_invalid_transition() {
        let err = ComputationMigrationError::InvalidStateTransition {
            state: MigratableComputationState::Completed,
            action: "suspend",
        };
        let display = err.to_string();
        assert!(display.contains("suspend"));
        assert!(display.contains("Completed"));
    }

    #[test]
    fn computation_migration_error_display_checkpoint_computation_mismatch() {
        let err = ComputationMigrationError::CheckpointComputationMismatch {
            expected: test_object_id("expected"),
            got: test_object_id("got"),
        };
        let display = err.to_string();
        assert!(display.contains("computation mismatch"));
    }

    #[test]
    fn computation_migration_error_display_checkpoint_zone_mismatch() {
        let err = ComputationMigrationError::CheckpointZoneMismatch {
            expected: ZoneId::work(),
            got: ZoneId::private(),
        };
        let display = err.to_string();
        assert!(display.contains("zone mismatch"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Comprehensive computation migration state machine tests
    // ─────────────────────────────────────────────────────────────────────────

    // --- Checkpoint binding validation: each field mismatch ---

    #[test]
    fn suspend_rejects_checkpoint_computation_id_mismatch() {
        let lease_id = test_object_id("lease");
        let mut checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        checkpoint.computation_id = test_object_id("wrong-computation");
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        let err = comp.suspend(&checkpoint, checkpoint_object_id).unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::CheckpointComputationMismatch { .. }
        ));
    }

    #[test]
    fn suspend_rejects_checkpoint_zone_mismatch() {
        let lease_id = test_object_id("lease");
        let mut checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        checkpoint.header.zone_id = ZoneId::private();
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        let err = comp.suspend(&checkpoint, checkpoint_object_id).unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::CheckpointZoneMismatch { .. }
        ));
    }

    #[test]
    fn suspend_rejects_checkpoint_holder_mismatch() {
        let lease_id = test_object_id("lease");
        let checkpoint = test_computation_checkpoint("wrong-holder", lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        let err = comp.suspend(&checkpoint, checkpoint_object_id).unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::CheckpointHolderMismatch { .. }
        ));
    }

    #[test]
    fn suspend_rejects_checkpoint_lease_id_mismatch() {
        let lease_id = test_object_id("lease");
        let wrong_lease_id = test_object_id("wrong-lease");
        let checkpoint = test_computation_checkpoint("holder", wrong_lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        let err = comp.suspend(&checkpoint, checkpoint_object_id).unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::CheckpointLeaseIdMismatch { .. }
        ));
    }

    #[test]
    fn suspend_rejects_capability_token_mismatch() {
        let lease_id = test_object_id("lease");
        let mut checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        checkpoint.capability_context.capability_token_jti = Uuid::from_bytes([0xAB; 16]);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        let err = comp.suspend(&checkpoint, checkpoint_object_id).unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::CapabilityTokenMismatch { .. }
        ));
    }

    #[test]
    fn suspend_rejects_checkpoint_object_id_mismatch_when_already_set() {
        let lease_id = test_object_id("lease");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        // Pre-set a different checkpoint_object_id to trigger the "already set" branch
        comp.checkpoint_object_id = Some(test_object_id("other-checkpoint"));
        let err = comp.suspend(&checkpoint, checkpoint_object_id).unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::CheckpointObjectMismatch { .. }
        ));
    }

    // --- Invalid state transitions: all non-Running states for suspend ---

    #[test]
    fn suspend_rejects_transferring_state() {
        let lease_id = test_object_id("lease");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        comp.state = MigratableComputationState::Transferring {
            target_holder: test_node_id("target"),
            next_lease_id: test_object_id("next-lease"),
            next_fencing_token: 8,
        };
        let err = comp.suspend(&checkpoint, checkpoint_object_id).unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::InvalidStateTransition {
                action: "suspend",
                ..
            }
        ));
    }

    #[test]
    fn suspend_rejects_completed_state() {
        let lease_id = test_object_id("lease");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        comp.state = MigratableComputationState::Completed;
        let err = comp.suspend(&checkpoint, checkpoint_object_id).unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::InvalidStateTransition {
                action: "suspend",
                ..
            }
        ));
    }

    #[test]
    fn suspend_rejects_failed_state() {
        let lease_id = test_object_id("lease");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        comp.state = MigratableComputationState::Failed;
        let err = comp.suspend(&checkpoint, checkpoint_object_id).unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::InvalidStateTransition {
                action: "suspend",
                ..
            }
        ));
    }

    // --- Invalid state transitions: begin_transfer from non-Suspended states ---

    #[test]
    fn begin_transfer_rejects_completed_state() {
        let lease_id = test_object_id("lease");
        let target_lease_id = test_object_id("lease-target");
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        comp.state = MigratableComputationState::Completed;
        let active_lease = test_migration_lease("holder", 7, 2_000);
        let handoff = test_migration_handoff(lease_id, target_lease_id, "holder", "target", 7, 8);
        let err = comp
            .begin_transfer(&active_lease, &handoff, 1_500)
            .unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::InvalidStateTransition {
                action: "begin_transfer",
                ..
            }
        ));
    }

    #[test]
    fn begin_transfer_rejects_failed_state() {
        let lease_id = test_object_id("lease");
        let target_lease_id = test_object_id("lease-target");
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        comp.state = MigratableComputationState::Failed;
        let active_lease = test_migration_lease("holder", 7, 2_000);
        let handoff = test_migration_handoff(lease_id, target_lease_id, "holder", "target", 7, 8);
        let err = comp
            .begin_transfer(&active_lease, &handoff, 1_500)
            .unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::InvalidStateTransition {
                action: "begin_transfer",
                ..
            }
        ));
    }

    #[test]
    fn begin_transfer_rejects_transferring_state() {
        let lease_id = test_object_id("lease");
        let target_lease_id = test_object_id("lease-target");
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        comp.state = MigratableComputationState::Transferring {
            target_holder: test_node_id("other"),
            next_lease_id: test_object_id("other-lease"),
            next_fencing_token: 9,
        };
        let active_lease = test_migration_lease("holder", 7, 2_000);
        let handoff = test_migration_handoff(lease_id, target_lease_id, "holder", "target", 7, 8);
        let err = comp
            .begin_transfer(&active_lease, &handoff, 1_500)
            .unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::InvalidStateTransition {
                action: "begin_transfer",
                ..
            }
        ));
    }

    // --- begin_transfer: wrong prior lease ---

    #[test]
    fn begin_transfer_rejects_wrong_prior_lease_id() {
        let lease_id = test_object_id("lease");
        let target_lease_id = test_object_id("lease-target");
        let wrong_lease_id = test_object_id("wrong-lease");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();

        let active_lease = test_migration_lease("holder", 7, 2_000);
        // Handoff references wrong_lease_id as previous
        let handoff =
            test_migration_handoff(wrong_lease_id, target_lease_id, "holder", "target", 7, 8);
        let err = comp
            .begin_transfer(&active_lease, &handoff, 1_500)
            .unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::UnexpectedPriorLeaseId { .. }
        ));
    }

    // --- Resume: invalid state transitions ---

    #[test]
    fn resume_rejects_running_state() {
        let lease_id = test_object_id("lease");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let comp_id = test_object_id("computation");
        let mut comp = MigratableComputation::new(
            comp_id,
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        // Already Running, try resume
        let resume_lease = test_migration_lease("holder", 7, 2_000);
        let err = comp
            .resume(
                &checkpoint,
                checkpoint_object_id,
                lease_id,
                &resume_lease,
                1_500,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::InvalidStateTransition {
                action: "resume",
                ..
            }
        ));
    }

    #[test]
    fn resume_rejects_failed_state() {
        let lease_id = test_object_id("lease");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        comp.state = MigratableComputationState::Failed;
        let resume_lease = test_migration_lease("holder", 7, 2_000);
        let err = comp
            .resume(
                &checkpoint,
                checkpoint_object_id,
                lease_id,
                &resume_lease,
                1_500,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::InvalidStateTransition {
                action: "resume",
                ..
            }
        ));
    }

    // --- Resume from Suspended: wrong lease_id, wrong holder, wrong fencing token ---

    #[test]
    fn resume_from_suspended_rejects_wrong_lease_id() {
        let lease_id = test_object_id("lease");
        let wrong_lease_id = test_object_id("wrong-lease");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();

        let resume_lease = test_migration_lease("holder", 7, 2_000);
        let err = comp
            .resume(
                &checkpoint,
                checkpoint_object_id,
                wrong_lease_id,
                &resume_lease,
                1_500,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::ResumeLeaseIdMismatch { .. }
        ));
    }

    #[test]
    fn resume_from_suspended_rejects_wrong_holder() {
        let lease_id = test_object_id("lease");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();

        let wrong_holder_lease = test_migration_lease("wrong-holder", 7, 2_000);
        let err = comp
            .resume(
                &checkpoint,
                checkpoint_object_id,
                lease_id,
                &wrong_holder_lease,
                1_500,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::ResumeHolderMismatch { .. }
        ));
    }

    #[test]
    fn resume_from_suspended_rejects_wrong_fencing_token() {
        let lease_id = test_object_id("lease");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();

        // Lease with wrong fencing token (99 instead of 7)
        let wrong_fence_lease = test_migration_lease("holder", 99, 2_000);
        let err = comp
            .resume(
                &checkpoint,
                checkpoint_object_id,
                lease_id,
                &wrong_fence_lease,
                1_500,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::ResumeFenceMismatch { .. }
        ));
    }

    #[test]
    fn resume_from_suspended_rejects_expired_lease() {
        let lease_id = test_object_id("lease");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();

        let expired_lease = test_migration_lease("holder", 7, 1_000);
        let err = comp
            .resume(
                &checkpoint,
                checkpoint_object_id,
                lease_id,
                &expired_lease,
                1_500,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::LeaseValidation(crate::LeaseValidationError::Expired {
                expired_at: 1_000,
                now: 1_500
            })
        ));
        assert_eq!(comp.state, MigratableComputationState::Suspended);
    }

    // --- Resume from Transferring: wrong lease_id, wrong fencing token ---

    #[test]
    fn resume_from_transferring_rejects_wrong_lease_id() {
        let source_lease_id = test_object_id("lease-source");
        let target_lease_id = test_object_id("lease-target");
        let wrong_lease_id = test_object_id("wrong-lease");
        let checkpoint = test_computation_checkpoint("node-source", source_lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("node-source"),
            source_lease_id,
            7,
            test_migration_context(0),
        );
        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();
        let active_lease = test_migration_lease("node-source", 7, 2_000);
        let handoff = test_migration_handoff(
            source_lease_id,
            target_lease_id,
            "node-source",
            "node-target",
            7,
            8,
        );
        comp.begin_transfer(&active_lease, &handoff, 1_500).unwrap();

        let target_lease = test_migration_lease("node-target", 8, 2_500);
        let err = comp
            .resume(
                &checkpoint,
                checkpoint_object_id,
                wrong_lease_id,
                &target_lease,
                1_600,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::ResumeLeaseIdMismatch { .. }
        ));
    }

    #[test]
    fn resume_from_transferring_rejects_wrong_fencing_token() {
        let source_lease_id = test_object_id("lease-source");
        let target_lease_id = test_object_id("lease-target");
        let checkpoint = test_computation_checkpoint("node-source", source_lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("node-source"),
            source_lease_id,
            7,
            test_migration_context(0),
        );
        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();
        let active_lease = test_migration_lease("node-source", 7, 2_000);
        let handoff = test_migration_handoff(
            source_lease_id,
            target_lease_id,
            "node-source",
            "node-target",
            7,
            8,
        );
        comp.begin_transfer(&active_lease, &handoff, 1_500).unwrap();

        // Target lease with wrong fencing token (99 instead of 8)
        let wrong_fence_lease = test_migration_lease("node-target", 99, 2_500);
        let err = comp
            .resume(
                &checkpoint,
                checkpoint_object_id,
                target_lease_id,
                &wrong_fence_lease,
                1_600,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::ResumeFenceMismatch { .. }
        ));
    }

    #[test]
    fn resume_from_transferring_rejects_superseded_target_lease() {
        let source_lease_id = test_object_id("lease-source");
        let target_lease_id = test_object_id("lease-target");
        let checkpoint = test_computation_checkpoint("node-source", source_lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("node-source"),
            source_lease_id,
            7,
            test_migration_context(0),
        );
        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();
        let active_lease = test_migration_lease("node-source", 7, 2_000);
        let handoff = test_migration_handoff(
            source_lease_id,
            target_lease_id,
            "node-source",
            "node-target",
            7,
            8,
        );
        comp.begin_transfer(&active_lease, &handoff, 1_500).unwrap();

        let stale_target_lease = test_migration_lease("node-target", 7, 2_500);
        let err = comp
            .resume(
                &checkpoint,
                checkpoint_object_id,
                target_lease_id,
                &stale_target_lease,
                1_600,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::LeaseValidation(crate::LeaseValidationError::Superseded {
                held_seq: 7,
                current_seq: 8
            })
        ));
        assert!(matches!(
            comp.state,
            MigratableComputationState::Transferring {
                next_fencing_token: 8,
                ..
            }
        ));
    }

    // --- Capability context updates after suspend and resume ---

    #[test]
    fn suspend_updates_capability_context_fields() {
        let lease_id = test_object_id("lease");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 3);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        assert!(comp.capability_context.checkpoint_id.is_none());
        assert_eq!(comp.capability_context.checkpoint_seq, 0);

        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();

        assert_eq!(
            comp.capability_context.checkpoint_id,
            Some(checkpoint_object_id)
        );
        assert_eq!(comp.capability_context.checkpoint_seq, 3);
    }

    #[test]
    fn resume_from_suspended_updates_capability_context() {
        let lease_id = test_object_id("lease");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 5);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();

        let resume_lease = test_migration_lease("holder", 7, 2_000);
        comp.resume(
            &checkpoint,
            checkpoint_object_id,
            lease_id,
            &resume_lease,
            1_500,
        )
        .unwrap();

        assert_eq!(
            comp.capability_context.checkpoint_id,
            Some(checkpoint_object_id)
        );
        assert_eq!(comp.capability_context.checkpoint_seq, 5);
    }

    #[test]
    fn resume_from_transferring_updates_holder_and_lease() {
        let source_lease_id = test_object_id("lease-source");
        let target_lease_id = test_object_id("lease-target");
        let checkpoint = test_computation_checkpoint("node-source", source_lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("node-source"),
            source_lease_id,
            7,
            test_migration_context(0),
        );
        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();
        let active_lease = test_migration_lease("node-source", 7, 2_000);
        let handoff = test_migration_handoff(
            source_lease_id,
            target_lease_id,
            "node-source",
            "node-target",
            7,
            8,
        );
        comp.begin_transfer(&active_lease, &handoff, 1_500).unwrap();

        let target_lease = test_migration_lease("node-target", 8, 2_500);
        comp.resume(
            &checkpoint,
            checkpoint_object_id,
            target_lease_id,
            &target_lease,
            1_600,
        )
        .unwrap();

        assert_eq!(comp.current_holder, test_node_id("node-target"));
        assert_eq!(comp.execution_lease_id, target_lease_id);
        assert_eq!(comp.lease_fencing_token, 8);
        assert_eq!(
            comp.capability_context.checkpoint_id,
            Some(checkpoint_object_id)
        );
    }

    // --- Multiple suspend/resume cycles ---

    #[test]
    fn double_suspend_resume_cycle_same_holder() {
        let lease_id = test_object_id("lease");
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );

        // First cycle
        let cp = test_computation_checkpoint("holder", lease_id, 7, 1);
        let cp_oid = cp.object_id().unwrap();
        comp.suspend(&cp, cp_oid).unwrap();
        assert_eq!(comp.state, MigratableComputationState::Suspended);
        let resume1 = test_migration_lease("holder", 7, 2_000);
        comp.resume(&cp, cp_oid, lease_id, &resume1, 1_500).unwrap();
        assert_eq!(comp.state, MigratableComputationState::Running);

        // Second cycle reuses the same checkpoint (state machine binds to checkpoint_object_id)
        comp.suspend(&cp, cp_oid).unwrap();
        assert_eq!(comp.state, MigratableComputationState::Suspended);
        let resume2 = test_migration_lease("holder", 7, 3_000);
        comp.resume(&cp, cp_oid, lease_id, &resume2, 2_500).unwrap();
        assert_eq!(comp.state, MigratableComputationState::Running);
    }

    // --- begin_transfer with expired active lease ---

    #[test]
    fn begin_transfer_rejects_expired_active_lease() {
        let lease_id = test_object_id("lease");
        let target_lease_id = test_object_id("lease-target");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();

        // Lease expired at 1_000
        let expired_lease = test_migration_lease("holder", 7, 1_000);
        let handoff = test_migration_handoff(lease_id, target_lease_id, "holder", "target", 7, 8);
        let err = comp
            .begin_transfer(&expired_lease, &handoff, 1_500)
            .unwrap_err();
        assert!(matches!(err, ComputationMigrationError::LeaseTransfer(..)));
    }

    // --- MigratableComputation::new always starts Running ---

    #[test]
    fn new_computation_starts_in_running_state() {
        let comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            test_object_id("lease"),
            7,
            test_migration_context(0),
        );
        assert_eq!(comp.state, MigratableComputationState::Running);
        assert!(comp.checkpoint_object_id.is_none());
    }

    // --- Serde roundtrip of full MigratableComputation ---

    #[test]
    fn migratable_computation_serde_roundtrip() {
        let comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            test_object_id("lease"),
            7,
            test_migration_context(0),
        );
        let json = serde_json::to_string(&comp).unwrap();
        let back: MigratableComputation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.computation_id, comp.computation_id);
        assert_eq!(back.state, MigratableComputationState::Running);
        assert_eq!(back.lease_fencing_token, 7);
    }

    #[test]
    fn migratable_computation_serde_roundtrip_suspended() {
        let lease_id = test_object_id("lease");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();
        let json = serde_json::to_string(&comp).unwrap();
        let back: MigratableComputation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.state, MigratableComputationState::Suspended);
        assert_eq!(back.checkpoint_object_id, Some(checkpoint_object_id));
    }

    #[test]
    fn migratable_computation_serde_roundtrip_transferring() {
        let source_lease_id = test_object_id("lease-source");
        let target_lease_id = test_object_id("lease-target");
        let checkpoint = test_computation_checkpoint("node-source", source_lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("node-source"),
            source_lease_id,
            7,
            test_migration_context(0),
        );
        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();
        let active_lease = test_migration_lease("node-source", 7, 2_000);
        let handoff = test_migration_handoff(
            source_lease_id,
            target_lease_id,
            "node-source",
            "node-target",
            7,
            8,
        );
        comp.begin_transfer(&active_lease, &handoff, 1_500).unwrap();

        let json = serde_json::to_string(&comp).unwrap();
        let back: MigratableComputation = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            back.state,
            MigratableComputationState::Transferring {
                next_fencing_token: 8,
                ..
            }
        ));
    }

    // --- Remaining ComputationMigrationError Display coverage ---

    #[test]
    fn computation_migration_error_display_checkpoint_holder_mismatch() {
        let err = ComputationMigrationError::CheckpointHolderMismatch {
            expected: test_node_id("expected"),
            got: test_node_id("got"),
        };
        let display = err.to_string();
        assert!(display.contains("holder mismatch"));
    }

    #[test]
    fn computation_migration_error_display_checkpoint_lease_id_mismatch() {
        let err = ComputationMigrationError::CheckpointLeaseIdMismatch {
            expected: test_object_id("expected"),
            got: test_object_id("got"),
        };
        let display = err.to_string();
        assert!(display.contains("lease id mismatch"));
    }

    #[test]
    fn computation_migration_error_display_checkpoint_fence_mismatch() {
        let err = ComputationMigrationError::CheckpointFenceMismatch {
            expected: 7,
            got: 6,
        };
        let display = err.to_string();
        assert!(display.contains("fencing token mismatch"));
    }

    #[test]
    fn computation_migration_error_display_capability_token_mismatch() {
        let err = ComputationMigrationError::CapabilityTokenMismatch {
            expected: Uuid::from_bytes([0xAA; 16]),
            got: Uuid::from_bytes([0xBB; 16]),
        };
        let display = err.to_string();
        assert!(display.contains("capability token mismatch"));
    }

    #[test]
    fn computation_migration_error_display_checkpoint_object_mismatch() {
        let err = ComputationMigrationError::CheckpointObjectMismatch {
            expected: Some(test_object_id("expected")),
            got: test_object_id("got"),
        };
        let display = err.to_string();
        assert!(display.contains("checkpoint object mismatch"));
    }

    #[test]
    fn computation_migration_error_display_unexpected_prior_lease() {
        let err = ComputationMigrationError::UnexpectedPriorLeaseId {
            expected: test_object_id("expected"),
            got: test_object_id("got"),
        };
        let display = err.to_string();
        assert!(display.contains("prior lease"));
    }

    #[test]
    fn computation_migration_error_display_resume_holder_mismatch() {
        let err = ComputationMigrationError::ResumeHolderMismatch {
            expected: test_node_id("expected"),
            got: test_node_id("got"),
        };
        let display = err.to_string();
        assert!(display.contains("resume holder mismatch"));
    }

    #[test]
    fn computation_migration_error_display_resume_lease_id_mismatch() {
        let err = ComputationMigrationError::ResumeLeaseIdMismatch {
            expected: test_object_id("expected"),
            got: test_object_id("got"),
        };
        let display = err.to_string();
        assert!(display.contains("resume lease id mismatch"));
    }

    #[test]
    fn computation_migration_error_display_resume_fence_mismatch() {
        let err = ComputationMigrationError::ResumeFenceMismatch {
            expected: 8,
            got: 7,
        };
        let display = err.to_string();
        assert!(display.contains("resume fencing token mismatch"));
    }

    // --- Terminal state immutability ---

    #[test]
    fn terminal_states_reject_all_operations() {
        for terminal_state in [
            MigratableComputationState::Completed,
            MigratableComputationState::Failed,
        ] {
            let lease_id = test_object_id("lease");
            let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
            let checkpoint_object_id = checkpoint.object_id().unwrap();
            let mut comp = MigratableComputation::new(
                test_object_id("computation"),
                ZoneId::work(),
                test_node_id("holder"),
                lease_id,
                7,
                test_migration_context(0),
            );
            comp.state = terminal_state.clone();

            // suspend should fail
            assert!(comp.suspend(&checkpoint, checkpoint_object_id).is_err());

            // begin_transfer should fail
            let active_lease = test_migration_lease("holder", 7, 2_000);
            let handoff = test_migration_handoff(
                lease_id,
                test_object_id("target-lease"),
                "holder",
                "target",
                7,
                8,
            );
            assert!(comp.begin_transfer(&active_lease, &handoff, 1_500).is_err());

            // resume should fail
            let resume_lease = test_migration_lease("holder", 7, 2_000);
            assert!(
                comp.resume(
                    &checkpoint,
                    checkpoint_object_id,
                    lease_id,
                    &resume_lease,
                    1_500,
                )
                .is_err()
            );
        }
    }

    // --- MigratableComputationState equality and clone ---

    #[test]
    fn migratable_computation_state_eq_and_clone() {
        let s1 = MigratableComputationState::Transferring {
            target_holder: test_node_id("n"),
            next_lease_id: test_object_id("l"),
            next_fencing_token: 10,
        };
        let s2 = s1.clone();
        assert_eq!(s1, s2);

        assert_ne!(
            MigratableComputationState::Running,
            MigratableComputationState::Suspended
        );
        assert_ne!(
            MigratableComputationState::Completed,
            MigratableComputationState::Failed
        );
    }

    // --- Checkpoint object_id derivation mismatch ---

    #[test]
    fn suspend_rejects_wrong_checkpoint_object_id() {
        let lease_id = test_object_id("lease");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        // Pass a fabricated object_id that doesn't match the checkpoint's derived id
        let wrong_oid = test_object_id("fabricated-checkpoint-oid");
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        let err = comp.suspend(&checkpoint, wrong_oid).unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::CheckpointObjectMismatch { .. }
        ));
    }

    // --- Resume checkpoint binding also validates ---

    #[test]
    fn resume_from_suspended_rejects_checkpoint_computation_mismatch() {
        let lease_id = test_object_id("lease");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();

        // Build a bad checkpoint with wrong computation_id
        let mut bad_checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        bad_checkpoint.computation_id = test_object_id("wrong-computation");
        let bad_oid = bad_checkpoint.object_id().unwrap();

        let resume_lease = test_migration_lease("holder", 7, 2_000);
        let err = comp
            .resume(&bad_checkpoint, bad_oid, lease_id, &resume_lease, 1_500)
            .unwrap_err();
        assert!(matches!(
            err,
            ComputationMigrationError::CheckpointComputationMismatch { .. }
        ));
    }

    // --- Suspend sets checkpoint_object_id ---

    #[test]
    fn suspend_sets_checkpoint_object_id() {
        let lease_id = test_object_id("lease");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("holder"),
            lease_id,
            7,
            test_migration_context(0),
        );
        assert!(comp.checkpoint_object_id.is_none());
        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();
        assert_eq!(comp.checkpoint_object_id, Some(checkpoint_object_id));
    }

    // --- Full migration cycle preserves zone_id ---

    #[test]
    fn full_migration_cycle_preserves_zone_id() {
        let zone = ZoneId::work();
        let source_lease_id = test_object_id("lease-source");
        let target_lease_id = test_object_id("lease-target");
        let checkpoint = test_computation_checkpoint("node-source", source_lease_id, 7, 1);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            zone.clone(),
            test_node_id("node-source"),
            source_lease_id,
            7,
            test_migration_context(0),
        );

        // suspend
        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();
        assert_eq!(comp.zone_id, zone);

        // transfer
        let active_lease = test_migration_lease("node-source", 7, 2_000);
        let handoff = test_migration_handoff(
            source_lease_id,
            target_lease_id,
            "node-source",
            "node-target",
            7,
            8,
        );
        comp.begin_transfer(&active_lease, &handoff, 1_500).unwrap();
        assert_eq!(comp.zone_id, zone);

        // resume
        let target_lease = test_migration_lease("node-target", 8, 2_500);
        comp.resume(
            &checkpoint,
            checkpoint_object_id,
            target_lease_id,
            &target_lease,
            1_600,
        )
        .unwrap();
        assert_eq!(comp.zone_id, zone);
        assert_eq!(comp.computation_id, test_object_id("computation"));
    }

    #[test]
    fn resume_boundary_detects_stale_checkpoint_sequence() {
        let lease_id = test_object_id("lease");
        let checkpoint = test_computation_checkpoint("holder", lease_id, 7, 3);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let boundary = ResumeBoundary::from_checkpoint(
            &checkpoint,
            checkpoint_object_id,
            Some(test_object_id("state")),
            Some(test_object_id("receipt")),
        )
        .unwrap();

        let freshness = boundary.assess_freshness(4, lease_id, 7);
        assert!(matches!(
            freshness,
            CheckpointFreshness::StaleCheckpoint {
                candidate_checkpoint_seq: 3,
                current_checkpoint_seq: 4,
            }
        ));
        assert!(!freshness.allows_resume());
    }

    #[test]
    fn checkpoint_handoff_artifact_captures_export_and_timeline() {
        let source_lease_id = test_object_id("lease-source");
        let target_lease_id = test_object_id("lease-target");
        let checkpoint = test_computation_checkpoint("node-source", source_lease_id, 7, 4);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("node-source"),
            source_lease_id,
            7,
            test_migration_context(4),
        );
        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();
        let active_lease = test_migration_lease("node-source", 7, 2_000);
        let handoff = test_migration_handoff_with_checkpoint(
            source_lease_id,
            target_lease_id,
            "node-source",
            "node-target",
            7,
            8,
            Some(checkpoint_object_id),
        );
        comp.begin_transfer(&active_lease, &handoff, 1_500).unwrap();

        let transfer_encoding = checkpoint.to_transfer_encoding(usize::MAX, 512).unwrap();
        let artifact = CheckpointHandoffArtifact::capture(
            &comp,
            &checkpoint,
            checkpoint_object_id,
            &transfer_encoding,
            &handoff,
            &HandoffArtifactInputs {
                state_object_id: Some(test_object_id("state")),
                receipt_head: Some(test_object_id("receipt")),
                resume_cause: ResumeCause::PlannedHandoff,
                observed_at_ms: 42,
            },
        )
        .unwrap();

        assert_eq!(artifact.subject_id, test_object_id("computation"));
        assert_eq!(
            artifact.export.boundary.checkpoint_object_id,
            checkpoint_object_id
        );
        assert_eq!(artifact.export.chunk_count, 1);
        assert_eq!(artifact.export.encoding, CheckpointExportEncoding::Inline);
        assert_eq!(
            artifact
                .timeline
                .iter()
                .map(|event| event.operation.as_str())
                .collect::<Vec<_>>(),
            vec!["checkpoint.exported", "handoff.authorized"]
        );

        let json = serde_json::to_string(&artifact).unwrap();
        let decoded: CheckpointHandoffArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, artifact);
    }

    #[test]
    fn resume_evidence_accepts_target_resume_after_handoff() {
        let source_lease_id = test_object_id("lease-source");
        let target_lease_id = test_object_id("lease-target");
        let checkpoint = test_computation_checkpoint("node-source", source_lease_id, 7, 6);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("node-source"),
            source_lease_id,
            7,
            test_migration_context(6),
        );
        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();
        let active_lease = test_migration_lease("node-source", 7, 2_000);
        let handoff = test_migration_handoff(
            source_lease_id,
            target_lease_id,
            "node-source",
            "node-target",
            7,
            8,
        );
        comp.begin_transfer(&active_lease, &handoff, 1_500).unwrap();

        let target_lease = test_migration_lease("node-target", 8, 2_500);
        let evidence = ResumeEvidence::evaluate(
            &comp,
            &checkpoint,
            checkpoint_object_id,
            target_lease_id,
            &target_lease,
            1_600,
            &ResumeEvidenceInputs {
                state_object_id: Some(test_object_id("state")),
                receipt_head: Some(test_object_id("receipt")),
                resume_cause: ResumeCause::Failover,
                duplicate_delivery_class: DuplicateDeliveryClass::ReplaySafeRetry,
                disposition: ResumeDisposition::Retry,
                observed_at_ms: 55,
            },
        )
        .unwrap();

        assert_eq!(evidence.outcome, ResumeOutcome::Accepted);
        assert_eq!(evidence.disposition, ResumeDisposition::Retry);
        assert!(matches!(evidence.freshness, CheckpointFreshness::Fresh));
        assert_eq!(evidence.lease_lineage.prior_lease_id, source_lease_id);
        assert_eq!(evidence.lease_lineage.resumed_lease_id, target_lease_id);
        assert_eq!(
            evidence
                .timeline
                .iter()
                .map(|event| event.operation.as_str())
                .collect::<Vec<_>>(),
            vec![
                "checkpoint.freshness_checked",
                "resume.classified",
                "resume.accepted",
            ]
        );
        assert!(evidence.validation_error.is_none());
    }

    #[test]
    fn resume_evidence_denies_stale_source_holder_after_handoff() {
        let source_lease_id = test_object_id("lease-source");
        let target_lease_id = test_object_id("lease-target");
        let checkpoint = test_computation_checkpoint("node-source", source_lease_id, 7, 6);
        let checkpoint_object_id = checkpoint.object_id().unwrap();
        let mut comp = MigratableComputation::new(
            test_object_id("computation"),
            ZoneId::work(),
            test_node_id("node-source"),
            source_lease_id,
            7,
            test_migration_context(6),
        );
        comp.suspend(&checkpoint, checkpoint_object_id).unwrap();
        let active_lease = test_migration_lease("node-source", 7, 2_000);
        let handoff = test_migration_handoff(
            source_lease_id,
            target_lease_id,
            "node-source",
            "node-target",
            7,
            8,
        );
        comp.begin_transfer(&active_lease, &handoff, 1_500).unwrap();

        let stale_source_lease = test_migration_lease("node-source", 7, 2_500);
        let evidence = ResumeEvidence::evaluate(
            &comp,
            &checkpoint,
            checkpoint_object_id,
            source_lease_id,
            &stale_source_lease,
            1_600,
            &ResumeEvidenceInputs {
                state_object_id: None,
                receipt_head: None,
                resume_cause: ResumeCause::Failover,
                duplicate_delivery_class: DuplicateDeliveryClass::EvidenceConflict,
                disposition: ResumeDisposition::Reconcile,
                observed_at_ms: 89,
            },
        )
        .unwrap();

        assert_eq!(evidence.outcome, ResumeOutcome::Denied);
        assert_eq!(evidence.disposition, ResumeDisposition::Deny);
        assert!(matches!(evidence.freshness, CheckpointFreshness::Fresh));
        assert!(evidence.validation_error.is_some());
        assert_eq!(
            evidence.timeline.last().unwrap().operation,
            "resume.denied".to_string()
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Bead 24llg.5.3.2: Fork resolution regression scenarios
    // ═══════════════════════════════════════════════════════════════════

    /// Helper: register two branches from the same prev to create a fork.
    fn setup_fork_detector(
        prev: ObjectId,
        branch_a: ObjectId,
        branch_b: ObjectId,
        lease_a: u64,
        lease_b: u64,
    ) -> (StateForkDetector, ForkEvent) {
        let mut detector = StateForkDetector::default();
        detector.register(branch_a, Some(prev), 10, lease_a);
        detector.register(branch_b, Some(prev), 20, lease_b);

        let result = detector.detect_fork(
            crate::ZoneId::work(),
            crate::ConnectorId::from_static("test.connector"),
            1_700_000_000,
        );
        let fork = match result {
            StateForkDetectionResult::ForkDetected(f) => f,
            StateForkDetectionResult::NoFork { .. } => {
                panic!("Expected fork detection, got NoFork")
            }
        };
        (detector, fork)
    }

    /// Scenario: conflict-heavy merge — two branches with different `lease_seq`
    /// values produce a deterministic winner with decision diagnostics.
    #[test]
    fn regression_lease_conflict_deterministic_winner() {
        let prev = test_object_id("prev");
        let branch_a = test_object_id("a");
        let branch_b = test_object_id("b");

        let (detector, fork) = setup_fork_detector(prev, branch_a, branch_b, 5, 10);

        let outcome = detector.resolve(
            &fork,
            ForkResolution::ChooseByLease,
            &ConnectorStateModel::SingletonWriter,
            1_700_000_000,
        );

        assert!(outcome.resolved, "Fork should be resolved");
        assert!(outcome.winning_head.is_some(), "Should have a winner");
        assert!(
            outcome.decision_detail.is_some(),
            "Successful resolution should have decision_detail"
        );
        let detail = outcome.decision_detail.unwrap();
        assert!(
            detail.contains("lease_seq"),
            "Decision detail should explain lease-based resolution: {detail}"
        );
    }

    /// Scenario: lease tie produces explicit failure diagnostic.
    #[test]
    fn regression_lease_tie_explicit_failure() {
        let prev = test_object_id("prev");
        let branch_a = test_object_id("a");
        let branch_b = test_object_id("b");

        let (detector, fork) = setup_fork_detector(prev, branch_a, branch_b, 7, 7);

        let outcome = detector.resolve(
            &fork,
            ForkResolution::ChooseByLease,
            &ConnectorStateModel::SingletonWriter,
            1_700_000_000,
        );

        assert!(!outcome.resolved, "Lease tie should not resolve");
        assert!(outcome.winning_head.is_none());
        assert!(
            outcome.failure_reason.as_ref().unwrap().contains("tie"),
            "Failure reason should mention tie: {:?}",
            outcome.failure_reason
        );
        assert!(
            outcome.decision_detail.is_some(),
            "Failed resolution should have decision_detail"
        );
    }

    /// Scenario: CRDT merge resolution produces diagnostic for both branches.
    #[test]
    fn regression_crdt_merge_resolution_diagnostic() {
        let prev = test_object_id("prev");
        let branch_a = test_object_id("a");
        let branch_b = test_object_id("b");

        let (detector, fork) = setup_fork_detector(prev, branch_a, branch_b, 0, 0);

        let outcome = detector.resolve(
            &fork,
            ForkResolution::CrdtMerge,
            &ConnectorStateModel::Crdt {
                crdt_type: CrdtType::LwwMap,
            },
            1_700_000_000,
        );

        assert!(outcome.resolved, "CRDT merge should resolve");
        assert!(outcome.decision_detail.is_some());
        let detail = outcome.decision_detail.unwrap();
        assert!(
            detail.contains("CRDT"),
            "CRDT merge detail should mention CRDT: {detail}"
        );
    }

    /// Scenario: invalid strategy for model produces explicit diagnostic.
    #[test]
    fn regression_invalid_strategy_diagnostic() {
        let prev = test_object_id("prev");
        let branch_a = test_object_id("a");
        let branch_b = test_object_id("b");

        let (detector, fork) = setup_fork_detector(prev, branch_a, branch_b, 0, 0);

        // CrdtMerge is invalid for SingletonWriter model
        let outcome = detector.resolve(
            &fork,
            ForkResolution::CrdtMerge,
            &ConnectorStateModel::SingletonWriter,
            1_700_000_000,
        );

        assert!(!outcome.resolved, "Invalid strategy should not resolve");
        assert!(
            outcome
                .failure_reason
                .as_ref()
                .unwrap()
                .contains("not valid"),
            "Should explain strategy invalidity: {:?}",
            outcome.failure_reason
        );
        assert!(
            outcome.decision_detail.is_some(),
            "Failed resolution should have decision_detail"
        );
    }

    /// Scenario: resolution outcome serializes with all diagnostic fields.
    #[test]
    fn regression_resolution_outcome_json_transcript() {
        let prev = test_object_id("prev");
        let branch_a = test_object_id("a");
        let branch_b = test_object_id("b");

        let (detector, fork) = setup_fork_detector(prev, branch_a, branch_b, 5, 10);

        let outcome = detector.resolve(
            &fork,
            ForkResolution::ChooseByLease,
            &ConnectorStateModel::SingletonWriter,
            1_700_000_000,
        );

        let json = serde_json::to_value(&outcome).unwrap();

        // Validate transcript-consumable fields
        assert!(json["resolved"].is_boolean());
        assert!(json["strategy"].is_string());
        assert!(json["resolved_at"].is_number());
        assert!(json["decision_detail"].is_string());
        assert!(json["fork_event"].is_object());
        assert!(json["fork_event"]["common_prev"].is_string());
        assert!(json["fork_event"]["branch_a"].is_string());
        assert!(json["fork_event"]["branch_b"].is_string());
    }
}
