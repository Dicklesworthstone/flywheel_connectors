//! Authorized transfer of an exact connector-state root between host stores.
//!
//! Peer authentication does not authorize disclosure or adoption of state.
//! Each direction needs a locally configured, expiring grant and a registered
//! adapter with pinned writer keys. Imports populate a retained replica store;
//! they do not activate connector state, acquire a lease, or authorize execution.

use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use chrono::{DateTime, Utc};
use fcp_evidence::StoredObject;
use fcp_kernel::{ConnectorId, InstanceId, ObjectId, ZoneId};
use fcp_store::{
    ConnectorStateReplicaBundle, ConnectorStateReplicaLimits, ConnectorStateStoreError,
    FcpStoreConnectorStateStore,
};
use serde::{Deserialize, Serialize};

use crate::{HostError, HostResult};

/// Maximum number of objects in one transfer, including the root.
pub const MAX_CONNECTOR_STATE_TRANSFER_OBJECTS: usize = 4096;
/// Maximum canonical object bytes in one transfer, independently of JSON size.
pub const MAX_CONNECTOR_STATE_TRANSFER_CANONICAL_BYTES: usize = 4 * 1024 * 1024;
/// Maximum inner JSON response size; the signed mesh wrapper has its own cap.
pub const MAX_CONNECTOR_STATE_TRANSFER_WIRE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum serialized export request before deserialization.
pub const MAX_CONNECTOR_STATE_EXPORT_REQUEST_BYTES: usize = 16 * 1024;
/// Version of the explicitly scoped state-transfer response.
pub const CONNECTOR_STATE_TRANSFER_SCHEMA_VERSION: &str = "fcp.host.state-transfer.v1";

const MAX_REGISTERED_STATE_STORES: usize = 256;
const MAX_STATE_TRANSFER_GRANTS: usize = 1024;
const MAX_TRANSFER_METADATA_BYTES: usize = 512;

/// Direction for which a store and peer have been explicitly authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorStateTransferDirection {
    /// Disclose a registered source root to the authenticated requesting peer.
    Export,
    /// Import a root from the configured donor into a retained replica store.
    Import,
}

/// Exact connector identity of one locally registered state adapter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorStateTransferScope {
    /// Canonical connector identity.
    pub connector_id: ConnectorId,
    /// State confidentiality and authorization boundary.
    pub zone_id: ZoneId,
    /// Exact connector instance, or explicitly unscoped state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,
}

/// Independent bounds on objects, canonical bytes, and serialized JSON bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorStateTransferLimits {
    /// State objects plus their single root.
    pub max_objects: usize,
    /// Sum of canonical object headers and bodies.
    pub max_canonical_bytes: usize,
    /// Entire inner JSON export response, including metadata and framing.
    pub max_wire_bytes: usize,
}

impl ConnectorStateTransferLimits {
    fn validate(self) -> HostResult<()> {
        if self.max_objects == 0
            || self.max_objects > MAX_CONNECTOR_STATE_TRANSFER_OBJECTS
            || self.max_canonical_bytes == 0
            || self.max_canonical_bytes > MAX_CONNECTOR_STATE_TRANSFER_CANONICAL_BYTES
            || self.max_wire_bytes == 0
            || self.max_wire_bytes > MAX_CONNECTOR_STATE_TRANSFER_WIRE_BYTES
        {
            return Err(invalid(
                "state-transfer limits are zero or exceed host bounds",
            ));
        }
        Ok(())
    }

    fn permits(self, requested: Self) -> bool {
        requested.max_objects <= self.max_objects
            && requested.max_canonical_bytes <= self.max_canonical_bytes
            && requested.max_wire_bytes <= self.max_wire_bytes
    }

    const fn store_limits(self) -> ConnectorStateReplicaLimits {
        ConnectorStateReplicaLimits {
            max_objects: self.max_objects,
            max_bytes: self.max_canonical_bytes,
        }
    }
}

/// Operator-selected authority for one exact root and transfer direction.
///
/// Grant identifiers identify local configuration; they are not bearer tokens.
/// The authenticated peer, direction, identity, root, expiry and bounds all
/// have to match. A donor and recipient each configure their own direction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorStateTransferGrant {
    /// Locally unique grant identifier, shared by the two configured peers.
    pub grant_id: String,
    /// Whether this host may disclose or import the root.
    pub direction: ConnectorStateTransferDirection,
    /// Requesting peer for export; authenticated donor for import.
    pub peer_node: String,
    /// Exact state identity admitted by this grant.
    pub scope: ConnectorStateTransferScope,
    /// Root selected by the operator from trusted state evidence.
    pub root_object_id: ObjectId,
    /// Exclusive validity boundary; checked again at publication admission.
    pub expires_at: DateTime<Utc>,
    /// Maximum resources this grant permits a request to consume.
    pub limits: ConnectorStateTransferLimits,
}

/// Payload signed by a requesting mesh peer for one exact-root export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorStateExportRequest {
    /// Grant configured independently at donor and recipient.
    pub grant_id: String,
    /// Exact connector, zone and instance binding.
    pub scope: ConnectorStateTransferScope,
    /// Exact selected root; no latest-root discovery occurs on this surface.
    pub root_object_id: ObjectId,
    /// Requested limits must narrow the configured grant.
    pub limits: ConnectorStateTransferLimits,
}

impl ConnectorStateExportRequest {
    /// Decode a bounded request without accepting unrecognized authority fields.
    ///
    /// # Errors
    /// Rejects oversized JSON, malformed fields and invalid resource limits.
    pub fn from_json(json: &str) -> HostResult<Self> {
        if json.len() > MAX_CONNECTOR_STATE_EXPORT_REQUEST_BYTES {
            return Err(invalid(
                "connector-state export request exceeds its wire limit",
            ));
        }
        let request: Self = serde_json::from_str(json)
            .map_err(|_| invalid("connector-state export request is malformed"))?;
        request.validate()?;
        Ok(request)
    }

    /// Encode the exact body to place inside a signed mesh request.
    ///
    /// # Errors
    /// Rejects invalid metadata, invalid bounds or an oversized JSON encoding.
    pub fn to_json(&self) -> HostResult<String> {
        self.validate()?;
        bounded_json(self, MAX_CONNECTOR_STATE_EXPORT_REQUEST_BYTES)
    }

    fn validate(&self) -> HostResult<()> {
        validate_metadata(&self.grant_id)?;
        validate_scope(&self.scope)?;
        self.limits.validate()
    }
}

/// Protected operator request to populate a host-owned replica from one donor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorStatePullRequest {
    /// Authenticated configured donor, never an arbitrary URL.
    pub peer_node: String,
    /// Exact-root request sent to the donor.
    pub request: ConnectorStateExportRequest,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectorStateExportResponse {
    schema_version: String,
    request: ConnectorStateExportRequest,
    bundle: ConnectorStateReplicaBundle,
}

/// Metadata returned after a verified replica has been retained by this host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorStatePullResponse {
    /// State-transfer schema version.
    pub schema_version: String,
    /// Authenticated donor that supplied this exact root.
    pub peer_node: String,
    /// Local import grant used for admission.
    pub grant_id: String,
    /// Identity checked against the registered replica adapter.
    pub scope: ConnectorStateTransferScope,
    /// Requested root whose complete ancestry was validated.
    pub root_object_id: ObjectId,
    /// Number of transferred objects, including the root.
    pub object_count: usize,
    /// Sum of canonical object bytes, excluding transport overhead.
    pub canonical_bytes: usize,
    /// Actual inner JSON response bytes.
    pub wire_bytes: usize,
    /// Whether import published a newer comparable root in the replica store.
    pub replica_root_published: bool,
    /// Always true: this operation never activates the live connector's state.
    pub replica_only: bool,
}

/// Explicitly registered source/replica adapters and immutable transfer grants.
///
/// Construct at host startup, then share one `Arc` for the host's lifetime.
/// A registration never opens a filesystem path or creates an independent
/// store. Hosts must retain the same adapter and backing-store ownership.
#[derive(Default)]
pub struct ConnectorStateReplicationService {
    stores: HashMap<
        (ConnectorStateTransferDirection, ConnectorStateTransferScope),
        Arc<FcpStoreConnectorStateStore>,
    >,
    grants: HashMap<String, RegisteredTransferGrant>,
}

struct RegisteredTransferGrant {
    grant: ConnectorStateTransferGrant,
    deadline: Instant,
    expired: AtomicBool,
}

impl RegisteredTransferGrant {
    fn new(grant: ConnectorStateTransferGrant) -> HostResult<Self> {
        let lifetime = (grant.expires_at - Utc::now())
            .to_std()
            .map_err(|_| invalid("connector-state transfer grant is already expired"))?;
        if lifetime.is_zero() {
            return Err(invalid("connector-state transfer grant is already expired"));
        }
        let deadline = Instant::now()
            .checked_add(lifetime)
            .ok_or_else(|| invalid("state-transfer grant lifetime cannot be represented"))?;
        Ok(Self {
            grant,
            deadline,
            expired: AtomicBool::new(false),
        })
    }

    fn check_at(&self, now: DateTime<Utc>, monotonic_now: Instant) -> HostResult<()> {
        if self.expired.load(Ordering::Acquire)
            || now >= self.grant.expires_at
            || monotonic_now >= self.deadline
        {
            // Once expiry was observed, a wall-clock rollback cannot revive
            // this grant. The captured monotonic deadline also limits a
            // rollback that happened before the first expiry observation.
            self.expired.store(true, Ordering::Release);
            return Err(HostError::PreflightFailed(
                "connector-state transfer grant expired".to_string(),
            ));
        }
        Ok(())
    }
}

impl ConnectorStateReplicationService {
    /// Start with no accessible state and no transfer authority.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a shared source or retained-replica adapter.
    ///
    /// # Errors
    /// Rejects missing writer pins, scope mismatches, duplicates and capacity.
    pub fn register_store(
        &mut self,
        direction: ConnectorStateTransferDirection,
        scope: ConnectorStateTransferScope,
        store: Arc<FcpStoreConnectorStateStore>,
    ) -> HostResult<()> {
        validate_scope(&scope)?;
        if !store.has_trusted_writer_keys() {
            return Err(invalid(
                "state-transfer registration requires nonempty trusted writer pins",
            ));
        }
        if store.connector_id() != &scope.connector_id
            || store.zone_id() != &scope.zone_id
            || store.instance_id() != scope.instance_id.as_ref()
        {
            return Err(invalid(
                "state-transfer registration differs from its adapter identity",
            ));
        }
        let key = (direction, scope);
        if self.stores.contains_key(&key) {
            return Err(invalid(
                "state-transfer adapter is already registered for this direction",
            ));
        }
        if self.stores.len() >= MAX_REGISTERED_STATE_STORES {
            return Err(invalid("state-transfer adapter capacity exhausted"));
        }
        self.stores.insert(key, store);
        Ok(())
    }

    /// Admit one operator-configured grant against an already registered store.
    ///
    /// # Errors
    /// Rejects malformed, expired, duplicate, oversized or unregistered grants.
    pub fn add_grant(&mut self, grant: ConnectorStateTransferGrant) -> HostResult<()> {
        validate_metadata(&grant.grant_id)?;
        validate_metadata(&grant.peer_node)?;
        validate_scope(&grant.scope)?;
        grant.limits.validate()?;
        if !self
            .stores
            .contains_key(&(grant.direction, grant.scope.clone()))
        {
            return Err(invalid("state-transfer grant has no registered adapter"));
        }
        if self.grants.contains_key(&grant.grant_id) {
            return Err(invalid(
                "state-transfer grant identifier is already configured",
            ));
        }
        if self.grants.len() >= MAX_STATE_TRANSFER_GRANTS {
            return Err(invalid("state-transfer grant capacity exhausted"));
        }
        self.grants
            .insert(grant.grant_id.clone(), RegisteredTransferGrant::new(grant)?);
        Ok(())
    }

    /// Check recipient-side import authority before starting any network work.
    ///
    /// # Errors
    /// Rejects requests that do not exactly match a current local import grant.
    pub fn validate_pull(&self, request: &ConnectorStatePullRequest) -> HostResult<()> {
        self.authorize(
            ConnectorStateTransferDirection::Import,
            &request.peer_node,
            &request.request,
        )?;
        Ok(())
    }

    /// Export only a granted root for an authenticated requesting peer.
    ///
    /// `authorize_transport` must check current peer membership and the host's
    /// confidential-transport policy. It is checked before and after all
    /// awaited reads, then again after bounded response serialization.
    ///
    /// # Errors
    /// Refuses missing/expired grants, wrong identity/root/direction, invalid
    /// state ancestry, untrusted writers and resource-limit violations.
    pub async fn export_for_peer<F>(
        &self,
        authenticated_peer: &str,
        request: &ConnectorStateExportRequest,
        authorize_transport: F,
    ) -> HostResult<String>
    where
        F: Fn() -> HostResult<()> + Send + Sync,
    {
        let (grant, store) = self.authorize(
            ConnectorStateTransferDirection::Export,
            authenticated_peer,
            request,
        )?;
        authorize_transport()?;
        let bundle = store
            .export_replica(request.root_object_id, request.limits.store_limits())
            .await
            .map_err(state_transfer_error)?;
        check_grant_expiry(grant)?;
        authorize_transport()?;
        let response = ConnectorStateExportResponse {
            schema_version: CONNECTOR_STATE_TRANSFER_SCHEMA_VERSION.to_string(),
            request: request.clone(),
            bundle,
        };
        let wire = bounded_json(&response, request.limits.max_wire_bytes)?;
        check_grant_expiry(grant)?;
        authorize_transport()?;
        tracing::info!(
            event = "fcp.connector_state.exported",
            connector_id = %request.scope.connector_id,
            zone_id = %request.scope.zone_id,
            object_count = response.bundle.objects.len(),
            wire_bytes = wire.len(),
            "exported an authorized exact connector-state root"
        );
        Ok(wire)
    }

    /// Validate a signed donor response and retain its state in the replica.
    ///
    /// Call only with the body of a reply whose signature, donor and request
    /// nonce have been verified. The transport callback is also run inside
    /// the store's publication gate, after awaited validation and immediately
    /// before root-write admission. Expiry prevents new publication work; it
    /// cannot undo a persistent write already admitted by the object store.
    ///
    /// # Errors
    /// Rejects unauthorized donors, expired grants, oversized or mismatched
    /// responses, invalid history, conflicting roots and persistence failures.
    pub async fn import_from_peer<F>(
        &self,
        request: &ConnectorStatePullRequest,
        wire: &str,
        authorize_transport: F,
    ) -> HostResult<ConnectorStatePullResponse>
    where
        F: Fn() -> HostResult<()> + Send + Sync,
    {
        let (grant, store) = self.authorize(
            ConnectorStateTransferDirection::Import,
            &request.peer_node,
            &request.request,
        )?;
        authorize_transport()?;
        if wire.len() > request.request.limits.max_wire_bytes {
            return Err(invalid(
                "connector-state export response exceeds its wire limit",
            ));
        }
        let response: ConnectorStateExportResponse = serde_json::from_str(wire)
            .map_err(|_| invalid("connector-state export response is malformed"))?;
        if response.schema_version != CONNECTOR_STATE_TRANSFER_SCHEMA_VERSION
            || response.request != request.request
            || response.bundle.root_object_id != request.request.root_object_id
        {
            return Err(invalid(
                "connector-state export response does not match the authorized request",
            ));
        }
        let object_count = response.bundle.objects.len();
        if object_count > request.request.limits.max_objects {
            return Err(invalid(
                "connector-state export response exceeds its object limit",
            ));
        }
        let canonical_bytes = canonical_size(&response.bundle, request.request.limits)?;
        let change = store
            .import_replica_checked(
                response.bundle,
                request.request.limits.store_limits(),
                || {
                    check_grant_expiry(grant)
                        .and_then(|()| authorize_transport())
                        .map_err(|_| ConnectorStateStoreError::InvalidReplica {
                            reason:
                                "state-transfer authority expired or changed before publication"
                                    .to_string(),
                        })
                },
            )
            .await
            .map_err(state_transfer_error)?;
        tracing::info!(
            event = "fcp.connector_state.replica_retained",
            connector_id = %request.request.scope.connector_id,
            zone_id = %request.request.scope.zone_id,
            object_count,
            canonical_bytes,
            replica_root_published = change.is_some(),
            "retained an authorized connector-state replica"
        );
        Ok(ConnectorStatePullResponse {
            schema_version: CONNECTOR_STATE_TRANSFER_SCHEMA_VERSION.to_string(),
            peer_node: request.peer_node.clone(),
            grant_id: request.request.grant_id.clone(),
            scope: request.request.scope.clone(),
            root_object_id: request.request.root_object_id,
            object_count,
            canonical_bytes,
            wire_bytes: wire.len(),
            replica_root_published: change.is_some(),
            replica_only: true,
        })
    }

    fn authorize(
        &self,
        direction: ConnectorStateTransferDirection,
        peer: &str,
        request: &ConnectorStateExportRequest,
    ) -> HostResult<(&RegisteredTransferGrant, &Arc<FcpStoreConnectorStateStore>)> {
        validate_metadata(peer)?;
        request.validate()?;
        let denied =
            || HostError::PreflightFailed("connector-state transfer is not authorized".to_string());
        let registered = self.grants.get(&request.grant_id).ok_or_else(denied)?;
        let grant = &registered.grant;
        if grant.direction != direction
            || grant.peer_node != peer
            || grant.scope != request.scope
            || grant.root_object_id != request.root_object_id
            || !grant.limits.permits(request.limits)
        {
            return Err(denied());
        }
        check_grant_expiry(registered)?;
        let store = self
            .stores
            .get(&(direction, request.scope.clone()))
            .ok_or_else(denied)?;
        Ok((registered, store))
    }
}

fn canonical_size(
    bundle: &ConnectorStateReplicaBundle,
    limits: ConnectorStateTransferLimits,
) -> HostResult<usize> {
    let mut total = 0usize;
    for object in &bundle.objects {
        let bytes = StoredObject::canonical_bytes(&object.header, &object.body)
            .map_err(|_| invalid("connector-state replica object cannot be canonically encoded"))?;
        total = total
            .checked_add(bytes.len())
            .ok_or_else(|| invalid("state-transfer byte count overflow"))?;
        if total > limits.max_canonical_bytes {
            return Err(invalid(
                "connector-state export response exceeds its canonical byte limit",
            ));
        }
    }
    Ok(total)
}

fn validate_scope(scope: &ConnectorStateTransferScope) -> HostResult<()> {
    validate_metadata(scope.connector_id.as_str())?;
    validate_metadata(scope.zone_id.as_str())?;
    if let Some(instance_id) = &scope.instance_id {
        validate_metadata(instance_id.as_str())?;
    }
    Ok(())
}

fn validate_metadata(value: &str) -> HostResult<()> {
    if value.trim().is_empty()
        || value.len() > MAX_TRANSFER_METADATA_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(invalid(
            "state-transfer metadata is empty, oversized or contains control characters",
        ));
    }
    Ok(())
}

fn check_grant_expiry(grant: &RegisteredTransferGrant) -> HostResult<()> {
    grant.check_at(Utc::now(), Instant::now())
}

fn invalid(message: &str) -> HostError {
    HostError::InvalidFilter(message.to_string())
}

fn state_transfer_error(error: ConnectorStateStoreError) -> HostError {
    // Decoder errors can include CBOR values, and storage errors can include
    // local paths. These diagnostics cross the HTTP and signed mesh boundary;
    // classify the failure without formatting any embedded data or reason.
    let reason = match error {
        ConnectorStateStoreError::ObjectStore(_) => "state storage is unavailable",
        ConnectorStateStoreError::UntrustedWriterKey { .. }
        | ConnectorStateStoreError::InvalidStateSignature(_)
        | ConnectorStateStoreError::InvalidSnapshotSignature(_)
        | ConnectorStateStoreError::SnapshotSigningUnavailable { .. } => {
            "state writer authentication failed"
        }
        ConnectorStateStoreError::IdentityMismatch { .. } => {
            "state identity differs from the registered scope"
        }
        ConnectorStateStoreError::MissingHead(_)
        | ConnectorStateStoreError::MissingLeaseReference(_) => {
            "complete authenticated state ancestry is unavailable"
        }
        ConnectorStateStoreError::ReplayLimitExceeded { .. }
        | ConnectorStateStoreError::ReplicaObjectLimitExceeded { .. }
        | ConnectorStateStoreError::ReplicaByteLimitExceeded { .. } => {
            "state exceeds configured resource limits"
        }
        ConnectorStateStoreError::ForkDetected { .. }
        | ConnectorStateStoreError::SnapshotNotAncestor { .. }
        | ConnectorStateStoreError::SequenceMismatch { .. }
        | ConnectorStateStoreError::SequenceOverflow(_)
        | ConnectorStateStoreError::StaleLease { .. }
        | ConnectorStateStoreError::ChainCycle(_)
        | ConnectorStateStoreError::ReplicaObjectConflict { .. } => {
            "state history is conflicting or discontinuous"
        }
        ConnectorStateStoreError::Serialization(_)
        | ConnectorStateStoreError::UnexpectedSchema { .. }
        | ConnectorStateStoreError::HeaderBodyMismatch
        | ConnectorStateStoreError::ContentIdMismatch { .. }
        | ConnectorStateStoreError::EmptyStateCbor
        | ConnectorStateStoreError::InvalidStateCbor(_)
        | ConnectorStateStoreError::SnapshotStateMismatch { .. }
        | ConnectorStateStoreError::InvalidReplica { .. } => "state validation failed",
    };
    HostError::Unavailable(format!("connector-state transfer failed: {reason}"))
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("state-transfer JSON wire limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_json(value: &impl Serialize, limit: usize) -> HostResult<String> {
    let mut writer = BoundedJsonWriter {
        bytes: Vec::with_capacity(limit.min(4096)),
        limit,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| {
        invalid("connector-state transfer JSON exceeds its wire limit or cannot be encoded")
    })?;
    String::from_utf8(writer.bytes)
        .map_err(|_| HostError::Internal("JSON serializer produced invalid UTF-8".to_string()))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use fcp_cbor::{CanonicalSerializer, SchemaId};
    use fcp_crypto::Ed25519SigningKey;
    use fcp_evidence::{ObjectHeader, ObjectIdKey, RetentionClass, StorageMeta};
    use fcp_kernel::{ConnectorStateModel, ConnectorStateObject, ConnectorStateRoot};
    use fcp_policy::Provenance;
    use fcp_prelude::Signature;
    use fcp_store::{MemoryObjectStore, MemoryObjectStoreConfig, ObjectStore};

    use super::*;

    fn run<F: std::future::Future>(future: F) -> F::Output {
        fcp_async_core::runtime::block_on_sync(future).expect("test runtime")
    }

    fn scope() -> ConnectorStateTransferScope {
        ConnectorStateTransferScope {
            connector_id: ConnectorId::from_static("slack:chat:v1"),
            zone_id: ZoneId::work(),
            instance_id: None,
        }
    }

    fn limits() -> ConnectorStateTransferLimits {
        ConnectorStateTransferLimits {
            max_objects: 16,
            max_canonical_bytes: 64 * 1024,
            max_wire_bytes: 128 * 1024,
        }
    }

    fn key() -> ObjectIdKey {
        ObjectIdKey::from_bytes([42; 32])
    }

    fn writer() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[0x5a; 32]).unwrap()
    }

    fn adapter(objects: Arc<dyn ObjectStore>) -> Arc<FcpStoreConnectorStateStore> {
        Arc::new(
            FcpStoreConnectorStateStore::new(objects, key(), scope().connector_id, scope().zone_id)
                .with_trusted_writer_keys([writer().verifying_key().to_bytes()]),
        )
    }

    fn header(schema: SchemaId, refs: Vec<ObjectId>) -> ObjectHeader {
        ObjectHeader {
            encryption_kind: Default::default(),
            schema,
            zone_id: scope().zone_id,
            created_at: 1_700_000_000,
            provenance: Provenance::new(scope().zone_id),
            refs,
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn stored(header: &ObjectHeader, value: &impl Serialize) -> StoredObject {
        let body = CanonicalSerializer::serialize(value, &header.schema).unwrap();
        StoredObject {
            object_id: StoredObject::derive_id(header, &body, &key()).unwrap(),
            header: header.clone(),
            body,
            storage: StorageMeta {
                retention: RetentionClass::Pinned,
            },
        }
    }

    struct Fixture {
        donor: ConnectorStateReplicationService,
        recipient: ConnectorStateReplicationService,
        replica: Arc<FcpStoreConnectorStateStore>,
        request: ConnectorStatePullRequest,
    }

    fn fixture() -> Fixture {
        let source_objects = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let lease_id = ObjectId::from_bytes([0x17; 32]);
        let mut state = ConnectorStateObject {
            header: header(
                FcpStoreConnectorStateStore::state_object_schema_id(),
                vec![lease_id],
            ),
            connector_id: scope().connector_id,
            instance_id: None,
            zone_id: scope().zone_id,
            prev: None,
            seq: 0,
            state_cbor: vec![0xa1, 0x61, b'n', 0x00],
            updated_at: 1_700_000_000,
            lease_seq: 17,
            lease_object_id: lease_id,
            writer_public_key: [0; 32],
            signature: Signature::zero(),
        };
        state.sign_with(&writer()).unwrap();
        let state_object = stored(&state.header, &state);
        let root = ConnectorStateRoot {
            header: header(
                FcpStoreConnectorStateStore::root_schema_id(),
                vec![state_object.object_id],
            ),
            connector_id: scope().connector_id,
            instance_id: None,
            zone_id: scope().zone_id,
            model: ConnectorStateModel::SingletonWriter,
            head: Some(state_object.object_id),
            state_schema_version: 1,
        };
        let root_object = stored(&root.header, &root);
        let root_object_id = root_object.object_id;
        run(source_objects.put(state_object)).unwrap();
        run(source_objects.put(root_object)).unwrap();
        let source = adapter(source_objects);
        let replica = adapter(Arc::new(MemoryObjectStore::new(
            MemoryObjectStoreConfig::default(),
        )));
        let mut donor = ConnectorStateReplicationService::new();
        donor
            .register_store(ConnectorStateTransferDirection::Export, scope(), source)
            .unwrap();
        let mut recipient = ConnectorStateReplicationService::new();
        recipient
            .register_store(
                ConnectorStateTransferDirection::Import,
                scope(),
                Arc::clone(&replica),
            )
            .unwrap();
        let grant = ConnectorStateTransferGrant {
            grant_id: "restore-state".to_string(),
            direction: ConnectorStateTransferDirection::Export,
            peer_node: "recipient".to_string(),
            scope: scope(),
            root_object_id,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            limits: limits(),
        };
        donor.add_grant(grant.clone()).unwrap();
        recipient
            .add_grant(ConnectorStateTransferGrant {
                direction: ConnectorStateTransferDirection::Import,
                peer_node: "donor".to_string(),
                ..grant
            })
            .unwrap();
        Fixture {
            donor,
            recipient,
            replica,
            request: ConnectorStatePullRequest {
                peer_node: "donor".to_string(),
                request: ConnectorStateExportRequest {
                    grant_id: "restore-state".to_string(),
                    scope: scope(),
                    root_object_id,
                    limits: limits(),
                },
            },
        }
    }

    fn export(fixture: &Fixture) -> String {
        run(fixture
            .donor
            .export_for_peer("recipient", &fixture.request.request, || Ok(())))
        .unwrap()
    }

    #[test]
    fn exact_root_transfer_populates_only_registered_replica_and_is_repeatable() {
        let fixture = fixture();
        assert!(run(fixture.replica.read_root()).unwrap().is_none());
        fixture.recipient.validate_pull(&fixture.request).unwrap();
        let wire = export(&fixture);
        let result = run(fixture
            .recipient
            .import_from_peer(&fixture.request, &wire, || Ok(())))
        .unwrap();
        assert_eq!(
            result.root_object_id,
            fixture.request.request.root_object_id
        );
        assert_eq!(result.peer_node, "donor");
        assert_eq!(result.object_count, 2);
        assert_eq!(result.wire_bytes, wire.len());
        assert!(result.canonical_bytes > 0);
        assert!(result.replica_only);
        assert!(result.replica_root_published);
        assert_eq!(
            run(fixture.replica.read_root()).unwrap().unwrap().0,
            result.root_object_id
        );
        let repeated = run(fixture
            .recipient
            .import_from_peer(&fixture.request, &wire, || Ok(())))
        .unwrap();
        assert!(!repeated.replica_root_published);
        assert!(repeated.replica_only);
    }

    #[test]
    fn registration_requires_exact_identity_and_nonempty_writer_pins() {
        let objects = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let unpinned = FcpStoreConnectorStateStore::new(
            objects.clone(),
            key(),
            scope().connector_id,
            scope().zone_id,
        );
        let mut service = ConnectorStateReplicationService::new();
        assert!(
            service
                .register_store(
                    ConnectorStateTransferDirection::Export,
                    scope(),
                    Arc::new(unpinned.clone())
                )
                .is_err()
        );
        assert!(
            service
                .register_store(
                    ConnectorStateTransferDirection::Export,
                    scope(),
                    Arc::new(unpinned.with_trusted_writer_keys([]))
                )
                .is_err()
        );
        let mut other_scope = scope();
        other_scope.instance_id = Some(InstanceId::new());
        assert!(
            service
                .register_store(
                    ConnectorStateTransferDirection::Export,
                    other_scope,
                    adapter(objects.clone())
                )
                .is_err()
        );
        service
            .register_store(
                ConnectorStateTransferDirection::Export,
                scope(),
                adapter(objects.clone()),
            )
            .unwrap();
        assert!(
            service
                .register_store(
                    ConnectorStateTransferDirection::Export,
                    scope(),
                    adapter(objects)
                )
                .is_err()
        );
    }

    #[test]
    fn grants_deny_wrong_peer_direction_scope_root_and_wider_limits() {
        let fixture = fixture();
        let empty = ConnectorStateReplicationService::new();
        assert!(empty.validate_pull(&fixture.request).is_err());
        assert!(
            run(fixture
                .donor
                .export_for_peer("intruder", &fixture.request.request, || Ok(())))
            .is_err()
        );
        assert!(fixture.donor.validate_pull(&fixture.request).is_err());
        let original = serde_json::to_value(&fixture.request).unwrap();
        for (pointer, replacement) in [
            ("/peer_node", serde_json::json!("intruder")),
            ("/request/grant_id", serde_json::json!("unknown")),
            ("/request/scope/zone_id", serde_json::json!("z:private")),
            (
                "/request/scope/connector_id",
                serde_json::json!("github:request_response:v1"),
            ),
            ("/request/root_object_id", serde_json::json!("f".repeat(64))),
            ("/request/limits/max_objects", serde_json::json!(17)),
            (
                "/request/limits/max_canonical_bytes",
                serde_json::json!(64 * 1024 + 1),
            ),
            (
                "/request/limits/max_wire_bytes",
                serde_json::json!(128 * 1024 + 1),
            ),
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            let changed: ConnectorStatePullRequest = serde_json::from_value(changed).unwrap();
            assert!(
                fixture.recipient.validate_pull(&changed).is_err(),
                "{pointer}"
            );
        }
        let mut wrong_instance = fixture.request.clone();
        wrong_instance.request.scope.instance_id = Some(InstanceId::new());
        assert!(fixture.recipient.validate_pull(&wrong_instance).is_err());
        let mut narrower = fixture.request.clone();
        narrower.request.limits.max_objects = 2;
        fixture.recipient.validate_pull(&narrower).unwrap();
    }

    #[test]
    fn export_and_import_recheck_transport_authority_after_initial_admission() {
        let fixture = fixture();
        let calls = AtomicUsize::new(0);
        assert!(
            run(fixture
                .donor
                .export_for_peer("recipient", &fixture.request.request, || {
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        Ok(())
                    } else {
                        Err(invalid("peer revoked"))
                    }
                }))
            .is_err()
        );
        assert!(calls.load(Ordering::SeqCst) >= 2);
        let wire = export(&fixture);
        calls.store(0, Ordering::SeqCst);
        assert!(
            run(fixture
                .recipient
                .import_from_peer(&fixture.request, &wire, || {
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        Ok(())
                    } else {
                        Err(invalid("peer revoked"))
                    }
                }))
            .is_err()
        );
        assert!(calls.load(Ordering::SeqCst) >= 2);
        assert!(run(fixture.replica.read_root()).unwrap().is_none());
    }

    #[test]
    fn expired_grants_and_zero_or_excessive_budgets_fail_closed() {
        let mut fixture = fixture();
        fixture
            .recipient
            .grants
            .get_mut("restore-state")
            .unwrap()
            .grant
            .expires_at = Utc::now();
        assert!(fixture.recipient.validate_pull(&fixture.request).is_err());
        let mut grant = fixture.donor.grants["restore-state"].grant.clone();
        grant.expires_at = Utc::now();
        grant.grant_id = "expired".to_string();
        assert!(fixture.donor.add_grant(grant).is_err());
        for bad_limits in [
            ConnectorStateTransferLimits {
                max_objects: 0,
                ..limits()
            },
            ConnectorStateTransferLimits {
                max_objects: MAX_CONNECTOR_STATE_TRANSFER_OBJECTS + 1,
                ..limits()
            },
            ConnectorStateTransferLimits {
                max_canonical_bytes: 0,
                ..limits()
            },
            ConnectorStateTransferLimits {
                max_wire_bytes: MAX_CONNECTOR_STATE_TRANSFER_WIRE_BYTES + 1,
                ..limits()
            },
        ] {
            assert!(bad_limits.validate().is_err());
        }
    }

    #[test]
    fn wall_clock_rollback_cannot_extend_or_revive_transfer_authority() {
        let fixture = fixture();
        let registered = &fixture.recipient.grants["restore-state"];
        let earlier = Utc::now() - chrono::Duration::hours(2);
        assert!(registered.check_at(Utc::now(), Instant::now()).is_ok());
        assert!(registered.check_at(earlier, registered.deadline).is_err());
        assert!(registered.check_at(earlier, Instant::now()).is_err());

        let other = fixture.donor.grants.get("restore-state").unwrap();
        assert!(
            other
                .check_at(other.grant.expires_at, Instant::now())
                .is_err()
        );
        assert!(other.check_at(earlier, Instant::now()).is_err());
    }

    #[test]
    fn wire_and_canonical_limits_are_independent_and_enforced_before_import() {
        let fixture = fixture();
        let wire = export(&fixture);
        let mut request = fixture.request.clone();
        request.request.limits.max_wire_bytes = wire.len() - 1;
        assert!(
            run(fixture
                .recipient
                .import_from_peer(&request, &wire, || Ok(())))
            .is_err()
        );
        assert!(
            run(fixture
                .donor
                .export_for_peer("recipient", &request.request, || Ok(())))
            .is_err()
        );
        request.request.limits = limits();
        request.request.limits.max_canonical_bytes = 1;
        assert!(
            run(fixture
                .donor
                .export_for_peer("recipient", &request.request, || Ok(())))
            .is_err()
        );
        request.request.limits = limits();
        request.request.limits.max_objects = 1;
        assert!(
            run(fixture
                .donor
                .export_for_peer("recipient", &request.request, || Ok(())))
            .is_err()
        );
        assert!(run(fixture.replica.read_root()).unwrap().is_none());
    }

    #[test]
    fn mismatched_or_corrupted_replica_never_publishes_a_root() {
        let fixture = fixture();
        let wire = export(&fixture);
        let original: serde_json::Value = serde_json::from_str(&wire).unwrap();
        for (pointer, replacement) in [
            ("/schema_version", serde_json::json!("unknown")),
            ("/request/grant_id", serde_json::json!("other")),
            ("/request/scope/zone_id", serde_json::json!("z:private")),
            ("/bundle/root_object_id", serde_json::json!("f".repeat(64))),
            ("/bundle/objects/0/body", serde_json::json!([0])),
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            let changed = serde_json::to_string(&changed).unwrap();
            assert!(
                run(fixture
                    .recipient
                    .import_from_peer(&fixture.request, &changed, || Ok(())))
                .is_err(),
                "{pointer}"
            );
            assert!(run(fixture.replica.read_root()).unwrap().is_none());
        }
    }

    #[test]
    fn request_encoding_refuses_unknown_fields_and_oversized_input() {
        let fixture = fixture();
        let wire = fixture.request.request.to_json().unwrap();
        assert_eq!(
            ConnectorStateExportRequest::from_json(&wire).unwrap(),
            fixture.request.request
        );
        let mut value = serde_json::to_value(&fixture.request.request).unwrap();
        value["source_path"] = serde_json::json!("/operator-only/path");
        assert!(
            ConnectorStateExportRequest::from_json(&serde_json::to_string(&value).unwrap())
                .is_err()
        );
        assert!(
            ConnectorStateExportRequest::from_json(
                &" ".repeat(MAX_CONNECTOR_STATE_EXPORT_REQUEST_BYTES + 1)
            )
            .is_err()
        );
    }

    #[test]
    fn transfer_errors_never_echo_payloads_paths_or_untrusted_reasons() {
        let marker = "transfer-secret-body".repeat(256);
        let errors = [
            ConnectorStateStoreError::Serialization(
                fcp_cbor::SerializationError::DuplicateMapKey {
                    key_hex: marker.clone(),
                },
            ),
            ConnectorStateStoreError::InvalidStateCbor(
                fcp_cbor::SerializationError::DuplicateMapKey {
                    key_hex: marker.clone(),
                },
            ),
            ConnectorStateStoreError::InvalidStateSignature(marker.clone()),
            ConnectorStateStoreError::InvalidReplica {
                reason: marker.clone(),
            },
            ConnectorStateStoreError::IdentityMismatch {
                field: "connector_id",
                expected: marker.clone(),
                got: marker.clone(),
            },
            ConnectorStateStoreError::UnexpectedSchema {
                kind: "state object",
                expected: marker.clone(),
                got: marker.clone(),
            },
            ConnectorStateStoreError::UntrustedWriterKey {
                writer_public_key: marker.clone(),
            },
            ConnectorStateStoreError::ObjectStore(fcp_store::ObjectStoreError::Io(format!(
                "/private/object-store/{marker}"
            ))),
        ];
        for error in errors {
            let public_error = state_transfer_error(error);
            let HostError::Unavailable(message) = public_error else {
                panic!("state-transfer error classification changed its HTTP error category");
            };
            assert!(message.starts_with("connector-state transfer failed: "));
            assert!(message.len() < 256);
            assert!(!message.contains("transfer-secret"));
            assert!(!message.contains("/private/object-store"));
        }
    }
}
