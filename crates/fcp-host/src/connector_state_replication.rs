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

pub(super) mod runtime;

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
/// Version of a read-only, exact-root replica inspection receipt.
pub const CONNECTOR_STATE_INSPECTION_SCHEMA_VERSION: &str = "fcp.host.state-inspection.v1";
/// Inspection returns bounded metadata, never serialized state objects.
pub const MAX_CONNECTOR_STATE_INSPECTION_RESPONSE_BYTES: usize = 16 * 1024;

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

/// Protected read-only request, distinct from a pull or a recovery plan.
///
/// The existing local import grant selects the replica and exact root. The
/// named donor is not contacted and need not currently be reachable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorStateInspectionRequest {
    /// Exact request whose retained replica should be verified, not imported.
    pub inspect: ConnectorStatePullRequest,
}

impl ConnectorStateInspectionRequest {
    /// Encode a bounded, unambiguous read-only command.
    ///
    /// # Errors
    /// Rejects invalid metadata, invalid limits and oversized request wrappers.
    pub fn to_json(&self) -> HostResult<String> {
        validate_metadata(&self.inspect.peer_node)?;
        self.inspect.request.validate()?;
        bounded_json(self, MAX_CONNECTOR_STATE_EXPORT_REQUEST_BYTES)
    }
}

/// Local observation of an explicitly authorized immutable root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorStateInspectionStatus {
    /// The exact root and its complete ancestry passed the adapter's checks.
    Verified,
    /// The exact root object was absent at the time of the read.
    /// An earlier admitted import may still publish it later.
    RootNotFound,
}

/// Metadata from checking the recipient's existing replica without writing.
///
/// This is not an import receipt, current-head assertion, durability proof,
/// mesh-wide replica count, or evidence that a previous writer has settled.
/// In particular, neither status authorizes an automatic retry of an import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorStateInspectionResponse {
    /// Always `CONNECTOR_STATE_INSPECTION_SCHEMA_VERSION`.
    pub schema_version: String,
    /// Exact request whose local import grant authorized this inspection.
    pub request: ConnectorStatePullRequest,
    /// Verified history or a narrowly classified missing root observation.
    pub status: ConnectorStateInspectionStatus,
    /// Validated objects including the root; zero only for a missing root.
    pub object_count: usize,
    /// Canonical bytes validated locally; no state bytes are disclosed.
    pub canonical_bytes: usize,
    /// Always true: live connector state was neither activated nor selected.
    pub replica_only: bool,
}

impl ConnectorStateInspectionResponse {
    /// Bind a receipt to the exact requested grant, donor, scope, root and limits.
    ///
    /// # Errors
    /// Rejects mismatched identities, unknown schemas and inconsistent counts.
    /// This checks metadata only; the caller must authenticate its host transport.
    pub fn validate_for(&self, request: &ConnectorStatePullRequest) -> HostResult<()> {
        validate_metadata(&request.peer_node)?;
        request.request.validate()?;
        let counts_valid = match self.status {
            ConnectorStateInspectionStatus::Verified => {
                self.object_count > 0
                    && self.object_count <= request.request.limits.max_objects
                    && self.canonical_bytes > 0
                    && self.canonical_bytes <= request.request.limits.max_canonical_bytes
            }
            ConnectorStateInspectionStatus::RootNotFound => {
                self.object_count == 0 && self.canonical_bytes == 0
            }
        };
        if self.schema_version != CONNECTOR_STATE_INSPECTION_SCHEMA_VERSION
            || self.request != *request
            || !self.replica_only
            || !counts_valid
        {
            return Err(invalid("connector-state inspection receipt does not match its request"));
        }
        Ok(())
    }
}

/// Explicitly registered source/replica adapters and immutable transfer grants.
///
/// Construct at host startup, then share one `Arc` for the host's lifetime.
/// A registration never opens a filesystem path or creates an independent
/// store. Hosts must retain the same adapter and backing-store ownership.
///
/// Shared admission permits at most eight active service operations, two per
/// peer, and aggregate reservations of 16 MiB each for canonical and wire bytes
/// plus 8192 objects. Admission is fail-fast, with no waiter queue. Reservations
/// end with the service future; this is not a bound on allocator overhead or
/// already-admitted persistent work inside the underlying object store.
#[derive(Default)]
pub struct ConnectorStateReplicationService {
    stores: HashMap<
        (ConnectorStateTransferDirection, ConnectorStateTransferScope),
        Arc<FcpStoreConnectorStateStore>,
    >,
    grants: HashMap<String, RegisteredTransferGrant>,
    pub(super) runtime: runtime::TransferRuntime,
    pub(super) page_concurrency: crate::connector_state_pages::PageConcurrency,
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

    /// Verify one exact root already in the registered retained-replica store.
    ///
    /// Call only through a protected local operator surface. Current local
    /// import authority is required before any store read and rechecked after
    /// awaited validation. No donor lookup, network request, import, root scan,
    /// cache publication, or state activation occurs. The caller must impose
    /// a total deadline, just as for the other state-transfer service methods.
    ///
    /// Reuses full keyed-ID, writer-pin and ancestry validation with the
    /// request's object/canonical-byte limits and the shared admission quota.
    /// The store releases each validated object instead of retaining a complete
    /// export, and returns canonical byte counts from that same validation pass.
    /// Grant expiry is checked between objects even when store reads stay ready.
    /// `max_wire_bytes` remains reserved conservatively, but no export payload
    /// is serialized; the metadata response has its own fixed 16 KiB bound.
    /// Missing ancestors, malformed objects and storage failures are errors,
    /// never a successful missing-root report. An absent root is only a local
    /// read observation: an earlier cancelled import may still finish later.
    ///
    /// # Errors
    /// Rejects missing/expired authority, resource exhaustion, incomplete or
    /// invalid history, and storage failures without disclosing state or paths.
    pub async fn inspect_replica(
        &self,
        request: &ConnectorStatePullRequest,
    ) -> HostResult<ConnectorStateInspectionResponse> {
        let (grant, store) = self.authorize(
            ConnectorStateTransferDirection::Import,
            &request.peer_node,
            &request.request,
        )?;
        let permit = self.runtime.admit(&request.peer_node, request.request.limits)?;
        let result = store
            .inspect_replica_checked(
                request.request.root_object_id,
                request.request.limits.store_limits(),
                || {
                    check_grant_expiry(grant).map_err(|_| {
                        ConnectorStateStoreError::InvalidReplica {
                            reason: "state-inspection authority expired during verification"
                                .to_string(),
                        }
                    })
                },
            )
            .await;
        check_grant_expiry(grant)?;
        let (status, object_count, canonical_bytes) = match result {
            Ok(inspection) => (
                ConnectorStateInspectionStatus::Verified,
                inspection.object_count,
                inspection.canonical_bytes,
            ),
            Err(ConnectorStateStoreError::ObjectStore(fcp_store::ObjectStoreError::NotFound(id)))
                if id == request.request.root_object_id =>
            {
                (ConnectorStateInspectionStatus::RootNotFound, 0, 0)
            }
            Err(error) => return Err(state_transfer_error(error)),
        };
        let response = ConnectorStateInspectionResponse {
            schema_version: CONNECTOR_STATE_INSPECTION_SCHEMA_VERSION.to_owned(),
            request: request.clone(),
            status,
            object_count,
            canonical_bytes,
            replica_only: true,
        };
        response.validate_for(request)?;
        // Metadata can contain escaped operator identifiers. Bound the actual
        // encoding, not just character counts, without serializing state bytes.
        bounded_json(&response, MAX_CONNECTOR_STATE_INSPECTION_RESPONSE_BYTES)?;
        check_grant_expiry(grant)?;
        permit.check(&self.runtime, &request.peer_node, request.request.limits)?;
        Ok(response)
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
        self.validate_export(authenticated_peer, request)?;
        authorize_transport()?;
        let permit = self.runtime.admit(authenticated_peer, request.limits)?;
        self.export_admitted(authenticated_peer, request, authorize_transport, &permit).await
    }

    pub(super) async fn export_admitted<F>(
        &self,
        authenticated_peer: &str,
        request: &ConnectorStateExportRequest,
        authorize_transport: F,
        permit: &runtime::TransferPermit<'_>,
    ) -> HostResult<String>
    where
        F: Fn() -> HostResult<()> + Send + Sync,
    {
        permit.check(&self.runtime, authenticated_peer, request.limits)?;
        let (grant, store) = self.authorize(
            ConnectorStateTransferDirection::Export,
            authenticated_peer,
            request,
        )?;
        authorize_transport()?;
        let result = store
            .export_replica_checked(
                request.root_object_id,
                request.limits.store_limits(),
                || {
                    check_grant_expiry(grant)
                        .and_then(|()| authorize_transport())
                        .map_err(|_| ConnectorStateStoreError::InvalidReplica {
                            reason: "state-transfer authority expired or changed during export"
                                .to_string(),
                        })
                },
            )
            .await;
        // Preserve the host refusal instead of relabeling an expired grant or
        // revoked transport as a missing or corrupt replica. No bytes escape.
        check_grant_expiry(grant)?;
        authorize_transport()?;
        let bundle = result.map_err(state_transfer_error)?;
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

    /// Validate a signed donor response and retain its exact root in the replica.
    ///
    /// A successful response retains the requested root even when local state
    /// has already advanced. Historical retention reports no canonical advance
    /// and never rolls back newer state. All ancestry and writer checks apply.
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
        self.validate_pull(request)?;
        authorize_transport()?;
        let permit = self.runtime.admit(&request.peer_node, request.request.limits)?;
        self.import_admitted(request, wire, authorize_transport, &permit).await
    }

    pub(super) async fn import_admitted<F>(
        &self,
        request: &ConnectorStatePullRequest,
        wire: &str,
        authorize_transport: F,
        permit: &runtime::TransferPermit<'_>,
    ) -> HostResult<ConnectorStatePullResponse>
    where
        F: Fn() -> HostResult<()> + Send + Sync,
    {
        permit.check(&self.runtime, &request.peer_node, request.request.limits)?;
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
        // An advance-only import may skip an older comparable root entirely.
        // A successful exact-root transfer must retain that root as well as its
        // ancestry, without selecting it over a newer canonical head.
        let change = store
            .retain_replica_checked(
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

    pub(super) fn validate_export(
        &self,
        authenticated_peer: &str,
        request: &ConnectorStateExportRequest,
    ) -> HostResult<()> {
        self.authorize(
            ConnectorStateTransferDirection::Export, authenticated_peer, request,
        )?;
        Ok(())
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
        fixture_with_state(vec![0xa1, 0x61, b'n', 0x00], limits())
    }

    fn fixture_with_state(
        state_cbor: Vec<u8>,
        transfer_limits: ConnectorStateTransferLimits,
    ) -> Fixture {
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
            state_cbor,
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
            limits: transfer_limits,
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
                    limits: transfer_limits,
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
    fn inspection_missing_root_is_read_only_and_does_not_contact_the_donor() {
        let fixture = fixture();
        let response = run(fixture.recipient.inspect_replica(&fixture.request)).unwrap();
        assert_eq!(response.status, ConnectorStateInspectionStatus::RootNotFound);
        assert_eq!((response.object_count, response.canonical_bytes), (0, 0));
        response.validate_for(&fixture.request).unwrap();
        assert!(response.replica_only);
        assert!(run(fixture.replica.read_root()).unwrap().is_none());
        assert_eq!(fixture.recipient.runtime.active(), 0);
        assert_eq!(fixture.donor.runtime.cache_builds_started(), 0);
    }

    #[test]
    fn inspection_revalidates_retained_history_without_a_publication_claim() {
        let fixture = fixture();
        let wire = export(&fixture);
        let retained = run(fixture.recipient.import_from_peer(
            &fixture.request, &wire, || Ok(()),
        )).unwrap();
        for _ in 0..2 {
            let response = run(fixture.recipient.inspect_replica(&fixture.request)).unwrap();
            assert_eq!(response.status, ConnectorStateInspectionStatus::Verified);
            assert_eq!(response.object_count, retained.object_count);
            assert_eq!(response.canonical_bytes, retained.canonical_bytes);
            response.validate_for(&fixture.request).unwrap();
            let value = serde_json::to_value(&response).unwrap();
            for absent in ["bundle", "objects", "state_cbor", "current_root", "replica_root_published"] {
                assert!(value.get(absent).is_none(), "unexpected claim or state field: {absent}");
            }
            assert_eq!(run(fixture.replica.read_root()).unwrap().unwrap().0, retained.root_object_id);
            assert_eq!(fixture.recipient.runtime.active(), 0);
        }
    }

    #[test]
    fn inspection_incomplete_ancestry_is_an_error_not_a_missing_root_receipt() {
        let mut fixture = fixture();
        let response: ConnectorStateExportResponse = serde_json::from_str(&export(&fixture)).unwrap();
        let objects = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        // Stage only the authenticated root. Its head is absent, as can happen
        // with damaged storage; presence of a root alone is not verification.
        let root = response.bundle.objects.into_iter()
            .find(|object| object.object_id == fixture.request.request.root_object_id).unwrap();
        run(objects.put(root)).unwrap();
        fixture.recipient.stores.insert(
            (ConnectorStateTransferDirection::Import, scope()), adapter(objects),
        );
        let error = run(fixture.recipient.inspect_replica(&fixture.request)).unwrap_err();
        assert!(matches!(error, HostError::Unavailable(_)));
        assert_eq!(fixture.recipient.runtime.active(), 0);
    }

    #[test]
    fn inspection_requires_pinned_writers_even_for_locally_present_objects() {
        let mut fixture = fixture();
        let response: ConnectorStateExportResponse = serde_json::from_str(&export(&fixture)).unwrap();
        let objects = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        for object in response.bundle.objects {
            run(objects.put(object)).unwrap();
        }
        let other = Ed25519SigningKey::from_bytes(&[0x6b; 32]).unwrap();
        let untrusted = FcpStoreConnectorStateStore::new(
            objects, key(), scope().connector_id, scope().zone_id,
        ).with_trusted_writer_keys([other.verifying_key().to_bytes()]);
        fixture.recipient.stores.insert(
            (ConnectorStateTransferDirection::Import, scope()), Arc::new(untrusted),
        );
        let error = run(fixture.recipient.inspect_replica(&fixture.request)).unwrap_err();
        assert!(error.to_string().contains("state writer authentication failed"));
        assert_eq!(fixture.recipient.runtime.active(), 0);
    }

    #[test]
    fn inspection_checks_authority_before_exposing_presence_or_capacity() {
        let fixture = fixture();
        let first = fixture.recipient.runtime.admit("donor", limits()).unwrap();
        let second = fixture.recipient.runtime.admit("donor", limits()).unwrap();
        assert!(matches!(run(fixture.recipient.inspect_replica(&fixture.request)),
            Err(HostError::Unavailable(_))));
        let mut wrong = fixture.request.clone();
        wrong.request.root_object_id = ObjectId::from_bytes([0xff; 32]);
        assert!(matches!(run(fixture.recipient.inspect_replica(&wrong)),
            Err(HostError::PreflightFailed(_))));
        wrong = fixture.request.clone();
        wrong.peer_node = "other-peer".to_owned();
        assert!(matches!(run(fixture.recipient.inspect_replica(&wrong)),
            Err(HostError::PreflightFailed(_))));
        assert!(run(fixture.donor.inspect_replica(&fixture.request)).is_err(),
            "an export-only registration is not a retained-replica read grant");
        drop((first, second));
        fixture.recipient.grants["restore-state"].expired.store(true, Ordering::Release);
        assert!(matches!(run(fixture.recipient.inspect_replica(&fixture.request)),
            Err(HostError::PreflightFailed(_))));
        assert_eq!(fixture.recipient.runtime.active(), 0);
        assert!(run(fixture.replica.read_root()).unwrap().is_none());
    }

    #[test]
    fn ready_export_rechecks_transport_within_its_object_walk() {
        let fixture = fixture();
        let checks = AtomicUsize::new(0);
        let result = run(fixture.donor.export_for_peer(
            "recipient",
            &fixture.request.request,
            || {
                if checks.fetch_add(1, Ordering::SeqCst) >= 5 {
                    Err(HostError::PreflightFailed("fixture transport revoked".to_owned()))
                } else {
                    Ok(())
                }
            },
        ));
        // The former export performed only four transport checks, all outside
        // its ancestry walk, and would incorrectly return this export as allowed.
        assert!(matches!(result, Err(HostError::PreflightFailed(_))));
        assert!(checks.load(Ordering::SeqCst) >= 6);
        assert_eq!(fixture.donor.runtime.active(), 0);
        assert!(run(fixture.replica.read_root()).unwrap().is_none());
    }

    #[test]
    fn payload_heavy_inspection_preserves_receipt_and_independent_wire_budget() {
        let state = fcp_cbor::to_canonical_cbor(&vec![7u64; 4096]).unwrap();
        let fixture = fixture_with_state(state, limits());
        let wire = export(&fixture);
        let retained = run(fixture.recipient.import_from_peer(
            &fixture.request, &wire, || Ok(()),
        )).unwrap();
        let mut request = fixture.request.clone();
        request.request.limits.max_objects = retained.object_count;
        request.request.limits.max_canonical_bytes = retained.canonical_bytes;
        request.request.limits.max_wire_bytes = 1;
        let inspected = run(fixture.recipient.inspect_replica(&request)).unwrap();
        inspected.validate_for(&request).unwrap();
        assert_eq!(inspected.status, ConnectorStateInspectionStatus::Verified);
        assert_eq!(inspected.object_count, retained.object_count);
        assert_eq!(inspected.canonical_bytes, retained.canonical_bytes);
        assert!(inspected.canonical_bytes > 4096);
        assert!(inspected.replica_only);
        let receipt = serde_json::to_value(&inspected).unwrap();
        for absent in ["bundle", "objects", "state_cbor", "current_root"] {
            assert!(receipt.get(absent).is_none());
        }
        assert_eq!(fixture.recipient.runtime.active(), 0);
    }

    #[test]
    fn successful_historical_pull_retains_exact_root_without_advancing_newer_state() {
        let fixture = fixture();
        let old_wire = export(&fixture);
        let old_response: ConnectorStateExportResponse = serde_json::from_str(&old_wire).unwrap();
        let old_state_object = old_response.bundle.objects[0].clone();
        let old_state: ConnectorStateObject = CanonicalSerializer::deserialize(
            &old_state_object.body, &FcpStoreConnectorStateStore::state_object_schema_id(),
        ).unwrap();
        let next_lease = ObjectId::from_bytes([0x18; 32]);
        let mut next_state = ConnectorStateObject {
            header: header(
                FcpStoreConnectorStateStore::state_object_schema_id(),
                vec![old_state_object.object_id, next_lease],
            ),
            prev: Some(old_state_object.object_id),
            seq: 1,
            lease_seq: 18,
            lease_object_id: next_lease,
            ..old_state
        };
        next_state.sign_with(&writer()).unwrap();
        let next_state_object = stored(&next_state.header, &next_state);
        let next_root = ConnectorStateRoot {
            header: header(
                FcpStoreConnectorStateStore::root_schema_id(),
                vec![next_state_object.object_id],
            ),
            connector_id: scope().connector_id,
            instance_id: None,
            zone_id: scope().zone_id,
            model: ConnectorStateModel::SingletonWriter,
            head: Some(next_state_object.object_id),
            state_schema_version: 1,
        };
        let next_root_object = stored(&next_root.header, &next_root);
        let next_root_id = next_root_object.object_id;
        let newer = ConnectorStateReplicaBundle {
            root_object_id: next_root_id,
            objects: vec![old_state_object, next_state_object, next_root_object],
        };
        run(fixture.replica.import_replica(newer, limits().store_limits())).unwrap().unwrap();
        // An ancestry bundle includes its state objects, not earlier root
        // envelopes. The requested historical root is therefore absent here.
        assert_eq!(
            run(fixture.recipient.inspect_replica(&fixture.request)).unwrap().status,
            ConnectorStateInspectionStatus::RootNotFound,
        );
        let receipt = run(fixture.recipient.import_from_peer(
            &fixture.request, &old_wire, || Ok(()),
        )).unwrap();
        assert_eq!(receipt.root_object_id, fixture.request.request.root_object_id);
        assert!(!receipt.replica_root_published, "historical retention must not advertise an advance");
        assert!(receipt.replica_only);
        let inspected = run(fixture.recipient.inspect_replica(&fixture.request)).unwrap();
        assert_eq!(inspected.status, ConnectorStateInspectionStatus::Verified);
        assert_eq!(inspected.object_count, receipt.object_count);
        assert_eq!(inspected.canonical_bytes, receipt.canonical_bytes);
        assert_eq!(run(fixture.replica.read_root()).unwrap().unwrap().0, next_root_id);
        assert_eq!(
            run(fixture.replica.export_replica(receipt.root_object_id, limits().store_limits()))
                .unwrap(),
            old_response.bundle,
        );
    }

    #[test]
    fn inspection_enforces_exact_object_and_canonical_budgets_without_exporting_state() {
        let fixture = fixture();
        let wire = export(&fixture);
        let retained = run(fixture.recipient.import_from_peer(
            &fixture.request, &wire, || Ok(()),
        )).unwrap();
        let mut exact = fixture.request.clone();
        exact.request.limits.max_objects = retained.object_count;
        exact.request.limits.max_canonical_bytes = retained.canonical_bytes;
        // No state export is serialized, so this transfer-payload bound is
        // not the bound on the small, separately capped inspection receipt.
        exact.request.limits.max_wire_bytes = 1;
        let receipt = run(fixture.recipient.inspect_replica(&exact)).unwrap();
        assert_eq!(receipt.status, ConnectorStateInspectionStatus::Verified);
        let mut too_small = exact.clone();
        too_small.request.limits.max_objects -= 1;
        assert!(run(fixture.recipient.inspect_replica(&too_small)).is_err());
        too_small = exact;
        too_small.request.limits.max_canonical_bytes -= 1;
        assert!(run(fixture.recipient.inspect_replica(&too_small)).is_err());
        assert_eq!(fixture.recipient.runtime.active(), 0);
        assert_eq!(run(fixture.replica.read_root()).unwrap().unwrap().0, retained.root_object_id);
    }

    #[test]
    fn inspection_receipt_binds_request_status_schema_and_resource_counts() {
        let fixture = fixture();
        let valid = run(fixture.recipient.inspect_replica(&fixture.request)).unwrap();
        let original = serde_json::to_value(&valid).unwrap();
        for (pointer, replacement) in [
            ("/schema_version", serde_json::json!("other")),
            ("/request/peer_node", serde_json::json!("other-peer")),
            ("/request/request/grant_id", serde_json::json!("other-grant")),
            ("/request/request/root_object_id", serde_json::json!("f".repeat(64))),
            ("/request/request/scope/zone_id", serde_json::json!("z:private")),
            ("/request/request/limits/max_objects", serde_json::json!(15)),
            ("/status", serde_json::json!("verified")),
            ("/object_count", serde_json::json!(1)),
            ("/canonical_bytes", serde_json::json!(1)),
            ("/replica_only", serde_json::json!(false)),
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            let changed: ConnectorStateInspectionResponse = serde_json::from_value(changed).unwrap();
            assert!(changed.validate_for(&fixture.request).is_err(), "{pointer}");
        }
        let mut unexpected = original;
        unexpected["raw_state"] = serde_json::json!("private");
        assert!(serde_json::from_value::<ConnectorStateInspectionResponse>(unexpected).is_err());
    }

    #[test]
    fn inspection_command_cannot_be_decoded_as_a_mutating_pull() {
        let fixture = fixture();
        let inspection = ConnectorStateInspectionRequest { inspect: fixture.request };
        let wire = inspection.to_json().unwrap();
        assert_eq!(serde_json::from_str::<ConnectorStateInspectionRequest>(&wire).unwrap(), inspection);
        assert!(serde_json::from_str::<ConnectorStatePullRequest>(&wire).is_err());
        let mut changed = serde_json::to_value(&inspection).unwrap();
        changed["candidates"] = serde_json::json!([]);
        assert!(serde_json::from_value::<ConnectorStateInspectionRequest>(changed).is_err());
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

    #[test]
    fn complete_export_and_import_share_per_service_admission() {
        let fixture = fixture();
        let first = fixture.donor.runtime.admit("recipient", limits()).unwrap();
        let second = fixture.donor.runtime.admit("recipient", limits()).unwrap();
        assert!(matches!(
            run(fixture.donor.export_for_peer("recipient", &fixture.request.request, || Ok(()))),
            Err(HostError::Unavailable(_))
        ));
        assert_eq!(fixture.donor.runtime.active(), 2);
        // Grant failure takes precedence over capacity: unknown callers do not
        // learn whether an authorized peer is currently consuming its budget.
        assert!(matches!(
            run(fixture.donor.export_for_peer("unknown", &fixture.request.request, || Ok(()))),
            Err(HostError::PreflightFailed(_))
        ));
        drop(first);
        let wire = export(&fixture);
        assert_eq!(fixture.donor.runtime.active(), 1);
        drop(second);

        let first = fixture.recipient.runtime.admit("donor", limits()).unwrap();
        let second = fixture.recipient.runtime.admit("donor", limits()).unwrap();
        assert!(matches!(
            run(fixture.recipient.import_from_peer(&fixture.request, &wire, || Ok(()))),
            Err(HostError::Unavailable(_))
        ));
        assert!(run(fixture.replica.read_root()).unwrap().is_none());
        drop(first);
        assert!(run(fixture.recipient.import_from_peer(&fixture.request, &wire, || Ok(()))).is_ok());
        assert_eq!(fixture.recipient.runtime.active(), 1);
        drop(second);
        assert_eq!(fixture.recipient.runtime.active(), 0);
        assert_eq!(fixture.donor.runtime.active(), 0);
    }

    #[test]
    fn failed_import_releases_capacity_and_services_do_not_share_counters() {
        let fixture = fixture();
        let first = fixture.donor.runtime.admit("recipient", limits()).unwrap();
        let second = fixture.donor.runtime.admit("recipient", limits()).unwrap();
        for _ in 0..4 {
            assert!(run(fixture.recipient.import_from_peer(&fixture.request, "invalid", || Ok(()))).is_err());
            assert_eq!(fixture.recipient.runtime.active(), 0);
        }
        assert_eq!(fixture.donor.runtime.active(), 2);
        assert!(run(fixture.replica.read_root()).unwrap().is_none());
        drop((first, second));
    }

    fn large_fixture() -> Fixture {
        // Canonical CBOR: {"n": <60,000-byte text>}. A real signed state,
        // not fabricated export bytes, forces more than one wire page.
        let mut state = vec![0xa1, 0x61, b'n', 0x79, 0xea, 0x60];
        state.resize(state.len() + 60_000, b'x');
        fixture_with_state(state, ConnectorStateTransferLimits {
            max_objects: 16,
            max_canonical_bytes: 256 * 1024,
            max_wire_bytes: 1024 * 1024,
        })
    }

    fn first_page_request(request: &ConnectorStateExportRequest) -> String {
        serde_json::json!({
            "schema_version": "fcp.host.state-transfer-page.v1",
            "export": request,
            "offset": 0,
            "wire_digest": null,
        }).to_string()
    }

    #[test]
    fn paged_recovery_reuses_one_snapshot_and_one_import_reservation() {
        let fixture = large_fixture();
        let held = fixture.recipient.runtime.admit("donor", fixture.request.request.limits).unwrap();
        let pages = AtomicUsize::new(0);
        let result = run(fixture.recipient.pull_paged_from_peer(
            &fixture.request,
            |request_json| {
                let (donor, recipient, pages) = (&fixture.donor, &fixture.recipient, &pages);
                async move {
                    assert_eq!(recipient.runtime.active(), 2);
                    pages.fetch_add(1, Ordering::SeqCst);
                    donor.export_transfer_for_peer("recipient", &request_json, || Ok(())).await
                }
            },
            || Ok(()),
        )).unwrap();
        assert!(pages.load(Ordering::SeqCst) > 1);
        assert!(result.wire_bytes > 48 * 1024);
        assert!(result.replica_root_published);
        assert_eq!(result.root_object_id, fixture.request.request.root_object_id);
        assert_eq!(run(fixture.replica.read_root()).unwrap().unwrap().0, result.root_object_id);
        assert_eq!(fixture.donor.runtime.cache_builds_started(), 1);
        assert_eq!(fixture.donor.runtime.active(), 0);
        assert_eq!(fixture.recipient.runtime.active(), 1);
        drop(held);
        assert_eq!(fixture.recipient.runtime.active(), 0);
    }

    #[test]
    fn parallel_paged_recovery_preserves_authentication_and_one_import_reservation() {
        let mut fixture = large_fixture();
        fixture.recipient = fixture.recipient.with_page_concurrency(2).unwrap();
        let held = fixture.recipient.runtime.admit("donor", fixture.request.request.limits).unwrap();
        let pages = AtomicUsize::new(0);
        let result = run(fixture.recipient.pull_paged_from_peer(
            &fixture.request,
            |request_json| {
                let (donor, recipient, pages) = (&fixture.donor, &fixture.recipient, &pages);
                async move {
                    assert_eq!(recipient.runtime.active(), 2);
                    pages.fetch_add(1, Ordering::SeqCst);
                    donor.export_transfer_for_peer("recipient", &request_json, || Ok(())).await
                }
            },
            || Ok(()),
        )).unwrap();
        assert!(pages.load(Ordering::SeqCst) >= 3);
        assert!(result.replica_only);
        assert!(result.replica_root_published);
        assert_eq!(result.root_object_id, fixture.request.request.root_object_id);
        assert_eq!(run(fixture.replica.read_root()).unwrap().unwrap().0, result.root_object_id);
        assert_eq!(fixture.donor.runtime.cache_builds_started(), 1);
        assert_eq!(fixture.donor.runtime.active(), 0);
        assert_eq!(fixture.recipient.runtime.active(), 1);
        drop(held);
        assert_eq!(fixture.recipient.runtime.active(), 0);
    }

    #[test]
    fn parallel_paged_failure_never_imports_and_releases_the_assembly_reservation() {
        let mut fixture = large_fixture();
        fixture.recipient = fixture.recipient.with_page_concurrency(2).unwrap();
        let attempts = AtomicUsize::new(0);
        let result = run(fcp_async_core::time::timeout(
            std::time::Duration::from_secs(5),
            fixture.recipient.pull_paged_from_peer(
                &fixture.request,
                |request_json| {
                    let (donor, attempts) = (&fixture.donor, &attempts);
                    async move {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        let page: serde_json::Value = serde_json::from_str(&request_json).unwrap();
                        let offset = page["offset"].as_u64().unwrap();
                        if offset == 48 * 1024 {
                            std::future::pending::<()>().await;
                        }
                        if offset == 2 * 48 * 1024 {
                            return Err(HostError::Unavailable("fixture later page failed".to_owned()));
                        }
                        donor.export_transfer_for_peer("recipient", &request_json, || Ok(())).await
                    }
                },
                || Ok(()),
            ),
        ))
        .expect("later-page failure must cancel the hung sibling");
        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 3, "no implicit retry or later window");
        assert!(run(fixture.replica.read_root()).unwrap().is_none());
        assert_eq!(fixture.recipient.runtime.active(), 0);
        assert_eq!(fixture.donor.runtime.active(), 0);
    }

    #[test]
    fn parallel_pages_are_used_by_the_shared_multi_donor_download_boundary() {
        let mut fixture = large_fixture();
        fixture.recipient = fixture.recipient.with_page_concurrency(2).unwrap();
        let plan = crate::ConnectorStateRecoveryRequest {
            candidates: vec![fixture.request.clone()],
            attempt_timeout_ms: 5_000,
            total_timeout_ms: 10_000,
        };
        let pages = AtomicUsize::new(0);
        let result = run(fixture.recipient.recover_from_peers(
            &plan,
            |index, request_json| {
                assert_eq!(index, 0);
                let (donor, recipient, pages) = (&fixture.donor, &fixture.recipient, &pages);
                async move {
                    assert_eq!(recipient.runtime.active(), 1);
                    pages.fetch_add(1, Ordering::SeqCst);
                    donor.export_transfer_for_peer("recipient", &request_json, || Ok(())).await
                }
            },
            |_| Ok(()),
        )).unwrap();
        assert!(pages.load(Ordering::SeqCst) >= 3);
        assert_eq!(result.attempts.len(), 1);
        assert!(result.replica.replica_only);
        assert!(result.replica.replica_root_published);
        assert_eq!(result.replica.root_object_id, fixture.request.request.root_object_id);
        assert_eq!(fixture.recipient.runtime.active(), 0);
        assert_eq!(fixture.donor.runtime.active(), 0);
    }

    #[test]
    fn paged_capacity_refusal_precedes_fetch_and_preserves_the_replica() {
        let fixture = fixture();
        let first = fixture.recipient.runtime.admit("donor", limits()).unwrap();
        let second = fixture.recipient.runtime.admit("donor", limits()).unwrap();
        let result = run(fixture.recipient.pull_paged_from_peer(
            &fixture.request,
            |_| async { panic!("capacity refusal must precede network work") },
            || Ok(()),
        ));
        assert!(matches!(result, Err(HostError::Unavailable(_))));
        assert!(run(fixture.replica.read_root()).unwrap().is_none());
        assert_eq!(fixture.recipient.runtime.active(), 2);
        drop((first, second));
    }

    #[test]
    fn cancelling_a_paged_pull_releases_its_whole_assembly_reservation() {
        use std::future::Future;
        use std::task::{Context, Poll, Wake, Waker};
        struct Noop;
        impl Wake for Noop { fn wake(self: Arc<Self>) {} }
        let fixture = fixture();
        let mut future = Box::pin(fixture.recipient.pull_paged_from_peer(
            &fixture.request,
            |_| std::future::pending::<HostResult<String>>(),
            || Ok(()),
        ));
        let waker = Waker::from(Arc::new(Noop));
        assert!(matches!(future.as_mut().poll(&mut Context::from_waker(&waker)), Poll::Pending));
        assert_eq!(fixture.recipient.runtime.active(), 1);
        drop(future);
        assert_eq!(fixture.recipient.runtime.active(), 0);
        assert!(run(fixture.replica.read_root()).unwrap().is_none());
    }

    #[test]
    fn failed_continuation_does_not_import_or_retain_a_reservation() {
        let fixture = large_fixture();
        let attempts = AtomicUsize::new(0);
        let result = run(fixture.recipient.pull_paged_from_peer(
            &fixture.request,
            |request_json| {
                let (donor, attempts) = (&fixture.donor, &attempts);
                async move {
                    if attempts.fetch_add(1, Ordering::SeqCst) == 1 {
                        return Err(HostError::Unavailable("fixture continuation failed".to_owned()));
                    }
                    donor.export_transfer_for_peer("recipient", &request_json, || Ok(())).await
                }
            },
            || Ok(()),
        ));
        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 2, "no implicit retries");
        assert!(run(fixture.replica.read_root()).unwrap().is_none());
        assert_eq!(fixture.recipient.runtime.active(), 0);
        assert_eq!(fixture.donor.runtime.active(), 0);
        // A new caller-requested pull can reuse the immutable donor bytes;
        // the failed pull retained neither partial replica state nor authority.
        let result = run(fixture.recipient.pull_paged_from_peer(
            &fixture.request,
            |request_json| {
                let donor = &fixture.donor;
                async move { donor.export_transfer_for_peer("recipient", &request_json, || Ok(())).await }
            },
            || Ok(()),
        )).unwrap();
        assert!(result.replica_root_published);
        assert_eq!(fixture.donor.runtime.cache_builds_started(), 1);
    }

    #[test]
    fn cached_pages_still_require_current_peer_and_grant_authority() {
        let mut fixture = fixture();
        let request = first_page_request(&fixture.request.request);
        let first = run(fixture.donor.export_transfer_for_peer("recipient", &request, || Ok(()))).unwrap();
        let again = run(fixture.donor.export_transfer_for_peer("recipient", &request, || Ok(()))).unwrap();
        assert_eq!(first, again);
        assert_eq!(fixture.donor.runtime.cache_builds_started(), 1);
        // Rejection AFTER a cache hit must still prevent disclosure.
        let checks = AtomicUsize::new(0);
        assert!(run(fixture.donor.export_transfer_for_peer("recipient", &request, || {
            if checks.fetch_add(1, Ordering::SeqCst) == 0 { Ok(()) }
            else { Err(HostError::PreflightFailed("fixture peer revoked".to_owned())) }
        })).is_err());
        assert_eq!(checks.load(Ordering::SeqCst), 2);
        assert!(run(fixture.donor.export_transfer_for_peer("other-peer", &request, || Ok(()))).is_err());
        fixture.donor.grants.get_mut("restore-state").unwrap().expired.store(true, Ordering::Release);
        assert!(run(fixture.donor.export_transfer_for_peer("recipient", &request, || Ok(()))).is_err());
        assert_eq!(fixture.donor.runtime.cache_builds_started(), 1);
        assert_eq!(fixture.donor.runtime.active(), 0);
    }

    #[test]
    fn cached_export_never_satisfies_changed_limits_or_a_wrong_digest() {
        let fixture = large_fixture();
        let first = run(fixture.donor.export_transfer_for_peer(
            "recipient", &first_page_request(&fixture.request.request), || Ok(()),
        )).unwrap();
        let mut continuation: serde_json::Value = serde_json::from_str(&first).unwrap();
        continuation["request"]["offset"] = serde_json::json!(48 * 1024);
        let digest = continuation["wire_digest"].as_str().unwrap();
        continuation["request"]["wire_digest"] = serde_json::json!(
            if digest == "0".repeat(64) { "1".repeat(64) } else { "0".repeat(64) }
        );
        assert!(run(fixture.donor.export_transfer_for_peer(
            "recipient", &continuation["request"].to_string(), || Ok(()),
        )).is_err());
        let mut narrower = fixture.request.request.clone();
        narrower.limits.max_wire_bytes = 1;
        assert!(run(fixture.donor.export_transfer_for_peer(
            "recipient", &first_page_request(&narrower), || Ok(()),
        )).is_err());
        assert_eq!(fixture.donor.runtime.cache_builds_started(), 2);
        assert_eq!(fixture.donor.runtime.active(), 0);
        assert!(run(fixture.replica.read_root()).unwrap().is_none());
    }
}
