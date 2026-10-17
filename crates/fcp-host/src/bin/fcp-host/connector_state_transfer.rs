//! Runtime wiring for explicitly granted, durable connector-state replicas.
//!
//! The configuration is operator-owned and loaded once at startup. Grants name
//! exact immutable roots; changing the authorized root or writer pins requires
//! a restart. Replicas remain separate from live connector execution state.
//! Pulls use bounded, independently authenticated pages under one total deadline;
//! the complete export is validated before any replica import is admitted.
//! The protected pull route also accepts ordered multi-donor recovery plans.
//! Each donor needs its own exact-root grant and a pinned transport incarnation.
//! Only downloads can fail over; import attempts are never retried.

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(test)]
use fcp_host::ConnectorStateExportRequest;
use fcp_host::mesh_routing::MeshRouter;
use fcp_host::{
    ConnectorStatePullRequest, ConnectorStatePullResponse, ConnectorStateRecoveryRequest,
    ConnectorStateRecoveryResponse, ConnectorStateReplicationService,
    ConnectorStateTransferDirection, ConnectorStateTransferGrant, ConnectorStateTransferScope,
    MAX_CONNECTOR_STATE_RECOVERY_REQUEST_BYTES,
};
use fcp_store::{
    DurableObjectStore, DurableObjectStoreConfig, FcpStoreConnectorStateStore,
    KeyedObjectIdVerifier, ObjectStore,
};

use super::*;

pub(super) const CONFIG_FILE_ENV: &str = "FCP_HOST_CONNECTOR_STATE_TRANSFER_CONFIG_FILE";
pub(super) const PULL_REQUEST_MAX_BYTES: usize = MAX_CONNECTOR_STATE_RECOVERY_REQUEST_BYTES;
const MAX_CONFIG_BYTES: u64 = 2 * 1024 * 1024;
const REPLICA_NAMESPACE: &str = "connector-state-replicas-v1";
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(60);

#[cfg(test)]
#[path = "connector_state_transfer_tests.rs"]
mod tests;

// Deliberately not Debug: this configuration contains zone key material.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferConfig {
    /// Dedicated parent for the host-owned replica namespace, never peer input.
    replica_root: Option<PathBuf>,
    stores: Vec<TransferStoreConfig>,
    grants: Vec<ConnectorStateTransferGrant>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferStoreConfig {
    scope: ConnectorStateTransferScope,
    object_id_key_hex: String,
    trusted_writer_keys_hex: Vec<String>,
    /// Existing canonical objects observed through a read-only snapshot.
    source_objects_dir: Option<PathBuf>,
    /// Optional MAC key matching the source's durable envelope format.
    source_mac_key_hex: Option<String>,
    #[serde(default)]
    retain_replica: bool,
    /// Write quota for the retained store; source recovery has its own bounds.
    max_store_bytes: u64,
}

fn invalid(message: &str) -> HostError {
    HostError::InvalidFilter(message.to_owned())
}

fn unavailable(message: &str) -> HostError {
    HostError::Unavailable(message.to_owned())
}

fn parse_key(value: &str) -> HostResult<[u8; 32]> {
    let mut key = [0u8; 32];
    hex::decode_to_slice(value, &mut key)
        .map_err(|_| invalid("state-transfer keys must contain exactly 64 hexadecimal digits"))?;
    Ok(key)
}

fn require_private_ingress(bind: &BindTarget) -> HostResult<()> {
    let private = match bind {
        BindTarget::Tcp(address) => address.ip().is_loopback(),
        #[cfg(unix)]
        BindTarget::Unix(_) => true,
    };
    if private {
        Ok(())
    } else {
        Err(invalid(
            "connector-state transfer requires a loopback or Unix-socket host listener behind a confidential ingress; remote peer URLs must use HTTPS",
        ))
    }
}

fn replica_objects_dir(root: &StdPath, scope: &ConnectorStateTransferScope) -> HostResult<PathBuf> {
    if !root.is_absolute() {
        return Err(invalid(
            "state-transfer replica_root must be an absolute path",
        ));
    }
    let scope_bytes = to_deterministic_cbor(scope)
        .map_err(|_| invalid("state-transfer scope cannot be encoded"))?;
    let digest = blake3::hash(&scope_bytes).to_hex();
    Ok(root
        .join(REPLICA_NAMESPACE)
        .join(digest.as_str())
        .join("objects"))
}

fn adapter(
    objects: Arc<dyn ObjectStore>,
    key: ObjectIdKey,
    scope: &ConnectorStateTransferScope,
    writers: &[[u8; 32]],
) -> Arc<FcpStoreConnectorStateStore> {
    let mut store = FcpStoreConnectorStateStore::new(
        objects,
        key,
        scope.connector_id.clone(),
        scope.zone_id.clone(),
    )
    .with_trusted_writer_keys(writers.iter().copied());
    if let Some(instance) = &scope.instance_id {
        store = store.with_instance_id(instance.clone());
    }
    Arc::new(store)
}

fn open_service(
    config: TransferConfig,
    bind: &BindTarget,
) -> HostResult<ConnectorStateReplicationService> {
    require_private_ingress(bind)?;
    if config.stores.is_empty() || config.stores.len() > 256 || config.grants.len() > 1024 {
        return Err(invalid(
            "state-transfer configuration has an invalid store or grant count",
        ));
    }
    let mut service = ConnectorStateReplicationService::new();
    for configured in config.stores {
        if configured.max_store_bytes == 0
            || configured.trusted_writer_keys_hex.is_empty()
            || configured.trusted_writer_keys_hex.len() > 64
            || (configured.source_objects_dir.is_none() && !configured.retain_replica)
        {
            return Err(invalid(
                "state-transfer store needs a source or replica, a nonzero quota, and 1..64 pinned writers",
            ));
        }
        let key = ObjectIdKey::from_bytes(parse_key(&configured.object_id_key_hex)?);
        let writers: Vec<[u8; 32]> = configured
            .trusted_writer_keys_hex
            .iter()
            .map(|value| parse_key(value))
            .collect::<HostResult<_>>()?;
        for writer in &writers {
            Ed25519VerifyingKey::from_bytes(writer).map_err(|_| {
                invalid("state-transfer writer pin is not an Ed25519 verifying key")
            })?;
        }

        let mut source = None;
        if let Some(path) = &configured.source_objects_dir {
            if !path.is_absolute() {
                return Err(invalid(
                    "state-transfer source_objects_dir must be an absolute path",
                ));
            }
            let mut durable = DurableObjectStoreConfig::new(path);
            durable.max_bytes = configured.max_store_bytes;
            durable.mac_key = configured
                .source_mac_key_hex
                .as_deref()
                .map(parse_key)
                .transpose()?;
            // A source may contain several zones. The state adapter verifies
            // keyed IDs and writer pins for the requested scope during export.
            // Never acquire another writer or repair a live connector's WAL.
            let objects = DurableObjectStore::open_read_only(durable)
                .map_err(|_| unavailable("state-transfer source snapshot could not be opened"))?;
            source = Some(adapter(Arc::new(objects), key, &configured.scope, &writers));
        } else if configured.source_mac_key_hex.is_some() {
            return Err(invalid("a source MAC key requires source_objects_dir"));
        }

        if configured.retain_replica {
            let root = config
                .replica_root
                .as_deref()
                .ok_or_else(|| invalid("retained state needs an explicit replica_root"))?;
            let path = replica_objects_dir(root, &configured.scope)?;
            let mut durable = DurableObjectStoreConfig::new(path);
            durable.max_bytes = configured.max_store_bytes;
            // The namespace is new and host-owned; all its durable records use
            // authenticated envelopes from the first write, including recovery.
            durable.mac_key = Some(blake3::derive_key(
                "fcp.host.connector-state-replica.wal.v1",
                key.as_bytes(),
            ));
            let verifier = KeyedObjectIdVerifier::new(HashMap::from([(
                configured.scope.zone_id.clone(),
                key,
            )]))
            .into_arc();
            let objects = DurableObjectStore::open_with_verifier(durable, Some(verifier))
                .map_err(|_| unavailable("state-transfer replica store could not acquire durable ownership or recover"))?;
            let replica = adapter(Arc::new(objects), key, &configured.scope, &writers);
            service.register_store(
                ConnectorStateTransferDirection::Import,
                configured.scope.clone(),
                Arc::clone(&replica),
            )?;
            // A retained replica can be an explicitly granted donor too. Reuse
            // its exact backing Arc, append lock and cache-invalidation bus.
            if source.is_none() {
                source = Some(replica);
            }
        }
        if let Some(source) = source {
            service.register_store(
                ConnectorStateTransferDirection::Export,
                configured.scope,
                source,
            )?;
        }
    }
    for grant in config.grants {
        service.add_grant(grant)?;
    }
    Ok(service)
}

pub(super) fn from_env(
    bind: &BindTarget,
    mesh: Option<&MeshRouter>,
) -> HostResult<Option<Arc<ConnectorStateReplicationService>>> {
    let Some(path) = read_optional_trimmed_env_string(CONFIG_FILE_ENV)? else {
        return Ok(None);
    };
    if mesh.is_none() {
        return Err(invalid(
            "connector-state transfer configuration requires mesh routing",
        ));
    }
    // Check before any source read or replica-directory creation.
    require_private_ingress(bind)?;
    let file = std::fs::File::open(path)
        .map_err(|_| invalid("state-transfer configuration file could not be opened"))?;
    if !file
        .metadata()
        .map_err(|_| invalid("state-transfer configuration metadata is unavailable"))?
        .is_file()
    {
        return Err(invalid(
            "state-transfer configuration must be a regular file",
        ));
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid("state-transfer configuration file could not be read"))?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(invalid("state-transfer configuration exceeds 2 MiB"));
    }
    let config: TransferConfig = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("state-transfer configuration is malformed"))?;
    open_service(config, bind).map(|service| Some(Arc::new(service)))
}

// The constituent request structs deny unknown fields, so a malformed recovery
// cannot silently become a single-donor pull by dropping authority fields.
#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum StatePullCommand {
    Single(Box<ConnectorStatePullRequest>),
    Recovery(ConnectorStateRecoveryRequest),
}

#[derive(Serialize)]
#[serde(untagged)]
pub(super) enum StatePullResponse {
    Single(ConnectorStatePullResponse),
    Recovery(ConnectorStateRecoveryResponse),
}

pub(super) async fn pull_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
    Json(request): Json<StatePullCommand>,
) -> Result<Json<StatePullResponse>, (StatusCode, String)> {
    let operation = async {
        match request {
            StatePullCommand::Single(request) => pull(&state, &connector_id, *request)
                .await
                .map(StatePullResponse::Single),
            StatePullCommand::Recovery(request) => recover(&state, &connector_id, request)
                .await
                .map(StatePullResponse::Recovery),
        }
    };
    fcp_async_core::time::timeout(TRANSFER_TIMEOUT, operation)
        .await
        .map_err(|_| {
            (
                StatusCode::GATEWAY_TIMEOUT,
                "state-transfer deadline elapsed; an admitted durable write may still complete"
                    .to_owned(),
            )
        })?
        .map(Json)
}

async fn pull(
    state: &AppState,
    connector_id: &str,
    request: ConnectorStatePullRequest,
) -> Result<ConnectorStatePullResponse, (StatusCode, String)> {
    let connector = parse_connector_id(connector_id)?;
    if connector != request.request.scope.connector_id {
        return Err((
            StatusCode::BAD_REQUEST,
            "state-transfer path and scope differ".to_owned(),
        ));
    }
    let service = state.connector_state_replication.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "connector-state transfer is not configured".to_owned(),
        )
    })?;
    let router = state.mesh.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "mesh routing is unavailable".to_owned(),
        )
    })?;
    // Exact local grant admission comes before resolving or contacting a donor.
    // No connector process need be installed for this replica-only operation.
    service.validate_pull(&request).map_err(map_host_error)?;
    let peer_node = TailscaleNodeId::try_new(&request.peer_node).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "state-transfer donor id is invalid".to_owned(),
        )
    })?;
    let peer = router.state_transfer_peer(&peer_node).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "state-transfer donor authority or transport is unavailable".to_owned(),
        )
    })?;
    // Keep the same authority snapshot for every page. Resolving the peer again
    // could silently authorize a removal/re-addition or key rotation mid-pull.
    let pinned_peer = &peer;
    let donor_failed = AtomicBool::new(false);
    let failure = &donor_failed;
    let response = service
        .pull_paged_from_peer(
            &request,
            |request_json| async move {
                // MeshRouter signs a fresh nonce and verifies the corresponding
                // signed reply on every call. Never retry or switch donors here.
                let reply = router
                    .forward_connector_state_export(pinned_peer, request_json)
                    .await
                    .map_err(|_| {
                        failure.store(true, Ordering::Relaxed);
                        unavailable("authenticated state-transfer page unavailable")
                    })?;
                if reply.status != StatusCode::OK.as_u16() {
                    failure.store(true, Ordering::Relaxed);
                    return Err(unavailable("donor refused the exact-root state-transfer page"));
                }
                Ok(reply.body_json)
            },
            || {
                router.check_state_transfer_peer(pinned_peer).map_err(|_| {
                    unavailable("state-transfer donor authority changed before publication")
                })
            },
        )
        .await
        .map_err(|error| {
            if donor_failed.load(Ordering::Relaxed) {
                // Preserve the admin API's upstream-failure status without
                // trusting or exposing a donor-controlled error body.
                (
                    StatusCode::BAD_GATEWAY,
                    "donor could not supply an authenticated state-transfer page; no replica publication was admitted"
                        .to_owned(),
                )
            } else {
                map_host_error(error)
            }
        })?;
    Ok(response)
}

async fn recover(
    state: &AppState,
    connector_id: &str,
    request: ConnectorStateRecoveryRequest,
) -> Result<ConnectorStateRecoveryResponse, (StatusCode, String)> {
    request.validate().map_err(map_host_error)?;
    let connector = parse_connector_id(connector_id)?;
    if connector != request.candidates[0].request.scope.connector_id {
        return Err((
            StatusCode::BAD_REQUEST,
            "state-recovery path and scope differ".to_owned(),
        ));
    }
    let service = state.connector_state_replication.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "connector-state transfer is not configured".to_owned(),
        )
    })?;
    let router = state.mesh.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "mesh routing is unavailable".to_owned(),
        )
    })?;
    // Reject the whole plan if any local grant is absent or mismatched. Do not
    // resolve a donor, start I/O, or partially execute a malformed plan first.
    service
        .validate_recovery(&request)
        .map_err(map_host_error)?;
    let peers: Vec<_> = request
        .candidates
        .iter()
        .map(|candidate| {
            candidate
                .peer_node
                .parse::<TailscaleNodeId>()
                .ok()
                .and_then(|node| router.state_transfer_peer(&node).ok())
        })
        .collect();
    // Pin each incarnation ONCE for the whole operation. An unavailable peer
    // stays unavailable; removal/re-addition cannot resurrect an old candidate.
    // A valid different candidate may still satisfy its own independent grant.
    let pinned = &peers;
    service
        .recover_from_peers(
            &request,
            |index, request_json| async move {
                let peer = pinned[index].as_ref().ok_or_else(|| {
                    unavailable(
                        "state-recovery donor authority or confidential transport unavailable",
                    )
                })?;
                let reply = router
                    .forward_connector_state_export(peer, request_json)
                    .await
                    .map_err(|_| unavailable("authenticated state-recovery page unavailable"))?;
                if reply.status != StatusCode::OK.as_u16() {
                    return Err(unavailable(
                        "donor refused the exact-root state-recovery page",
                    ));
                }
                Ok(reply.body_json)
            },
            |index| {
                let peer = pinned[index].as_ref().ok_or_else(|| {
                    unavailable(
                        "state-recovery donor authority or confidential transport unavailable",
                    )
                })?;
                router.check_state_transfer_peer(peer).map_err(|_| {
                    unavailable("state-recovery donor authority changed before publication")
                })
            },
        )
        .await
        .map_err(map_host_error)
}

/// The mesh handler has already verified the signature and consumed the nonce.
pub(super) async fn export_reply(
    state: &AppState,
    router: &MeshRouter,
    envelope: &fcp_mesh::invoke_route::MeshForwardEnvelope,
    request_json: &str,
) -> (u16, String) {
    let result = fcp_async_core::time::timeout(TRANSFER_TIMEOUT, async {
        let service = state
            .connector_state_replication
            .as_ref()
            .ok_or_else(|| unavailable("connector-state export is not configured"))?;
        let peer = router.state_transfer_origin(envelope).map_err(|_| {
            HostError::PreflightFailed(
                "state-transfer origin authority or transport is unavailable".to_owned(),
            )
        })?;
        service
            .export_transfer_for_peer(envelope.origin_node.as_str(), request_json, || {
                router.check_state_transfer_peer(&peer).map_err(|_| {
                    unavailable("state-transfer origin authority changed before disclosure")
                })
            })
            .await
    })
    .await
    .unwrap_or_else(|_| Err(unavailable("connector-state export deadline elapsed")));
    match result {
        Ok(wire) => (StatusCode::OK.as_u16(), wire),
        Err(error) => mesh_reply_body::<()>(Err(map_host_error(error))),
    }
}
