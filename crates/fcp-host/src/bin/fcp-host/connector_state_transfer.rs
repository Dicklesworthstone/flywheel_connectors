//! Runtime wiring for explicitly granted, durable connector-state replicas.
//!
//! The configuration is operator-owned and loaded once at startup. Grants name
//! exact immutable roots; changing the authorized root or writer pins requires
//! a restart. Replicas remain separate from live connector execution state.

use std::io::Read;

use fcp_host::mesh_routing::MeshRouter;
use fcp_host::{
    ConnectorStateExportRequest, ConnectorStatePullRequest, ConnectorStatePullResponse,
    ConnectorStateReplicationService, ConnectorStateTransferDirection, ConnectorStateTransferGrant,
    ConnectorStateTransferScope, MAX_CONNECTOR_STATE_EXPORT_REQUEST_BYTES,
};
use fcp_store::{
    DurableObjectStore, DurableObjectStoreConfig, FcpStoreConnectorStateStore,
    KeyedObjectIdVerifier, ObjectStore,
};

use super::*;

pub(super) const CONFIG_FILE_ENV: &str = "FCP_HOST_CONNECTOR_STATE_TRANSFER_CONFIG_FILE";
pub(super) const PULL_REQUEST_MAX_BYTES: usize = MAX_CONNECTOR_STATE_EXPORT_REQUEST_BYTES + 1024;
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

pub(super) async fn pull_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
    Json(request): Json<ConnectorStatePullRequest>,
) -> Result<Json<ConnectorStatePullResponse>, (StatusCode, String)> {
    fcp_async_core::time::timeout(TRANSFER_TIMEOUT, pull(&state, &connector_id, request))
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
    let request_json = request.request.to_json().map_err(map_host_error)?;
    let reply = router.forward_connector_state_export(&peer, request_json).await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "authenticated state-transfer response unavailable; no replica publication was admitted".to_owned()))?;
    if reply.status != StatusCode::OK.as_u16() {
        return Err((
            StatusCode::BAD_GATEWAY,
            "donor refused the exact-root state transfer".to_owned(),
        ));
    }
    let response = service
        .import_from_peer(&request, &reply.body_json, || {
            router.check_state_transfer_peer(&peer).map_err(|_| {
                unavailable("state-transfer donor authority changed before publication")
            })
        })
        .await
        .map_err(map_host_error)?;
    Ok(response)
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
        let request = ConnectorStateExportRequest::from_json(request_json)?;
        let peer = router.state_transfer_origin(envelope).map_err(|_| {
            HostError::PreflightFailed(
                "state-transfer origin authority or transport is unavailable".to_owned(),
            )
        })?;
        service
            .export_for_peer(envelope.origin_node.as_str(), &request, || {
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
