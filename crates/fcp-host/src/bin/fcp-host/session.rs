//! Native connector authority preparation for instance-bound capability tokens.
//!
//! This endpoint is a control-plane read/negotiation, NOT token issuance.
//! The ordinary invoke path continues to enforce signatures, policy, leases,
//! approval, revocation and admission independently.

use fcp_core::CapabilityId;
use super::*;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrepareSessionRequest {
    zone_id: ZoneId,
}

#[derive(Debug, Serialize)]
pub(super) struct PreparedSession {
    connector_id: ConnectorId,
    zone_id: ZoneId,
    instance_id: InstanceId,
    protocol_version: &'static str,
}

type HttpFailure = (StatusCode, String);

/// Request precisely the deduplicated capabilities declared by introspection.
/// A valid handshake is never a substitute for a signed invoke token.
pub(super) fn requested_capabilities(catalog: &Introspection) -> HostResult<Vec<CapabilityId>> {
    if catalog.operations.is_empty() {
        return Err(HostError::RegistryError(
            "connector declared no operations for handshake".into(),
        ));
    }
    let mut operations = BTreeMap::new();
    let mut capabilities = BTreeMap::new();
    for operation in &catalog.operations {
        if operations.insert(operation.id.as_str(), operation.capability.as_str()).is_some() {
            return Err(HostError::RegistryError(
                "connector declared duplicate operation IDs".into(),
            ));
        }
        capabilities.insert(operation.capability.as_str().to_owned(), operation.capability.clone());
    }
    Ok(capabilities.into_values().collect())
}

/// No grant may exceed the requested capabilities or claim an operation whose
/// catalog entry names another capability. A narrower grant is permitted.
pub(super) fn validate_negotiated_grants(
    request: &HandshakeRequest,
    response: &HandshakeResponse,
    catalog: &Introspection,
) -> HostResult<()> {
    if response.capabilities_granted.iter().any(|grant| {
        !request.capabilities_requested.contains(&grant.capability)
            || grant.operation.as_ref().is_some_and(|id| {
                !catalog.operations.iter().any(|operation| {
                    operation.id == *id && operation.capability == grant.capability
                })
            })
    }) {
        return Err(HostError::RegistryError(
            "connector returned unrequested capability grants".into(),
        ));
    }
    Ok(())
}

fn failure(status: StatusCode, message: &str) -> HttpFailure {
    (status, message.to_owned())
}

fn require_zone(allowed: &[String], zone: &ZoneId) -> Result<(), HttpFailure> {
    if !allowed.iter().any(|entry| entry == zone.as_str()) {
        return Err(failure(
            StatusCode::FORBIDDEN,
            "connector is not bound to the requested zone",
        ));
    }
    Ok(())
}

/// Accept only the typed, ready health of the actual negotiated process,
/// not an instance ID supplied by an API caller or guessed by the host.
fn prepared_from_health(
    connector_id: ConnectorId,
    zone_id: ZoneId,
    value: Value,
) -> Result<PreparedSession, HttpFailure> {
    let invalid = || failure(
        StatusCode::BAD_GATEWAY,
        "connector did not report a ready, authenticated native instance",
    );
    let snapshot: HealthSnapshot =
        serde_json::from_value(value.clone()).map_err(|_| invalid())?;
    if !snapshot.is_ready() {
        return Err(invalid());
    }
    let details = snapshot.details.as_ref().ok_or_else(invalid)?;
    if details.get("configured").and_then(Value::as_bool) != Some(true)
        || details.get("handshaken").and_then(Value::as_bool) != Some(true)
    {
        return Err(invalid());
    }
    let instance_id: InstanceId = serde_json::from_value(
        details.get("instance_id").cloned().ok_or_else(invalid)?,
    ).map_err(|_| invalid())?;
    if let Some(flat) = value.get("instance_id") {
        let flat: InstanceId = serde_json::from_value(flat.clone()).map_err(|_| invalid())?;
        if flat != instance_id {
            return Err(invalid());
        }
    }
    for field in ["configured", "handshaken"] {
        if value.get(field).is_some_and(|flag| flag.as_bool() != Some(true)) {
            return Err(invalid());
        }
    }
    Ok(PreparedSession {
        connector_id,
        zone_id,
        instance_id,
        protocol_version: "2.0",
    })
}

/// POST /rpc/admin/connectors/{connector_id}/session
///
/// Uses the on-demand native executor, not a warm-pool control process.
/// Instance identity is a snapshot, not a lease: reconfiguration or process
/// replacement can invalidate it before the issuer signs its token.
pub(super) async fn prepare_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<PrepareSessionRequest>,
) -> Result<(HeaderMap, Json<PreparedSession>), HttpFailure> {
    validate_admin_authorization(state.as_ref(), &headers).map_err(map_host_error)?;
    let connector_id = parse_connector_id(&connector_id)?;
    let connector = {
        let registry = state.registry.state.read().await;
        let entry = registry.connectors.get(&connector_id)
            .ok_or_else(|| failure(StatusCode::NOT_FOUND, "connector is not registered"))?;
        require_zone(&entry.config.allowed_zones, &request.zone_id)?;
        match &entry.connector {
            ConnectorRuntime::Native(native) => Arc::clone(native),
            _ => return Err(failure(
                StatusCode::CONFLICT,
                "on-demand native connector required; warm-pool and WASI sessions unsupported",
            )),
        }
    };
    if connector.capability_verifying_key.is_none() {
        return Err(failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "host capability verification is not configured",
        ));
    }
    // This holds the same connector session lock through handshake + health.
    // Failed or cancelled preparation cannot publish cached authority.
    let health = connector.rpc_in_handshaken_zone(
        &request.zone_id, "health", json!({}),
    ).await.map_err(|_| failure(
        StatusCode::BAD_GATEWAY,
        "connector session preparation failed; no instance authority was returned",
    ))?;
    let prepared = prepared_from_health(
        connector_id.clone(), request.zone_id.clone(), health,
    )?;
    // Ensure the process wasn't replaced during I/O. No registry lock is
    // held across subprocess I/O, and no snapshot can guarantee future life.
    {
        let registry = state.registry.state.read().await;
        let entry = registry.connectors.get(&connector_id)
            .ok_or_else(|| failure(
                StatusCode::CONFLICT, "connector changed during session preparation",
            ))?;
        require_zone(&entry.config.allowed_zones, &request.zone_id)?;
        if !matches!(&entry.connector, ConnectorRuntime::Native(current)
            if Arc::ptr_eq(current, &connector))
        {
            return Err(failure(
                StatusCode::CONFLICT, "connector changed during session preparation",
            ));
        }
    }
    let mut response_headers = HeaderMap::new();
    response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok((response_headers, Json(prepared)))
}

#[cfg(test)]
mod tests;
