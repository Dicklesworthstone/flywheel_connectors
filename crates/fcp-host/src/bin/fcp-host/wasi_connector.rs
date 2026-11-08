//! Retained, operation-isolated WASI sessions carrying actual FCP messages.
//!
//! Preparation obtains the guest's real instance identity. Invocations reuse
//! that exact guest; a signed token never creates or renames a guest instance.

use std::sync::atomic::{AtomicBool, Ordering};

use fcp_sandbox::{MAX_WASI_RPC_BYTES, WasiConnectorSession};
use futures_util::lock::Mutex as SessionMutex;
use serde::de::DeserializeOwned;

use super::*;

const MAX_RESIDENT_SESSIONS: usize = 8;
const CONTROL_BYTES: usize = 64 * 1024;

#[derive(Default)]
pub(super) struct WasiSessions {
    slots: StdMutex<BTreeMap<(String, String), Arc<SessionSlot>>>,
}

#[derive(Default)]
struct SessionSlot {
    guest: SessionMutex<Option<PreparedGuest>>,
    ready: Arc<AtomicBool>,
}

struct PreparedGuest {
    session: WasiConnectorSession,
    instance_id: InstanceId,
    ready: Arc<AtomicBool>,
}

pub(super) enum SessionRetirement {
    Absent,
    Retired(InstanceId),
    InstanceChanged,
}

impl Drop for PreparedGuest {
    fn drop(&mut self) {
        self.ready.store(false, Ordering::Release);
    }
}

fn unavailable(message: &str) -> HostError {
    HostError::PreflightFailed(message.to_owned())
}

fn protocol_failure() -> HostError {
    HostError::RegistryError(
        "WASI guest returned an invalid FCP response; prepare a new session".into(),
    )
}

fn encode<T: serde::Serialize>(value: &T) -> HostResult<Vec<u8>> {
    let bytes = fcp_cbor::to_canonical_cbor(value)
        .map_err(|_| unavailable("WASI request cannot be encoded as bounded canonical CBOR"))?;
    if bytes.len() > MAX_WASI_RPC_BYTES {
        return Err(unavailable(
            "WASI request exceeds the component transport limit",
        ));
    }
    Ok(bytes)
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> HostResult<T> {
    let mut input = bytes;
    let value: ciborium::Value = ciborium::de::from_reader_with_recursion_limit(
        &mut input,
        fcp_cbor::MAX_DESERIALIZATION_RECURSION_LIMIT,
    )
    .map_err(|_| protocol_failure())?;
    if !input.is_empty()
        || fcp_cbor::to_canonical_cbor(&value).map_err(|_| protocol_failure())? != bytes
    {
        return Err(protocol_failure());
    }
    value.deserialized().map_err(|_| protocol_failure())
}

async fn call<T: serde::Serialize, R: DeserializeOwned>(
    session: &mut WasiConnectorSession,
    method: &str,
    request: &T,
    limit: usize,
) -> HostResult<R> {
    let request = encode(request)?;
    let response = session
        .call(method, &request, limit.min(MAX_WASI_RPC_BYTES))
        .await
        .map_err(|_| {
            HostError::RegistryError(
                "WASI component call failed; prepare a new session before further work".into(),
            )
        })?;
    decode(&response)
}

impl WasiSessions {
    fn existing_slot(
        &self,
        zone: &ZoneId,
        operation: &OperationId,
    ) -> HostResult<Option<Arc<SessionSlot>>> {
        let slots = self
            .slots
            .lock()
            .map_err(|_| HostError::Internal("WASI session registry is unavailable".into()))?;
        Ok(slots
            .get(&(zone.to_string(), operation.to_string()))
            .map(Arc::clone))
    }

    fn slot(
        &self,
        zone: &ZoneId,
        operation: &OperationId,
        create: bool,
    ) -> HostResult<Arc<SessionSlot>> {
        let mut slots = self
            .slots
            .lock()
            .map_err(|_| HostError::Internal("WASI session registry is unavailable".into()))?;
        let key = (zone.to_string(), operation.to_string());
        if let Some(slot) = slots.get(&key) {
            return Ok(Arc::clone(slot));
        }
        if !create {
            return Err(unavailable(
                "WASI operation session is not prepared; prepare it before issuing an instance-bound token",
            ));
        }
        // Reclaim only empty retired slots with no owner or waiting caller.
        slots.retain(|_, slot| slot.ready.load(Ordering::Acquire) || Arc::strong_count(slot) != 1);
        if slots.len() >= MAX_RESIDENT_SESSIONS {
            return Err(unavailable(
                "WASI connector has reached its eight resident operation-session limit",
            ));
        }
        let slot = Arc::new(SessionSlot::default());
        slots.insert(key, Arc::clone(&slot));
        Ok(slot)
    }

    pub(super) fn has_ready_session(&self) -> bool {
        self.slots.lock().is_ok_and(|slots| {
            slots
                .values()
                .any(|slot| slot.ready.load(Ordering::Acquire))
        })
    }
}

impl WasiConnector {
    pub(super) async fn retire_session(
        &self,
        zone: &ZoneId,
        operation: &OperationId,
        expected_instance: &InstanceId,
        fence: &InventoryDispatchFence,
        deadline: Instant,
    ) -> HostResult<SessionRetirement> {
        self.operation_authority(zone, operation)?;
        let require_current = || {
            if Instant::now() >= deadline {
                return Err(HostError::Unavailable(
                    "WASI session retirement deadline expired before selection".into(),
                ));
            }
            fence.require_current()
        };
        let Some(slot) = self.sessions.existing_slot(zone, operation)? else {
            require_current()?;
            return Ok(SessionRetirement::Absent);
        };
        let mut held = slot.guest.lock().await;
        // Inventory and time may have changed while another call owned this
        // guest. Check before taking it, not after retirement has happened.
        require_current()?;
        let Some(guest) = held.as_ref() else {
            return Ok(SessionRetirement::Absent);
        };
        if &guest.instance_id != expected_instance {
            return Ok(SessionRetirement::InstanceChanged);
        }
        let instance_id = guest.instance_id.clone();
        // No awaited operation follows selection. Existing waiters keep this
        // exact slot; only normal unowned-empty reclamation may remove it.
        drop(held.take());
        Ok(SessionRetirement::Retired(instance_id))
    }

    pub(super) fn admitted_introspection(&self) -> HostResult<Introspection> {
        if self.manifest.source.is_none() || self.manifest.operation_authorities.is_empty() {
            return Err(unavailable(
                "WASI connector requires an admitted manifest operation catalog",
            ));
        }
        let operations = self
            .manifest
            .operation_authorities
            .iter()
            .map(|(id, operation)| {
                Ok(fcp_core::OperationInfo {
                    id: OperationId::new(id)
                        .map_err(|_| unavailable("WASI manifest operation ID is invalid"))?,
                    summary: operation.description.clone(),
                    description: Some(operation.description.clone()),
                    input_schema: operation.input_schema.clone(),
                    output_schema: operation.output_schema.clone(),
                    capability: operation.capability.clone(),
                    risk_level: operation.risk_level,
                    safety_tier: operation.safety_tier,
                    idempotency: operation.idempotency,
                    ai_hints: operation.ai_hints.clone(),
                    rate_limit: operation.rate_limit.clone(),
                    requires_approval: Some(operation.approval_mode),
                })
            })
            .collect::<HostResult<Vec<_>>>()?;
        Ok(Introspection {
            operations,
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: None,
        })
    }

    fn operation_authority(
        &self,
        zone: &ZoneId,
        operation: &OperationId,
    ) -> HostResult<&ManifestOperationAuthority> {
        if !self
            .config
            .allowed_zones
            .iter()
            .any(|allowed| allowed == zone.as_str())
        {
            return Err(unavailable(
                "WASI connector is not admitted to the requested zone",
            ));
        }
        if (!self.config.allowed_operations.is_empty() || self.config.enforce_empty_allow_lists)
            && !self
                .config
                .allowed_operations
                .iter()
                .any(|allowed| allowed == operation.as_str())
        {
            return Err(unavailable(
                "WASI connector is not admitted for the requested operation",
            ));
        }
        self.manifest
            .operation_authority(&self.summary.id, operation.as_str())?
            .ok_or_else(|| unavailable("WASI connector requires an admitted manifest"))
    }

    /// Only the explicit admin preparation path may instantiate a guest.
    pub(super) async fn prepare_session(
        &self,
        zone: &ZoneId,
        operation: &OperationId,
    ) -> HostResult<session::PreparedSession> {
        let authority = self.operation_authority(zone, operation)?;
        let host_public_key = self
            .capability_verifying_key
            .ok_or_else(|| unavailable("host capability verification is not configured"))?;
        self.state_policy.require_admitted_manifest(&self.config)?;
        let slot = self.sessions.slot(zone, operation, true)?;
        let mut held = slot.guest.lock().await;
        // Taking before awaited guest work ensures cancellation cannot restore
        // an instance whose state or canonical return area is uncertain.
        let mut guest = if let Some(guest) = held.take() {
            guest
        } else {
            let (runner, _) = self.runner_for_operation(operation, "", zone)?;
            let bytes = self.component_bytes(operation)?;
            let validated = runner.load_and_validate(bytes.as_ref()).map_err(|_| {
                unavailable("WASI component cannot be loaded for session preparation")
            })?;
            let mut runtime = runner
                .instantiate_session(&validated.component)
                .await
                .map_err(|_| {
                    unavailable("WASI component does not provide the required FCP dispatch ABI")
                })?;
            let _: Value = call(
                &mut runtime,
                "configure",
                &self.config.config.clone().unwrap_or_else(|| json!({})),
                CONTROL_BYTES,
            )
            .await?;
            let nonce = *blake3::hash(RequestId::random().0.as_bytes()).as_bytes();
            let request = HandshakeRequest {
                protocol_version: "2.0.0".into(),
                zone: zone.clone(),
                zone_dir: None,
                host_public_key,
                nonce,
                capabilities_requested: vec![authority.capability.clone()],
                host: None,
                transport_caps: None,
                requested_instance_id: None,
            };
            let response: HandshakeResponse =
                call(&mut runtime, "handshake", &request, CONTROL_BYTES).await?;
            let catalog = self.admitted_introspection()?;
            session::validate_negotiated_grants(&request, &response, &catalog)?;
            if response.status != "accepted"
                || response.nonce != nonce
                || !response.capabilities_granted.iter().any(|grant| {
                    grant.capability == authority.capability
                        && grant
                            .operation
                            .as_ref()
                            .is_none_or(|granted| granted == operation)
                })
            {
                return Err(protocol_failure());
            }
            let health: Value = call(&mut runtime, "health", &json!({}), CONTROL_BYTES).await?;
            let prepared =
                session::prepared_from_health(self.summary.id.clone(), zone.clone(), health)
                    .map_err(|_| protocol_failure())?;
            PreparedGuest {
                session: runtime,
                instance_id: prepared.instance_id,
                ready: Arc::clone(&slot.ready),
            }
        };
        let health: Value = call(&mut guest.session, "health", &json!({}), CONTROL_BYTES).await?;
        let mut prepared =
            session::prepared_from_health(self.summary.id.clone(), zone.clone(), health)
                .map_err(|_| protocol_failure())?;
        if prepared.instance_id != guest.instance_id {
            return Err(protocol_failure());
        }
        prepared.operation_id = Some(operation.clone());
        slot.ready.store(true, Ordering::Release);
        *held = Some(guest);
        Ok(prepared)
    }

    fn verify_instance(
        &self,
        connector: &ConnectorId,
        zone: &ZoneId,
        operation: &OperationId,
        input: &Value,
        token: &fcp_core::CapabilityToken,
        instance: &InstanceId,
    ) -> HostResult<()> {
        if connector != &self.summary.id {
            return Err(unavailable("WASI invocation targets another connector"));
        }
        let operation_authority = self.operation_authority(zone, operation)?;
        let key = self
            .capability_verifying_key
            .ok_or_else(|| unavailable("host capability verification is not configured"))?;
        // The ordinary gateway checks are intentionally unbound. This is the
        // actual selected guest boundary: enforce the original signed binding.
        let resources = live_constraint_resource_uri(input)
            .into_iter()
            .collect::<Vec<_>>();
        CapabilityVerifier::new(key, zone.clone(), instance.clone())
            .verify_bound(
                token.clone(),
                &operation_authority.capability,
                operation,
                &resources,
            )
            .map_err(|_| unavailable("capability does not authorize the prepared WASI instance"))?;
        Ok(())
    }

    pub(super) async fn invoke_prepared(
        &self,
        request: InvokeRequest,
        inventory_fence: Option<&InventoryDispatchFence>,
        deployment_guard: Option<&deployment_evidence::DeploymentDispatchGuard>,
        authority_guard: Option<&live_authority::LiveAuthorityDispatchGuard>,
    ) -> HostResult<InvokeResponse> {
        let result = self
            .invoke_prepared_inner(request, inventory_fence, deployment_guard, authority_guard)
            .await;
        if result.is_err()
            && let Some(guard) = authority_guard
        {
            // The shared effect marker still wins if guest execution began.
            guard.record_dispatch_refusal();
        }
        result
    }

    async fn invoke_prepared_inner(
        &self,
        request: InvokeRequest,
        inventory_fence: Option<&InventoryDispatchFence>,
        deployment_guard: Option<&deployment_evidence::DeploymentDispatchGuard>,
        authority_guard: Option<&live_authority::LiveAuthorityDispatchGuard>,
    ) -> HostResult<InvokeResponse> {
        let slot = self
            .sessions
            .slot(&request.zone_id, &request.operation, false)?;
        let mut held = slot.guest.lock().await;
        let guest = held.as_ref().ok_or_else(|| {
            unavailable("WASI operation session was retired; prepare a new instance")
        })?;
        self.verify_instance(
            &request.connector_id,
            &request.zone_id,
            &request.operation,
            &request.input,
            &request.capability_token,
            &guest.instance_id,
        )?;
        let payload = encode(&request)?;
        let response_limit = native_rpc_response_limits(&self.config, &self.manifest)
            .for_request("invoke", Some(request.operation.as_str()))
            .min(MAX_WASI_RPC_BYTES);
        // The session mutex wait may outlive admission. Refresh after waiting,
        // immediately before executing this guest's actual operation.
        let deployment = deployment_guard
            .map(deployment_evidence::DeploymentDispatchGuard::refresh)
            .transpose()?;
        let authority = authority_guard
            .map(live_authority::LiveAuthorityDispatchGuard::refresh)
            .transpose()?;
        if let Some(fence) = inventory_fence {
            fence.require_current()?;
        }
        if let Some(permit) = deployment {
            permit.require_current()?;
        }
        if let Some(permit) = authority {
            permit.require_current()?;
        }
        let mut guest = held
            .take()
            .expect("prepared guest was checked under the session lock");
        if let Some(guard) = authority_guard {
            guard.mark_effect_started();
        }
        let bytes = guest.session.call("invoke", &payload, response_limit).await
            .map_err(|_| HostError::RegistryError("WASI invocation failed; its outcome may be unknown and its session was retired".into()))?;
        let response: InvokeResponse = decode(&bytes)?;
        if response.r#type != "response"
            || response.id != request.id
            || match response.status {
                fcp_kernel::InvokeStatus::Ok => {
                    response.result.is_none() || response.error.is_some()
                }
                fcp_kernel::InvokeStatus::Error => {
                    response.error.is_none() || response.result.is_some()
                }
            }
        {
            return Err(protocol_failure());
        }
        *held = Some(guest);
        Ok(response)
    }
}

#[cfg(test)]
#[path = "wasi_connector/tests.rs"]
mod tests;

#[cfg(test)]
pub(super) fn write_test_fixture(
    directory: &StdPath,
    connector_id: &'static str,
) -> ConnectorConfig {
    tests::write_fixture(directory, connector_id)
}
