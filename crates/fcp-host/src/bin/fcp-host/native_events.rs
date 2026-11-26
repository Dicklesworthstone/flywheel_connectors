//! Authorized, durable consumer delivery for continuously demultiplexed native events.
//!
//! The HTTP boundary never treats a stream identifier as authority. Each call
//! verifies a fresh signed capability against the host-pinned event declaration,
//! zone policy, revocations, and the retained consumer identity. Provider credit
//! is released only after the consumer decision has reached durable storage.

use super::*;
use fcp_core::{CapabilityId, EventAck, SubscribeResponse, TailscaleNodeId};
use fcp_host::{NativeEventAdmission, NativeEventBinding, NativeEventJournal};

const JOURNAL_ENV: &str = "FCP_HOST_EVENT_JOURNAL_FILE";
const JOURNAL_MAX_BYTES_ENV: &str = "FCP_HOST_EVENT_JOURNAL_MAX_BYTES";
const REQUEST_BYTES: usize = fcp_mesh::invoke_route::MAX_MESH_STREAM_BODY_BYTES;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

#[path = "native_event_mesh.rs"]
mod mesh;

#[cfg(all(test, unix))]
#[path = "native_events_tests.rs"]
mod tests;

/// No Debug implementation: request bodies carry bearer capabilities.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamAuthority {
    request_id: String,
    connector_id: ConnectorId,
    zone_id: ZoneId,
    topic: String,
    capability_token: fcp_core::CapabilityToken,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    holder_proof: Option<fcp_core::HolderProof>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenRequest {
    auth: StreamAuthority,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    executor_node: Option<TailscaleNodeId>,
    #[serde(default)]
    stream_id: Option<String>,
    #[serde(default = "default_window")]
    window_size: u32,
}

const fn default_window() -> u32 {
    1
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PollRequest {
    auth: StreamAuthority,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    executor_node: Option<TailscaleNodeId>,
    stream_id: String,
    #[serde(default = "default_limit")]
    limit: usize,
}

const fn default_limit() -> usize {
    1
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AckRequest {
    auth: StreamAuthority,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    executor_node: Option<TailscaleNodeId>,
    stream_id: String,
    ack: EventAck,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloseRequest {
    auth: StreamAuthority,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    executor_node: Option<TailscaleNodeId>,
    stream_id: String,
}

struct Admission {
    binding: NativeEventBinding,
    connector: Arc<SubprocessConnector>,
    resource_uri: String,
    operation: OperationId,
    capability: CapabilityId,
    enforce_operation_network_constraints: bool,
    generation: u64,
    authority: live_authority::LiveAuthorityDispatchGuard,
    /// The exact control input used by policy and executor-local quota admission.
    /// Never persist or log this request: it retains the original bearer token.
    metered_request: InvokeRequest,
}

struct Attachment {
    stream_id: String,
    connector: Arc<SubprocessConnector>,
    transport: native_stream::NativeEventTransport,
    accepting: Arc<AtomicBool>,
    authority: Arc<std::sync::Mutex<live_authority::LiveAuthorityDispatchGuard>>,
    _ack_relay: JoinHandle<()>,
}

impl Drop for Attachment {
    fn drop(&mut self) {
        self.accepting.store(false, Ordering::Release);
    }
}

pub(super) struct EventService {
    journal: Option<Arc<NativeEventJournal>>,
    attachments: futures_util::lock::Mutex<HashMap<ConnectorId, Attachment>>,
}

fn invalid(message: &str) -> HostError {
    HostError::InvalidFilter(message.to_owned())
}

fn denied(message: &str) -> HostError {
    HostError::PreflightFailed(message.to_owned())
}

fn unavailable(message: &str) -> HostError {
    HostError::Unavailable(message.to_owned())
}

fn validate_ack_control(auth: &StreamAuthority, ack: &EventAck) -> HostResult<()> {
    if ack.r#type != "ack"
        || ack.seqs.is_empty()
        || ack.seqs.len() > fcp_host::NATIVE_EVENT_MAX_WINDOW as usize
        || ack.seqs.len() != ack.cursors.len()
    {
        return Err(invalid(
            "acknowledgement requires 1 to 64 exact sequence/cursor pairs",
        ));
    }
    if ack.topic != auth.topic {
        return Err(denied(
            "acknowledgement topic differs from the authorized topic",
        ));
    }
    let mut cursors = HashSet::new();
    for cursor in &ack.cursors {
        // Keep the journal's identifier bound at this pre-debit boundary too.
        if cursor.is_empty()
            || cursor.len() > 1024
            || cursor.chars().any(char::is_control)
            || cursor.trim() != cursor
            || !cursors.insert(cursor)
        {
            return Err(invalid("invalid or duplicate acknowledgement cursor"));
        }
    }
    Ok(())
}

/// Open custody before any connector starts, so a second writer cannot race it.
pub(super) fn open_journal() -> HostResult<Option<Arc<NativeEventJournal>>> {
    let path = if let Some(value) = read_optional_trimmed_env_string(JOURNAL_ENV)? {
        Some(PathBuf::from(value))
    } else {
        HostAdminStateStore::persistence_path_from_env()?.map(|path| {
            let mut name = path.as_os_str().to_os_string();
            name.push(".events.json");
            PathBuf::from(name)
        })
    };
    let max_database_bytes = read_optional_trimmed_env_string(JOURNAL_MAX_BYTES_ENV)?
        .map(|value| {
            value.parse::<u64>().map_err(|_| {
                invalid("FCP_HOST_EVENT_JOURNAL_MAX_BYTES must be an unsigned byte count")
            })
        })
        .transpose()?;
    path.map(|path| {
        match max_database_bytes {
            Some(bytes) => NativeEventJournal::open_with_max_database_bytes(path, bytes),
            None => NativeEventJournal::open(path),
        }
        .map(Arc::new)
    })
    .transpose()
}

pub(super) fn routes(host: Arc<AppState>) -> Router<Arc<AppState>> {
    routes_with_intakes(
        host,
        mesh_forward_intake::Intake::for_rpc(REQUEST_BYTES),
        mesh_forward_intake::Intake::for_rpc(REQUEST_BYTES),
    )
}

fn routes_with_intakes(
    host: Arc<AppState>,
    work: mesh_forward_intake::Intake,
    control: mesh_forward_intake::Intake,
) -> Router<Arc<AppState>> {
    // An open can wait on the connector, while polling adds consumer work.
    // Neither may consume the reservations needed to acknowledge retained
    // events or close a stream. Both lanes bound uploads before decoding and
    // retain their permit through the bounded dispatch, including authority
    // waits and peer forwarding; there is no separate stream-control job queue.
    let work_routes = Router::new()
        .route("/rpc/streams/open", post(open_handler))
        .route("/rpc/streams/poll", post(poll_handler))
        .layer(axum::Extension(work));
    let control_routes = Router::new()
        .route("/rpc/streams/ack", post(ack_handler))
        .route("/rpc/streams/close", post(close_handler))
        .layer(axum::Extension(control));
    Router::new()
        .merge(work_routes)
        .merge(control_routes)
        .layer(axum::extract::DefaultBodyLimit::max(REQUEST_BYTES))
        .with_state(host)
}

impl EventService {
    pub(super) fn new(journal: Option<Arc<NativeEventJournal>>) -> Self {
        Self {
            journal,
            attachments: futures_util::lock::Mutex::new(HashMap::new()),
        }
    }

    /// Dispatch only on the executor selected in the authenticated peer request.
    /// The peer envelope authenticates the relay; local capability and custody
    /// admission remain mandatory for every operation.
    pub(super) async fn execute_forward(
        &self,
        host: &Arc<AppState>,
        method: &str,
        request_json: &str,
    ) -> Result<Value, (StatusCode, String)> {
        let request = mesh::Request::decode(method, request_json)?;
        mesh::dispatch(self, host, request, true).await
    }

    fn journal(&self) -> HostResult<&Arc<NativeEventJournal>> {
        self.journal.as_ref().ok_or_else(|| {
            unavailable("native consumer delivery requires FCP_HOST_EVENT_JOURNAL_FILE or a persistent host lifecycle store")
        })
    }

    /// Authentication does not call the connector: an invocation can be
    /// waiting for exactly the acknowledgement this consumer is submitting.
    async fn authorize(
        &self,
        host: &AppState,
        auth: &StreamAuthority,
        execution: bool,
        admitted_execution_fence: Option<fcp_host::ConnectorExecutionFence>,
        control: Value,
    ) -> HostResult<Admission> {
        self.journal()?;
        if auth.request_id.is_empty()
            || auth.request_id.len() > 128
            || auth.request_id.chars().any(char::is_control)
            || auth.topic.is_empty()
            || auth.topic.len() > 256
        {
            return Err(invalid("invalid stream request identity or topic"));
        }
        // Capture before any asynchronous authority lookup. A revocation
        // published while those reads wait must invalidate this admission.
        let lifecycle_fence = host.lifecycle.capability_revocation_fence();
        // Closing retained custody remains available after disable. Opening,
        // consuming and replenishing upstream credit require live authority.
        let execution_fence = if execution {
            Some(match admitted_execution_fence {
                Some(fence) => {
                    fence.require_current()?;
                    fence
                }
                None => {
                    host.lifecycle
                        .connector_execution_fence(&auth.connector_id)
                        .await?
                }
            })
        } else {
            None
        };
        let generation = host.registry.version.load(Ordering::Acquire);
        let (config, connector, declaration) = {
            let state = host.registry.state.read().await;
            let entry = state
                .connectors
                .get(&auth.connector_id)
                .ok_or_else(|| HostError::ConnectorNotFound(auth.connector_id.to_string()))?;
            require_allowed_zones_configured(&auth.connector_id, &entry.config.allowed_zones)?;
            if !entry
                .config
                .allowed_zones
                .iter()
                .any(|zone| zone == auth.zone_id.as_str())
            {
                return Err(denied(
                    "connector is not admitted in the requested event zone",
                ));
            }
            let ConnectorRuntime::Native(connector) = &entry.connector else {
                return Err(unavailable(
                    "event streams require a dedicated native connector process",
                ));
            };
            let mut events = entry
                .manifest_constraints
                .event_authorities
                .iter()
                .filter(|(id, event)| event.topic.as_deref().unwrap_or(id.as_str()) == auth.topic);
            let (_, declaration) = events.next().ok_or_else(|| {
                denied("event topic is absent from the host-pinned connector manifest")
            })?;
            if events.next().is_some() {
                return Err(denied("manifest maps more than one event to this topic"));
            }
            (
                entry.config.clone(),
                Arc::clone(connector),
                declaration.clone(),
            )
        };
        let (Some(capability), Some(operation), Some(resource_uri)) = (
            declaration.capability,
            declaration.subscribe_operation,
            declaration.resource_uri,
        ) else {
            return Err(denied(
                "event manifest has no complete consumer authority declaration",
            ));
        };
        if !declaration.streaming || !declaration.requires_ack {
            return Err(denied(
                "event declaration must support streaming and explicit acknowledgements",
            ));
        }
        if (config.allowed_operations.is_empty() && config.enforce_empty_allow_lists)
            || (!config.allowed_operations.is_empty()
                && !config
                    .allowed_operations
                    .iter()
                    .any(|allowed| allowed == &operation))
        {
            return Err(denied(
                "subscription control operation is not allowed by connector inventory",
            ));
        }
        let capability = CapabilityId::new(capability)
            .map_err(|_| denied("invalid manifest event capability"))?;
        let operation: OperationId = operation
            .parse()
            .map_err(|_| denied("invalid manifest subscription operation"))?;
        let key = host
            .capability_verifying_key
            .as_ref()
            .ok_or_else(|| denied("host capability verification key is unavailable"))?;
        let verified = CapabilityVerifier::without_instance_binding(
            key.to_bytes(),
            auth.zone_id.clone(),
        )
        .verify_unbound(
            auth.capability_token.clone(),
            &capability,
            &operation,
            std::slice::from_ref(&resource_uri),
        )
        .map_err(|_| {
            denied(
                "event capability signature, timing, grant, zone, or resource scope was rejected",
            )
        })?;
        let claims = verified.claims();
        let principal = claims_principal(claims)
            .ok_or_else(|| denied("event capability needs a verified subject"))?
            .to_owned();
        verify_live_revocation_cascade(host, &auth.zone_id, &auth.capability_token, claims)?;
        let request = InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new(auth.request_id.clone()),
            connector_id: auth.connector_id.clone(),
            operation: operation.clone(),
            zone_id: auth.zone_id.clone(),
            input: json!({
                "topic": auth.topic,
                "resource_uri": resource_uri,
                "control": control,
            }),
            capability_token: auth.capability_token.clone(),
            holder_proof: auth.holder_proof.clone(),
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };
        // The transcript uses the host-pinned subscription operation, never a
        // caller-supplied operation or the relay peer's transport signature.
        enforce_live_holder_proof(host, &request, claims)
            .map_err(|_| denied("event holder proof or current mesh membership was rejected"))?;
        verify_live_hybrid_owner_capability(host, &request)?;
        let persisted = host
            .lifecycle
            .verify_capability_token(&CapabilityTokenVerifyRequest {
                token_cbor_b64: capability_token_b64(&auth.capability_token)?,
                operation_id: Some(operation.to_string()),
                connector_id: Some(auth.connector_id.to_string()),
            })
            .await
            .map_err(|_| denied("persisted event capability verification failed"))?;
        if !persisted.valid
            && authoritative_persisted_capability_rejection_reason(
                &persisted,
                "event capability rejected by host state",
            )
            .is_some()
        {
            return Err(denied(
                "event capability rejected by persisted host authority",
            ));
        }
        if execution {
            enforce_live_capability_constraints(&request, claims, &principal, Some(&resource_uri))?;
        } else {
            // Cleanup starts no subscription, delivery, or provider credit.
            // Exhausted grants may still stop their own retained stream.
            enforce_live_capability_constraints_with_usage(
                &request,
                claims,
                &principal,
                Some(&resource_uri),
                0,
                0,
            )?;
        }
        let policy = simulate_policy_decision(&PolicySimulationInput {
            zone_policy: host.lookup_zone_policy(&auth.zone_id).await?,
            invoke_request: request.clone(),
            transport: TransportMode::Lan,
            checkpoint_fresh: true,
            revocation_fresh: true,
            execution_approval_required: false,
            sanitizer_receipts: Vec::new(),
            related_object_ids: Vec::new(),
            request_object_id: None,
            request_input_hash: Some(request_input_hash(&request.input)?),
            safety_tier: SafetyTier::Safe,
            principal: Some(principal.clone()),
            capability_id: Some(capability.to_string()),
            provenance_record: None,
            now_ms: None,
            posture_attestation: None,
        })
        .map_err(|_| denied("event zone policy evaluation failed"))?;
        if policy.decision == Decision::Deny {
            return Err(denied("zone policy denied event consumption"));
        }
        if generation != host.registry.version.load(Ordering::Acquire) {
            return Err(denied(
                "connector inventory changed during event authorization; retry",
            ));
        }
        let authority = live_authority::LiveAuthorityDispatchGuard::new(
            host,
            &request,
            lifecycle_fence,
            execution_fence,
            None,
        )?;
        authority.refresh()?.require_current()?;
        Ok(Admission {
            binding: NativeEventBinding {
                principal,
                connector_id: auth.connector_id.clone(),
                zone_id: auth.zone_id.clone(),
                topic: auth.topic.clone(),
            },
            connector,
            resource_uri,
            operation,
            capability,
            enforce_operation_network_constraints: config.enforce_operation_network_constraints,
            generation,
            authority,
            metered_request: request,
        })
    }

    fn require_current_admission(&self, host: &AppState, admission: &Admission) -> HostResult<()> {
        if admission.generation != host.registry.version.load(Ordering::Acquire) {
            return Err(denied("connector changed during event admission; retry"));
        }
        admission.authority.refresh()?.require_current()
    }

    /// One executor-local call and canonical control-input byte debit precedes
    /// custody or upstream work. This shares the token's invocation account;
    /// relay origins never reach this method. Failed or uncertain work cannot
    /// refund authority. Event payload and provider bytes are not metered here.
    async fn reserve_usage(&self, host: &AppState, admission: &Admission) -> HostResult<()> {
        self.require_current_admission(host, admission)?;
        let key = host
            .capability_verifying_key
            .as_ref()
            .ok_or_else(|| denied("host event verification key is unavailable"))?;
        host.lifecycle
            .reserve_capability_usage(
                &admission.metered_request,
                key,
                &admission.binding.principal,
            )
            .await?;
        // The durable store may wait behind another writer. Never let that
        // wait turn earlier lifecycle, inventory, or token authority stale.
        self.require_current_admission(host, admission)
    }

    fn verify_instance(
        &self,
        host: &AppState,
        auth: &StreamAuthority,
        admission: &Admission,
        instance: &InstanceId,
    ) -> HostResult<()> {
        let key = host
            .capability_verifying_key
            .as_ref()
            .ok_or_else(|| denied("host event verification key is unavailable"))?;
        CapabilityVerifier::new(key.to_bytes(), auth.zone_id.clone(), instance.clone())
            .verify_bound(
                auth.capability_token.clone(),
                &admission.capability,
                &admission.operation,
                std::slice::from_ref(&admission.resource_uri),
            )
            .map_err(|_| {
                denied("event capability does not authorize the retained connector instance")
            })?;
        Ok(())
    }

    fn authorize_retained(
        &self,
        host: &AppState,
        auth: &StreamAuthority,
        admission: &Admission,
        stream_id: &str,
    ) -> HostResult<InstanceId> {
        self.require_current_admission(host, admission)?;
        let retained = self.journal()?.describe(stream_id)?;
        if retained.binding != admission.binding {
            return Err(denied("event stream belongs to another consumer or scope"));
        }
        self.verify_instance(host, auth, admission, &retained.instance_id)?;
        Ok(retained.instance_id)
    }

    async fn open(
        &self,
        host: &AppState,
        request: OpenRequest,
        execution_fence: Option<fcp_host::ConnectorExecutionFence>,
    ) -> HostResult<Value> {
        if !(1..=fcp_host::NATIVE_EVENT_MAX_WINDOW).contains(&request.window_size) {
            return Err(invalid("event window must be between 1 and 64"));
        }
        let admission = self
            .authorize(
                host,
                &request.auth,
                true,
                execution_fence,
                json!({
                    "method": "open",
                    "stream_id": request.stream_id,
                    "window_size": request.window_size,
                }),
            )
            .await?;
        let termination = NativeInvocationTermination::new(Instant::now() + REQUEST_TIMEOUT);
        termination.bind_inventory_fence(host.registry.inventory_fence(admission.generation));
        termination.bind_authority_guard(admission.authority.clone());
        if admission.enforce_operation_network_constraints {
            return Err(denied(
                "native streaming cannot bypass strict per-operation egress enforcement",
            ));
        }
        // A native subscription starts provider traffic. Apply the same
        // runtime egress gate used by invoke before dispatching it.
        host.registry
            .enforce_runtime_network_policy(&admission.metered_request)
            .await?;
        let stream_id = match request.stream_id {
            Some(stream_id) => stream_id,
            None => {
                let identity =
                    to_deterministic_cbor(&(&admission.binding, &request.auth.request_id))
                        .map_err(|_| invalid("stream identity could not be encoded"))?;
                let hash = blake3::derive_key("fcp.host.native-event-subscription.v1", &identity);
                format!("stream_{}", hex::encode(hash))
            }
        };
        let journal = self.journal()?;
        let attached_instance = {
            let attachments = self.attachments.lock().await;
            if let Some(old) = attachments.get(&admission.binding.connector_id)
                && Arc::ptr_eq(&old.connector, &admission.connector)
            {
                if old.stream_id != stream_id {
                    return Err(unavailable(
                        "this native process is attached to another logical stream; resume it or restart the connector after closing it",
                    ));
                }
                if old.transport.is_failed() {
                    return Err(unavailable(
                        "native event transport has retired; restart the connector before resuming",
                    ));
                }
                Some(journal.describe(&stream_id)?.instance_id)
            } else {
                None
            }
        };
        // An existing attachment already proved its physical instance. Do not
        // enqueue a health RPC behind a webhook waiting for consumer credit.
        let instance_id = if let Some(instance_id) = attached_instance {
            instance_id
        } else {
            let health = admission
                .connector
                .rpc_in_handshaken_zone_with_termination(
                    &admission.binding.zone_id,
                    "health",
                    json!({}),
                    Some(&termination),
                )
                .await?;
            session::prepared_from_health(
                admission.binding.connector_id.clone(),
                admission.binding.zone_id.clone(),
                health,
            )
            .map_err(|_| unavailable("connector did not prove its ready native instance"))?
            .instance_id
        };
        self.verify_instance(host, &request.auth, &admission, &instance_id)?;
        let mut attachments = self.attachments.lock().await;
        if admission.generation != host.registry.version.load(Ordering::Acquire) {
            return Err(denied("connector changed before event attachment; retry"));
        }
        if let Some(old) = attachments.get(&admission.binding.connector_id)
            && Arc::ptr_eq(&old.connector, &admission.connector)
            && old.stream_id != stream_id
        {
            return Err(unavailable(
                "a concurrent subscription already attached this process",
            ));
        }
        // Health preparation and attachment ownership can both wait. Refresh
        // before durable custody changes; the physical RPC has its own guard
        // at actor selection after any subsequent zone-lock or queue wait.
        self.require_current_admission(host, &admission)?;
        journal.check_registration(
            &stream_id,
            &admission.binding,
            request.window_size,
            &instance_id,
        )?;
        self.reserve_usage(host, &admission).await?;
        // Quota persistence is an authorization wait, not permission to reuse
        // stale identity or custody. Recheck before the first journal write;
        // registration and the native writer repeat their own final fences.
        self.verify_instance(host, &request.auth, &admission, &instance_id)?;
        self.require_current_admission(host, &admission)?;
        // Persist ownership before retiring any previous process. A token for
        // a different principal must not disrupt its retained consumer.
        let stream = journal.register(
            &stream_id,
            admission.binding.clone(),
            request.window_size,
            instance_id,
        )?;
        let mut retired = None;
        if let Some(old) = attachments.get(&admission.binding.connector_id) {
            if !Arc::ptr_eq(&old.connector, &admission.connector) {
                old.accepting.store(false, Ordering::Release);
                retired = Some((old.transport.clone(), old.stream_id.clone()));
            }
        }
        let needs_attachment = attachments
            .get(&admission.binding.connector_id)
            .is_none_or(|old| !Arc::ptr_eq(&old.connector, &admission.connector));
        if needs_attachment {
            let transport =
                admission.connector.event_transport.clone().ok_or_else(|| {
                    unavailable("native process has no continuous event transport")
                })?;
            let accepting = Arc::new(AtomicBool::new(true));
            let authority = Arc::new(std::sync::Mutex::new(admission.authority.clone()));
            let (ack_tx, mut ack_rx) =
                mpsc::channel::<(EventAck, live_authority::LiveAuthorityDispatchGuard)>(64);
            let relay_transport = transport.clone();
            let relay_stream = stream_id.clone();
            let relay_accepting = Arc::clone(&accepting);
            let relay = task::try_spawn(async move {
                while let Some((ack, authority)) = ack_rx.recv().await {
                    if !relay_accepting.load(Ordering::Acquire) {
                        break;
                    }
                    if let Err(error) = relay_transport
                        .acknowledge_with_authority(&relay_stream, &ack, &authority)
                        .await
                    {
                        if error.kind() != std::io::ErrorKind::PermissionDenied {
                            break;
                        }
                    }
                }
            })
            .map_err(|_| unavailable("event acknowledgement relay could not start"))?;
            let sink_journal = Arc::clone(journal);
            let sink_stream = stream_id.clone();
            let sink_binding = admission.binding.clone();
            let sink_accepting = Arc::clone(&accepting);
            let sink_authority = Arc::clone(&authority);
            transport
                .install_sink(Arc::new(move |incoming_stream, event| {
                    if !sink_accepting.load(Ordering::Acquire) || incoming_stream != sink_stream {
                        return Err(std::io::Error::other(
                            "native event belongs to a retired stream",
                        ));
                    }
                    // Custody persistence can block while a fresh open renews
                    // the stream. This arrival keeps its original admission.
                    let authority = sink_authority
                        .lock()
                        .map_err(|_| {
                            std::io::Error::other(
                                "native replay acknowledgement authority unavailable",
                            )
                        })?
                        .clone();
                    let admitted = sink_journal
                        .ingest(
                            incoming_stream,
                            &sink_binding.connector_id,
                            &sink_binding.zone_id,
                            event,
                        )
                        .map_err(|_| {
                            std::io::Error::other("native event custody rejected the event")
                        })?;
                    if let NativeEventAdmission::AlreadyAcknowledged(ack) = admitted {
                        ack_tx.try_send((ack, authority)).map_err(|_| {
                            std::io::Error::other(
                                "native replay acknowledgement queue is unavailable",
                            )
                        })?;
                    }
                    Ok(())
                }))
                .map_err(|_| unavailable("native event sink could not be attached"))?;
            attachments.insert(
                admission.binding.connector_id.clone(),
                Attachment {
                    stream_id: stream_id.clone(),
                    connector: Arc::clone(&admission.connector),
                    transport,
                    accepting,
                    authority,
                    _ack_relay: relay,
                },
            );
        } else if let Some(attachment) = attachments.get(&admission.binding.connector_id) {
            // A fresh open can renew a retained stream's authority. ACKs
            // already queued retain their original guard and cannot revive.
            *attachment.authority.lock().map_err(|_| {
                unavailable("native replay acknowledgement authority unavailable")
            })? = admission.authority.clone();
        }
        drop(attachments);
        if let Some((transport, previous_stream)) = retired {
            let _ = transport.close_stream(&previous_stream).await;
        }
        let result = admission
            .connector
            .rpc_in_handshaken_zone_with_termination(
                &admission.binding.zone_id,
                "subscribe",
                json!({
                    "type": "subscribe",
                    "id": request.auth.request_id,
                    "stream_id": stream_id,
                    "topics": [admission.binding.topic],
                    "window_size": request.window_size,
                    "capability_token": request.auth.capability_token,
                }),
                Some(&termination),
            )
            .await?;
        let subscribed: SubscribeResponse = serde_json::from_value(result)
            .map_err(|_| unavailable("connector returned an invalid subscription response"))?;
        if subscribed.id.0 != request.auth.request_id
            || subscribed.result.confirmed_topics != vec![admission.binding.topic]
        {
            return Err(unavailable(
                "connector did not confirm the exact authorized topic",
            ));
        }
        let current = journal.describe(&stream_id)?;
        let still_attached = {
            let attachments = self.attachments.lock().await;
            attachments
                .get(&admission.binding.connector_id)
                .is_some_and(|attachment| {
                    attachment.stream_id == stream_id
                        && Arc::ptr_eq(&attachment.connector, &admission.connector)
                        && attachment.accepting.load(Ordering::Acquire)
                        && !attachment.transport.is_failed()
                })
        };
        let authority_current = admission
            .authority
            .refresh()
            .is_ok_and(|permit| permit.is_current());
        if !authority_current
            || current.closed
            || current.instance_id != stream.instance_id
            || admission.generation != host.registry.version.load(Ordering::Acquire)
            || !still_attached
        {
            // Close can race a queued subscription RPC. Cancel any producer
            // that the now-obsolete RPC started after the close notification.
            if let Some(transport) = &admission.connector.event_transport {
                let _ = transport.close_stream(&stream_id).await;
            }
            return Err(unavailable(
                "event stream changed while subscribing; reconcile the retained stream before retrying",
            ));
        }
        tracing::info!(event = "native_stream_open", stream_id, connector_id = %admission.binding.connector_id,
            zone_id = %admission.binding.zone_id, "authorized durable native stream attached");
        Ok(
            json!({"stream": current, "attached": true, "replay_supported": subscribed.result.replay_supported}),
        )
    }

    async fn poll(
        &self,
        host: &AppState,
        request: PollRequest,
        execution_fence: Option<fcp_host::ConnectorExecutionFence>,
    ) -> HostResult<Value> {
        if request.limit == 0 || request.limit > fcp_host::NATIVE_EVENT_MAX_WINDOW as usize {
            return Err(invalid("event poll limit must be between 1 and 64"));
        }
        let admitted = self
            .authorize(
                host,
                &request.auth,
                true,
                execution_fence,
                json!({"method": "poll", "stream_id": request.stream_id, "limit": request.limit}),
            )
            .await?;
        self.authorize_retained(host, &request.auth, &admitted, &request.stream_id)?;
        self.reserve_usage(host, &admitted).await?;
        let instance =
            self.authorize_retained(host, &request.auth, &admitted, &request.stream_id)?;
        let batch = self.journal()?.poll(
            &request.stream_id,
            &admitted.binding,
            &instance,
            request.limit,
        )?;
        serde_json::to_value(batch).map_err(|_| unavailable("event batch could not be encoded"))
    }

    async fn acknowledge(
        &self,
        host: &AppState,
        request: AckRequest,
        execution_fence: Option<fcp_host::ConnectorExecutionFence>,
    ) -> HostResult<Value> {
        validate_ack_control(&request.auth, &request.ack)?;
        let admitted = self
            .authorize(
                host,
                &request.auth,
                true,
                execution_fence,
                json!({"method": "ack", "stream_id": request.stream_id, "ack": request.ack}),
            )
            .await?;
        self.authorize_retained(host, &request.auth, &admitted, &request.stream_id)?;
        self.reserve_usage(host, &admitted).await?;
        let instance =
            self.authorize_retained(host, &request.auth, &admitted, &request.stream_id)?;
        // This synchronization is the custody handoff. No connector ACK may
        // precede it, even when the consumer retries after a lost response.
        let native_ack = self.journal()?.acknowledge(
            &request.stream_id,
            &admitted.binding,
            &instance,
            &request.ack,
        )?;
        let transport = {
            let attachments = self.attachments.lock().await;
            attachments
                .get(&admitted.binding.connector_id)
                .filter(|attachment| {
                    attachment.stream_id == request.stream_id
                        && attachment.accepting.load(Ordering::Acquire)
                        && Arc::ptr_eq(&attachment.connector, &admitted.connector)
                })
                .map(|attachment| {
                    (
                        attachment.transport.clone(),
                        Arc::clone(&attachment.accepting),
                    )
                })
        };
        let mut upstream_notified =
            transport.is_some() && native_ack.seqs.len() == request.ack.seqs.len();
        if let Some((transport, accepting)) = transport {
            for (seq, cursor) in native_ack.seqs.iter().zip(&native_ack.cursors) {
                if admitted
                    .authority
                    .refresh()
                    .and_then(|permit| permit.require_current())
                    .is_err()
                {
                    upstream_notified = false;
                    break;
                }
                if !accepting.load(Ordering::Acquire) {
                    upstream_notified = false;
                    break;
                }
                let ack =
                    EventAck::new(&native_ack.topic, vec![*seq]).with_cursors(vec![cursor.clone()]);
                if transport
                    .acknowledge_with_authority(&request.stream_id, &ack, &admitted.authority)
                    .await
                    .is_err()
                {
                    upstream_notified = false;
                    break;
                }
            }
        }
        Ok(
            json!({"acknowledged": true, "upstream_notified": upstream_notified,
            "stream": self.journal()?.describe(&request.stream_id)?}),
        )
    }

    async fn close(&self, host: &AppState, request: CloseRequest) -> HostResult<Value> {
        let admitted = self
            .authorize(
                host,
                &request.auth,
                false,
                None,
                json!({"method": "close", "stream_id": request.stream_id}),
            )
            .await?;
        let instance =
            self.authorize_retained(host, &request.auth, &admitted, &request.stream_id)?;
        let stream = self
            .journal()?
            .close(&request.stream_id, &admitted.binding, &instance)?;
        let transport = {
            let attachments = self.attachments.lock().await;
            attachments
                .get(&admitted.binding.connector_id)
                .filter(|attachment| {
                    attachment.stream_id == request.stream_id
                        && Arc::ptr_eq(&attachment.connector, &admitted.connector)
                })
                .map(|attachment| {
                    attachment.accepting.store(false, Ordering::Release);
                    attachment.transport.clone()
                })
        };
        let upstream_notified = if let Some(transport) = transport {
            transport.close_stream(&request.stream_id).await.is_ok()
        } else {
            false
        };
        Ok(json!({"stream": stream, "upstream_notified": upstream_notified}))
    }
}

async fn open_handler(
    State(host): State<Arc<AppState>>,
    mesh_forward_intake::RpcJson {
        value: request,
        permit: _permit,
    }: mesh_forward_intake::RpcJson<OpenRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    mesh::dispatch(
        &host.native_events,
        &host,
        mesh::Request::Open(request),
        false,
    )
    .await
    .map(Json)
}

async fn poll_handler(
    State(host): State<Arc<AppState>>,
    mesh_forward_intake::RpcJson {
        value: request,
        permit: _permit,
    }: mesh_forward_intake::RpcJson<PollRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    mesh::dispatch(
        &host.native_events,
        &host,
        mesh::Request::Poll(request),
        false,
    )
    .await
    .map(Json)
}

async fn ack_handler(
    State(host): State<Arc<AppState>>,
    mesh_forward_intake::RpcJson {
        value: request,
        permit: _permit,
    }: mesh_forward_intake::RpcJson<AckRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    mesh::dispatch(
        &host.native_events,
        &host,
        mesh::Request::Ack(request),
        false,
    )
    .await
    .map(Json)
}

async fn close_handler(
    State(host): State<Arc<AppState>>,
    mesh_forward_intake::RpcJson {
        value: request,
        permit: _permit,
    }: mesh_forward_intake::RpcJson<CloseRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    mesh::dispatch(
        &host.native_events,
        &host,
        mesh::Request::Close(request),
        false,
    )
    .await
    .map(Json)
}
