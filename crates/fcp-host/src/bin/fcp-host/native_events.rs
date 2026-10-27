//! Authorized, durable consumer delivery for continuously demultiplexed native events.
//!
//! The HTTP boundary never treats a stream identifier as authority. Each call
//! verifies a fresh signed capability against the host-pinned event declaration,
//! zone policy, revocations, and the retained consumer identity. Provider credit
//! is released only after the consumer decision has reached durable storage.

use super::*;
use fcp_core::{CapabilityId, EventAck, SubscribeResponse};
use fcp_host::{NativeEventAdmission, NativeEventBinding, NativeEventJournal};

const JOURNAL_ENV: &str = "FCP_HOST_EVENT_JOURNAL_FILE";
const REQUEST_BYTES: usize = 64 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

#[cfg(all(test, unix))]
#[path = "native_events_tests.rs"]
mod tests;

/// No Debug implementation: request bodies carry bearer capabilities.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamAuthority {
    request_id: String,
    connector_id: ConnectorId,
    zone_id: ZoneId,
    topic: String,
    capability_token: fcp_core::CapabilityToken,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenRequest {
    auth: StreamAuthority,
    #[serde(default)]
    stream_id: Option<String>,
    #[serde(default = "default_window")]
    window_size: u32,
}

const fn default_window() -> u32 {
    1
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PollRequest {
    auth: StreamAuthority,
    stream_id: String,
    #[serde(default = "default_limit")]
    limit: usize,
}

const fn default_limit() -> usize {
    1
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AckRequest {
    auth: StreamAuthority,
    stream_id: String,
    ack: EventAck,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CloseRequest {
    auth: StreamAuthority,
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
}

struct Attachment {
    stream_id: String,
    connector: Arc<SubprocessConnector>,
    transport: native_stream::NativeEventTransport,
    accepting: Arc<AtomicBool>,
    _ack_relay: JoinHandle<()>,
}

impl Drop for Attachment {
    fn drop(&mut self) {
        self.accepting.store(false, Ordering::Release);
    }
}

struct EventService {
    host: Arc<AppState>,
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
    path.map(|path| NativeEventJournal::open(path).map(Arc::new))
        .transpose()
}

pub(super) fn routes(
    host: Arc<AppState>,
    journal: Option<Arc<NativeEventJournal>>,
) -> Router<Arc<AppState>> {
    Router::new()
        .route("/rpc/streams/open", post(open_handler))
        .route("/rpc/streams/poll", post(poll_handler))
        .route("/rpc/streams/ack", post(ack_handler))
        .route("/rpc/streams/close", post(close_handler))
        .layer(axum::extract::DefaultBodyLimit::max(REQUEST_BYTES))
        .with_state(Arc::new(EventService {
            host,
            journal,
            attachments: futures_util::lock::Mutex::new(HashMap::new()),
        }))
}

impl EventService {
    fn journal(&self) -> HostResult<&Arc<NativeEventJournal>> {
        self.journal.as_ref().ok_or_else(|| {
            unavailable("native consumer delivery requires FCP_HOST_EVENT_JOURNAL_FILE or a persistent host lifecycle store")
        })
    }

    /// Authentication does not call the connector: an invocation can be
    /// waiting for exactly the acknowledgement this consumer is submitting.
    async fn authorize(&self, auth: &StreamAuthority) -> HostResult<Admission> {
        self.journal()?;
        if auth.request_id.is_empty()
            || auth.request_id.len() > 128
            || auth.request_id.chars().any(char::is_control)
            || auth.topic.is_empty()
            || auth.topic.len() > 256
        {
            return Err(invalid("invalid stream request identity or topic"));
        }
        let generation = self.host.registry.version.load(Ordering::Acquire);
        let (config, connector, declaration) = {
            let state = self.host.registry.state.read().await;
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
        let key = self
            .host
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
        // HTTP event calls do not yet carry the mesh request transcript needed
        // for holder proofs. Never downgrade a holder-bound token to a bearer.
        if claims.get_holder_node().is_some() {
            return Err(denied(
                "holder-bound capabilities require a supported holder-proof transport",
            ));
        }
        verify_live_revocation_cascade(&self.host, &auth.capability_token, claims)?;
        let request = InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new(auth.request_id.clone()),
            connector_id: auth.connector_id.clone(),
            operation: operation.clone(),
            zone_id: auth.zone_id.clone(),
            input: json!({"topic": auth.topic, "resource_uri": resource_uri}),
            capability_token: auth.capability_token.clone(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };
        verify_live_hybrid_owner_capability(&self.host, &request)?;
        let persisted = self
            .host
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
        enforce_live_capability_constraints(&request, claims, &principal, Some(&resource_uri))?;
        let policy = simulate_policy_decision(&PolicySimulationInput {
            zone_policy: self.host.lookup_zone_policy(&auth.zone_id).await?,
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
        if generation != self.host.registry.version.load(Ordering::Acquire) {
            return Err(denied(
                "connector inventory changed during event authorization; retry",
            ));
        }
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
        })
    }

    fn verify_instance(
        &self,
        auth: &StreamAuthority,
        admission: &Admission,
        instance: &InstanceId,
    ) -> HostResult<()> {
        let key = self
            .host
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
        auth: &StreamAuthority,
        admission: &Admission,
        stream_id: &str,
    ) -> HostResult<InstanceId> {
        let retained = self.journal()?.describe(stream_id)?;
        if retained.binding != admission.binding {
            return Err(denied("event stream belongs to another consumer or scope"));
        }
        self.verify_instance(auth, admission, &retained.instance_id)?;
        Ok(retained.instance_id)
    }

    async fn open(&self, request: OpenRequest) -> HostResult<Value> {
        let admission = self.authorize(&request.auth).await?;
        if admission.enforce_operation_network_constraints {
            return Err(denied(
                "native streaming cannot bypass strict per-operation egress enforcement",
            ));
        }
        // A native subscription starts provider traffic. Apply the same
        // runtime egress gate used by invoke before dispatching it.
        let network_request = InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new(request.auth.request_id.clone()),
            connector_id: request.auth.connector_id.clone(),
            operation: admission.operation.clone(),
            zone_id: request.auth.zone_id.clone(),
            input: json!({"resource_uri": admission.resource_uri}),
            capability_token: request.auth.capability_token.clone(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };
        self.host
            .registry
            .enforce_runtime_network_policy(&network_request)
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
                .rpc_in_handshaken_zone(&admission.binding.zone_id, "health", json!({}))
                .await?;
            session::prepared_from_health(
                admission.binding.connector_id.clone(),
                admission.binding.zone_id.clone(),
                health,
            )
            .map_err(|_| unavailable("connector did not prove its ready native instance"))?
            .instance_id
        };
        self.verify_instance(&request.auth, &admission, &instance_id)?;
        let mut attachments = self.attachments.lock().await;
        if admission.generation != self.host.registry.version.load(Ordering::Acquire) {
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
            let (ack_tx, mut ack_rx) = mpsc::channel::<EventAck>(64);
            let relay_transport = transport.clone();
            let relay_stream = stream_id.clone();
            let relay_accepting = Arc::clone(&accepting);
            let relay = task::try_spawn(async move {
                while let Some(ack) = ack_rx.recv().await {
                    if !relay_accepting.load(Ordering::Acquire) {
                        break;
                    }
                    if relay_transport
                        .acknowledge(&relay_stream, &ack)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            })
            .map_err(|_| unavailable("event acknowledgement relay could not start"))?;
            let sink_journal = Arc::clone(journal);
            let sink_stream = stream_id.clone();
            let sink_binding = admission.binding.clone();
            let sink_accepting = Arc::clone(&accepting);
            transport
                .install_sink(Arc::new(move |incoming_stream, event| {
                    if !sink_accepting.load(Ordering::Acquire) || incoming_stream != sink_stream {
                        return Err(std::io::Error::other(
                            "native event belongs to a retired stream",
                        ));
                    }
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
                        ack_tx.try_send(ack).map_err(|_| {
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
                    _ack_relay: relay,
                },
            );
        }
        drop(attachments);
        if let Some((transport, previous_stream)) = retired {
            let _ = transport.close_stream(&previous_stream).await;
        }
        let result = admission
            .connector
            .rpc_in_handshaken_zone(
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
        if current.closed
            || current.instance_id != stream.instance_id
            || admission.generation != self.host.registry.version.load(Ordering::Acquire)
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

    async fn poll(&self, request: PollRequest) -> HostResult<Value> {
        let admitted = self.authorize(&request.auth).await?;
        let instance = self.authorize_retained(&request.auth, &admitted, &request.stream_id)?;
        let batch = self.journal()?.poll(
            &request.stream_id,
            &admitted.binding,
            &instance,
            request.limit,
        )?;
        serde_json::to_value(batch).map_err(|_| unavailable("event batch could not be encoded"))
    }

    async fn acknowledge(&self, request: AckRequest) -> HostResult<Value> {
        let admitted = self.authorize(&request.auth).await?;
        let instance = self.authorize_retained(&request.auth, &admitted, &request.stream_id)?;
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
                if !accepting.load(Ordering::Acquire) {
                    upstream_notified = false;
                    break;
                }
                let ack =
                    EventAck::new(&native_ack.topic, vec![*seq]).with_cursors(vec![cursor.clone()]);
                if transport
                    .acknowledge(&request.stream_id, &ack)
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

    async fn close(&self, request: CloseRequest) -> HostResult<Value> {
        let admitted = self.authorize(&request.auth).await?;
        let instance = self.authorize_retained(&request.auth, &admitted, &request.stream_id)?;
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

async fn bounded<T>(
    future: impl std::future::Future<Output = HostResult<T>>,
) -> Result<T, (StatusCode, String)> {
    fcp_async_core::time::timeout(REQUEST_TIMEOUT, future).await
        .map_err(|_| map_host_error(unavailable("event request deadline expired; retry with the original stream and event identities")))?
        .map_err(map_host_error)
}

async fn open_handler(
    State(service): State<Arc<EventService>>,
    Json(request): Json<OpenRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    bounded(service.open(request)).await.map(Json)
}

async fn poll_handler(
    State(service): State<Arc<EventService>>,
    Json(request): Json<PollRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    bounded(service.poll(request)).await.map(Json)
}

async fn ack_handler(
    State(service): State<Arc<EventService>>,
    Json(request): Json<AckRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    bounded(service.acknowledge(request)).await.map(Json)
}

async fn close_handler(
    State(service): State<Arc<EventService>>,
    Json(request): Json<CloseRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    bounded(service.close(request)).await.map(Json)
}
