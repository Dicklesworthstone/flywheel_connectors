#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use fcp_async_core::channel::{mpsc, oneshot};
use fcp_async_core::{AsyncError, TaskGroup, task, time};
use fcp_crypto::{Ed25519SigningKey, Ed25519VerifyingKey, X25519PublicKey, X25519SecretKey};
use fcp_mesh::{
    AdaptiveRevocationPushFanoutConfig, AvailabilityProfile, CpuArch, DeviceProfile,
    FanoutDecision, GossipConfig, GossipMessage, GossipRequest, LatencyClass, MeshGossip, MeshNode,
    MeshNodeConfig, ObjectAdmissionClass, PowerSource, PriorityGossipPolicy,
    RevocationPushFanoutEvidence, RevocationPushMessage,
};
use fcp_prelude::{EpochId, NodeSignature, ObjectId, TailscaleNodeId, ZoneId};
use fcp_store::{
    MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig,
    ObjectAdmissionPolicy, ObjectSymbolMeta, QuarantineStore, StoredSymbol,
};
use fcp_tailscale::NodeId;
use thiserror::Error;

const NODE_COUNT: usize = 3;
const NODE_EVENT_CHANNEL_CAPACITY: usize = 160;
const OUTBOUND_CHANNEL_CAPACITY: usize = 128;
const CONTROL_REPLY_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);
const FLUSH_SETTLE_YIELDS: usize = 8;
const FLUSH_IDLE_ROUNDS: usize = 2;

#[derive(Debug, Clone)]
pub struct NodePublicIdentity {
    pub node_id: NodeId,
    pub signing_public_key: Ed25519VerifyingKey,
    pub encryption_public_key: X25519PublicKey,
    pub issuance_public_key: Ed25519VerifyingKey,
}

#[derive(Debug, Clone)]
pub struct NodeIdentity {
    pub node_id: NodeId,
    pub signing_key: Ed25519SigningKey,
    pub encryption_key: X25519SecretKey,
    pub issuance_key: Ed25519SigningKey,
}

impl NodeIdentity {
    #[must_use]
    pub fn public_identity(&self) -> NodePublicIdentity {
        NodePublicIdentity {
            node_id: self.node_id.clone(),
            signing_public_key: self.signing_key.verifying_key(),
            encryption_public_key: self.encryption_key.public_key(),
            issuance_public_key: self.issuance_key.verifying_key(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ObservedMessage {
    pub from: NodeId,
    pub received_at_ms: u64,
    pub message: GossipMessage,
    pub dispatch_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NodeSnapshot {
    pub node_id: NodeId,
    pub peer_count: usize,
    pub known_objects: Vec<ObjectId>,
    pub observed_messages: Vec<ObservedMessage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryDisposition {
    Queued,
    DroppedByPartition,
    DroppedByPacketLoss,
}

#[derive(Debug, Error)]
pub enum HarnessError {
    #[error("node `{0}` is not part of the harness")]
    UnknownNode(String),
    #[error("control channel `{0}` is closed")]
    ControlChannelClosed(&'static str),
    #[error("network channel for `{0}` is closed")]
    NetworkChannelClosed(String),
    #[error("oneshot reply channel dropped before sending a response")]
    ReplyDropped,
    #[error("timed out waiting {timeout_ms}ms for `{operation}` reply")]
    ReplyTimeout {
        operation: &'static str,
        timeout_ms: u64,
    },
    #[error("timed out after {timeout_ms}ms during `{operation}`")]
    OperationTimeout {
        operation: &'static str,
        timeout_ms: u64,
    },
    #[error("async runtime error: {0}")]
    Async(#[from] AsyncError),
}

#[derive(Debug)]
struct NodeHandle {
    identity: NodeIdentity,
    event_tx: mpsc::Sender<NodeEvent>,
}

#[derive(Debug, Clone)]
struct LinkBehavior {
    latency: Duration,
    packet_loss: f64,
}

impl Default for LinkBehavior {
    fn default() -> Self {
        Self {
            latency: Duration::ZERO,
            packet_loss: 0.0,
        }
    }
}

#[derive(Debug)]
struct PendingDelivery {
    deliver_at_ms: u64,
    envelope: InboundEnvelope,
}

impl Ord for PendingDelivery {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .deliver_at_ms
            .cmp(&self.deliver_at_ms)
            .then_with(|| {
                self.envelope
                    .from
                    .as_str()
                    .cmp(other.envelope.from.as_str())
            })
            .then_with(|| self.envelope.to.as_str().cmp(other.envelope.to.as_str()))
    }
}

impl PartialOrd for PendingDelivery {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for PendingDelivery {
    fn eq(&self, other: &Self) -> bool {
        self.deliver_at_ms == other.deliver_at_ms
            && self.envelope.from == other.envelope.from
            && self.envelope.to == other.envelope.to
    }
}

impl Eq for PendingDelivery {}

#[derive(Debug)]
struct InboundEnvelope {
    from: NodeId,
    to: NodeId,
    delivered_at_ms: u64,
    message: GossipMessage,
}

#[derive(Debug)]
struct OutboundEnvelope {
    from: NodeId,
    to: NodeId,
    created_at_ms: u64,
    message: GossipMessage,
}

#[derive(Debug)]
enum NodeCommand {
    RegisterPeers {
        peers: Vec<NodePublicIdentity>,
        now_ms: u64,
        reply: oneshot::Sender<()>,
    },
    RegisterZoneOwnerKey {
        zone_id: ZoneId,
        key: Ed25519VerifyingKey,
        reply: oneshot::Sender<()>,
    },
    AnnounceObject {
        zone_id: ZoneId,
        object_id: ObjectId,
        admission: ObjectAdmissionClass,
        now_ms: u64,
        reply: oneshot::Sender<bool>,
    },
    AnnounceSymbol {
        zone_id: ZoneId,
        object_id: ObjectId,
        esi: u32,
        admission: ObjectAdmissionClass,
        now_ms: u64,
        reply: oneshot::Sender<bool>,
    },
    StoreObjectMeta {
        meta: ObjectSymbolMeta,
        reply: oneshot::Sender<()>,
    },
    StoreSymbol {
        symbol: StoredSymbol,
        reply: oneshot::Sender<()>,
    },
    CanReconstruct {
        object_id: ObjectId,
        reply: oneshot::Sender<bool>,
    },
    CreateSummary {
        zone_id: ZoneId,
        epoch_id: EpochId,
        sign: bool,
        reply: oneshot::Sender<Option<fcp_mesh::GossipSummary>>,
    },
    CreateObjectRequest {
        zone_id: ZoneId,
        object_ids: Vec<ObjectId>,
        now_secs: u64,
        reply: oneshot::Sender<GossipRequest>,
    },
    CreateSymbolRequest {
        zone_id: ZoneId,
        symbols: Vec<(ObjectId, u32)>,
        now_secs: u64,
        reply: oneshot::Sender<GossipRequest>,
    },
    Snapshot {
        zone_id: ZoneId,
        limit: usize,
        reply: oneshot::Sender<NodeSnapshot>,
    },
    Shutdown,
}

#[derive(Debug)]
enum NodeEvent {
    Command(NodeCommand),
    Network(InboundEnvelope),
}

pub struct MultiNodeMeshHarness {
    now_ms: u64,
    rng_state: u64,
    nodes: BTreeMap<String, NodeHandle>,
    pending: BinaryHeap<PendingDelivery>,
    link_behaviors: HashMap<(String, String), LinkBehavior>,
    partitions: Vec<HashSet<String>>,
    outbound_rx: mpsc::Receiver<OutboundEnvelope>,
    tasks: TaskGroup,
    /// Shared zone-owner signing key used to sign revocation-push
    /// `owner_signature` fields (br-uxsnk). The matching verifying
    /// key is registered on every node when
    /// [`Self::send_revocation_push`] is invoked for a zone, so all
    /// nodes accept owner-signed pushes for that zone.
    zone_owner_signing_key: Ed25519SigningKey,
    /// Zones for which the owner verifying key has already been
    /// broadcast to every node, so we don't re-register on every push.
    zone_owner_registered: HashSet<ZoneId>,
}

impl MultiNodeMeshHarness {
    #[allow(clippy::unused_async)]
    pub async fn new_three_node(seed: u64) -> Result<Self, HarnessError> {
        Self::new_with_node_count(seed, NODE_COUNT).await
    }

    #[allow(clippy::unused_async)]
    pub async fn new_with_node_count(seed: u64, node_count: usize) -> Result<Self, HarnessError> {
        Self::new_with_node_count_and_gossip_config(seed, node_count, GossipConfig::default()).await
    }

    #[allow(clippy::unused_async)]
    pub async fn new_with_node_count_and_gossip_config(
        seed: u64,
        node_count: usize,
        gossip_config: GossipConfig,
    ) -> Result<Self, HarnessError> {
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_CHANNEL_CAPACITY);
        let mut tasks = TaskGroup::new();
        let mut nodes = BTreeMap::new();

        for index in 0..node_count {
            let node_name = format!("mesh-harness-node-{}", index + 1);
            let identity = derive_identity(seed, &node_name);
            let sender_instance_id = derive_u64(seed, &node_name, "sender-instance");
            let local_node_id = derive_u64(seed, &node_name, "symbol-store-node");
            let mesh_node = build_mesh_node_with_gossip_config(
                &node_name,
                sender_instance_id,
                local_node_id,
                gossip_config.clone(),
            );

            let (event_tx, event_rx) = mpsc::channel(NODE_EVENT_CHANNEL_CAPACITY);

            tasks.spawn(
                format!("multi-node-harness-{node_name}"),
                run_node_task(identity.clone(), mesh_node, event_rx, outbound_tx.clone()),
            );

            nodes.insert(node_name, NodeHandle { identity, event_tx });
        }

        Ok(Self {
            now_ms: 0,
            rng_state: seed.max(1),
            nodes,
            pending: BinaryHeap::new(),
            link_behaviors: HashMap::new(),
            partitions: Vec::new(),
            outbound_rx,
            tasks,
            zone_owner_signing_key: Ed25519SigningKey::generate(),
            zone_owner_registered: HashSet::new(),
        })
    }

    #[must_use]
    pub fn node_ids(&self) -> Vec<NodeId> {
        self.nodes
            .values()
            .map(|handle| handle.identity.node_id.clone())
            .collect()
    }

    #[must_use]
    pub fn public_identities(&self) -> Vec<NodePublicIdentity> {
        self.nodes
            .values()
            .map(|handle| handle.identity.public_identity())
            .collect()
    }

    #[must_use]
    pub const fn now_ms(&self) -> u64 {
        self.now_ms
    }

    #[must_use]
    pub fn pending_message_count(&self) -> usize {
        self.pending.len()
    }

    pub fn set_latency(&mut self, from: &NodeId, to: &NodeId, latency: Duration) {
        self.link_behaviors
            .entry(link_key(from, to))
            .or_default()
            .latency = latency;
    }

    pub fn set_bidirectional_latency(&mut self, left: &NodeId, right: &NodeId, latency: Duration) {
        self.set_latency(left, right, latency);
        self.set_latency(right, left, latency);
    }

    pub fn set_packet_loss(&mut self, from: &NodeId, to: &NodeId, packet_loss: f64) {
        self.link_behaviors
            .entry(link_key(from, to))
            .or_default()
            .packet_loss = packet_loss.clamp(0.0, 1.0);
    }

    pub fn set_bidirectional_packet_loss(
        &mut self,
        left: &NodeId,
        right: &NodeId,
        packet_loss: f64,
    ) {
        self.set_packet_loss(left, right, packet_loss);
        self.set_packet_loss(right, left, packet_loss);
    }

    pub fn partition(&mut self, isolated: &[NodeId]) {
        let members = isolated
            .iter()
            .map(|node_id| node_id.as_str().to_string())
            .collect::<HashSet<_>>();
        self.partitions.push(members);
    }

    pub fn heal_partitions(&mut self) {
        self.partitions.clear();
    }

    pub async fn register_all_peers(&mut self) -> Result<(), HarnessError> {
        let peers = self.public_identities();
        let now_ms = self.now_ms;

        for handle in self.nodes.values() {
            let (reply_tx, reply_rx) = oneshot::channel();
            send_with_timeout(
                &handle.event_tx,
                NodeCommand::RegisterPeers {
                    peers: peers.clone(),
                    now_ms,
                    reply: reply_tx,
                },
                "register_peers",
            )
            .await?;
            await_reply("register_peers", reply_rx).await?;
        }

        Ok(())
    }

    pub async fn announce_object(
        &mut self,
        node_id: &NodeId,
        zone_id: ZoneId,
        object_id: ObjectId,
        admission: ObjectAdmissionClass,
    ) -> Result<bool, HarnessError> {
        let handle = self.node_handle(node_id)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        send_with_timeout(
            &handle.event_tx,
            NodeCommand::AnnounceObject {
                zone_id,
                object_id,
                admission,
                now_ms: self.now_ms,
                reply: reply_tx,
            },
            "announce_object",
        )
        .await?;
        await_reply("announce_object", reply_rx).await
    }

    pub async fn announce_symbol(
        &mut self,
        node_id: &NodeId,
        zone_id: ZoneId,
        object_id: ObjectId,
        esi: u32,
        admission: ObjectAdmissionClass,
    ) -> Result<bool, HarnessError> {
        let handle = self.node_handle(node_id)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        send_with_timeout(
            &handle.event_tx,
            NodeCommand::AnnounceSymbol {
                zone_id,
                object_id,
                esi,
                admission,
                now_ms: self.now_ms,
                reply: reply_tx,
            },
            "announce_symbol",
        )
        .await?;
        await_reply("announce_symbol", reply_rx).await
    }

    pub async fn store_object_meta(
        &mut self,
        node_id: &NodeId,
        meta: ObjectSymbolMeta,
    ) -> Result<(), HarnessError> {
        let handle = self.node_handle(node_id)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        send_with_timeout(
            &handle.event_tx,
            NodeCommand::StoreObjectMeta {
                meta,
                reply: reply_tx,
            },
            "store_object_meta",
        )
        .await?;
        await_reply("store_object_meta", reply_rx).await
    }

    pub async fn store_symbol(
        &mut self,
        node_id: &NodeId,
        symbol: StoredSymbol,
    ) -> Result<(), HarnessError> {
        let handle = self.node_handle(node_id)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        send_with_timeout(
            &handle.event_tx,
            NodeCommand::StoreSymbol {
                symbol,
                reply: reply_tx,
            },
            "store_symbol",
        )
        .await?;
        await_reply("store_symbol", reply_rx).await
    }

    pub async fn can_reconstruct(
        &mut self,
        node_id: &NodeId,
        object_id: ObjectId,
    ) -> Result<bool, HarnessError> {
        let handle = self.node_handle(node_id)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        send_with_timeout(
            &handle.event_tx,
            NodeCommand::CanReconstruct {
                object_id,
                reply: reply_tx,
            },
            "can_reconstruct",
        )
        .await?;
        await_reply("can_reconstruct", reply_rx).await
    }

    pub async fn send_summary(
        &mut self,
        from: &NodeId,
        to: &NodeId,
        zone_id: ZoneId,
        epoch_id: EpochId,
    ) -> Result<DeliveryDisposition, HarnessError> {
        let handle = self.node_handle(from)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        send_with_timeout(
            &handle.event_tx,
            NodeCommand::CreateSummary {
                zone_id,
                epoch_id,
                sign: true,
                reply: reply_tx,
            },
            "create_summary",
        )
        .await?;

        let Some(summary) = await_reply("create_summary", reply_rx).await? else {
            return Ok(DeliveryDisposition::Queued);
        };

        let disposition =
            self.schedule_message(from, to, GossipMessage::Summary(summary), self.now_ms);
        self.flush().await?;
        Ok(disposition)
    }

    pub async fn send_unsigned_summary(
        &mut self,
        from: &NodeId,
        to: &NodeId,
        zone_id: ZoneId,
        epoch_id: EpochId,
    ) -> Result<DeliveryDisposition, HarnessError> {
        let handle = self.node_handle(from)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        send_with_timeout(
            &handle.event_tx,
            NodeCommand::CreateSummary {
                zone_id,
                epoch_id,
                sign: false,
                reply: reply_tx,
            },
            "create_unsigned_summary",
        )
        .await?;

        let Some(summary) = await_reply("create_unsigned_summary", reply_rx).await? else {
            return Ok(DeliveryDisposition::Queued);
        };

        let disposition =
            self.schedule_message(from, to, GossipMessage::Summary(summary), self.now_ms);
        self.flush().await?;
        Ok(disposition)
    }

    pub async fn send_revocation_push(
        &mut self,
        from: &NodeId,
        to: &NodeId,
        zone_id: ZoneId,
        revoked_ids: Vec<ObjectId>,
        new_rev_seq: u64,
        sign: bool,
    ) -> Result<DeliveryDisposition, HarnessError> {
        // Ensure every node has the zone-owner verifying key registered
        // so owner_signature verification can succeed (br-uxsnk). Idempotent
        // per zone — we only broadcast once per zone_id.
        if !self.zone_owner_registered.contains(&zone_id) {
            let owner_vk = self.zone_owner_signing_key.verifying_key();
            let names: Vec<String> = self.nodes.keys().cloned().collect();
            for name in names {
                let (tx, rx) = oneshot::channel();
                let event = NodeEvent::Command(NodeCommand::RegisterZoneOwnerKey {
                    zone_id: zone_id.clone(),
                    key: owner_vk.clone(),
                    reply: tx,
                });
                let handle = self
                    .nodes
                    .get(&name)
                    .ok_or_else(|| HarnessError::UnknownNode(name.clone()))?;
                handle
                    .event_tx
                    .send(event)
                    .await
                    .map_err(|_| HarnessError::ControlChannelClosed("register-zone-owner"))?;
                rx.await.map_err(|_| HarnessError::ReplyDropped)?;
            }
            self.zone_owner_registered.insert(zone_id.clone());
        }

        let handle = self.node_handle(from)?;
        let mut push = RevocationPushMessage::new(
            TailscaleNodeId::new(from.as_str()),
            zone_id,
            revoked_ids,
            new_rev_seq,
            self.now_ms / 1000,
        );
        if sign {
            let signature = handle.identity.signing_key.sign(&push.signing_bytes());
            push.signature = Some(NodeSignature::new(
                fcp_core::NodeId::new(from.as_str()),
                signature.to_bytes(),
                push.timestamp,
            ));
            let owner_sig = self
                .zone_owner_signing_key
                .sign(&push.owner_signing_bytes());
            push.owner_signature = Some(NodeSignature::new(
                fcp_core::NodeId::new("harness-zone-owner"),
                owner_sig.to_bytes(),
                push.timestamp,
            ));
        }

        let disposition =
            self.schedule_message(from, to, GossipMessage::RevocationPush(push), self.now_ms);
        self.flush().await?;
        Ok(disposition)
    }

    pub async fn broadcast_summaries(
        &mut self,
        zone_id: ZoneId,
        epoch_id: EpochId,
    ) -> Result<(), HarnessError> {
        let node_ids = self.node_ids();
        for from in &node_ids {
            for to in &node_ids {
                if from != to {
                    let _ = self
                        .send_summary(from, to, zone_id.clone(), epoch_id.clone())
                        .await?;
                }
            }
        }
        Ok(())
    }

    pub async fn request_objects(
        &mut self,
        requester: &NodeId,
        responder: &NodeId,
        zone_id: ZoneId,
        object_ids: Vec<ObjectId>,
    ) -> Result<DeliveryDisposition, HarnessError> {
        let observed_before = self
            .snapshot(requester, zone_id.clone(), 0)
            .await?
            .observed_messages
            .len();
        let handle = self.node_handle(requester)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        send_with_timeout(
            &handle.event_tx,
            NodeCommand::CreateObjectRequest {
                zone_id: zone_id.clone(),
                object_ids,
                now_secs: self.now_ms / 1000,
                reply: reply_tx,
            },
            "create_object_request",
        )
        .await?;
        let request = await_reply("create_object_request", reply_rx).await?;
        let disposition = self.schedule_message(
            requester,
            responder,
            GossipMessage::Request(request),
            self.now_ms,
        );
        self.flush().await?;
        if disposition == DeliveryDisposition::Queued {
            self.wait_for_observed_response(requester, responder, zone_id, observed_before)
                .await?;
        }
        Ok(disposition)
    }

    pub async fn request_symbols(
        &mut self,
        requester: &NodeId,
        responder: &NodeId,
        zone_id: ZoneId,
        symbols: Vec<(ObjectId, u32)>,
    ) -> Result<DeliveryDisposition, HarnessError> {
        let observed_before = self
            .snapshot(requester, zone_id.clone(), 0)
            .await?
            .observed_messages
            .len();
        let handle = self.node_handle(requester)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        send_with_timeout(
            &handle.event_tx,
            NodeCommand::CreateSymbolRequest {
                zone_id: zone_id.clone(),
                symbols,
                now_secs: self.now_ms / 1000,
                reply: reply_tx,
            },
            "create_symbol_request",
        )
        .await?;
        let request = await_reply("create_symbol_request", reply_rx).await?;
        let disposition = self.schedule_message(
            requester,
            responder,
            GossipMessage::Request(request),
            self.now_ms,
        );
        self.flush().await?;
        if disposition == DeliveryDisposition::Queued {
            self.wait_for_observed_response(requester, responder, zone_id, observed_before)
                .await?;
        }
        Ok(disposition)
    }

    pub async fn snapshot(
        &mut self,
        node_id: &NodeId,
        zone_id: ZoneId,
        limit: usize,
    ) -> Result<NodeSnapshot, HarnessError> {
        let handle = self.node_handle(node_id)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        send_with_timeout(
            &handle.event_tx,
            NodeCommand::Snapshot {
                zone_id,
                limit,
                reply: reply_tx,
            },
            "snapshot",
        )
        .await?;
        await_reply("snapshot", reply_rx).await
    }

    async fn wait_for_observed_response(
        &mut self,
        requester: &NodeId,
        responder: &NodeId,
        zone_id: ZoneId,
        observed_before: usize,
    ) -> Result<(), HarnessError> {
        time::timeout(CONTROL_REPLY_TIMEOUT, async {
            loop {
                self.flush().await?;
                let snapshot = self.snapshot(requester, zone_id.clone(), 0).await?;
                if snapshot
                    .observed_messages
                    .iter()
                    .skip(observed_before)
                    .any(|entry| {
                        entry.from == *responder
                            && matches!(entry.message, GossipMessage::Response(_))
                    })
                {
                    return Ok(());
                }

                task::yield_now().await;
            }
        })
        .await
        .map_err(|_| HarnessError::ReplyTimeout {
            operation: "wait_for_observed_response",
            timeout_ms: u64::try_from(CONTROL_REPLY_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
        })?
    }

    pub async fn advance_time(&mut self, duration: Duration) -> Result<(), HarnessError> {
        let delta_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        self.now_ms = self.now_ms.saturating_add(delta_ms);
        self.flush().await
    }

    pub async fn shutdown(self) -> Result<(), HarnessError> {
        for handle in self.nodes.values() {
            send_with_timeout(&handle.event_tx, NodeCommand::Shutdown, "shutdown").await?;
        }
        self.tasks.shutdown(Duration::from_secs(1)).await?;
        Ok(())
    }

    fn schedule_message(
        &mut self,
        from: &NodeId,
        to: &NodeId,
        message: GossipMessage,
        created_at_ms: u64,
    ) -> DeliveryDisposition {
        if self.is_partitioned(from, to) {
            return DeliveryDisposition::DroppedByPartition;
        }

        let behavior = self
            .link_behaviors
            .get(&link_key(from, to))
            .cloned()
            .unwrap_or_default();
        if self.should_drop(behavior.packet_loss) {
            return DeliveryDisposition::DroppedByPacketLoss;
        }

        let delay_ms = u64::try_from(behavior.latency.as_millis()).unwrap_or(u64::MAX);
        let delivered_at_ms = created_at_ms.saturating_add(delay_ms);
        self.pending.push(PendingDelivery {
            deliver_at_ms: delivered_at_ms,
            envelope: InboundEnvelope {
                from: from.clone(),
                to: to.clone(),
                delivered_at_ms,
                message,
            },
        });
        DeliveryDisposition::Queued
    }

    async fn flush(&mut self) -> Result<(), HarnessError> {
        time::timeout(FLUSH_TIMEOUT, self.flush_inner())
            .await
            .map_err(|_| HarnessError::OperationTimeout {
                operation: "flush",
                timeout_ms: u64::try_from(FLUSH_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
            })?
    }

    async fn flush_inner(&mut self) -> Result<(), HarnessError> {
        let mut idle_rounds = 0usize;

        loop {
            self.pump_outbound();

            let mut delivered = 0usize;
            while let Some(delivery) = self.pop_ready() {
                let event_tx = self.node_handle(&delivery.envelope.to)?.event_tx.clone();
                let recipient = delivery.envelope.to.as_str().to_string();
                time::timeout(
                    IO_TIMEOUT,
                    event_tx.send(NodeEvent::Network(delivery.envelope)),
                )
                .await
                .map_err(|_| HarnessError::OperationTimeout {
                    operation: "network_send",
                    timeout_ms: u64::try_from(IO_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
                })?
                .map_err(|_| HarnessError::NetworkChannelClosed(recipient))?;
                delivered += 1;
            }

            // Yield/pump in bounded rounds so request handling can surface outbound
            // responses before we declare the harness quiescent.
            for _ in 0..FLUSH_SETTLE_YIELDS {
                task::yield_now().await;
                self.pump_outbound();
                if self.has_ready_messages() {
                    break;
                }
            }

            if delivered == 0 && !self.has_ready_messages() {
                idle_rounds += 1;
                if idle_rounds >= FLUSH_IDLE_ROUNDS {
                    break;
                }
            } else {
                idle_rounds = 0;
            }
        }

        Ok(())
    }

    fn pump_outbound(&mut self) {
        while let Ok(outbound) = self.outbound_rx.try_recv() {
            let _ = self.schedule_message(
                &outbound.from,
                &outbound.to,
                outbound.message,
                outbound.created_at_ms,
            );
        }
    }

    fn has_ready_messages(&self) -> bool {
        self.pending
            .peek()
            .is_some_and(|delivery| delivery.deliver_at_ms <= self.now_ms)
    }

    fn pop_ready(&mut self) -> Option<PendingDelivery> {
        if self
            .pending
            .peek()
            .is_some_and(|delivery| delivery.deliver_at_ms <= self.now_ms)
        {
            self.pending.pop()
        } else {
            None
        }
    }

    fn node_handle(&self, node_id: &NodeId) -> Result<&NodeHandle, HarnessError> {
        self.nodes
            .get(node_id.as_str())
            .ok_or_else(|| HarnessError::UnknownNode(node_id.as_str().to_string()))
    }

    fn is_partitioned(&self, from: &NodeId, to: &NodeId) -> bool {
        self.partitions.iter().any(|partition| {
            let from_in = partition.contains(from.as_str());
            let to_in = partition.contains(to.as_str());
            from_in ^ to_in
        })
    }

    fn should_drop(&mut self, packet_loss: f64) -> bool {
        if packet_loss <= 0.0 {
            return false;
        }
        if packet_loss >= 1.0 {
            return true;
        }

        self.rng_state = self
            .rng_state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        #[allow(clippy::cast_precision_loss)]
        let sample = (self.rng_state >> 11) as f64 / ((u64::MAX >> 11) as f64);
        sample < packet_loss
    }
}

fn link_key(from: &NodeId, to: &NodeId) -> (String, String) {
    (from.as_str().to_string(), to.as_str().to_string())
}

async fn run_node_task(
    identity: NodeIdentity,
    mut mesh: MeshNode,
    mut event_rx: mpsc::Receiver<NodeEvent>,
    outbound_tx: mpsc::Sender<OutboundEnvelope>,
) -> Result<(), AsyncError> {
    let mut observed_messages = Vec::new();

    while let Some(event) = event_rx.recv().await {
        match event {
            NodeEvent::Command(command) => match command {
                NodeCommand::RegisterPeers {
                    peers,
                    now_ms,
                    reply,
                } => {
                    mesh.update_local_state(
                        default_profile(&identity.node_id),
                        HashSet::new(),
                        Vec::new(),
                    );
                    mesh.update_local_zones(HashSet::from([ZoneId::work()]));
                    for peer in peers {
                        if peer.node_id == identity.node_id {
                            continue;
                        }
                        let peer_id = peer.node_id.clone();
                        mesh.update_peer_state(
                            peer_id.clone(),
                            default_profile(&peer_id),
                            HashSet::new(),
                            Vec::new(),
                            now_ms,
                        );
                        mesh.update_peer_zones(&peer_id, HashSet::from([ZoneId::work()]));
                        mesh.register_peer_signing_key(peer_id, peer.signing_public_key);
                    }
                    let _ = reply.send(());
                }
                NodeCommand::RegisterZoneOwnerKey {
                    zone_id,
                    key,
                    reply,
                } => {
                    mesh.register_zone_owner_key(zone_id, key);
                    let _ = reply.send(());
                }
                NodeCommand::AnnounceObject {
                    zone_id,
                    object_id,
                    admission,
                    now_ms,
                    reply,
                } => {
                    let added = mesh.announce_object(&zone_id, &object_id, admission, now_ms);
                    let _ = reply.send(added);
                }
                NodeCommand::AnnounceSymbol {
                    zone_id,
                    object_id,
                    esi,
                    admission,
                    now_ms,
                    reply,
                } => {
                    let added = mesh.announce_symbol(&zone_id, &object_id, esi, admission, now_ms);
                    let _ = reply.send(added);
                }
                NodeCommand::StoreObjectMeta { meta, reply } => {
                    mesh.symbol_store()
                        .put_object_meta(meta)
                        .await
                        .expect("storing object metadata in harness should succeed");
                    let _ = reply.send(());
                }
                NodeCommand::StoreSymbol { symbol, reply } => {
                    mesh.symbol_store()
                        .put_symbol(symbol)
                        .await
                        .expect("storing symbols in harness should succeed");
                    let _ = reply.send(());
                }
                NodeCommand::CanReconstruct { object_id, reply } => {
                    let result = mesh.symbol_store().can_reconstruct(&object_id).await;
                    let _ = reply.send(result);
                }
                NodeCommand::CreateSummary {
                    zone_id,
                    epoch_id,
                    sign,
                    reply,
                } => {
                    let summary =
                        mesh.gossip_mut()
                            .create_summary(&zone_id, epoch_id)
                            .map(|mut summary| {
                                if sign {
                                    let signature =
                                        identity.signing_key.sign(&summary.signing_bytes());
                                    summary.signature = Some(NodeSignature::new(
                                        fcp_core::NodeId::new(identity.node_id.as_str()),
                                        signature.to_bytes(),
                                        summary.timestamp,
                                    ));
                                } else {
                                    summary.signature = None;
                                }
                                summary
                            });
                    let _ = reply.send(summary);
                }
                NodeCommand::CreateObjectRequest {
                    zone_id,
                    object_ids,
                    now_secs,
                    reply,
                } => {
                    let request = mesh
                        .gossip_mut()
                        .create_request(&zone_id, object_ids, now_secs);
                    let _ = reply.send(request);
                }
                NodeCommand::CreateSymbolRequest {
                    zone_id,
                    symbols,
                    now_secs,
                    reply,
                } => {
                    let request = GossipRequest::for_symbols(
                        TailscaleNodeId::new(identity.node_id.as_str()),
                        zone_id,
                        symbols,
                        now_secs,
                    );
                    let _ = reply.send(request);
                }
                NodeCommand::Snapshot {
                    zone_id,
                    limit,
                    reply,
                } => {
                    let snapshot = NodeSnapshot {
                        node_id: identity.node_id.clone(),
                        peer_count: mesh.peer_count(),
                        known_objects: mesh.gossip_mut().list_objects_in_zone(&zone_id, limit),
                        observed_messages: observed_messages.clone(),
                    };
                    let _ = reply.send(snapshot);
                }
                NodeCommand::Shutdown => return Ok(()),
            },
            NodeEvent::Network(envelope) => {
                let InboundEnvelope {
                    from,
                    delivered_at_ms,
                    message,
                    ..
                } = envelope;
                let observed = ObservedMessage {
                    from: from.clone(),
                    received_at_ms: delivered_at_ms,
                    message: message.clone(),
                    dispatch_error: None,
                };

                let mut observed = observed;
                match message {
                    GossipMessage::Summary(summary) => {
                        if let Err(err) = mesh.handle_gossip_message(
                            GossipMessage::Summary(summary),
                            delivered_at_ms / 1000,
                        ) {
                            observed.dispatch_error = Some(err.to_string());
                        }
                    }
                    GossipMessage::PeerCapabilities(advertisement) => {
                        if let Err(err) = mesh.handle_gossip_message(
                            GossipMessage::PeerCapabilities(advertisement),
                            delivered_at_ms / 1000,
                        ) {
                            observed.dispatch_error = Some(err.to_string());
                        }
                    }
                    GossipMessage::Request(request) => {
                        let response = mesh.gossip_mut().handle_request(&request);
                        let outbound = OutboundEnvelope {
                            from: identity.node_id.clone(),
                            to: NodeId::new(request.from.as_str()),
                            created_at_ms: delivered_at_ms,
                            message: GossipMessage::Response(response),
                        };
                        outbound_tx
                            .send(outbound)
                            .await
                            .map_err(|_| AsyncError::ChannelClosed)?;
                    }
                    GossipMessage::Response(_response) => {}
                    GossipMessage::ReconcileRequest(_request) => {}
                    GossipMessage::ReconcileResponse(_response) => {}
                    GossipMessage::RevocationPush(push) => {
                        if let Err(err) = mesh.handle_gossip_message(
                            GossipMessage::RevocationPush(push),
                            delivered_at_ms / 1000,
                        ) {
                            observed.dispatch_error = Some(err.to_string());
                        }
                    }
                }

                observed_messages.push(observed);
            }
        }
    }

    Ok(())
}

fn build_mesh_node_with_gossip_config(
    name: &str,
    sender_instance_id: u64,
    local_node_id: u64,
    gossip_config: GossipConfig,
) -> MeshNode {
    let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
    let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig {
        local_node_id,
        ..MemorySymbolStoreConfig::default()
    }));
    let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

    MeshNode::new(
        MeshNodeConfig::new(name)
            .with_sender_instance_id(sender_instance_id)
            .with_gossip_config(gossip_config),
        object_store,
        symbol_store,
        quarantine_store,
    )
}

fn default_profile(node_id: &NodeId) -> DeviceProfile {
    DeviceProfile::builder(node_id.clone())
        .cpu_cores(4)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(8192)
        .power_source(PowerSource::Mains)
        .latency_class(LatencyClass::Lan)
        .availability(AvailabilityProfile::AlwaysOn)
        .bandwidth_estimate_kbps(100_000)
        .build()
}

fn derive_identity(seed: u64, node_name: &str) -> NodeIdentity {
    let signing_seed = derive_key_material(seed, node_name, "signing");
    let encryption_seed = derive_key_material(seed, node_name, "encryption");
    let issuance_seed = derive_key_material(seed, node_name, "issuance");

    NodeIdentity {
        node_id: NodeId::new(node_name),
        signing_key: Ed25519SigningKey::from_bytes(&signing_seed)
            .expect("derived signing seed should be valid"),
        encryption_key: X25519SecretKey::from_bytes(encryption_seed),
        issuance_key: Ed25519SigningKey::from_bytes(&issuance_seed)
            .expect("derived issuance seed should be valid"),
    }
}

fn derive_key_material(seed: u64, node_name: &str, purpose: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fcp-mesh-multi-node-harness");
    hasher.update(&seed.to_le_bytes());
    hasher.update(node_name.as_bytes());
    hasher.update(purpose.as_bytes());
    *hasher.finalize().as_bytes()
}

fn derive_u64(seed: u64, node_name: &str, purpose: &str) -> u64 {
    let bytes = derive_key_material(seed, node_name, purpose);
    let mut value = [0_u8; 8];
    value.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(value)
}

async fn send_with_timeout(
    sender: &mpsc::Sender<NodeEvent>,
    command: NodeCommand,
    operation: &'static str,
) -> Result<(), HarnessError> {
    time::timeout(IO_TIMEOUT, sender.send(NodeEvent::Command(command)))
        .await
        .map_err(|_| HarnessError::OperationTimeout {
            operation,
            timeout_ms: u64::try_from(IO_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
        })?
        .map_err(|_| HarnessError::ControlChannelClosed(operation))
}

async fn await_reply<T>(
    operation: &'static str,
    reply_rx: oneshot::Receiver<T>,
) -> Result<T, HarnessError> {
    time::timeout(CONTROL_REPLY_TIMEOUT, reply_rx)
        .await
        .map_err(|_| HarnessError::ReplyTimeout {
            operation,
            timeout_ms: u64::try_from(CONTROL_REPLY_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
        })?
        .map_err(|_| HarnessError::ReplyDropped)
}

fn test_object_id(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
}

fn test_symbol(
    object_id: ObjectId,
    zone_id: ZoneId,
    esi: u32,
    source_node: u64,
    symbol_size: usize,
) -> StoredSymbol {
    let esi_byte = u8::try_from(esi).unwrap_or(0xFF);
    StoredSymbol {
        meta: fcp_store::SymbolMeta {
            object_id,
            esi,
            zone_id,
            source_node: Some(source_node),
            stored_at: 0,
        },
        data: Bytes::from(vec![esi_byte; symbol_size]),
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct RevocationDeliveryCounts {
    queued: usize,
    dropped_by_partition: usize,
    dropped_by_packet_loss: usize,
}

impl RevocationDeliveryCounts {
    const fn record(&mut self, disposition: DeliveryDisposition) {
        match disposition {
            DeliveryDisposition::Queued => self.queued += 1,
            DeliveryDisposition::DroppedByPartition => self.dropped_by_partition += 1,
            DeliveryDisposition::DroppedByPacketLoss => self.dropped_by_packet_loss += 1,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct RevocationObservationCounts {
    observed_messages: usize,
    unique_recipients: usize,
    duplicate_messages: usize,
    bytes_sent: usize,
    duplicate_ratio: f64,
    propagation_latency_ms: Option<u64>,
}

fn plan_swarm_revocation_fanout(
    local_node: &NodeId,
    config: GossipConfig,
    zone_id: &ZoneId,
    peers: &[TailscaleNodeId],
    policy: PriorityGossipPolicy,
    now_ms: u64,
) -> (RevocationPushFanoutEvidence, Vec<TailscaleNodeId>) {
    let mut gossip = MeshGossip::new(TailscaleNodeId::new(local_node.as_str()), config);
    let plan = gossip.plan_revocation_push_fanout(zone_id, peers, policy, now_ms);
    (plan.redacted_evidence(), plan.selected_peers)
}

async fn deliver_revocation_pushes(
    harness: &mut MultiNodeMeshHarness,
    from: &NodeId,
    selected_peers: &[TailscaleNodeId],
    zone_id: &ZoneId,
    revoked_id: ObjectId,
    new_rev_seq: u64,
) -> Result<RevocationDeliveryCounts, HarnessError> {
    let mut counts = RevocationDeliveryCounts::default();
    for peer in selected_peers {
        let to = NodeId::new(peer.as_str());
        let disposition = harness
            .send_revocation_push(
                from,
                &to,
                zone_id.clone(),
                vec![revoked_id],
                new_rev_seq,
                true,
            )
            .await?;
        counts.record(disposition);
    }
    Ok(counts)
}

#[allow(clippy::cast_precision_loss)]
async fn collect_revocation_observations(
    harness: &mut MultiNodeMeshHarness,
    zone_id: &ZoneId,
    revoked_id: ObjectId,
    new_rev_seq: u64,
    scenario_start_ms: u64,
) -> Result<RevocationObservationCounts, HarnessError> {
    let mut recipient_counts = BTreeMap::<String, usize>::new();
    let mut observed_messages = 0usize;
    let mut bytes_sent = 0usize;
    let mut latest_received_at_ms = scenario_start_ms;

    for node_id in harness.node_ids() {
        let snapshot = harness.snapshot(&node_id, zone_id.clone(), 0).await?;
        for entry in snapshot.observed_messages {
            let GossipMessage::RevocationPush(push) = &entry.message else {
                continue;
            };
            if push.new_rev_seq != new_rev_seq || !push.revoked_ids.contains(&revoked_id) {
                continue;
            }

            observed_messages += 1;
            *recipient_counts
                .entry(snapshot.node_id.as_str().to_string())
                .or_default() += 1;
            bytes_sent += serde_json::to_vec(&entry.message)
                .expect("revocation push observation should serialize")
                .len();
            latest_received_at_ms = latest_received_at_ms.max(entry.received_at_ms);
        }
    }

    let unique_recipients = recipient_counts.len();
    let duplicate_messages = observed_messages.saturating_sub(unique_recipients);
    let duplicate_ratio = if observed_messages == 0 {
        0.0
    } else {
        duplicate_messages as f64 / observed_messages as f64
    };
    let propagation_latency_ms =
        (observed_messages > 0).then(|| latest_received_at_ms.saturating_sub(scenario_start_ms));

    Ok(RevocationObservationCounts {
        observed_messages,
        unique_recipients,
        duplicate_messages,
        bytes_sent,
        duplicate_ratio,
        propagation_latency_ms,
    })
}

async fn seed_bulk_symbol_announcements(
    harness: &mut MultiNodeMeshHarness,
    nodes: &[NodeId],
    zone_id: &ZoneId,
    object_count: usize,
    symbols_per_object: u32,
) -> Result<usize, HarnessError> {
    if nodes.is_empty() {
        return Err(HarnessError::UnknownNode(
            "bulk-symbol-empty-harness".to_string(),
        ));
    }

    let symbol_size = 64usize;
    let symbol_size_u64 = u64::try_from(symbol_size).expect("symbol_size fits u64");
    let source_symbols = symbols_per_object;
    let mut announced_symbols = 0usize;

    for object_index in 0..object_count {
        let object_id = test_object_id(&format!("adaptive-bulk-symbol-{object_index}"));
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti: fcp_raptorq::ObjectTransmissionInformation::new(
                u64::from(source_symbols) * symbol_size_u64,
                u16::try_from(symbol_size).expect("symbol_size fits in u16"),
                1,
                1,
                8,
            ),
            source_symbols,
            first_symbol_at: 0,
        };

        for node in nodes {
            harness.store_object_meta(node, meta.clone()).await?;
            harness
                .announce_object(
                    node,
                    zone_id.clone(),
                    object_id,
                    ObjectAdmissionClass::Admitted,
                )
                .await?;
        }

        for esi in 0..symbols_per_object {
            let node_index = (object_index
                + usize::try_from(esi).expect("test ESI should fit usize"))
                % nodes.len();
            let node = nodes.get(node_index).ok_or_else(|| {
                HarnessError::UnknownNode(format!("bulk-symbol-node-index-{node_index}"))
            })?;
            let source_node = 10_000 + u64::try_from(object_index).expect("test index fits u64");
            harness
                .store_symbol(
                    node,
                    test_symbol(object_id, zone_id.clone(), esi, source_node, symbol_size),
                )
                .await?;
            harness
                .announce_symbol(
                    node,
                    zone_id.clone(),
                    object_id,
                    esi,
                    ObjectAdmissionClass::Admitted,
                )
                .await?;
            announced_symbols += 1;
        }
    }

    Ok(announced_symbols)
}

#[allow(clippy::too_many_arguments)]
fn swarm_evidence_entry(
    scenario_id: &'static str,
    node_count: usize,
    topology: &'static str,
    static_baseline: &RevocationPushFanoutEvidence,
    adaptive: &RevocationPushFanoutEvidence,
    delivery: RevocationDeliveryCounts,
    observations: RevocationObservationCounts,
    skip_reason: Option<&'static str>,
    details: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "scenario_id": scenario_id,
        "node_count": node_count,
        "topology": topology,
        "peer_fanout": {
            "static_baseline": static_baseline,
            "adaptive": adaptive,
            "static_selected_peers": static_baseline.selected_peer_count,
            "adaptive_selected_peers": adaptive.selected_peer_count,
            "suppressed_by_adaptive": static_baseline
                .selected_peer_count
                .saturating_sub(adaptive.selected_peer_count),
        },
        "message_counts": {
            "queued": delivery.queued,
            "dropped_by_partition": delivery.dropped_by_partition,
            "dropped_by_packet_loss": delivery.dropped_by_packet_loss,
            "observed": observations.observed_messages,
            "unique_recipients": observations.unique_recipients,
            "duplicates": observations.duplicate_messages,
        },
        "bytes_sent": observations.bytes_sent,
        "convergence_latency_ms": observations.propagation_latency_ms,
        "revocation_propagation_latency_ms": observations.propagation_latency_ms,
        "duplicate_ratio": observations.duplicate_ratio,
        "fallback_reason": adaptive.fallback_reason,
        "skip_reason": skip_reason,
        "details": details,
    })
}

fn swarm_jsonl(entries: &[serde_json::Value]) -> String {
    entries
        .iter()
        .map(|entry| serde_json::to_string(entry).expect("swarm evidence should serialize"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_swarm_jsonl_contract(jsonl: &str) {
    let required_fields = [
        "scenario_id",
        "node_count",
        "topology",
        "peer_fanout",
        "message_counts",
        "bytes_sent",
        "convergence_latency_ms",
        "revocation_propagation_latency_ms",
        "duplicate_ratio",
        "fallback_reason",
        "skip_reason",
    ];

    for line in jsonl.lines() {
        let value: serde_json::Value =
            serde_json::from_str(line).expect("swarm evidence line should be valid JSON");
        for field in required_fields {
            assert!(
                value.get(field).is_some(),
                "swarm evidence line missing `{field}`: {line}"
            );
        }
        assert!(
            value["node_count"].as_u64().is_some_and(|count| count >= 3),
            "swarm evidence must carry a realistic node_count: {line}"
        );
        assert!(
            value["message_counts"]["observed"]
                .as_u64()
                .is_some_and(|observed| observed > 0),
            "each swarm scenario must observe at least one real revocation push: {line}"
        );
    }
}

fn maybe_write_swarm_jsonl_artifact(jsonl: &str) -> std::io::Result<()> {
    let Some(path) = std::env::var_os("FCP_SWARM_JSONL_OUT") else {
        return Ok(());
    };

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(jsonl.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

#[fcp_async_core::runtime::test]
async fn adaptive_revocation_swarm_jsonl_evidence_compares_static_baseline() {
    const SWARM_NODE_COUNT: usize = 20;
    const STATIC_FANOUT_CAP: usize = 12;

    let zone_id = ZoneId::work();
    let source_revocation_id = test_object_id("adaptive-swarm-normal");
    let churn_revocation_id = test_object_id("adaptive-swarm-churn");
    let partition_revocation_id = test_object_id("adaptive-swarm-partition");
    let heal_revocation_id = test_object_id("adaptive-swarm-heal");
    let emergency_revocation_id = test_object_id("adaptive-swarm-emergency");
    let overload_revocation_id = test_object_id("adaptive-swarm-overload");

    let static_config = GossipConfig {
        max_revocation_push_peers: STATIC_FANOUT_CAP,
        ..GossipConfig::default()
    };
    let adaptive_config = GossipConfig {
        max_revocation_push_peers: STATIC_FANOUT_CAP,
        adaptive_revocation_push_fanout: AdaptiveRevocationPushFanoutConfig::enabled(),
        ..GossipConfig::default()
    };

    let mut harness = MultiNodeMeshHarness::new_with_node_count_and_gossip_config(
        0x51A9_4E11_D00D,
        SWARM_NODE_COUNT,
        adaptive_config.clone(),
    )
    .await
    .unwrap();
    harness.register_all_peers().await.unwrap();

    let node_ids = harness.node_ids();
    assert_eq!(node_ids.len(), SWARM_NODE_COUNT);
    let (source, peer_nodes) = node_ids
        .split_first()
        .expect("swarm harness should contain a source node");
    let source = source.clone();
    let peers = peer_nodes
        .iter()
        .map(|node_id| TailscaleNodeId::new(node_id.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(peers.len(), SWARM_NODE_COUNT - 1);

    let (static_direct, _) = plan_swarm_revocation_fanout(
        &source,
        static_config.clone(),
        &zone_id,
        &peers,
        PriorityGossipPolicy::DirectPush,
        1_000,
    );
    let (adaptive_direct, adaptive_selected) = plan_swarm_revocation_fanout(
        &source,
        adaptive_config.clone(),
        &zone_id,
        &peers,
        PriorityGossipPolicy::DirectPush,
        1_000,
    );
    assert_eq!(static_direct.selected_peer_count, STATIC_FANOUT_CAP);
    assert_eq!(adaptive_direct.decision, FanoutDecision::AdaptiveCapped);
    assert!(
        adaptive_direct.selected_peer_count < static_direct.selected_peer_count,
        "adaptive gate should reduce ordinary direct-push amplification"
    );

    let mut entries = Vec::new();

    for peer in &adaptive_selected {
        harness.set_latency(
            &source,
            &NodeId::new(peer.as_str()),
            Duration::from_millis(5),
        );
    }
    let normal_start_ms = harness.now_ms();
    let normal_delivery = deliver_revocation_pushes(
        &mut harness,
        &source,
        &adaptive_selected,
        &zone_id,
        source_revocation_id,
        1,
    )
    .await
    .unwrap();
    harness
        .advance_time(Duration::from_millis(5))
        .await
        .unwrap();
    let normal_observations = collect_revocation_observations(
        &mut harness,
        &zone_id,
        source_revocation_id,
        1,
        normal_start_ms,
    )
    .await
    .unwrap();
    assert_eq!(
        normal_observations.unique_recipients,
        adaptive_direct.selected_peer_count
    );
    entries.push(swarm_evidence_entry(
        "normal_load_adaptive",
        SWARM_NODE_COUNT,
        "full_mesh",
        &static_direct,
        &adaptive_direct,
        normal_delivery,
        normal_observations,
        None,
        &serde_json::json!({
            "comparison": "adaptive fanout is lower than static baseline",
            "static_cap": STATIC_FANOUT_CAP,
        }),
    ));

    for peer in &adaptive_selected {
        harness.set_latency(&source, &NodeId::new(peer.as_str()), Duration::ZERO);
    }

    let churned_peer = NodeId::new(
        adaptive_selected
            .first()
            .expect("adaptive plan should select a churn target")
            .as_str(),
    );
    harness.set_packet_loss(&source, &churned_peer, 1.0);
    let churn_start_ms = harness.now_ms();
    let churn_delivery = deliver_revocation_pushes(
        &mut harness,
        &source,
        &adaptive_selected,
        &zone_id,
        churn_revocation_id,
        2,
    )
    .await
    .unwrap();
    harness.set_packet_loss(&source, &churned_peer, 0.0);
    let churn_observations = collect_revocation_observations(
        &mut harness,
        &zone_id,
        churn_revocation_id,
        2,
        churn_start_ms,
    )
    .await
    .unwrap();
    assert_eq!(churn_delivery.dropped_by_packet_loss, 1);
    assert_eq!(
        churn_observations.unique_recipients,
        adaptive_direct.selected_peer_count - 1
    );
    entries.push(swarm_evidence_entry(
        "churn_packet_loss",
        SWARM_NODE_COUNT,
        "full_mesh_one_lossy_link",
        &static_direct,
        &adaptive_direct,
        churn_delivery,
        churn_observations,
        None,
        &serde_json::json!({
            "churned_peer_index": 0,
            "packet_loss": 1.0,
        }),
    ));

    let partitioned_peer = NodeId::new(
        adaptive_selected
            .get(1)
            .expect("adaptive plan should select a partition target")
            .as_str(),
    );
    harness.partition(std::slice::from_ref(&partitioned_peer));
    let partition_start_ms = harness.now_ms();
    let partition_delivery = deliver_revocation_pushes(
        &mut harness,
        &source,
        &adaptive_selected,
        &zone_id,
        partition_revocation_id,
        3,
    )
    .await
    .unwrap();
    let partition_observations = collect_revocation_observations(
        &mut harness,
        &zone_id,
        partition_revocation_id,
        3,
        partition_start_ms,
    )
    .await
    .unwrap();
    assert_eq!(partition_delivery.dropped_by_partition, 1);

    harness.heal_partitions();
    let healed_peer = [TailscaleNodeId::new(partitioned_peer.as_str())];
    let heal_start_ms = harness.now_ms();
    let heal_delivery = deliver_revocation_pushes(
        &mut harness,
        &source,
        &healed_peer,
        &zone_id,
        heal_revocation_id,
        4,
    )
    .await
    .unwrap();
    let heal_observations = collect_revocation_observations(
        &mut harness,
        &zone_id,
        heal_revocation_id,
        4,
        heal_start_ms,
    )
    .await
    .unwrap();
    assert_eq!(heal_observations.unique_recipients, 1);
    entries.push(swarm_evidence_entry(
        "partition_heal",
        SWARM_NODE_COUNT,
        "single_peer_partition_then_heal",
        &static_direct,
        &adaptive_direct,
        partition_delivery,
        partition_observations,
        None,
        &serde_json::json!({
            "partitioned_peer_index": 1,
            "post_heal": {
                "queued": heal_delivery.queued,
                "observed": heal_observations.observed_messages,
                "bytes_sent": heal_observations.bytes_sent,
                "revocation_propagation_latency_ms": heal_observations.propagation_latency_ms,
            },
        }),
    ));

    let (static_emergency, _) = plan_swarm_revocation_fanout(
        &source,
        static_config.clone(),
        &zone_id,
        &peers,
        PriorityGossipPolicy::Emergency,
        2_000,
    );
    let (adaptive_emergency, emergency_selected) = plan_swarm_revocation_fanout(
        &source,
        adaptive_config.clone(),
        &zone_id,
        &peers,
        PriorityGossipPolicy::Emergency,
        2_000,
    );
    assert_eq!(adaptive_emergency.decision, FanoutDecision::EmergencyBurst);
    assert_eq!(adaptive_emergency.selected_peer_count, peers.len());
    let bulk_object_count = 6usize;
    let bulk_symbols_per_object = 8u32;
    let bulk_symbol_announcements = seed_bulk_symbol_announcements(
        &mut harness,
        &node_ids,
        &zone_id,
        bulk_object_count,
        bulk_symbols_per_object,
    )
    .await
    .unwrap();
    harness
        .broadcast_summaries(
            zone_id.clone(),
            EpochId::new("adaptive-bulk-symbol-pressure"),
        )
        .await
        .unwrap();
    let bulk_pressure_snapshot = harness
        .snapshot(&source, zone_id.clone(), bulk_object_count)
        .await
        .unwrap();
    assert!(
        bulk_pressure_snapshot.known_objects.len() >= bulk_object_count,
        "bulk object gossip should be present before emergency revocation"
    );
    let emergency_start_ms = harness.now_ms();
    let emergency_delivery = deliver_revocation_pushes(
        &mut harness,
        &source,
        &emergency_selected,
        &zone_id,
        emergency_revocation_id,
        5,
    )
    .await
    .unwrap();
    let emergency_observations = collect_revocation_observations(
        &mut harness,
        &zone_id,
        emergency_revocation_id,
        5,
        emergency_start_ms,
    )
    .await
    .unwrap();
    assert_eq!(emergency_observations.unique_recipients, peers.len());
    entries.push(swarm_evidence_entry(
        "priority_revocation_emergency",
        SWARM_NODE_COUNT,
        "full_mesh_priority_bypass",
        &static_emergency,
        &adaptive_emergency,
        emergency_delivery,
        emergency_observations,
        None,
        &serde_json::json!({
            "priority_policy": "emergency",
            "adaptive_bypass_expected": true,
            "bulk_symbol_announcements": bulk_symbol_announcements,
            "bulk_observed_messages_before_revocation": bulk_pressure_snapshot.observed_messages.len(),
        }),
    ));

    let overload_config = GossipConfig {
        max_revocation_push_peers: STATIC_FANOUT_CAP,
        adaptive_revocation_push_fanout: AdaptiveRevocationPushFanoutConfig {
            max_selected_peers: 4,
            ..AdaptiveRevocationPushFanoutConfig::enabled()
        },
        ..GossipConfig::default()
    };
    let (static_overload, _) = plan_swarm_revocation_fanout(
        &source,
        static_config,
        &zone_id,
        &peers,
        PriorityGossipPolicy::DirectPush,
        3_000,
    );
    let (adaptive_overload, overload_selected) = plan_swarm_revocation_fanout(
        &source,
        overload_config,
        &zone_id,
        &peers,
        PriorityGossipPolicy::DirectPush,
        3_000,
    );
    assert_eq!(adaptive_overload.decision, FanoutDecision::AdaptiveCapped);
    assert_eq!(adaptive_overload.selected_peer_count, 4);
    let overload_start_ms = harness.now_ms();
    let overload_delivery = deliver_revocation_pushes(
        &mut harness,
        &source,
        &overload_selected,
        &zone_id,
        overload_revocation_id,
        6,
    )
    .await
    .unwrap();
    let overload_observations = collect_revocation_observations(
        &mut harness,
        &zone_id,
        overload_revocation_id,
        6,
        overload_start_ms,
    )
    .await
    .unwrap();
    assert_eq!(overload_observations.unique_recipients, 4);
    entries.push(swarm_evidence_entry(
        "overload_adaptive_cap",
        SWARM_NODE_COUNT,
        "full_mesh_overload_gate",
        &static_overload,
        &adaptive_overload,
        overload_delivery,
        overload_observations,
        None,
        &serde_json::json!({
            "adaptive_max_selected_peers": 4,
            "static_baseline_selected_peers": static_overload.selected_peer_count,
        }),
    ));

    let jsonl = swarm_jsonl(&entries);
    assert_eq!(jsonl.lines().count(), 5);
    assert_swarm_jsonl_contract(&jsonl);
    maybe_write_swarm_jsonl_artifact(&jsonl).expect("swarm JSONL artifact should be writable");

    harness.shutdown().await.unwrap();
}

#[fcp_async_core::runtime::test]
async fn multi_node_harness_routes_real_gossip_messages() {
    let zone_id = ZoneId::work();
    let epoch = EpochId::new("epoch-harness");
    let mut harness = MultiNodeMeshHarness::new_three_node(0x00C0_FFEE)
        .await
        .unwrap();
    harness.register_all_peers().await.unwrap();

    let node_ids = harness.node_ids();
    let node_a = node_ids[0].clone();
    let node_b = node_ids[1].clone();
    let node_c = node_ids[2].clone();

    let object_a = test_object_id("object-a");
    let object_b = test_object_id("object-b");

    assert!(
        harness
            .announce_object(
                &node_a,
                zone_id.clone(),
                object_a,
                ObjectAdmissionClass::Admitted
            )
            .await
            .unwrap()
    );
    assert!(
        harness
            .announce_object(
                &node_a,
                zone_id.clone(),
                object_b,
                ObjectAdmissionClass::Admitted
            )
            .await
            .unwrap()
    );

    harness
        .broadcast_summaries(zone_id.clone(), epoch.clone())
        .await
        .unwrap();
    harness
        .request_objects(&node_b, &node_a, zone_id.clone(), vec![object_a, object_b])
        .await
        .unwrap();
    harness
        .request_objects(&node_c, &node_a, zone_id.clone(), vec![object_b])
        .await
        .unwrap();

    let snapshot_a = harness
        .snapshot(&node_a, zone_id.clone(), 10)
        .await
        .unwrap();
    let snapshot_b = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    let snapshot_c = harness
        .snapshot(&node_c, zone_id.clone(), 10)
        .await
        .unwrap();

    assert_eq!(snapshot_a.peer_count, 2);
    assert_eq!(snapshot_b.peer_count, 2);
    assert_eq!(snapshot_c.peer_count, 2);
    assert_eq!(snapshot_a.known_objects.len(), 2);

    assert!(
        snapshot_b
            .observed_messages
            .iter()
            .any(|entry| matches!(entry.message, GossipMessage::Summary(_))),
        "node-b should observe a summary from node-a"
    );
    assert!(
        snapshot_b
            .observed_messages
            .iter()
            .any(|entry| matches!(&entry.message, GossipMessage::Response(response) if response.have_objects == vec![object_a, object_b])),
        "node-b should observe a concrete gossip response from node-a"
    );
    assert!(
        snapshot_c
            .observed_messages
            .iter()
            .any(|entry| matches!(&entry.message, GossipMessage::Response(response) if response.have_objects == vec![object_b])),
        "node-c should observe a concrete gossip response from node-a"
    );

    harness.shutdown().await.unwrap();
}

#[fcp_async_core::runtime::test]
async fn multi_node_harness_enforces_latency_loss_and_partitions() {
    let zone_id = ZoneId::work();
    let epoch = EpochId::new("epoch-network-controls");
    let mut harness = MultiNodeMeshHarness::new_three_node(0x0BAD_5EED)
        .await
        .unwrap();
    harness.register_all_peers().await.unwrap();

    let node_ids = harness.node_ids();
    let node_a = node_ids[0].clone();
    let node_b = node_ids[1].clone();
    let node_c = node_ids[2].clone();

    let delayed_object = test_object_id("delayed-object");
    harness
        .announce_object(
            &node_a,
            zone_id.clone(),
            delayed_object,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    harness.set_latency(&node_a, &node_b, Duration::from_millis(250));
    let disposition = harness
        .send_summary(&node_a, &node_b, zone_id.clone(), epoch.clone())
        .await
        .unwrap();
    assert_eq!(disposition, DeliveryDisposition::Queued);

    let pre_delivery = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    assert!(
        pre_delivery.observed_messages.is_empty(),
        "latency should keep the summary pending until time advances"
    );

    harness
        .advance_time(Duration::from_millis(249))
        .await
        .unwrap();
    let still_pending = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    assert!(
        still_pending.observed_messages.is_empty(),
        "summary should still be pending before latency budget expires"
    );

    harness
        .advance_time(Duration::from_millis(1))
        .await
        .unwrap();
    let delivered = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    assert!(
        delivered
            .observed_messages
            .iter()
            .any(|entry| matches!(entry.message, GossipMessage::Summary(_))),
        "summary should arrive after advancing past the configured latency"
    );

    harness.set_packet_loss(&node_a, &node_c, 1.0);
    let dropped = harness
        .send_summary(&node_a, &node_c, zone_id.clone(), epoch.clone())
        .await
        .unwrap();
    assert_eq!(dropped, DeliveryDisposition::DroppedByPacketLoss);
    let dropped_snapshot = harness
        .snapshot(&node_c, zone_id.clone(), 10)
        .await
        .unwrap();
    assert!(
        dropped_snapshot.observed_messages.is_empty(),
        "100% packet loss should prevent delivery"
    );

    harness.partition(std::slice::from_ref(&node_a));
    let partitioned = harness
        .request_objects(&node_a, &node_b, zone_id.clone(), vec![delayed_object])
        .await
        .unwrap();
    assert_eq!(partitioned, DeliveryDisposition::DroppedByPartition);
    let partitioned_snapshot = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    assert_eq!(
        partitioned_snapshot
            .observed_messages
            .iter()
            .filter(|entry| matches!(entry.message, GossipMessage::Request(_)))
            .count(),
        0,
        "partitioned links should drop request traffic before delivery"
    );

    harness.heal_partitions();
    harness.shutdown().await.unwrap();
}

#[fcp_async_core::runtime::test]
async fn multi_node_harness_enforces_summary_signature_boundary() {
    let zone_id = ZoneId::work();
    let epoch = EpochId::new("epoch-signature-boundary");
    let mut harness = MultiNodeMeshHarness::new_three_node(0x51A9_4E11)
        .await
        .unwrap();
    harness.register_all_peers().await.unwrap();

    let node_ids = harness.node_ids();
    let node_a = node_ids[0].clone();
    let node_b = node_ids[1].clone();
    let object_id = test_object_id("signed-summary-object");

    harness
        .announce_object(
            &node_a,
            zone_id.clone(),
            object_id,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    let signed = harness
        .send_summary(&node_a, &node_b, zone_id.clone(), epoch.clone())
        .await
        .unwrap();
    assert_eq!(signed, DeliveryDisposition::Queued);

    let signed_snapshot = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    assert_eq!(signed_snapshot.peer_count, 2);
    assert!(
        signed_snapshot
            .observed_messages
            .iter()
            .any(|entry| matches!(entry.message, GossipMessage::Summary(_))
                && entry.dispatch_error.is_none()),
        "signed summaries should cross the verified dispatch boundary"
    );

    let unsigned = harness
        .send_unsigned_summary(&node_a, &node_b, zone_id.clone(), epoch)
        .await
        .unwrap();
    assert_eq!(unsigned, DeliveryDisposition::Queued);

    let rejected_snapshot = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    assert_eq!(rejected_snapshot.peer_count, 2);
    assert!(
        rejected_snapshot
            .observed_messages
            .iter()
            .any(|entry| matches!(entry.message, GossipMessage::Summary(_))
                && entry
                    .dispatch_error
                    .as_deref()
                    .is_some_and(|err| err.contains("invalid gossip summary signature"))),
        "unsigned summaries should be rejected at the verified dispatch boundary"
    );

    let revocation_id = test_object_id("revocation-boundary-object");
    let signed_push = harness
        .send_revocation_push(
            &node_a,
            &node_b,
            zone_id.clone(),
            vec![revocation_id],
            1,
            true,
        )
        .await
        .unwrap();
    assert_eq!(signed_push, DeliveryDisposition::Queued);

    let signed_push_snapshot = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    assert!(
        signed_push_snapshot
            .observed_messages
            .iter()
            .any(
                |entry| matches!(entry.message, GossipMessage::RevocationPush(_))
                    && entry.dispatch_error.is_none()
            ),
        "signed revocation pushes should cross the verified dispatch boundary"
    );

    let unsigned_push = harness
        .send_revocation_push(
            &node_a,
            &node_b,
            zone_id.clone(),
            vec![revocation_id],
            2,
            false,
        )
        .await
        .unwrap();
    assert_eq!(unsigned_push, DeliveryDisposition::Queued);

    let unsigned_push_snapshot = harness.snapshot(&node_b, zone_id, 10).await.unwrap();
    assert!(
        unsigned_push_snapshot
            .observed_messages
            .iter()
            .any(
                |entry| matches!(entry.message, GossipMessage::RevocationPush(_))
                    && entry
                        .dispatch_error
                        .as_deref()
                        .is_some_and(|err| err.contains("invalid revocation push signature"))
            ),
        "unsigned revocation pushes should be rejected at the verified dispatch boundary"
    );

    harness.shutdown().await.unwrap();
}

#[fcp_async_core::runtime::test]
async fn multi_node_harness_supports_symbol_store_seeding() {
    let zone_id = ZoneId::work();
    let object_id = test_object_id("symbol-seeding");
    let mut harness = MultiNodeMeshHarness::new_three_node(0xFACE_FEED)
        .await
        .unwrap();
    let node = harness.node_ids()[0].clone();

    let meta = ObjectSymbolMeta {
        object_id,
        zone_id: zone_id.clone(),
        oti: fcp_raptorq::ObjectTransmissionInformation::new(192, 64, 1, 1, 8),
        source_symbols: 3,
        first_symbol_at: 0,
    };

    harness
        .store_object_meta(&node, meta.clone())
        .await
        .unwrap();
    for esi in 0..meta.source_symbols {
        harness
            .store_symbol(&node, test_symbol(object_id, zone_id.clone(), esi, 1, 64))
            .await
            .unwrap();
    }

    assert!(harness.can_reconstruct(&node, object_id).await.unwrap());
    harness.shutdown().await.unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// c73d6.2: Gossip convergence — all 3 nodes agree on object set
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn gossip_convergence_all_nodes_agree_after_exchange() {
    let zone_id = ZoneId::work();
    let epoch = EpochId::new("epoch-convergence");
    let mut harness = MultiNodeMeshHarness::new_three_node(0xC0FF_EE01)
        .await
        .unwrap();
    harness.register_all_peers().await.unwrap();

    let node_ids = harness.node_ids();
    let node_a = node_ids[0].clone();
    let node_b = node_ids[1].clone();
    let node_c = node_ids[2].clone();

    // Node A creates obj_a, Node B creates obj_b
    let obj_a = test_object_id("conv-obj-a");
    let obj_b = test_object_id("conv-obj-b");
    harness
        .announce_object(
            &node_a,
            zone_id.clone(),
            obj_a,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();
    harness
        .announce_object(
            &node_b,
            zone_id.clone(),
            obj_b,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // Before gossip: each node only knows its own objects
    let snap_a = harness
        .snapshot(&node_a, zone_id.clone(), 10)
        .await
        .unwrap();
    let snap_b = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    let snap_c = harness
        .snapshot(&node_c, zone_id.clone(), 10)
        .await
        .unwrap();
    assert_eq!(snap_a.known_objects.len(), 1, "A should know 1 object");
    assert_eq!(snap_b.known_objects.len(), 1, "B should know 1 object");
    assert_eq!(snap_c.known_objects.len(), 0, "C should know 0 objects");

    // Gossip round 1: broadcast summaries so everyone learns what exists
    harness
        .broadcast_summaries(zone_id.clone(), epoch.clone())
        .await
        .unwrap();

    // Each node requests what it's missing. The gossip response tells them WHAT
    // exists, then the data transfer (simulated here by announce_object on the
    // receiver) makes it locally known.

    // B learns about obj_a from A's summary, requests it, then admits it locally
    let _ = harness
        .request_objects(&node_b, &node_a, zone_id.clone(), vec![obj_a])
        .await;
    harness
        .announce_object(
            &node_b,
            zone_id.clone(),
            obj_a,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // A learns about obj_b from B's summary, requests it, then admits it locally
    let _ = harness
        .request_objects(&node_a, &node_b, zone_id.clone(), vec![obj_b])
        .await;
    harness
        .announce_object(
            &node_a,
            zone_id.clone(),
            obj_b,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // C learns about both from summaries, requests and admits them
    let _ = harness
        .request_objects(&node_c, &node_a, zone_id.clone(), vec![obj_a])
        .await;
    harness
        .announce_object(
            &node_c,
            zone_id.clone(),
            obj_a,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();
    let _ = harness
        .request_objects(&node_c, &node_b, zone_id.clone(), vec![obj_b])
        .await;
    harness
        .announce_object(
            &node_c,
            zone_id.clone(),
            obj_b,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // Verify convergence: all 3 nodes have both objects
    let final_a = harness
        .snapshot(&node_a, zone_id.clone(), 10)
        .await
        .unwrap();
    let final_b = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    let final_c = harness
        .snapshot(&node_c, zone_id.clone(), 10)
        .await
        .unwrap();

    assert_eq!(final_a.known_objects.len(), 2, "A should have 2 objects");
    assert_eq!(final_b.known_objects.len(), 2, "B should have 2 objects");
    assert_eq!(final_c.known_objects.len(), 2, "C should have 2 objects");

    // All nodes agree on the exact same set
    let mut a_set: Vec<_> = final_a.known_objects;
    let mut b_set: Vec<_> = final_b.known_objects;
    let mut c_set: Vec<_> = final_c.known_objects;
    a_set.sort();
    b_set.sort();
    c_set.sort();
    assert_eq!(a_set, b_set, "A and B must agree on object set");
    assert_eq!(b_set, c_set, "B and C must agree on object set");

    harness.shutdown().await.unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// c73d6.3: Symbol distribution across 3 nodes
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn symbol_distribution_across_three_nodes() {
    let zone_id = ZoneId::work();
    let object_id = test_object_id("distributed-obj");
    let mut harness = MultiNodeMeshHarness::new_three_node(0xD1575).await.unwrap();
    harness.register_all_peers().await.unwrap();

    let node_ids = harness.node_ids();
    let node_a = node_ids[0].clone();
    let node_b = node_ids[1].clone();
    let node_c = node_ids[2].clone();

    // Configure: K=10 source symbols, 5 repair, symbol_size=64 bytes
    let source_symbols: u32 = 10;
    let repair_symbols: u32 = 5;
    let symbol_size: usize = 64;
    let total_symbols = source_symbols + repair_symbols;

    let meta = ObjectSymbolMeta {
        object_id,
        zone_id: zone_id.clone(),
        oti: fcp_raptorq::ObjectTransmissionInformation::new(
            u64::from(source_symbols) * (symbol_size as u64),
            u16::try_from(symbol_size).expect("symbol_size fits in u16"),
            1,
            1,
            8,
        ),
        source_symbols,
        first_symbol_at: 0,
    };

    // Store meta on all nodes
    for node in [&node_a, &node_b, &node_c] {
        harness.store_object_meta(node, meta.clone()).await.unwrap();
    }

    // Distribute symbols: A gets [0..5), B gets [5..10), C gets [10..15) (repair)
    for esi in 0..5 {
        harness
            .store_symbol(
                &node_a,
                test_symbol(object_id, zone_id.clone(), esi, 1, symbol_size),
            )
            .await
            .unwrap();
    }
    for esi in 5..10 {
        harness
            .store_symbol(
                &node_b,
                test_symbol(object_id, zone_id.clone(), esi, 2, symbol_size),
            )
            .await
            .unwrap();
    }
    for esi in 10..total_symbols {
        harness
            .store_symbol(
                &node_c,
                test_symbol(object_id, zone_id.clone(), esi, 3, symbol_size),
            )
            .await
            .unwrap();
    }

    // Announce the object from all nodes
    for node in [&node_a, &node_b, &node_c] {
        harness
            .announce_object(
                node,
                zone_id.clone(),
                object_id,
                ObjectAdmissionClass::Admitted,
            )
            .await
            .unwrap();
    }

    // Verify distribution: no single node can reconstruct alone
    // (each has only 5 symbols, need 10)
    assert!(
        !harness.can_reconstruct(&node_a, object_id).await.unwrap(),
        "A alone should NOT be able to reconstruct (has 5/10 symbols)"
    );
    assert!(
        !harness.can_reconstruct(&node_b, object_id).await.unwrap(),
        "B alone should NOT be able to reconstruct (has 5/10 symbols)"
    );
    assert!(
        !harness.can_reconstruct(&node_c, object_id).await.unwrap(),
        "C alone should NOT be able to reconstruct (has 5/10 repair symbols)"
    );

    // Verify each node has exactly its assigned symbols
    let snap_a = harness
        .snapshot(&node_a, zone_id.clone(), 10)
        .await
        .unwrap();
    let snap_b = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    let snap_c = harness
        .snapshot(&node_c, zone_id.clone(), 10)
        .await
        .unwrap();
    assert_eq!(snap_a.known_objects.len(), 1, "A knows 1 object");
    assert_eq!(snap_b.known_objects.len(), 1, "B knows 1 object");
    assert_eq!(snap_c.known_objects.len(), 1, "C knows 1 object");

    harness.shutdown().await.unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// c73d6.4: Object reconstruction from symbols across nodes
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn object_reconstruction_from_distributed_symbols() {
    let zone_id = ZoneId::work();
    let object_id = test_object_id("reconstruct-obj");
    let mut harness = MultiNodeMeshHarness::new_three_node(0xABCDE).await.unwrap();
    harness.register_all_peers().await.unwrap();

    let node_ids = harness.node_ids();
    let node_a = node_ids[0].clone();
    let node_b = node_ids[1].clone();
    let _node_c = node_ids[2].clone();

    let source_symbols: u32 = 6;
    let symbol_size: usize = 64;

    let meta = ObjectSymbolMeta {
        object_id,
        zone_id: zone_id.clone(),
        oti: fcp_raptorq::ObjectTransmissionInformation::new(
            u64::from(source_symbols) * (symbol_size as u64),
            u16::try_from(symbol_size).expect("symbol_size fits in u16"),
            1,
            1,
            8,
        ),
        source_symbols,
        first_symbol_at: 0,
    };

    // Store meta on node_a
    harness
        .store_object_meta(&node_a, meta.clone())
        .await
        .unwrap();

    // Node A has symbols [0,1,2] - not enough alone (need 6)
    for esi in 0..3 {
        harness
            .store_symbol(
                &node_a,
                test_symbol(object_id, zone_id.clone(), esi, 1, symbol_size),
            )
            .await
            .unwrap();
    }
    assert!(
        !harness.can_reconstruct(&node_a, object_id).await.unwrap(),
        "A with 3/6 symbols should NOT reconstruct"
    );

    // Add symbols [3,4,5] to A (simulating receipt from other nodes via gossip)
    for esi in 3..6 {
        harness
            .store_symbol(
                &node_a,
                test_symbol(object_id, zone_id.clone(), esi, 2, symbol_size),
            )
            .await
            .unwrap();
    }
    assert!(
        harness.can_reconstruct(&node_a, object_id).await.unwrap(),
        "A with 6/6 symbols SHOULD reconstruct (fungibility: any 6 symbols suffice)"
    );

    // Verify insufficient symbols fail
    harness
        .store_object_meta(&node_b, meta.clone())
        .await
        .unwrap();
    for esi in 0..5 {
        harness
            .store_symbol(
                &node_b,
                test_symbol(object_id, zone_id.clone(), esi, 1, symbol_size),
            )
            .await
            .unwrap();
    }
    assert!(
        !harness.can_reconstruct(&node_b, object_id).await.unwrap(),
        "B with 5/6 symbols should NOT reconstruct"
    );

    harness.shutdown().await.unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// c73d6.6: Network partition recovery
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn partition_recovery_nodes_reconverge_after_healing() {
    let zone_id = ZoneId::work();
    let epoch = EpochId::new("epoch-partition");
    let mut harness = MultiNodeMeshHarness::new_three_node(0x00FA_DE01)
        .await
        .unwrap();
    harness.register_all_peers().await.unwrap();

    let node_ids = harness.node_ids();
    let node_a = node_ids[0].clone();
    let node_b = node_ids[1].clone();
    let node_c = node_ids[2].clone();

    // Phase 1: All connected, A creates obj_shared, all converge
    let obj_shared = test_object_id("shared-before-partition");
    harness
        .announce_object(
            &node_a,
            zone_id.clone(),
            obj_shared,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // One gossip round to distribute the shared object
    harness
        .broadcast_summaries(zone_id.clone(), epoch.clone())
        .await
        .unwrap();
    let _ = harness
        .request_objects(&node_b, &node_a, zone_id.clone(), vec![obj_shared])
        .await;
    harness
        .announce_object(
            &node_b,
            zone_id.clone(),
            obj_shared,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();
    let _ = harness
        .request_objects(&node_c, &node_a, zone_id.clone(), vec![obj_shared])
        .await;
    harness
        .announce_object(
            &node_c,
            zone_id.clone(),
            obj_shared,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // Phase 2: PARTITION — isolate node A from {B, C}
    harness.partition(std::slice::from_ref(&node_a));

    // A creates a new object during partition
    let obj_a_during = test_object_id("created-by-a-during-partition");
    harness
        .announce_object(
            &node_a,
            zone_id.clone(),
            obj_a_during,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // B creates a new object during partition
    let obj_b_during = test_object_id("created-by-b-during-partition");
    harness
        .announce_object(
            &node_b,
            zone_id.clone(),
            obj_b_during,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // Gossip during partition — A's messages to B/C are dropped
    harness
        .broadcast_summaries(zone_id.clone(), epoch.clone())
        .await
        .unwrap();

    // B and C can exchange with each other (not partitioned from each other)
    let _ = harness
        .request_objects(&node_c, &node_b, zone_id.clone(), vec![obj_b_during])
        .await;
    harness
        .announce_object(
            &node_c,
            zone_id.clone(),
            obj_b_during,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // Verify: A doesn't know about B's object, B/C don't know about A's
    let snap_a = harness
        .snapshot(&node_a, zone_id.clone(), 10)
        .await
        .unwrap();
    let snap_b = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    assert!(
        !snap_a.known_objects.contains(&obj_b_during),
        "A should NOT know B's object during partition"
    );
    assert!(
        !snap_b.known_objects.contains(&obj_a_during),
        "B should NOT know A's object during partition"
    );

    // Phase 3: HEAL partition
    harness.heal_partitions();

    // Post-healing gossip round to reconverge
    harness
        .broadcast_summaries(zone_id.clone(), epoch.clone())
        .await
        .unwrap();

    // A requests and admits B's object
    let _ = harness
        .request_objects(&node_a, &node_b, zone_id.clone(), vec![obj_b_during])
        .await;
    harness
        .announce_object(
            &node_a,
            zone_id.clone(),
            obj_b_during,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // B requests and admits A's object
    let _ = harness
        .request_objects(&node_b, &node_a, zone_id.clone(), vec![obj_a_during])
        .await;
    harness
        .announce_object(
            &node_b,
            zone_id.clone(),
            obj_a_during,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // C requests and admits A's object
    let _ = harness
        .request_objects(&node_c, &node_a, zone_id.clone(), vec![obj_a_during])
        .await;
    harness
        .announce_object(
            &node_c,
            zone_id.clone(),
            obj_a_during,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // Verify: ALL nodes have ALL objects (convergence after partition heal)
    let final_a = harness
        .snapshot(&node_a, zone_id.clone(), 10)
        .await
        .unwrap();
    let final_b = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    let final_c = harness
        .snapshot(&node_c, zone_id.clone(), 10)
        .await
        .unwrap();

    let expected_objects = vec![obj_shared, obj_a_during, obj_b_during];
    for obj in &expected_objects {
        assert!(
            final_a.known_objects.contains(obj),
            "A should know {obj:?} after partition heal"
        );
        assert!(
            final_b.known_objects.contains(obj),
            "B should know {obj:?} after partition heal"
        );
        assert!(
            final_c.known_objects.contains(obj),
            "C should know {obj:?} after partition heal"
        );
    }

    // No data loss: exactly 3 objects on every node
    assert_eq!(
        final_a.known_objects.len(),
        3,
        "A should have all 3 objects"
    );
    assert_eq!(
        final_b.known_objects.len(),
        3,
        "B should have all 3 objects"
    );
    assert_eq!(
        final_c.known_objects.len(),
        3,
        "C should have all 3 objects"
    );

    harness.shutdown().await.unwrap();
}
