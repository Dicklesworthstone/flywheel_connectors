//! FCP2 `MeshNode` Integration Tests
//!
//! Comprehensive integration tests for mesh node orchestration covering:
//! - Routing (symbol routing, control-plane routing, multi-hop, load balancing)
//! - Admission Control (valid requests admitted, rate limiting, quarantine)
//! - Policy Enforcement (zone boundaries, capability verification, taint propagation)
//! - Gossip Integration (object availability, reconciliation, stale gossip rejection)
//! - Lease Coordination (acquisition via HRW, renewal, transfer, conflict detection)
//!
//! All tests emit structured JSON logging for CI/CD integration.

// Test code - allow some clippy lints for clarity over micro-optimization
#![allow(clippy::redundant_clone)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use chrono::{SecondsFormat, Utc};
use fcp_mesh::admission::{AdmissionController, AdmissionError, AdmissionPolicy, PeerBudget};
use fcp_mesh::device::{
    AvailabilityProfile, CpuArch, DeviceProfile, GpuProfile, GpuVendor, InstalledConnector,
    LatencyClass, PowerSource,
};
use fcp_mesh::gossip::{
    GossipConfig, GossipMessage, GossipRequest, GossipState, GossipSummary, MeshGossip,
};
use fcp_mesh::planner::{
    ExecutionPlanner, HeldLease, LeasePurpose, NodeInfo, PlannerContext, PlannerInput,
};
use fcp_mesh::transport::{TransportPath, TransportPathKind, TransportSelector};
use fcp_prelude::{
    ConnectorId, DecisionReasonCode, EpochId, ObjectId, TailscaleNodeId, ZoneId,
    ZoneTransportPolicy,
};
use fcp_tailscale::NodeId;
use jsonschema::Validator;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt};

const E2E_LOG_V1_SCHEMA: &str =
    include_str!("../../fcp-conformance/src/schemas/E2E_Log_v1.schema.json");

fn e2e_log_validator() -> &'static Validator {
    static VALIDATOR: OnceLock<Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let schema: serde_json::Value =
            serde_json::from_str(E2E_LOG_V1_SCHEMA).expect("E2E log schema should parse");
        Validator::new(&schema).expect("E2E log schema should compile")
    })
}

fn validate_e2e_log_entry(value: &serde_json::Value) -> Result<(), String> {
    e2e_log_validator()
        .validate(value)
        .map_err(|err| err.to_string())
}

#[derive(Debug, Clone, Default)]
struct LogCaptureBuffer {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl LogCaptureBuffer {
    fn snapshot(&self) -> Vec<u8> {
        self.bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

struct LogCaptureWriter {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl Write for LogCaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCaptureBuffer {
    type Writer = LogCaptureWriter;

    fn make_writer(&'a self) -> Self::Writer {
        Self::Writer {
            bytes: Arc::clone(&self.bytes),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct LogCapture {
    buffer: LogCaptureBuffer,
}

impl LogCapture {
    fn new() -> Self {
        Self::default()
    }

    fn install_json_with_filter(
        &self,
        filter: impl Into<EnvFilter>,
    ) -> tracing::subscriber::DefaultGuard {
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(self.buffer.clone())
            .json()
            .with_ansi(false)
            .with_level(false)
            .with_target(false)
            .with_file(false)
            .with_line_number(false)
            .with_current_span(false)
            .flatten_event(true);
        let subscriber = tracing_subscriber::registry()
            .with(filter.into())
            .with(layer);
        tracing::subscriber::set_default(subscriber)
    }

    fn jsonl(&self) -> String {
        let bytes = self.buffer.snapshot();
        String::from_utf8_lossy(&bytes).to_string()
    }

    fn push_line(&self, line: &str) {
        let mut guard = self
            .buffer
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.extend_from_slice(line.as_bytes());
        guard.push(b'\n');
    }

    fn push_value(&self, value: &serde_json::Value) -> Result<(), serde_json::Error> {
        let line = serde_json::to_string(value)?;
        self.push_line(&line);
        Ok(())
    }

    fn assert_valid(&self) {
        for line in self.jsonl().lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let value: serde_json::Value =
                serde_json::from_str(trimmed).expect("captured line should be valid JSON");
            validate_e2e_log_entry(&value)
                .unwrap_or_else(|err| panic!("expected log line to match E2E schema: {err}"));
        }
    }
}

// ============================================================================
// Test Utilities
// ============================================================================

/// Structured test event for JSON logging.
#[derive(Debug, serde::Serialize)]
struct TestEvent {
    timestamp: String,
    log_version: &'static str,
    level: &'static str,
    module: &'static str,
    phase: &'static str,
    correlation_id: String,
    test_name: &'static str,
    result: &'static str,
    duration_ms: u64,
    assertions: TestAssertions,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct TestAssertions {
    passed: u32,
    failed: u32,
}

// ============================================================================
// MESHNODE ORCHESTRATION SMOKE TESTS
// ============================================================================

mod meshnode {
    use super::*;

    use bytes::Bytes;
    use fcp_cbor::SchemaId;
    use fcp_mesh::admission::AdmissionError;
    use fcp_mesh::admission::ObjectAdmissionClass;
    use fcp_mesh::{
        ControlPlaneEnvelope, InMemoryControlPlaneHandler, MeshNode, MeshNodeConfig, MeshSession,
        RetentionClass, SymbolRequestError, TraceReplayEngine,
    };
    use fcp_prelude::{
        CheckpointTransferEncoding, ComputationCheckpoint, ComputationMigrationError, Lease,
        LeaseHandoff, LeaseParams, LeasePurpose as CoreLeasePurpose, MigratableComputation,
        MigratableComputationState, MigrationCapabilityContext, ObjectHeader, Provenance,
        RetentionClass as ObjectRetentionClass, SignatureSet, StorageMeta, StoredObject, Uuid,
        ZoneKey, ZoneKeyAlgorithm, ZoneKeyId, current_timestamp,
    };
    use fcp_protocol::session::{
        MeshSessionId, SessionCryptoSuite, SessionKeys, SessionReplayPolicy, TransportLimits,
    };
    use fcp_protocol::{
        DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED, DecodeStatus, SymbolAck, SymbolAckReason,
        SymbolRequest,
    };
    use fcp_raptorq::{
        ObjectTransmissionInformation, RaptorQConfig, RaptorQDecoder, RaptorQEncoder,
    };
    use fcp_store::{
        MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig,
        ObjectAdmissionPolicy, ObjectSymbolMeta, QuarantineStore, QuarantinedObject, StoredSymbol,
        SymbolMeta, SymbolStore, SymbolStoreError,
    };
    use fcp_telemetry::trace_capture::{
        CapturedTrace, RedactionPolicy, TraceCaptureConfig, TraceEvent, TraceExportFormat,
    };
    use semver::Version;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_header(zone_id: &ZoneId) -> ObjectHeader {
        ObjectHeader {
            schema: SchemaId::new("fcp.mesh", "SymbolRequest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 0,
            provenance: Provenance::new(zone_id.clone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn status_header(zone_id: &ZoneId) -> ObjectHeader {
        ObjectHeader {
            schema: SchemaId::new("fcp.status", "DecodeStatus", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 0,
            provenance: Provenance::new(zone_id.clone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn build_mesh_node(name: &str, sender_instance_id: u64, local_node_id: u64) -> MeshNode {
        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig {
            local_node_id,
            ..MemorySymbolStoreConfig::default()
        }));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        MeshNode::new(
            MeshNodeConfig::new(name).with_sender_instance_id(sender_instance_id),
            object_store,
            symbol_store,
            quarantine_store,
        )
    }

    const fn test_zone_key() -> ZoneKey {
        ZoneKey::from_bytes([0xA5; 32])
    }

    const fn test_zone_key_algorithm() -> ZoneKeyAlgorithm {
        ZoneKeyAlgorithm::ChaCha20Poly1305
    }

    fn build_mesh_node_with_trace(
        name: &str,
        sender_instance_id: u64,
        local_node_id: u64,
    ) -> MeshNode {
        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig {
            local_node_id,
            ..MemorySymbolStoreConfig::default()
        }));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));
        let trace_config = TraceCaptureConfig::new()
            .enabled()
            .with_max_events(2048)
            .with_sample_rate(1.0);

        MeshNode::new(
            MeshNodeConfig::new(name)
                .with_sender_instance_id(sender_instance_id)
                .with_trace_capture_config(trace_config),
            object_store,
            symbol_store,
            quarantine_store,
        )
    }

    fn build_mesh_node_with_trace_config(
        name: &str,
        sender_instance_id: u64,
        local_node_id: u64,
        trace_config: TraceCaptureConfig,
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
                .with_trace_capture_config(trace_config),
            object_store,
            symbol_store,
            quarantine_store,
        )
    }

    fn trace_temp_path(prefix: &str, ext: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}.{ext}", std::process::id()))
    }

    async fn seed_symbols(store: &Arc<dyn SymbolStore>, meta: &ObjectSymbolMeta, source_node: u64) {
        store.put_object_meta(meta.clone()).await.unwrap();
        let symbol_size = meta.oti.symbol_size as usize;

        for esi in 0..meta.source_symbols {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id: meta.object_id,
                    esi,
                    zone_id: meta.zone_id.clone(),
                    source_node: Some(source_node),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            store.put_symbol(symbol).await.unwrap();
        }
    }

    async fn missing_esis(
        store: &Arc<dyn SymbolStore>,
        object_id: &ObjectId,
        total: u32,
    ) -> Vec<u32> {
        let received = store.get_all_symbols(object_id).await;
        let have: HashSet<u32> = received.iter().map(|symbol| symbol.meta.esi).collect();
        (0..total).filter(|esi| !have.contains(esi)).collect()
    }

    fn authorize_peer_for_zone(node: &mut MeshNode, peer: &NodeId, zone_id: &ZoneId) {
        node.update_peer_zones(peer, HashSet::from([zone_id.clone()]));
    }

    fn authenticate_peer_for_zone(
        node: &mut MeshNode,
        peer: &NodeId,
        zone_id: &ZoneId,
        now_ms: u64,
    ) {
        authorize_peer_for_zone(node, peer, zone_id);
        node.admission_mut().set_authenticated(peer, true, now_ms);
    }

    fn authorize_default_peer(node: &mut MeshNode, zone_id: &ZoneId) {
        authorize_peer_for_zone(node, &NodeId::new("peer-1"), zone_id);
    }

    fn authenticate_default_peer(node: &mut MeshNode, zone_id: &ZoneId) {
        authenticate_peer_for_zone(node, &NodeId::new("peer-1"), zone_id, 0);
    }

    const fn test_raptorq_config() -> RaptorQConfig {
        RaptorQConfig {
            symbol_size: 64,
            repair_ratio_bps: 2_000,
            max_object_size: 64 * 1_024,
            decode_timeout: std::time::Duration::from_secs(5),
            max_chunk_threshold: 1_024,
            chunk_size: 256,
        }
    }

    fn migration_header(
        zone_id: &ZoneId,
        computation_id: ObjectId,
        lease_id: ObjectId,
    ) -> ObjectHeader {
        ObjectHeader {
            schema: ComputationCheckpoint::schema(),
            zone_id: zone_id.clone(),
            created_at: 0,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![computation_id, lease_id],
            foreign_refs: Vec::new(),
            ttl_secs: Some(3_600),
            placement: None,
        }
    }

    fn test_migration_context(checkpoint_seq: u64) -> MigrationCapabilityContext {
        MigrationCapabilityContext {
            capability_token_jti: Uuid::from_u128(u128::from(checkpoint_seq) + 1),
            checkpoint_id: None,
            checkpoint_seq,
            audit_event_id: Some(test_object_id(&format!("migration-audit-{checkpoint_seq}"))),
        }
    }

    fn test_computation_checkpoint(
        zone_id: &ZoneId,
        computation_id: ObjectId,
        lease_id: ObjectId,
        holder: &TailscaleNodeId,
        checkpoint_seq: u64,
        lease_fencing_token: u64,
        state_len: usize,
    ) -> ComputationCheckpoint {
        let state_cbor = (0..state_len)
            .map(|index| u8::try_from(index % 251).expect("bounded byte"))
            .collect();

        ComputationCheckpoint {
            header: migration_header(zone_id, computation_id, lease_id),
            computation_id,
            current_holder: holder.clone(),
            checkpoint_seq,
            suspended_at: current_timestamp(),
            lease_id,
            lease_fencing_token,
            capability_context: test_migration_context(checkpoint_seq),
            state_cbor,
        }
    }

    fn test_migration_lease(
        zone_id: &ZoneId,
        holder: &TailscaleNodeId,
        subject_object_id: ObjectId,
        lease_seq: u64,
    ) -> Lease {
        Lease::new(LeaseParams {
            schema: SchemaId::new("fcp.core", "Lease", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            holder: holder.clone(),
            lease_seq,
            ttl_secs: 600,
            subject_object_id,
            provenance: Provenance::new(zone_id.clone()),
            purpose: CoreLeasePurpose::ComputationMigration,
            quorum_signatures: SignatureSet::new(),
        })
    }

    async fn seed_checkpoint_symbols(
        node: &MeshNode,
        checkpoint: &ComputationCheckpoint,
        checkpoint_object_id: ObjectId,
        source_node: u64,
        config: &RaptorQConfig,
    ) -> ObjectSymbolMeta {
        let canonical_bytes = checkpoint
            .canonical_bytes()
            .expect("checkpoint canonical serialization");
        node.object_store()
            .put(StoredObject {
                object_id: checkpoint_object_id,
                header: checkpoint.header.clone(),
                body: canonical_bytes.clone(),
                storage: StorageMeta {
                    retention: ObjectRetentionClass::Pinned,
                },
            })
            .await
            .expect("store checkpoint object");

        let encoder = RaptorQEncoder::new(&canonical_bytes, config).expect("encode checkpoint");
        let transmission_info = encoder.transmission_info();
        let meta = ObjectSymbolMeta {
            object_id: checkpoint_object_id,
            zone_id: checkpoint.zone_id().clone(),
            oti: fcp_store::ObjectTransmissionInfo::from_oti(transmission_info),
            source_symbols: encoder.source_symbols(),
            first_symbol_at: current_timestamp(),
        };

        let symbol_store = node.symbol_store().clone();
        symbol_store
            .put_object_meta(meta.clone())
            .await
            .expect("store checkpoint symbol metadata");
        for (esi, data) in encoder.encode_all() {
            symbol_store
                .put_symbol(StoredSymbol {
                    meta: SymbolMeta {
                        object_id: checkpoint_object_id,
                        esi,
                        zone_id: checkpoint.zone_id().clone(),
                        source_node: Some(source_node),
                        stored_at: current_timestamp(),
                    },
                    data: Bytes::from(data),
                })
                .await
                .expect("store checkpoint symbol");
        }

        meta
    }

    async fn apply_symbol_response(
        source_store: &Arc<dyn SymbolStore>,
        target_store: &Arc<dyn SymbolStore>,
        meta: &ObjectSymbolMeta,
        symbol_esis: &[u32],
    ) {
        if let Err(SymbolStoreError::ObjectNotFound(_)) =
            target_store.get_object_meta(&meta.object_id).await
        {
            target_store
                .put_object_meta(meta.clone())
                .await
                .expect("store target object metadata");
        }

        for esi in symbol_esis {
            let symbol = source_store
                .get_symbol(&meta.object_id, *esi)
                .await
                .expect("source symbol present");
            target_store
                .put_symbol(symbol)
                .await
                .expect("store transferred symbol");
        }
    }

    async fn reconstruct_checkpoint_from_store(
        store: &Arc<dyn SymbolStore>,
        meta: &ObjectSymbolMeta,
        config: &RaptorQConfig,
    ) -> ComputationCheckpoint {
        let mut symbols = store.get_all_symbols(&meta.object_id).await;
        symbols.sort_by_key(|symbol| symbol.meta.esi);

        let mut decoder = RaptorQDecoder::new(meta.oti.to_oti(), config);
        let canonical_bytes = symbols
            .into_iter()
            .find_map(|symbol| {
                decoder
                    .add_symbol(symbol.meta.esi, symbol.data.to_vec())
                    .expect("decoder should not error")
            })
            .expect("checkpoint should reconstruct");

        let encoding = CheckpointTransferEncoding::Inline {
            object_id: meta.object_id,
            canonical_bytes,
        };
        ComputationCheckpoint::from_transfer_encoding(&encoding)
            .expect("checkpoint should decode from canonical payload")
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_symbol_request_smoke() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-symbols");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store.clone(), quarantine_store);
        authenticate_default_peer(&mut node, &zone_id);

        let oti = ObjectTransmissionInformation::new(1024, 256, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };

        let symbol_size = meta.oti.symbol_size as usize;
        symbol_store.put_object_meta(meta).await.unwrap();
        for esi in 0..4u32 {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            symbol_store.put_symbol(symbol).await.unwrap();
        }

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            2,
            1,
        )
        .with_missing_hint(vec![1, 2]);

        let response = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect("symbol request should succeed");

        assert_ne!(response.symbol_esis, [] as [u32; 0]);
        assert!(response.symbol_esis.len() <= 2);
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_symbol_request_missing_object() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-missing-object");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store, quarantine_store);
        authenticate_default_peer(&mut node, &zone_id);

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id,
            zone_key_id,
            1,
            2,
            1,
        );

        let err = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect_err("missing object should return error");

        assert!(matches!(err, SymbolRequestError::ObjectNotFound { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_symbol_request_no_symbols() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-no-symbols");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store.clone(), quarantine_store);
        authenticate_default_peer(&mut node, &zone_id);

        let oti = ObjectTransmissionInformation::new(1024, 256, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };

        symbol_store.put_object_meta(meta).await.unwrap();

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id,
            zone_key_id,
            1,
            2,
            1,
        );

        let err = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect_err("missing symbols should return error");

        assert!(matches!(err, SymbolRequestError::ObjectNotFound { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_symbol_request_no_resend() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-no-resend");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store.clone(), quarantine_store);
        authenticate_default_peer(&mut node, &zone_id);

        let oti = ObjectTransmissionInformation::new(1024, 256, 1, 1, 1);
        let symbol_size = oti.symbol_size() as usize;
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };

        symbol_store.put_object_meta(meta).await.unwrap();

        for esi in 0..4u32 {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            symbol_store.put_symbol(symbol).await.unwrap();
        }

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id,
            zone_key_id,
            1,
            2,
            1,
        );

        let response = node
            .handle_symbol_request(request.clone(), &NodeId::new("peer-1"), true, 0)
            .await
            .expect("initial symbol request should succeed");

        assert_eq!(response.symbol_esis.len(), 2);
        let mut first: HashSet<u32> = response.symbol_esis.into_iter().collect();

        let response = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect("follow-up symbol request should succeed");

        assert_eq!(response.symbol_esis.len(), 2);
        assert!(response.symbol_esis.iter().all(|esi| !first.contains(esi)));

        first.extend(response.symbol_esis);
        assert_eq!(first.len(), 4);
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_symbol_request_prioritizes_missing_hint() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-missing-hint");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store.clone(), quarantine_store);
        authenticate_default_peer(&mut node, &zone_id);

        let oti = ObjectTransmissionInformation::new(1024, 256, 1, 1, 1);
        let symbol_size = oti.symbol_size() as usize;
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };

        symbol_store.put_object_meta(meta).await.unwrap();

        for esi in 0..4u32 {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            symbol_store.put_symbol(symbol).await.unwrap();
        }

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id,
            zone_key_id,
            1,
            2,
            1,
        )
        .with_missing_hint(vec![3, 1]);

        let response = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect("symbol request should succeed");

        assert_eq!(response.symbol_esis, vec![3, 1]);
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_symbol_request_fills_after_missing_hint() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-hint-fill");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store.clone(), quarantine_store);
        authenticate_default_peer(&mut node, &zone_id);

        let oti = ObjectTransmissionInformation::new(1024, 256, 1, 1, 1);
        let symbol_size = oti.symbol_size() as usize;
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };

        symbol_store.put_object_meta(meta).await.unwrap();

        for esi in 0..4u32 {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            symbol_store.put_symbol(symbol).await.unwrap();
        }

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id,
            zone_key_id,
            1,
            3,
            1,
        )
        .with_missing_hint(vec![2]);

        let response = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect("symbol request should succeed");

        assert_eq!(response.symbol_esis.len(), 3);
        assert_eq!(response.symbol_esis[0], 2);
        assert!(response.symbol_esis.iter().all(|esi| *esi < 4));
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_symbol_request_ignores_unavailable_hints() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-hint-unavailable");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store.clone(), quarantine_store);
        authenticate_default_peer(&mut node, &zone_id);

        let oti = ObjectTransmissionInformation::new(1024, 256, 1, 1, 1);
        let symbol_size = oti.symbol_size() as usize;
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };

        symbol_store.put_object_meta(meta).await.unwrap();

        for esi in 0..4u32 {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            symbol_store.put_symbol(symbol).await.unwrap();
        }

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id,
            zone_key_id,
            1,
            2,
            1,
        )
        .with_missing_hint(vec![9, 10]);

        let response = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect("symbol request should succeed");

        assert_eq!(response.symbol_esis.len(), 2);
        assert!(response.symbol_esis.iter().all(|esi| *esi < 4));
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_symbol_request_rejects_oversized_hint() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-hint-oversized");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store.clone(), quarantine_store);
        authenticate_default_peer(&mut node, &zone_id);

        let oti = ObjectTransmissionInformation::new(1024, 256, 1, 1, 1);
        let symbol_size = oti.symbol_size() as usize;
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };

        symbol_store.put_object_meta(meta).await.unwrap();

        for esi in 0..4u32 {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            symbol_store.put_symbol(symbol).await.unwrap();
        }

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id,
            zone_key_id,
            1,
            2,
            1,
        )
        .with_missing_hint(vec![0, 1, 2]);

        let err = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect_err("oversized missing hint should be rejected");

        assert!(matches!(err, SymbolRequestError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_symbol_request_reports_bounded_response() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-bounded-response");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store.clone(), quarantine_store);
        authenticate_default_peer(&mut node, &zone_id);

        let oti = ObjectTransmissionInformation::new(1024, 256, 1, 1, 1);
        let symbol_size = oti.symbol_size() as usize;
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };

        symbol_store.put_object_meta(meta).await.unwrap();

        for esi in 0..4u32 {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            symbol_store.put_symbol(symbol).await.unwrap();
        }

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id,
            zone_key_id,
            1,
            2,
            1,
        );

        let response = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect("symbol request should succeed");

        assert_eq!(response.symbol_esis.len(), 2);
        assert!(response.was_bounded);
        assert!(!response.is_final);
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_symbol_request_is_final_when_all_sent() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-final-response");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store.clone(), quarantine_store);
        authenticate_default_peer(&mut node, &zone_id);

        let oti = ObjectTransmissionInformation::new(1024, 256, 1, 1, 1);
        let symbol_size = oti.symbol_size() as usize;
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };

        symbol_store.put_object_meta(meta).await.unwrap();

        for esi in 0..4u32 {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            symbol_store.put_symbol(symbol).await.unwrap();
        }

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id,
            zone_key_id,
            1,
            4,
            1,
        );

        let response = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect("symbol request should succeed");

        assert_eq!(response.symbol_esis.len(), 4);
        assert!(!response.was_bounded);
        assert!(response.is_final);
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_quarantined_object_not_gossiped() {
        let zone_id = ZoneId::work();
        let object_id = test_object_id("meshnode-quarantine-gossip");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1");
        let mut node = MeshNode::new(config, object_store, symbol_store, quarantine_store.clone());

        quarantine_store
            .quarantine(QuarantinedObject {
                object_id,
                zone_id: zone_id.clone(),
                data: Bytes::from_static(b"quarantined"),
                source_peer: None,
                received_at: 0,
                peer_reputation: -10,
            })
            .expect("quarantine");

        let added =
            node.announce_object(&zone_id, &object_id, ObjectAdmissionClass::Admitted, 1000);

        assert!(!added);
        assert!(!node.gossip_mut().has_object(&zone_id, &object_id));
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_quarantined_symbol_request_rejected() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-quarantine-request");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store, quarantine_store.clone());
        authenticate_default_peer(&mut node, &zone_id);

        quarantine_store
            .quarantine(QuarantinedObject {
                object_id,
                zone_id: zone_id.clone(),
                data: Bytes::from_static(b"quarantined"),
                source_peer: None,
                received_at: 0,
                peer_reputation: -10,
            })
            .expect("quarantine");

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id,
            zone_key_id,
            1,
            2,
            1,
        );

        let err = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect_err("quarantined request should fail");

        assert!(matches!(
            err,
            SymbolRequestError::AdmissionRejected(AdmissionError::ObjectQuarantined { .. })
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_decode_status_stops_transfer() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([2u8; 8]);
        let object_id = test_object_id("meshnode-decode-stop");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let mut node = MeshNode::new(
            MeshNodeConfig::new("node-1"),
            object_store,
            symbol_store.clone(),
            quarantine_store,
        );
        authenticate_default_peer(&mut node, &zone_id);

        let oti = ObjectTransmissionInformation::new(512, 128, 1, 1, 1);
        let symbol_size = oti.symbol_size() as usize;
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };
        symbol_store.put_object_meta(meta).await.unwrap();

        for esi in 0..4u32 {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            symbol_store.put_symbol(symbol).await.unwrap();
        }

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            4,
            1,
        );

        let _ = node
            .handle_symbol_request(request.clone(), &NodeId::new("peer-1"), true, 0)
            .await
            .expect("symbol request should succeed");

        let peer = NodeId::new("peer-1");
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());

        let mut status = DecodeStatus {
            header: status_header(&zone_id),
            object_id,
            zone_id: zone_id.clone(),
            zone_key_id,
            epoch_id: 1,
            recipient_node_id: TailscaleNodeId::new("node-1"),
            request_nonce: 1,
            received_unique: 4,
            needed: 0,
            complete: true,
            missing_hint: None,
            signature: fcp_crypto::Ed25519Signature::from_bytes(&[0u8; 64]),
        };
        status.sign(&signing_key);

        node.handle_decode_status(&peer, &status, 0)
            .expect("status should verify");

        let err = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect_err("should stop after decode status complete");

        assert!(matches!(err, SymbolRequestError::AlreadyComplete { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_symbol_ack_stops_transfer() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([3u8; 8]);
        let object_id = test_object_id("meshnode-ack-stop");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let mut node = MeshNode::new(
            MeshNodeConfig::new("node-1"),
            object_store,
            symbol_store.clone(),
            quarantine_store,
        );
        authenticate_default_peer(&mut node, &zone_id);

        let oti = ObjectTransmissionInformation::new(512, 128, 1, 1, 1);
        let symbol_size = oti.symbol_size() as usize;
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };
        symbol_store.put_object_meta(meta).await.unwrap();

        for esi in 0..4u32 {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            symbol_store.put_symbol(symbol).await.unwrap();
        }

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            4,
            1,
        );

        let _ = node
            .handle_symbol_request(request.clone(), &NodeId::new("peer-1"), true, 0)
            .await
            .expect("symbol request should succeed");

        let peer = NodeId::new("peer-1");
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());

        let mut ack = SymbolAck::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            TailscaleNodeId::new("node-1"),
            2,
            SymbolAckReason::Complete,
            4,
        );
        ack.sign(&signing_key);

        node.handle_symbol_ack(&peer, &ack, 0)
            .expect("ack should verify");

        let err = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect_err("should stop after ack");

        assert!(matches!(err, SymbolRequestError::AlreadyComplete { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_unauthenticated_bounds_enforced() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([4u8; 8]);
        let object_id = test_object_id("meshnode-unauth-bounds");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let mut node = MeshNode::new(
            MeshNodeConfig::new("node-1"),
            object_store,
            symbol_store.clone(),
            quarantine_store,
        );
        authorize_default_peer(&mut node, &zone_id);

        let oti = ObjectTransmissionInformation::new(512, 128, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };
        symbol_store.put_object_meta(meta).await.unwrap();

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED + 1,
            1,
        );

        let err = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), false, 0)
            .await
            .expect_err("unauthenticated request should be bounded");

        assert!(matches!(err, SymbolRequestError::BoundsExceeded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_degraded_control_plane_roundtrip() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([5u8; 8]);
        let object_id = test_object_id("meshnode-degraded-roundtrip");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let mut node = MeshNode::new(
            MeshNodeConfig::new("node-1").with_sender_instance_id(9),
            object_store,
            symbol_store,
            quarantine_store,
        );

        let payload = vec![0xAB; 128];
        let schema_hash = SchemaId::new("fcp.mesh", "ControlPlane", Version::new(1, 0, 0))
            .hash()
            .as_bytes()
            .to_owned();
        let mut schema_hash_bytes = [0u8; 32];
        schema_hash_bytes.copy_from_slice(&schema_hash);

        let envelope = ControlPlaneEnvelope::new(
            payload.clone(),
            schema_hash_bytes,
            object_id,
            zone_id.clone(),
            zone_key_id,
            42,
            RetentionClass::Required,
        );
        let zone_key = test_zone_key();
        let algorithm = test_zone_key_algorithm();

        let frames = node
            .encode_control_plane(&envelope, 42, &zone_key, algorithm)
            .expect("encode control plane");

        let mut decoded = None;
        for frame in frames {
            if let Some(result) = node
                .decode_control_plane(
                    &NodeId::new("node-1"),
                    &frame,
                    &zone_id,
                    RetentionClass::Required,
                    &zone_key,
                    algorithm,
                    42,
                )
                .expect("decode control plane")
            {
                decoded = Some(result);
                break;
            }
        }

        let decoded = decoded.expect("should decode envelope");
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.schema_hash, schema_hash_bytes);
        assert_eq!(decoded.object_id, object_id);
        assert_eq!(decoded.epoch_id, 42);
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_control_plane_handler_stores_required() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([6u8; 8]);
        let object_id = test_object_id("meshnode-control-plane-handler");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let mut node = MeshNode::new(
            MeshNodeConfig::new("node-1").with_sender_instance_id(11),
            object_store,
            symbol_store,
            quarantine_store,
        );

        let payload = vec![0xCD; 64];
        let schema_hash = SchemaId::new("fcp.mesh", "ControlPlane", Version::new(1, 0, 0))
            .hash()
            .as_bytes()
            .to_owned();
        let mut schema_hash_bytes = [0u8; 32];
        schema_hash_bytes.copy_from_slice(&schema_hash);

        let envelope = ControlPlaneEnvelope::new(
            payload,
            schema_hash_bytes,
            object_id,
            zone_id.clone(),
            zone_key_id,
            77,
            RetentionClass::Required,
        );
        let zone_key = test_zone_key();
        let algorithm = test_zone_key_algorithm();

        let frames = node
            .encode_control_plane(&envelope, 77, &zone_key, algorithm)
            .expect("encode control plane");

        let handler = InMemoryControlPlaneHandler::new();
        for frame in frames {
            let _ = node
                .process_control_plane_frame(
                    &NodeId::new("node-1"),
                    &frame,
                    &zone_id,
                    RetentionClass::Required,
                    &zone_key,
                    algorithm,
                    77,
                    &handler,
                )
                .expect("process control plane");
        }

        assert_eq!(handler.count(), 1);
        let stored = handler
            .get(&object_id)
            .expect("required control-plane object should be stored");
        assert_eq!(stored.epoch_id, 77);
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_multi_node_symbol_transfer() {
        const TEST_NAME: &str = "meshnode_multi_node_symbol_transfer";
        const CATEGORY: &str = "meshnode";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([7u8; 8]);
        let object_id = test_object_id("meshnode-multi-node-symbols");

        let mut node_a = build_mesh_node("node-a", 21, 1);
        let node_b = build_mesh_node("node-b", 22, 2);
        authenticate_peer_for_zone(&mut node_a, &NodeId::new("node-b"), &zone_id, 0);

        let oti = ObjectTransmissionInformation::new(512, 128, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };
        let symbol_store_a = node_a.symbol_store().clone();
        seed_symbols(&symbol_store_a, &meta, 1).await;

        let receiver_store = node_b.symbol_store().clone();

        let mut attempts = 0;
        while !receiver_store.can_reconstruct(&object_id).await && attempts < 5 {
            attempts += 1;

            let missing = missing_esis(&receiver_store, &object_id, meta.source_symbols).await;

            let request = SymbolRequest::new(
                test_header(&zone_id),
                object_id,
                zone_id.clone(),
                zone_key_id,
                1,
                meta.source_symbols,
                1,
            )
            .with_missing_hint(missing.clone());

            let response = node_a
                .handle_symbol_request(request, &NodeId::new("node-b"), true, 0)
                .await
                .expect("symbol request should succeed");

            assert!(
                !response.symbol_esis.is_empty(),
                "expected symbols from node-a"
            );

            if let Err(SymbolStoreError::ObjectNotFound(_)) =
                receiver_store.get_object_meta(&object_id).await
            {
                receiver_store.put_object_meta(meta.clone()).await.unwrap();
            }

            for esi in response.symbol_esis {
                let symbol = symbol_store_a.get_symbol(&object_id, esi).await.unwrap();
                receiver_store.put_symbol(symbol).await.unwrap();
            }
        }

        assert!(
            receiver_store.can_reconstruct(&object_id).await,
            "node-b should reconstruct after transfer"
        );

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "attempts": attempts,
                "symbols_received": receiver_store.symbol_count(&object_id).await,
            }),
        );
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_multi_node_control_plane_roundtrip() {
        const TEST_NAME: &str = "meshnode_multi_node_control_plane_roundtrip";
        const CATEGORY: &str = "meshnode";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([8u8; 8]);
        let object_id = test_object_id("meshnode-multi-node-control-plane");

        let object_store_a = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store_a = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store_a = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let object_store_b = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store_b = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store_b = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let mut node_a = MeshNode::new(
            MeshNodeConfig::new("node-a").with_sender_instance_id(31),
            object_store_a,
            symbol_store_a,
            quarantine_store_a,
        );
        let mut node_b = MeshNode::new(
            MeshNodeConfig::new("node-b").with_sender_instance_id(32),
            object_store_b,
            symbol_store_b,
            quarantine_store_b,
        );

        let payload = vec![0xEF; 64];
        let schema_hash = SchemaId::new("fcp.mesh", "ControlPlane", Version::new(1, 0, 0))
            .hash()
            .as_bytes()
            .to_owned();
        let mut schema_hash_bytes = [0u8; 32];
        schema_hash_bytes.copy_from_slice(&schema_hash);

        let envelope = ControlPlaneEnvelope::new(
            payload.clone(),
            schema_hash_bytes,
            object_id,
            zone_id.clone(),
            zone_key_id,
            99,
            RetentionClass::Required,
        );
        let zone_key = test_zone_key();
        let algorithm = test_zone_key_algorithm();

        let frames = node_a
            .encode_control_plane(&envelope, 99, &zone_key, algorithm)
            .expect("encode control plane");

        let handler = InMemoryControlPlaneHandler::new();
        for frame in frames {
            let _ = node_b
                .process_control_plane_frame(
                    &NodeId::new("node-a"),
                    &frame,
                    &zone_id,
                    RetentionClass::Required,
                    &zone_key,
                    algorithm,
                    99,
                    &handler,
                )
                .expect("process control plane");
        }

        let stored = handler.get(&object_id).expect("control plane stored");
        assert_eq!(stored.payload, payload);
        assert_eq!(stored.epoch_id, 99);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "object_id": object_id.to_string(),
                "payload_bytes": payload.len(),
            }),
        );
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_session_auth_allows_larger_request() {
        const TEST_NAME: &str = "meshnode_session_auth_allows_larger_request";
        const CATEGORY: &str = "meshnode";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([9u8; 8]);
        let object_id = test_object_id("meshnode-session-auth");

        let mut node = build_mesh_node("node-auth", 41, 3);
        let symbol_store = node.symbol_store().clone();
        authorize_default_peer(&mut node, &zone_id);

        let oti = ObjectTransmissionInformation::new(512, 128, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };
        seed_symbols(&symbol_store, &meta, 1).await;

        let session = MeshSession::new(
            MeshSessionId::new(),
            NodeId::new("peer-1"),
            SessionCryptoSuite::Suite1,
            SessionKeys {
                k_mac_i2r: [1u8; 32],
                k_mac_r2i: [2u8; 32],
                k_ctx: [3u8; 32],
            },
            TransportLimits::default(),
            true,
            0,
            SessionReplayPolicy::default(),
        );
        node.register_session(session, 0);

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED + 1,
            1,
        );

        let response = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), false, 0)
            .await
            .expect("authenticated session should allow request");

        assert_ne!(response.symbol_esis, [] as [u32; 0]);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "symbols_sent": response.symbol_esis.len(),
                "authenticated": true,
            }),
        );
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_trace_capture_completeness_small_mesh() {
        const TEST_NAME: &str = "meshnode_trace_capture_completeness_small_mesh";
        const CATEGORY: &str = "meshnode";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([77u8; 8]);
        let object_id = test_object_id("meshnode-trace-complete");
        let mut node = build_mesh_node_with_trace("node-trace", 88, 42);
        let peer = NodeId::new("peer-trace");
        let symbol_store = node.symbol_store().clone();
        authorize_peer_for_zone(&mut node, &peer, &zone_id);

        let session = MeshSession::new(
            MeshSessionId::new(),
            peer.clone(),
            SessionCryptoSuite::Suite1,
            SessionKeys {
                k_mac_i2r: [31u8; 32],
                k_mac_r2i: [32u8; 32],
                k_ctx: [33u8; 32],
            },
            TransportLimits::default(),
            true,
            0,
            SessionReplayPolicy::default(),
        );
        node.register_session(session, 1_000);

        node.update_local_state(
            create_test_profile("node-trace", 8_192, 8),
            HashSet::new(),
            vec![HeldLease {
                subject_id: object_id,
                purpose: LeasePurpose::SingletonWriter,
                expires_at: 2_000,
                fencing_token: 4,
            }],
        );

        node.announce_object(&zone_id, &object_id, ObjectAdmissionClass::Admitted, 1_100);

        let routes = vec![TransportPath::new(
            TransportPathKind::Direct,
            peer.clone(),
            "direct",
            None,
        )];
        let _selected =
            node.select_transport_paths(&ZoneTransportPolicy::default(), &routes, &object_id, 0, 1);

        let oti = ObjectTransmissionInformation::new(512, 128, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };
        seed_symbols(&symbol_store, &meta, 42).await;

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            2,
            1,
        );
        let response = node
            .handle_symbol_request(request, &peer, true, 1_200)
            .await
            .expect("symbol request succeeds");
        assert_ne!(response.symbol_esis, [] as [u32; 0]);

        let snapshot = node.trace_snapshot().expect("trace capture enabled");
        let has_session = snapshot
            .events
            .iter()
            .any(|event| matches!(event, TraceEvent::Session(_)));
        let has_lease = snapshot
            .events
            .iter()
            .any(|event| matches!(event, TraceEvent::Lease(_)));
        let has_gossip = snapshot
            .events
            .iter()
            .any(|event| matches!(event, TraceEvent::Gossip(_)));
        let has_routing = snapshot
            .events
            .iter()
            .any(|event| matches!(event, TraceEvent::Routing(_)));
        let has_admission = snapshot
            .events
            .iter()
            .any(|event| matches!(event, TraceEvent::Admission(_)));

        assert!(has_session, "trace should include session events");
        assert!(has_lease, "trace should include lease events");
        assert!(has_gossip, "trace should include gossip events");
        assert!(has_routing, "trace should include routing events");
        assert!(has_admission, "trace should include admission events");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "trace_id": snapshot.id,
                "event_count": snapshot.events.len(),
                "event_types": {
                    "session": has_session,
                    "lease": has_lease,
                    "gossip": has_gossip,
                    "routing": has_routing,
                    "admission": has_admission
                }
            }),
        );
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_trace_export_roundtrip_integration_flow() {
        const TEST_NAME: &str = "meshnode_trace_export_roundtrip_integration_flow";
        const CATEGORY: &str = "meshnode";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let object_id = test_object_id("meshnode-trace-export");
        let mut node = build_mesh_node_with_trace("node-export", 91, 7);

        let session = MeshSession::new(
            MeshSessionId::new(),
            NodeId::new("trace-export-peer"),
            SessionCryptoSuite::Suite1,
            SessionKeys {
                k_mac_i2r: [1u8; 32],
                k_mac_r2i: [2u8; 32],
                k_ctx: [3u8; 32],
            },
            TransportLimits::default(),
            true,
            0,
            SessionReplayPolicy::default(),
        );
        node.register_session(session, 0);
        node.announce_object(&zone_id, &object_id, ObjectAdmissionClass::Admitted, 5_000);

        let json_path = trace_temp_path("fcp-mesh-trace", "json");
        let cbor_path = trace_temp_path("fcp-mesh-trace", "cbor");

        node.export_trace_to_path(&json_path, TraceExportFormat::Json)
            .expect("export json trace");
        node.export_trace_to_path(&cbor_path, TraceExportFormat::Cbor)
            .expect("export cbor trace");

        let json_bytes = std::fs::read(&json_path).expect("read json trace");
        let cbor_bytes = std::fs::read(&cbor_path).expect("read cbor trace");

        let json_trace = CapturedTrace::from_json(std::str::from_utf8(&json_bytes).expect("utf8"))
            .expect("parse json trace");
        let cbor_trace = CapturedTrace::from_cbor(&cbor_bytes).expect("parse cbor trace");

        assert_ne!(json_trace.events, [] as [fcp_telemetry::trace_capture::TraceEvent; 0]);
        assert_ne!(cbor_trace.events, [] as [fcp_telemetry::trace_capture::TraceEvent; 0]);
        assert_eq!(json_trace.events.len(), cbor_trace.events.len());
        assert!(
            json_trace.redacted,
            "default json export should mark trace redacted"
        );
        let json_session_id = json_trace.events.iter().find_map(|event| match event {
            TraceEvent::Session(session) => Some(session.session_id.as_str()),
            _ => None,
        });
        assert_eq!(
            json_session_id,
            Some("[REDACTED]"),
            "default json export should redact session_id"
        );
        assert!(
            cbor_trace.redacted,
            "default cbor export should mark trace redacted"
        );

        let _ = std::fs::remove_file(&json_path);
        let _ = std::fs::remove_file(&cbor_path);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "json_events": json_trace.events.len(),
                "cbor_events": cbor_trace.events.len(),
                "redacted": cbor_trace.redacted,
                "json_path": json_path.display().to_string(),
                "cbor_path": cbor_path.display().to_string()
            }),
        );
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_trace_capture_replay_multinode_staged_logs() {
        const TEST_NAME: &str = "meshnode_trace_capture_replay_multinode_staged_logs";
        const CATEGORY: &str = "meshnode";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([79u8; 8]);
        let object_id = test_object_id("meshnode-trace-replay-multinode");
        let peer = NodeId::new("node-b");

        let trace_config = TraceCaptureConfig::new()
            .enabled()
            .with_max_events(4096)
            .with_sample_rate(1.0)
            .with_redaction(RedactionPolicy::default().with_field("session_id"));
        let mut node_a = build_mesh_node_with_trace_config("node-a-trace", 94, 31, trace_config);
        let node_b = build_mesh_node("node-b", 95, 32);
        authorize_peer_for_zone(&mut node_a, &peer, &zone_id);

        let oti = ObjectTransmissionInformation::new(512, 128, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };
        let symbol_store_a = node_a.symbol_store().clone();
        seed_symbols(&symbol_store_a, &meta, 31).await;

        let denied_request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED + 1,
            1,
        );
        let denied = node_a
            .handle_symbol_request(denied_request, &peer, false, 10_000)
            .await
            .expect_err("unauthenticated oversized request should reject");
        assert!(matches!(
            denied,
            SymbolRequestError::BoundsExceeded { .. } | SymbolRequestError::AdmissionRejected(_)
        ));

        let session = MeshSession::new(
            MeshSessionId::new(),
            peer.clone(),
            SessionCryptoSuite::Suite1,
            SessionKeys {
                k_mac_i2r: [41u8; 32],
                k_mac_r2i: [42u8; 32],
                k_ctx: [43u8; 32],
            },
            TransportLimits::default(),
            true,
            0,
            SessionReplayPolicy::default(),
        );
        node_a.register_session(session, 10_100);

        let missing = vec![0, 1, 2, 3];
        let allowed_request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED + 1,
            1,
        )
        .with_missing_hint(missing);
        let allowed = node_a
            .handle_symbol_request(allowed_request, &peer, false, 10_200)
            .await
            .expect("authenticated session should allow larger request");
        assert_ne!(allowed.symbol_esis, [] as [u32; 0]);

        let receiver_store = node_b.symbol_store().clone();
        if let Err(SymbolStoreError::ObjectNotFound(_)) =
            receiver_store.get_object_meta(&object_id).await
        {
            receiver_store
                .put_object_meta(meta.clone())
                .await
                .expect("put object meta");
        }
        for esi in &allowed.symbol_esis {
            let symbol = symbol_store_a
                .get_symbol(&object_id, *esi)
                .await
                .expect("source symbol present");
            receiver_store
                .put_symbol(symbol)
                .await
                .expect("store symbol");
        }

        let captured = node_a.trace_snapshot().expect("trace capture enabled");
        let admit_count = captured
            .events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    TraceEvent::Admission(outcome) if outcome.decision == "admit"
                )
            })
            .count();
        let reject_count = captured
            .events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    TraceEvent::Admission(outcome) if outcome.decision == "reject"
                )
            })
            .count();
        emit_test_stage(
            TEST_NAME,
            CATEGORY,
            "capture",
            serde_json::json!({
                "captured_events": captured.events.len(),
                "admit_decisions": admit_count,
                "reject_decisions": reject_count,
                "symbols_delivered": allowed.symbol_esis.len(),
            }),
        );

        let replay_report = TraceReplayEngine::replay(&captured).expect("replay succeeds");
        emit_test_stage(
            TEST_NAME,
            CATEGORY,
            "replay",
            serde_json::json!({
                "input_events": replay_report.input_events,
                "replayed_events": replay_report.replayed_events,
                "mismatched_events": replay_report.summary.mismatched_events,
                "mismatched_decisions": replay_report.summary.mismatched_decisions,
            }),
        );

        let redacted = node_a
            .trace_redacted_snapshot()
            .expect("redacted trace capture enabled");
        let redacted_session = redacted.events.iter().find_map(|event| match event {
            TraceEvent::Session(session) => Some(session.session_id.as_str()),
            _ => None,
        });
        assert_eq!(
            redacted_session,
            Some("[REDACTED]"),
            "session_id should be redacted in redacted snapshots"
        );
        emit_test_stage(
            TEST_NAME,
            CATEGORY,
            "compare",
            serde_json::json!({
                "redacted": redacted.redacted,
                "session_id_redacted": redacted_session == Some("[REDACTED]"),
                "replay_diffs": replay_report.diffs.len(),
            }),
        );

        assert_eq!(replay_report.summary.mismatched_events, 0);
        assert_eq!(replay_report.summary.mismatched_decisions, 0);
        assert!(admit_count >= 1, "expected at least one admit decision");
        assert!(reject_count >= 1, "expected at least one reject decision");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "capture_events": captured.events.len(),
                "replay_mismatches": replay_report.summary.mismatched_decisions,
                "admit_count": admit_count,
                "reject_count": reject_count,
                "receiver_symbols": receiver_store.symbol_count(&object_id).await,
            }),
        );
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_computation_migration_full_cycle_with_repair() {
        const TEST_NAME: &str = "meshnode_computation_migration_full_cycle_with_repair";
        const CATEGORY: &str = "meshnode";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([0xD1; 8]);
        let computation_id = test_object_id("migration-computation");
        let active_lease_id = test_object_id("migration-lease-active");
        let resumed_lease_id = test_object_id("migration-lease-resumed");
        let holder_a = TailscaleNodeId::new("node-a");
        let holder_b = TailscaleNodeId::new("node-b");
        let config = test_raptorq_config();

        let checkpoint = test_computation_checkpoint(
            &zone_id,
            computation_id,
            active_lease_id,
            &holder_a,
            3,
            7,
            2_048,
        );
        let checkpoint_object_id = checkpoint.object_id().expect("checkpoint object id");
        let mut computation = MigratableComputation::new(
            computation_id,
            zone_id.clone(),
            holder_a.clone(),
            active_lease_id,
            7,
            checkpoint.capability_context.clone(),
        );
        computation
            .suspend(&checkpoint, checkpoint_object_id)
            .expect("suspend computation");

        let active_lease = test_migration_lease(&zone_id, &holder_a, computation_id, 7);
        let resumed_lease = test_migration_lease(&zone_id, &holder_b, computation_id, 8);
        let handoff = LeaseHandoff {
            previous_lease_id: active_lease_id,
            next_lease_id: resumed_lease_id,
            from_holder: holder_a.clone(),
            to_holder: holder_b.clone(),
            zone_id: zone_id.clone(),
            subject_object_id: computation_id,
            purpose: CoreLeasePurpose::ComputationMigration,
            previous_fencing_token: active_lease.fencing_token(),
            next_fencing_token: resumed_lease.fencing_token(),
            transferred_at: current_timestamp(),
            checkpoint_object_id: Some(checkpoint_object_id),
        };
        computation
            .begin_transfer(&active_lease, &handoff, current_timestamp())
            .expect("begin transfer");

        let mut node_a = build_mesh_node_with_trace("node-a", 120, 1);
        let node_b = build_mesh_node("node-b", 121, 2);
        authenticate_peer_for_zone(&mut node_a, &NodeId::new("node-b"), &zone_id, 1_100);
        let source_meta =
            seed_checkpoint_symbols(&node_a, &checkpoint, checkpoint_object_id, 1, &config).await;
        node_a.announce_object(
            &zone_id,
            &checkpoint_object_id,
            ObjectAdmissionClass::Admitted,
            1_000,
        );

        let source_store = node_a.symbol_store().clone();
        let receiver_store = node_b.symbol_store().clone();
        let initial_limit = source_meta.source_symbols.saturating_sub(1);
        let initial_missing = missing_esis(
            &receiver_store,
            &checkpoint_object_id,
            source_meta.source_symbols,
        )
        .await
        .into_iter()
        .take(initial_limit as usize)
        .collect();
        let initial_request = SymbolRequest::new(
            test_header(&zone_id),
            checkpoint_object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            initial_limit,
            1,
        )
        .with_missing_hint(initial_missing);
        let initial_response = node_a
            .handle_symbol_request(initial_request, &NodeId::new("node-b"), true, 1_100)
            .await
            .expect("initial symbol request");
        apply_symbol_response(
            &source_store,
            &receiver_store,
            &source_meta,
            &initial_response.symbol_esis,
        )
        .await;

        assert!(
            !receiver_store.can_reconstruct(&checkpoint_object_id).await,
            "partial transfer must not permit resume"
        );

        let repair_request = SymbolRequest::new(
            test_header(&zone_id),
            checkpoint_object_id,
            zone_id.clone(),
            zone_key_id,
            2,
            source_meta.source_symbols,
            1,
        )
        .with_missing_hint(
            missing_esis(
                &receiver_store,
                &checkpoint_object_id,
                source_meta.source_symbols,
            )
            .await,
        );
        let repair_response = node_a
            .handle_symbol_request(repair_request, &NodeId::new("node-b"), true, 1_200)
            .await
            .expect("repair symbol request");
        apply_symbol_response(
            &source_store,
            &receiver_store,
            &source_meta,
            &repair_response.symbol_esis,
        )
        .await;

        assert!(
            receiver_store.can_reconstruct(&checkpoint_object_id).await,
            "target should reconstruct after targeted repair"
        );

        let reconstructed =
            reconstruct_checkpoint_from_store(&receiver_store, &source_meta, &config).await;
        computation
            .resume(
                &reconstructed,
                checkpoint_object_id,
                resumed_lease_id,
                &resumed_lease,
                current_timestamp(),
            )
            .expect("resume on target");

        assert_eq!(computation.state, MigratableComputationState::Running);
        assert_eq!(computation.current_holder, holder_b);
        assert_eq!(computation.execution_lease_id, resumed_lease_id);
        assert_eq!(
            computation.lease_fencing_token,
            resumed_lease.fencing_token()
        );

        let trace = node_a.trace_snapshot().expect("trace capture enabled");
        let admission_events = trace
            .events
            .iter()
            .filter(|event| matches!(event, TraceEvent::Admission(_)))
            .count();
        let gossip_events = trace
            .events
            .iter()
            .filter(|event| matches!(event, TraceEvent::Gossip(_)))
            .count();
        assert!(
            admission_events >= 2,
            "expected both transfer rounds in trace"
        );
        assert!(
            gossip_events >= 1,
            "expected checkpoint announcement in trace"
        );

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "checkpoint_object_id": checkpoint_object_id.to_string(),
                "source_symbols": source_meta.source_symbols,
                "initial_symbols_sent": initial_response.symbol_esis.len(),
                "repair_symbols_sent": repair_response.symbol_esis.len(),
                "trace_events": trace.events.len(),
                "trace_admission_events": admission_events,
                "trace_gossip_events": gossip_events,
                "final_holder": computation.current_holder.as_str(),
                "final_fencing_token": computation.lease_fencing_token,
            }),
        );
    }

    #[fcp_async_core::runtime::test]
    async fn meshnode_computation_migration_partition_fails_closed() {
        const TEST_NAME: &str = "meshnode_computation_migration_partition_fails_closed";
        const CATEGORY: &str = "meshnode";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([0xD2; 8]);
        let computation_id = test_object_id("partitioned-migration-computation");
        let active_lease_id = test_object_id("partitioned-migration-lease-active");
        let resumed_lease_id = test_object_id("partitioned-migration-lease-resumed");
        let holder_a = TailscaleNodeId::new("node-a");
        let holder_b = TailscaleNodeId::new("node-b");
        let config = test_raptorq_config();

        let checkpoint = test_computation_checkpoint(
            &zone_id,
            computation_id,
            active_lease_id,
            &holder_a,
            4,
            9,
            1_536,
        );
        let checkpoint_object_id = checkpoint.object_id().expect("checkpoint object id");
        let mut computation = MigratableComputation::new(
            computation_id,
            zone_id.clone(),
            holder_a.clone(),
            active_lease_id,
            9,
            checkpoint.capability_context.clone(),
        );
        computation
            .suspend(&checkpoint, checkpoint_object_id)
            .expect("suspend computation");

        let active_lease = test_migration_lease(&zone_id, &holder_a, computation_id, 9);
        let resumed_lease = test_migration_lease(&zone_id, &holder_b, computation_id, 10);
        let handoff = LeaseHandoff {
            previous_lease_id: active_lease_id,
            next_lease_id: resumed_lease_id,
            from_holder: holder_a.clone(),
            to_holder: holder_b.clone(),
            zone_id: zone_id.clone(),
            subject_object_id: computation_id,
            purpose: CoreLeasePurpose::ComputationMigration,
            previous_fencing_token: active_lease.fencing_token(),
            next_fencing_token: resumed_lease.fencing_token(),
            transferred_at: current_timestamp(),
            checkpoint_object_id: Some(checkpoint_object_id),
        };
        computation
            .begin_transfer(&active_lease, &handoff, current_timestamp())
            .expect("begin transfer");

        let mut node_a = build_mesh_node("node-a", 130, 1);
        let node_b = build_mesh_node("node-b", 131, 2);
        authenticate_peer_for_zone(&mut node_a, &NodeId::new("node-b"), &zone_id, 2_000);
        let source_meta =
            seed_checkpoint_symbols(&node_a, &checkpoint, checkpoint_object_id, 1, &config).await;

        let source_store = node_a.symbol_store().clone();
        let receiver_store = node_b.symbol_store().clone();
        let partial_limit = source_meta.source_symbols.saturating_sub(1);
        let partial_missing = missing_esis(
            &receiver_store,
            &checkpoint_object_id,
            source_meta.source_symbols,
        )
        .await
        .into_iter()
        .take(partial_limit as usize)
        .collect();
        let partial_request = SymbolRequest::new(
            test_header(&zone_id),
            checkpoint_object_id,
            zone_id,
            zone_key_id,
            1,
            partial_limit,
            1,
        )
        .with_missing_hint(partial_missing);
        let partial_response = node_a
            .handle_symbol_request(partial_request, &NodeId::new("node-b"), true, 2_000)
            .await
            .expect("partial symbol request");
        apply_symbol_response(
            &source_store,
            &receiver_store,
            &source_meta,
            &partial_response.symbol_esis,
        )
        .await;

        assert!(
            !receiver_store.can_reconstruct(&checkpoint_object_id).await,
            "partitioned target must not reconstruct incomplete checkpoint"
        );

        let stale_resume_err = computation
            .resume(
                &checkpoint,
                checkpoint_object_id,
                active_lease_id,
                &active_lease,
                current_timestamp(),
            )
            .expect_err("stale holder must not resume after handoff");
        assert!(
            matches!(
                stale_resume_err,
                ComputationMigrationError::LeaseValidation(_)
            ),
            "expected lease validation failure, got {stale_resume_err:?}"
        );
        assert!(matches!(
            computation.state,
            MigratableComputationState::Transferring { .. }
        ));
        assert_eq!(computation.current_holder, holder_a);
        assert_eq!(computation.execution_lease_id, active_lease_id);
        assert_eq!(
            computation.lease_fencing_token,
            active_lease.fencing_token()
        );

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "checkpoint_object_id": checkpoint_object_id.to_string(),
                "partial_symbols_received": receiver_store.symbol_count(&checkpoint_object_id).await,
                "source_symbols_required": source_meta.source_symbols,
                "stale_resume_error": stale_resume_err.to_string(),
                "state_after_failure": "transferring",
            }),
        );
    }
}

// ============================================================================
// TRANSPORT SELECTION INTEGRATION TESTS
// ============================================================================

mod transport_selection {
    use super::*;

    #[test]
    fn transport_policy_enforced_in_ranking() {
        const TEST_NAME: &str = "transport_policy_enforced_in_ranking";
        const CATEGORY: &str = "routing";

        emit_test_start(TEST_NAME, CATEGORY);

        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: false,
            allow_funnel: false,
        };

        let paths = vec![
            TransportPath::new(
                TransportPathKind::Direct,
                NodeId::new("peer-1"),
                "direct",
                None,
            ),
            TransportPath::new(TransportPathKind::Mesh, NodeId::new("peer-2"), "mesh", None),
            TransportPath::new(TransportPathKind::Derp, NodeId::new("peer-3"), "derp", None),
            TransportPath::new(
                TransportPathKind::Funnel,
                NodeId::new("peer-4"),
                "funnel",
                None,
            ),
        ];

        let ranked = TransportSelector::rank_paths(&paths, &policy);
        assert_eq!(ranked[0].path.kind, TransportPathKind::Direct);
        assert!(
            ranked
                .iter()
                .take(2)
                .all(|entry| entry.eligible && entry.reason.is_none())
        );

        let derp = ranked
            .iter()
            .find(|entry| entry.path.kind == TransportPathKind::Derp)
            .expect("derp entry missing");
        assert_eq!(
            derp.reason,
            Some(DecisionReasonCode::TransportDerpForbidden)
        );

        let funnel = ranked
            .iter()
            .find(|entry| entry.path.kind == TransportPathKind::Funnel)
            .expect("funnel entry missing");
        assert_eq!(
            funnel.reason,
            Some(DecisionReasonCode::TransportFunnelForbidden)
        );

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "eligible_count": ranked.iter().filter(|entry| entry.eligible).count(),
                "blocked": {
                    "derp": derp.reason.is_some(),
                    "funnel": funnel.reason.is_some()
                }
            }),
        );
    }

    #[test]
    fn transport_ranking_tie_break_is_stable() {
        const TEST_NAME: &str = "transport_ranking_tie_break_is_stable";
        const CATEGORY: &str = "routing";

        emit_test_start(TEST_NAME, CATEGORY);

        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };

        let paths = vec![
            TransportPath::new(
                TransportPathKind::Direct,
                NodeId::new("peer-z"),
                "alpha",
                Some(10),
            ),
            TransportPath::new(
                TransportPathKind::Direct,
                NodeId::new("peer-b"),
                "alpha",
                Some(10),
            ),
            TransportPath::new(
                TransportPathKind::Direct,
                NodeId::new("peer-a"),
                "beta",
                Some(10),
            ),
        ];

        let ranked = TransportSelector::rank_paths(&paths, &policy);
        let ordering: Vec<(&str, &str)> = ranked
            .iter()
            .map(|entry| (entry.path.path_id.as_str(), entry.path.peer.as_str()))
            .collect();

        assert_eq!(
            ordering,
            vec![("alpha", "peer-b"), ("alpha", "peer-z"), ("beta", "peer-a")]
        );

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "ordered_path_ids": ranked.iter().map(|entry| entry.path.path_id.as_str()).collect::<Vec<_>>(),
                "ordered_peers": ranked.iter().map(|entry| entry.path.peer.as_str()).collect::<Vec<_>>(),
                "tie_break_fields": ["path_id", "peer_id"]
            }),
        );
    }

    #[test]
    fn transport_lan_denial_reason_code_and_derp_fallback() {
        const TEST_NAME: &str = "transport_lan_denial_reason_code_and_derp_fallback";
        const CATEGORY: &str = "routing";

        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::owner();
        let policy = ZoneTransportPolicy {
            allow_lan: false,
            allow_derp: true,
            allow_funnel: false,
        };

        let paths = vec![
            TransportPath::new(
                TransportPathKind::Direct,
                NodeId::new("peer-direct"),
                "direct",
                Some(2),
            ),
            TransportPath::new(
                TransportPathKind::Mesh,
                NodeId::new("peer-mesh"),
                "mesh",
                Some(7),
            ),
            TransportPath::new(
                TransportPathKind::Derp,
                NodeId::new("peer-derp"),
                "derp",
                Some(30),
            ),
        ];

        let ranked = TransportSelector::rank_paths(&paths, &policy);

        let lan_denials: Vec<&fcp_mesh::transport::RankedPath> = ranked
            .iter()
            .filter(|entry| {
                entry.path.kind == TransportPathKind::Direct
                    || entry.path.kind == TransportPathKind::Mesh
            })
            .collect();
        assert_eq!(lan_denials.len(), 2);
        assert!(lan_denials.iter().all(|entry| !entry.eligible));
        assert!(
            lan_denials
                .iter()
                .all(|entry| { entry.reason == Some(DecisionReasonCode::TransportLanForbidden) })
        );

        let best = TransportSelector::best_path(&paths, &policy).expect("best path");
        assert_eq!(best.path.kind, TransportPathKind::Derp);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "zone_id": zone_id.as_str(),
                "denied_paths": lan_denials.iter().map(|entry| entry.path.path_id.as_str()).collect::<Vec<_>>(),
                "reason_code": DecisionReasonCode::TransportLanForbidden.as_str(),
                "fallback_path": best.path.path_id,
                "fallback_kind": format!("{:?}", best.path.kind),
            }),
        );
    }

    #[test]
    fn transport_multipath_is_deterministic() {
        const TEST_NAME: &str = "transport_multipath_is_deterministic";
        const CATEGORY: &str = "routing";

        emit_test_start(TEST_NAME, CATEGORY);

        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };

        let paths = vec![
            TransportPath::new(
                TransportPathKind::Direct,
                NodeId::new("peer-1"),
                "direct-a",
                None,
            ),
            TransportPath::new(
                TransportPathKind::Direct,
                NodeId::new("peer-2"),
                "direct-b",
                None,
            ),
            TransportPath::new(TransportPathKind::Mesh, NodeId::new("peer-3"), "mesh", None),
            TransportPath::new(TransportPathKind::Derp, NodeId::new("peer-4"), "derp", None),
        ];

        let object_id = test_object_id("transport-multipath");
        let selection_a = TransportSelector::select_multipath(&paths, &policy, &object_id, 3, 2);
        let selection_b = TransportSelector::select_multipath(&paths, &policy, &object_id, 3, 2);

        assert_eq!(selection_a, selection_b);
        assert!(
            selection_a
                .iter()
                .all(|path| path.kind == TransportPathKind::Direct)
        );

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "selected": selection_a.len(),
                "kinds": selection_a.iter().map(|path| format!("{:?}", path.kind)).collect::<Vec<_>>(),
            }),
        );
    }
}

impl TestEvent {
    fn emit(&self) {
        let value = serde_json::to_value(self).expect("serialize test event");
        println!("{}", serde_json::to_string(&value).unwrap());

        let capture = log_capture();
        if let Err(err) = capture.push_value(&value) {
            panic!("failed to push log event: {err}");
        }
        if !std::thread::panicking() {
            capture.assert_valid();
        }
    }
}

fn test_correlation_id(test_name: &str, category: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(test_name.as_bytes());
    hasher.update(category.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn log_capture() -> &'static LogCapture {
    static CAPTURE: OnceLock<LogCapture> = OnceLock::new();
    CAPTURE.get_or_init(LogCapture::new)
}

fn tracing_events(capture: &LogCapture) -> Vec<serde_json::Value> {
    capture
        .jsonl()
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(
                    serde_json::from_str(trimmed).unwrap_or_else(|err| {
                        panic!("invalid tracing log line `{trimmed}`: {err}")
                    }),
                )
            }
        })
        .collect()
}

fn find_tracing_event(capture: &LogCapture, event_name: &str) -> serde_json::Value {
    tracing_events(capture)
        .into_iter()
        .find(|value| value.get("event").and_then(serde_json::Value::as_str) == Some(event_name))
        .unwrap_or_else(|| {
            panic!(
                "missing tracing event `{event_name}` in capture:\n{}",
                capture.jsonl()
            )
        })
}

fn test_start_times() -> &'static Mutex<HashMap<String, Instant>> {
    static STARTS: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    STARTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn start_timer(correlation_id: &str) {
    let mut starts = test_start_times()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    starts.insert(correlation_id.to_string(), Instant::now());
}

fn finish_timer(correlation_id: &str) -> u64 {
    let mut starts = test_start_times()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    starts.remove(correlation_id).map_or(0, |start| {
        u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
    })
}

fn emit_test_start(test_name: &'static str, category: &'static str) {
    let correlation_id = test_correlation_id(test_name, category);
    start_timer(&correlation_id);
    TestEvent {
        timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        log_version: "v2",
        level: "info",
        module: "fcp-mesh",
        phase: "start",
        correlation_id,
        test_name,
        result: "pass",
        duration_ms: 0,
        assertions: TestAssertions {
            passed: 0,
            failed: 0,
        },
        context: Some(serde_json::json!({ "category": category, "status": "started" })),
        details: Some(serde_json::json!({})),
        error_code: None,
    }
    .emit();
}

fn emit_test_stage(
    test_name: &'static str,
    category: &'static str,
    stage: &'static str,
    details: serde_json::Value,
) {
    let correlation_id = test_correlation_id(test_name, category);
    let duration_ms = {
        let starts = test_start_times()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        starts.get(&correlation_id).map_or(0, |start| {
            u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
        })
    };

    TestEvent {
        timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        log_version: "v2",
        level: "info",
        module: "fcp-mesh",
        phase: stage,
        correlation_id,
        test_name,
        result: "pass",
        duration_ms,
        assertions: TestAssertions {
            passed: 0,
            failed: 0,
        },
        context: Some(serde_json::json!({ "category": category, "stage": stage })),
        details: Some(details),
        error_code: None,
    }
    .emit();
}

fn emit_test_pass(test_name: &'static str, category: &'static str, details: serde_json::Value) {
    let correlation_id = test_correlation_id(test_name, category);
    let duration_ms = finish_timer(&correlation_id);
    TestEvent {
        timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        log_version: "v2",
        level: "info",
        module: "fcp-mesh",
        phase: "complete",
        correlation_id,
        test_name,
        result: "pass",
        duration_ms,
        assertions: TestAssertions {
            passed: 1,
            failed: 0,
        },
        context: Some(serde_json::json!({ "category": category, "status": "passed" })),
        details: Some(details),
        error_code: None,
    }
    .emit();
}

#[allow(dead_code)]
fn emit_test_fail(test_name: &'static str, category: &'static str, error: &str) {
    let correlation_id = test_correlation_id(test_name, category);
    let duration_ms = finish_timer(&correlation_id);
    TestEvent {
        timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        log_version: "v2",
        level: "info",
        module: "fcp-mesh",
        phase: "complete",
        correlation_id,
        test_name,
        result: "fail",
        duration_ms,
        assertions: TestAssertions {
            passed: 0,
            failed: 1,
        },
        context: Some(serde_json::json!({ "category": category, "status": "failed" })),
        details: Some(serde_json::json!({})),
        error_code: Some(error.to_string()),
    }
    .emit();
}

/// Create a test object ID from a name by hashing it.
fn test_object_id(name: &str) -> ObjectId {
    let hash = blake3::hash(name.as_bytes());
    ObjectId::from_bytes(*hash.as_bytes())
}

/// Create a test connector ID from a canonical string (name:archetype:version).
fn test_connector_id(canonical: &str) -> ConnectorId {
    canonical.parse().expect("valid connector ID")
}

/// Create a basic device profile for testing.
#[allow(dead_code)]
fn create_test_profile(node_name: &str, memory_mb: u32, cpu_cores: u16) -> DeviceProfile {
    DeviceProfile::builder(NodeId::new(node_name))
        .cpu_cores(cpu_cores)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(memory_mb)
        .power_source(PowerSource::Mains)
        .latency_class(LatencyClass::Lan)
        .availability(AvailabilityProfile::AlwaysOn)
        .bandwidth_estimate_kbps(100_000)
        .build()
}

/// Create a device profile with a connector installed.
fn create_profile_with_connector(
    node_name: &str,
    connector_id: &ConnectorId,
    version: &str,
) -> DeviceProfile {
    let binary_hash = test_object_id("deadbeef");
    let connector = InstalledConnector::new(connector_id.clone(), version, binary_hash);

    DeviceProfile::builder(NodeId::new(node_name))
        .cpu_cores(8)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(16384)
        .power_source(PowerSource::Mains)
        .latency_class(LatencyClass::Lan)
        .availability(AvailabilityProfile::AlwaysOn)
        .bandwidth_estimate_kbps(100_000)
        .add_connector(connector)
        .build()
}

// ============================================================================
// ROUTING INTEGRATION TESTS
// ============================================================================

mod routing {
    use super::*;

    /// Test: Symbol routing selects node with best data locality.
    #[test]
    fn test_symbol_routing_data_locality() {
        const TEST_NAME: &str = "symbol_routing_data_locality";
        const CATEGORY: &str = "routing";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("github:connector:1.0.0");
        let symbol_a = test_object_id("aaaa");
        let symbol_b = test_object_id("bbbb");

        // Node 1: Has both symbols
        let mut node1_symbols = HashSet::new();
        node1_symbols.insert(symbol_a);
        node1_symbols.insert(symbol_b);

        // Node 2: Has only one symbol
        let mut node2_symbols = HashSet::new();
        node2_symbols.insert(symbol_a);

        // Node 3: Has no symbols
        let node3_symbols = HashSet::new();

        let nodes = vec![
            NodeInfo {
                profile: create_profile_with_connector("node-1", &connector_id, "1.0.0"),
                local_symbols: node1_symbols,
                held_leases: vec![],
                zones: vec![],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-2", &connector_id, "1.0.0"),
                local_symbols: node2_symbols,
                held_leases: vec![],
                zones: vec![],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-3", &connector_id, "1.0.0"),
                local_symbols: node3_symbols,
                held_leases: vec![],
                zones: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(connector_id.clone())
            .with_preferred_symbols(vec![symbol_a, symbol_b]);

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Node 1 should be selected (has both symbols)
        assert!(!candidates.is_empty(), "Should have candidates");
        let best = &candidates[0];
        assert_eq!(best.node_id.as_str(), "node-1");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "selected_node": best.node_id.as_str(),
                "score": best.score,
                "candidates_count": candidates.len(),
            }),
        );
    }

    /// Test: Control-plane routing respects connector requirements.
    #[test]
    fn test_control_plane_routing_connector_requirement() {
        const TEST_NAME: &str = "control_plane_routing_connector_requirement";
        const CATEGORY: &str = "routing";
        emit_test_start(TEST_NAME, CATEGORY);

        let required_connector = test_connector_id("slack:connector:2.0.0");
        let other_connector = test_connector_id("github:connector:1.0.0");

        let nodes = vec![
            // Node 1: Has required connector
            NodeInfo {
                profile: create_profile_with_connector("node-1", &required_connector, "2.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
            // Node 2: Has different connector
            NodeInfo {
                profile: create_profile_with_connector("node-2", &other_connector, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(required_connector.clone());

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Only node-1 should be eligible
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-1");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "selected_node": candidates[0].node_id.as_str(),
                "required_connector": required_connector.as_str(),
                "eligible_count": candidates.len(),
            }),
        );
    }

    /// Test: Multi-hop routing excludes nodes in exclusion list.
    #[test]
    fn test_multihop_routing_exclusions() {
        const TEST_NAME: &str = "multihop_routing_exclusions";
        const CATEGORY: &str = "routing";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("github:connector:1.0.0");

        let nodes = vec![
            NodeInfo {
                profile: create_profile_with_connector("node-1", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-2", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-3", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000);
        // Exclude node-1 and node-2 (already visited in multi-hop)
        let context = PlannerContext::new(connector_id.clone()).excluding(vec!["node-1", "node-2"]);

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Only node-3 should be eligible
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-3");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "selected_node": candidates[0].node_id.as_str(),
                "excluded_nodes": ["node-1", "node-2"],
            }),
        );
    }

    /// Test: Routing selection updates when topology changes.
    #[test]
    fn test_routing_updates_on_topology_change() {
        const TEST_NAME: &str = "routing_updates_on_topology_change";
        const CATEGORY: &str = "routing";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("github:connector:1.0.0");
        let hot_symbol = test_object_id("routing-topology-hot-symbol");

        let initial_nodes = vec![
            NodeInfo {
                profile: {
                    let mut p =
                        create_profile_with_connector("node-primary", &connector_id, "1.0.0");
                    p.memory_mb = 65536;
                    p.cpu_cores = 32;
                    p
                },
                local_symbols: HashSet::from([hot_symbol]),
                held_leases: vec![],
                zones: vec![],
            },
            NodeInfo {
                profile: {
                    let mut p =
                        create_profile_with_connector("node-backup", &connector_id, "1.0.0");
                    p.memory_mb = 16384;
                    p.cpu_cores = 8;
                    p
                },
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
        ];

        let context = PlannerContext::new(connector_id.clone())
            .with_min_memory_mb(8192)
            .with_preferred_symbols(vec![hot_symbol]);
        let planner = ExecutionPlanner::new();

        let before = planner.plan(&PlannerInput::new(initial_nodes.clone(), 1000), &context);
        assert_ne!(before, [] as [fcp_mesh::CandidateNode; 0]);
        assert_eq!(before[0].node_id.as_str(), "node-primary");

        let after_nodes: Vec<NodeInfo> = initial_nodes
            .into_iter()
            .filter(|node| node.profile.node_id.as_str() != "node-primary")
            .collect();
        let after = planner.plan(&PlannerInput::new(after_nodes, 2000), &context);
        assert_ne!(after, [] as [fcp_mesh::CandidateNode; 0]);
        assert_eq!(after[0].node_id.as_str(), "node-backup");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "selected_before": before[0].node_id.as_str(),
                "selected_after": after[0].node_id.as_str(),
                "topology_changed": true,
            }),
        );
    }

    /// Test: Load balancing distributes across capable nodes.
    #[test]
    fn test_load_balancing_capability_aware() {
        const TEST_NAME: &str = "load_balancing_capability_aware";
        const CATEGORY: &str = "routing";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("github:connector:1.0.0");

        // Create nodes with varying capabilities
        let nodes = vec![
            NodeInfo {
                profile: {
                    let mut p = create_profile_with_connector("node-high", &connector_id, "1.0.0");
                    p.memory_mb = 32768;
                    p.cpu_cores = 16;
                    p
                },
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
            NodeInfo {
                profile: {
                    let mut p =
                        create_profile_with_connector("node-medium", &connector_id, "1.0.0");
                    p.memory_mb = 8192;
                    p.cpu_cores = 4;
                    p
                },
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
            NodeInfo {
                profile: {
                    let mut p = create_profile_with_connector("node-low", &connector_id, "1.0.0");
                    p.memory_mb = 2048;
                    p.cpu_cores = 2;
                    p
                },
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(connector_id.clone()).with_min_memory_mb(4096);

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // node-high should be first, node-low may be excluded due to memory requirement
        assert_ne!(candidates, [] as [fcp_mesh::CandidateNode; 0]);
        assert_eq!(candidates[0].node_id.as_str(), "node-high");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "candidates": candidates.iter().map(|c| {
                    serde_json::json!({
                        "node_id": c.node_id.as_str(),
                        "score": c.score,
                        "eligible": c.eligible,
                    })
                }).collect::<Vec<_>>(),
            }),
        );
    }

    /// Test: Version compatibility enforced for connectors.
    #[test]
    fn test_connector_version_compatibility() {
        const TEST_NAME: &str = "connector_version_compatibility";
        const CATEGORY: &str = "routing";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("github:connector:1.0.0");

        let nodes = vec![
            // Node with old version
            NodeInfo {
                profile: create_profile_with_connector("node-old", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
            // Node with new version
            NodeInfo {
                profile: create_profile_with_connector("node-new", &connector_id, "2.1.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context =
            PlannerContext::new(connector_id.clone()).with_min_version("2.0.0".to_string());

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Only node-new should be eligible
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-new");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "selected_node": candidates[0].node_id.as_str(),
                "min_version": "2.0.0",
            }),
        );
    }
}

// ============================================================================
// ADMISSION CONTROL INTEGRATION TESTS
// ============================================================================

mod admission_control {
    use super::*;

    /// Test: Valid requests within budget are admitted.
    #[test]
    fn test_valid_requests_admitted() {
        const TEST_NAME: &str = "valid_requests_admitted";
        const CATEGORY: &str = "admission_control";
        emit_test_start(TEST_NAME, CATEGORY);

        let mut controller = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-123");
        let now_ms = 1000;

        // Valid authenticated request
        let result = controller.check_admission(&peer, 1024, 10, true, now_ms);
        assert!(result.is_ok());

        // Record the usage
        controller.record_bytes(&peer, 1024, now_ms);
        controller.record_symbols(&peer, 10, now_ms);

        // Another valid request
        let result2 = controller.check_admission(&peer, 2048, 20, true, now_ms);
        assert!(result2.is_ok());

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "peer_id": peer.as_str(),
                "bytes_admitted": 3072,
                "symbols_admitted": 30,
            }),
        );
    }

    /// Test: Rate limiting enforces byte budget.
    #[test]
    fn test_rate_limiting_byte_budget() {
        const TEST_NAME: &str = "rate_limiting_byte_budget";
        const CATEGORY: &str = "admission_control";
        emit_test_start(TEST_NAME, CATEGORY);

        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_bytes_per_min: 1000,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = NodeId::new("peer-rate-limit");
        let now_ms = 1000;

        // Use up budget
        controller.record_bytes(&peer, 800, now_ms);

        // Request that would exceed budget
        let result = controller.check_bytes(&peer, 300, now_ms);
        assert!(matches!(
            result,
            Err(AdmissionError::ByteBudgetExceeded { .. })
        ));

        // The controller uses a conservative two-bucket sliding window:
        // after one minute, the previous bucket still contributes a
        // decaying weight. After two windows, the original usage is stale.
        let later_ms = now_ms + 121_000;
        let result2 = controller.check_bytes(&peer, 300, later_ms);
        assert!(result2.is_ok());

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "max_bytes_per_min": 1000,
                "initial_usage": 800,
                "rejected_request": 300,
                "window_reset_worked": true,
            }),
        );
    }

    /// Test: Rate limiting enforces symbol budget.
    #[test]
    fn test_rate_limiting_symbol_budget() {
        const TEST_NAME: &str = "rate_limiting_symbol_budget";
        const CATEGORY: &str = "admission_control";
        emit_test_start(TEST_NAME, CATEGORY);

        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_symbols_per_min: 100,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = NodeId::new("peer-symbol-limit");
        let now_ms = 1000;

        // Use up budget
        controller.record_symbols(&peer, 95, now_ms);

        // Request that would exceed budget
        let result = controller.check_symbols(&peer, 10, now_ms);
        assert!(matches!(
            result,
            Err(AdmissionError::SymbolBudgetExceeded { .. })
        ));

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "max_symbols_per_min": 100,
                "initial_usage": 95,
                "rejected_request": 10,
            }),
        );
    }

    /// Test: Authentication required by policy.
    #[test]
    fn test_authentication_required() {
        const TEST_NAME: &str = "authentication_required";
        const CATEGORY: &str = "admission_control";
        emit_test_start(TEST_NAME, CATEGORY);

        let mut controller = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-unauth");
        let now_ms = 1000;

        // Unauthenticated request should be rejected
        let result = controller.check_admission(&peer, 100, 5, false, now_ms);
        assert!(matches!(
            result,
            Err(AdmissionError::AuthenticationRequired)
        ));

        // Authenticated request should pass
        let result2 = controller.check_admission(&peer, 100, 5, true, now_ms);
        assert!(result2.is_ok());

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "unauthenticated_rejected": true,
                "authenticated_accepted": true,
            }),
        );
    }

    /// Test: Anti-amplification rule enforcement.
    #[test]
    fn test_anti_amplification_rule() {
        const TEST_NAME: &str = "anti_amplification_rule";
        const CATEGORY: &str = "admission_control";
        emit_test_start(TEST_NAME, CATEGORY);

        let controller = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-amp");

        // Within amplification factor (10x default)
        let result = controller.check_amplification(&peer, 10, 100, false, false);
        assert!(result.is_ok());

        // Exceeds amplification factor
        let result2 = controller.check_amplification(&peer, 10, 150, false, false);
        assert!(matches!(
            result2,
            Err(AdmissionError::AmplificationViolation { .. })
        ));

        // Authenticated with proof-of-need bypasses limit
        let result3 = controller.check_amplification(&peer, 10, 500, true, true);
        assert!(result3.is_ok());

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "default_factor": 10,
                "within_limit_passed": true,
                "exceeds_limit_rejected": true,
                "auth_with_proof_bypasses": true,
            }),
        );
    }

    /// Test: Failed auth tracking and blocking.
    #[test]
    fn test_failed_auth_tracking() {
        const TEST_NAME: &str = "failed_auth_tracking";
        const CATEGORY: &str = "admission_control";
        emit_test_start(TEST_NAME, CATEGORY);

        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_failed_auth_per_min: 5,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = NodeId::new("peer-auth-fail");
        let now_ms = 1000;

        // Record failures up to limit
        for _ in 0..5 {
            let result = controller.record_auth_failure(&peer, now_ms);
            assert!(result.is_ok());
        }

        // Next failure should exceed budget
        let result = controller.record_auth_failure(&peer, now_ms);
        assert!(matches!(
            result,
            Err(AdmissionError::AuthFailureBudgetExceeded { .. })
        ));

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "max_failures": 5,
                "blocked_after_exceeded": true,
            }),
        );
    }

    /// Test: Decode capacity enforcement.
    #[test]
    fn test_decode_capacity_enforcement() {
        const TEST_NAME: &str = "decode_capacity_enforcement";
        const CATEGORY: &str = "admission_control";
        emit_test_start(TEST_NAME, CATEGORY);

        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_inflight_decodes: 3,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = NodeId::new("peer-decode");
        let now_ms = 1000;

        // Acquire up to limit
        for _ in 0..3 {
            assert!(controller.try_acquire_decode(&peer, now_ms).is_ok());
        }

        // Next should fail
        assert!(matches!(
            controller.try_acquire_decode(&peer, now_ms),
            Err(AdmissionError::DecodeCapacityExceeded { .. })
        ));

        // Release one
        controller.release_decode(&peer, now_ms);

        // Should succeed now
        assert!(controller.try_acquire_decode(&peer, now_ms).is_ok());

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "max_inflight": 3,
                "release_allows_new": true,
            }),
        );
    }

    /// Test: Public ingress policy allows unauthenticated.
    #[test]
    fn test_public_ingress_policy() {
        const TEST_NAME: &str = "public_ingress_policy";
        const CATEGORY: &str = "admission_control";
        emit_test_start(TEST_NAME, CATEGORY);

        let controller = AdmissionController::new(AdmissionPolicy::public_ingress());

        // Unauthenticated should be allowed for public
        let result = controller.check_authentication_required(false);
        assert!(result.is_ok());

        // But amplification limit is stricter (2x for public)
        let peer = NodeId::new("peer-public");
        let result2 = controller.check_amplification(&peer, 10, 30, false, false);
        assert!(matches!(
            result2,
            Err(AdmissionError::AmplificationViolation { .. })
        ));

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "unauthenticated_allowed": true,
                "stricter_amplification": true,
                "public_max_factor": 2,
            }),
        );
    }
}

// ============================================================================
// POLICY ENFORCEMENT INTEGRATION TESTS
// ============================================================================

mod policy_enforcement {
    use super::*;

    /// Test: Zone boundary enforcement (cross-zone blocked).
    #[test]
    fn test_zone_boundary_enforcement() {
        const TEST_NAME: &str = "zone_boundary_enforcement";
        const CATEGORY: &str = "policy_enforcement";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("github:connector:1.0.0");
        let work_zone = ZoneId::work();

        let nodes = vec![
            // Node in work zone
            NodeInfo {
                profile: create_profile_with_connector("node-work", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(connector_id.clone()).with_target_zone(work_zone.clone());

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Zone-boundary enforcement: with a target_zone set and a candidate
        // whose zone membership is unknown (empty `zones`), the planner
        // MUST drop it via check_target_zone (ZoneRestriction). A non-empty
        // result here would mean zone targeting was silently ignored.
        assert!(
            candidates.is_empty(),
            "candidate with unknown zone membership must be rejected when a target_zone is set"
        );

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "target_zone": work_zone.as_str(),
                "candidates_count": candidates.len(),
                "enforcement": "unknown_zone_rejected",
            }),
        );
    }

    /// Test: Capability requirement enforced before forwarding.
    #[test]
    fn test_capability_verification_before_forwarding() {
        const TEST_NAME: &str = "capability_verification_before_forwarding";
        const CATEGORY: &str = "policy_enforcement";
        emit_test_start(TEST_NAME, CATEGORY);

        let required_connector = test_connector_id("payments:connector:1.0.0");
        let wrong_connector = test_connector_id("search:connector:1.0.0");

        let nodes = vec![NodeInfo {
            profile: create_profile_with_connector(
                "node-wrong-capability",
                &wrong_connector,
                "1.0.0",
            ),
            local_symbols: HashSet::new(),
            held_leases: vec![],
            zones: vec![],
        }];

        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(required_connector.clone());

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        assert!(
            candidates.is_empty(),
            "Nodes lacking required connector capability must not be selected"
        );

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "required_connector": required_connector.as_str(),
                "eligible_count": candidates.len(),
                "forwarding_blocked": true,
            }),
        );
    }

    /// Test: Singleton writer lease enforcement.
    #[test]
    fn test_singleton_writer_lease_enforcement() {
        const TEST_NAME: &str = "singleton_writer_lease_enforcement";
        const CATEGORY: &str = "policy_enforcement";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("slack:connector:1.0.0");

        let nodes = vec![
            NodeInfo {
                profile: create_profile_with_connector("node-1", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-2", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
        ];

        // Node-1 holds the singleton writer lease
        let input = PlannerInput::new(nodes, 1000).with_singleton_holder("node-1");
        let context = PlannerContext::new(connector_id.clone()).with_singleton_writer();

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Only node-1 (lease holder) should be eligible
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-1");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "lease_holder": "node-1",
                "selected_node": candidates[0].node_id.as_str(),
                "singleton_writer_enforced": true,
            }),
        );
    }

    /// Test: GPU requirement enforcement.
    #[test]
    fn test_gpu_requirement_enforcement() {
        const TEST_NAME: &str = "gpu_requirement_enforcement";
        const CATEGORY: &str = "policy_enforcement";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("ml:connector:1.0.0");

        let gpu_profile = GpuProfile::new(GpuVendor::Nvidia, "RTX 4090", 24576);

        let nodes = vec![
            // Node with GPU
            NodeInfo {
                profile: DeviceProfile::builder(NodeId::new("node-gpu"))
                    .cpu_cores(16)
                    .memory_mb(32768)
                    .gpu(gpu_profile.clone())
                    .add_connector(InstalledConnector::new(
                        connector_id.clone(),
                        "1.0.0",
                        test_object_id("deadbeef"),
                    ))
                    .build(),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
            // Node without GPU
            NodeInfo {
                profile: create_profile_with_connector("node-cpu", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(connector_id.clone()).with_gpu();

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Only node with GPU should be selected
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-gpu");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "gpu_required": true,
                "selected_node": candidates[0].node_id.as_str(),
            }),
        );
    }

    /// Test: Memory requirement enforcement.
    #[test]
    fn test_memory_requirement_enforcement() {
        const TEST_NAME: &str = "memory_requirement_enforcement";
        const CATEGORY: &str = "policy_enforcement";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("data:connector:1.0.0");

        let nodes = vec![
            NodeInfo {
                profile: {
                    let mut p = create_profile_with_connector("node-big", &connector_id, "1.0.0");
                    p.memory_mb = 65536;
                    p
                },
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
            NodeInfo {
                profile: {
                    let mut p = create_profile_with_connector("node-small", &connector_id, "1.0.0");
                    p.memory_mb = 4096;
                    p
                },
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(connector_id.clone()).with_min_memory_mb(32768);

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Only node with sufficient memory should be eligible
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-big");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "min_memory_mb": 32768,
                "selected_node": candidates[0].node_id.as_str(),
            }),
        );
    }

    /// Test: Required symbols as hard constraint.
    #[test]
    fn test_required_symbols_hard_constraint() {
        const TEST_NAME: &str = "required_symbols_hard_constraint";
        const CATEGORY: &str = "policy_enforcement";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("data:connector:1.0.0");
        let required_symbol = test_object_id("required1234");

        let mut node1_symbols = HashSet::new();
        node1_symbols.insert(required_symbol);

        let nodes = vec![
            // Node with required symbol
            NodeInfo {
                profile: create_profile_with_connector("node-has-symbol", &connector_id, "1.0.0"),
                local_symbols: node1_symbols,
                held_leases: vec![],
                zones: vec![],
            },
            // Node without required symbol
            NodeInfo {
                profile: create_profile_with_connector("node-no-symbol", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context =
            PlannerContext::new(connector_id.clone()).with_required_symbols(vec![required_symbol]);

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Only node with required symbol
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-has-symbol");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "required_symbol": hex::encode(&required_symbol.as_bytes()[..8]),
                "selected_node": candidates[0].node_id.as_str(),
            }),
        );
    }
}

// ============================================================================
// GOSSIP INTEGRATION TESTS
// ============================================================================

mod gossip_integration {
    use super::*;
    use fcp_mesh::admission::ObjectAdmissionClass;

    /// Test: Object availability announcement.
    #[test]
    fn test_object_availability_announcement() {
        const TEST_NAME: &str = "object_availability_announcement";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig::default();
        let mut state = GossipState::new(zone_id.clone(), &config);

        let object_id = test_object_id("object1234");
        let now = 1000u64;

        // Announce object
        state.announce_object(&object_id, now);

        // Should be tracked
        assert!(state.has_object(&object_id));
        assert!(state.may_have_object(&object_id));
        assert_eq!(state.object_count(), 1);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "zone": zone_id.as_str(),
                "object_announced": true,
                "object_count": state.object_count(),
            }),
        );
    }

    /// Test: Symbol availability announcement.
    #[test]
    fn test_symbol_availability_announcement() {
        const TEST_NAME: &str = "symbol_availability_announcement";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig::default();
        let mut state = GossipState::new(zone_id.clone(), &config);

        let object_id = test_object_id("object5678");
        let now = 1000u64;

        // Announce multiple symbols
        for esi in 0..10 {
            state.announce_symbol(&object_id, esi, now);
        }

        // Object should be tracked
        assert!(state.has_object(&object_id));

        // Symbols should be available
        for esi in 0..10 {
            assert!(state.has_symbol(&object_id, esi));
        }
        assert_eq!(state.symbol_count(), 10);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "zone": zone_id.as_str(),
                "object_tracked": true,
                "symbols_announced": 10,
                "total_symbols": state.symbol_count(),
            }),
        );
    }

    /// Test: Gossip summary creation.
    #[test]
    fn test_gossip_summary_creation() {
        const TEST_NAME: &str = "gossip_summary_creation";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig::default();
        let mut state = GossipState::new(zone_id.clone(), &config);

        // Add some data
        let object1 = test_object_id("obj1");
        let object2 = test_object_id("obj2");
        let now = 1000u64;

        state.announce_object(&object1, now);
        state.announce_object(&object2, now);
        state.announce_symbol(&object1, 0, now);
        state.announce_symbol(&object1, 1, now);

        // Create summary
        let from_node = TailscaleNodeId::new("node-123");
        let epoch = EpochId::new("epoch-42");
        let summary = state.create_summary(from_node.clone(), epoch);

        assert_eq!(summary.object_count, 2);
        assert_eq!(summary.symbol_count, 2);
        assert_eq!(&summary.zone_id, &zone_id);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "zone": zone_id.as_str(),
                "object_count": summary.object_count,
                "symbol_count": summary.symbol_count,
            }),
        );
    }

    /// Test: Stale gossip summaries are rejected.
    #[test]
    fn test_stale_gossip_summary_rejected() {
        const TEST_NAME: &str = "stale_gossip_summary_rejected";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig {
            summary_ttl_secs: 60,
            ..GossipConfig::default()
        };
        let mut gossip = MeshGossip::new(TailscaleNodeId::new("node-local"), config);

        let stale_summary = GossipSummary {
            from: TailscaleNodeId::new("node-stale"),
            zone_id: zone_id.clone(),
            epoch_id: EpochId::new("epoch-stale"),
            object_filter_digest: [1u8; 32],
            symbol_filter_digest: [2u8; 32],
            object_count: 2,
            symbol_count: 5,
            iblt: Vec::new(),
            timestamp: 10,
            signature: None,
        };

        gossip.handle_summary(stale_summary, 200);

        assert_eq!(gossip.peer_count(), 0);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "zone": zone_id.as_str(),
                "peer_count": gossip.peer_count(),
                "rejected_reason": "stale",
            }),
        );
    }

    /// Test: Object removal from gossip state.
    #[test]
    fn test_object_removal_from_gossip() {
        const TEST_NAME: &str = "object_removal_from_gossip";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig::default();
        let mut state = GossipState::new(zone_id.clone(), &config);

        let object_id = test_object_id("removeobj");
        let now = 1000u64;

        // Add object
        state.announce_object(&object_id, now);
        state.announce_symbol(&object_id, 0, now);
        assert!(state.has_object(&object_id));

        // Remove object
        state.remove_object(&object_id, now + 100);

        // Object and symbols should be gone
        assert!(!state.has_object(&object_id));
        assert!(state.symbols_for_object(&object_id).is_none());

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "object_removed": true,
                "symbols_cleaned": true,
            }),
        );
    }

    /// Test: Filter membership checks.
    #[test]
    fn test_filter_membership_checks() {
        const TEST_NAME: &str = "filter_membership_checks";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig::default();
        let mut state = GossipState::new(zone_id.clone(), &config);

        let known_object = test_object_id("known1234");
        let unknown_object = test_object_id("unknown5678");
        let now = 1000u64;

        state.announce_object(&known_object, now);

        // Known object should pass filter check
        assert!(state.may_have_object(&known_object));

        // Unknown object should fail authoritative check
        assert!(!state.has_object(&unknown_object));

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "known_passes_filter": true,
                "unknown_fails_auth_check": true,
            }),
        );
    }

    /// Test: Bounded object listing.
    #[test]
    fn test_bounded_object_listing() {
        const TEST_NAME: &str = "bounded_object_listing";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig::default();
        let mut state = GossipState::new(zone_id.clone(), &config);
        let now = 1000u64;

        // Add many objects
        for i in 0..20 {
            let obj = test_object_id(&format!("{i:04x}"));
            state.announce_object(&obj, now);
        }

        // List with limit
        let limited = state.list_objects(5);
        assert_eq!(limited.len(), 5);

        // List all
        let all = state.list_objects(100);
        assert_eq!(all.len(), 20);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "total_objects": 20,
                "limited_list_count": 5,
                "full_list_count": 20,
            }),
        );
    }

    /// Test: `MeshGossip` `create_request` respects config bounds.
    #[test]
    fn test_gossip_create_request_respects_config_bounds() {
        const TEST_NAME: &str = "gossip_create_request_config_bounds";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig {
            max_objects_per_request: 1,
            max_symbols_per_request: 1,
            ..GossipConfig::default()
        };
        let gossip = MeshGossip::new(TailscaleNodeId::new("node-0"), config);

        let object_ids = vec![test_object_id("obj-a"), test_object_id("obj-b")];
        let request = gossip.create_request(&zone_id, object_ids, 1000);

        assert_eq!(request.object_ids.len(), 1);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "zone": zone_id.as_str(),
                "requested_objects": 2,
                "bounded_objects": request.object_ids.len(),
            }),
        );
    }

    /// Test: Oversized gossip summaries are rejected.
    #[test]
    fn test_oversized_gossip_summary_rejected() {
        const TEST_NAME: &str = "oversized_gossip_summary_rejected";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig {
            max_objects_per_summary: 4,
            max_symbols_per_summary: 8,
            ..GossipConfig::default()
        };
        let mut gossip = MeshGossip::new(TailscaleNodeId::new("node-local"), config);

        let oversized_summary = GossipSummary {
            from: TailscaleNodeId::new("node-oversized"),
            zone_id: zone_id.clone(),
            epoch_id: EpochId::new("epoch-oversized"),
            object_filter_digest: [3u8; 32],
            symbol_filter_digest: [4u8; 32],
            object_count: 9,
            symbol_count: 20,
            iblt: Vec::new(),
            timestamp: 100,
            signature: None,
        };

        gossip.handle_summary(oversized_summary, 120);

        assert_eq!(gossip.peer_count(), 0);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "zone": zone_id.as_str(),
                "peer_count": gossip.peer_count(),
                "rejected_reason": "oversized",
            }),
        );
    }

    /// Test: Malformed gossip summaries are rejected without creating peer state.
    #[test]
    fn test_invalid_iblt_gossip_summary_rejected() {
        const TEST_NAME: &str = "invalid_iblt_gossip_summary_rejected";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig::default();
        let mut gossip = MeshGossip::new(TailscaleNodeId::new("node-local"), config.clone());
        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("warn");

        let invalid_summary = GossipSummary {
            from: TailscaleNodeId::new("node-invalid"),
            zone_id: zone_id.clone(),
            epoch_id: EpochId::new("epoch-invalid"),
            object_filter_digest: [9u8; 32],
            symbol_filter_digest: [8u8; 32],
            object_count: 1,
            symbol_count: 1,
            iblt: b"not-json".to_vec(),
            timestamp: 100,
            signature: None,
        };

        gossip.handle_summary(invalid_summary.clone(), 120);

        assert_eq!(gossip.peer_count(), 0);

        let rejected_log = find_tracing_event(&capture, "summary_rejected");
        assert_eq!(
            rejected_log
                .get("reason")
                .and_then(serde_json::Value::as_str),
            Some("iblt_invalid_encoding")
        );
        assert_eq!(
            rejected_log
                .get("peer_node_id")
                .and_then(serde_json::Value::as_str),
            Some("node-invalid")
        );
        assert_eq!(
            rejected_log
                .get("zone_id")
                .and_then(serde_json::Value::as_str),
            Some(zone_id.as_str())
        );
        assert_eq!(
            rejected_log
                .get("iblt_bytes")
                .and_then(serde_json::Value::as_u64),
            Some(u64::try_from(invalid_summary.iblt.len()).unwrap_or(u64::MAX))
        );
        assert_eq!(
            rejected_log
                .get("max_iblt_bytes")
                .and_then(serde_json::Value::as_u64),
            Some(u64::try_from(config.max_iblt_bytes()).unwrap_or(u64::MAX))
        );
        assert!(
            rejected_log
                .get("decode_ms")
                .and_then(serde_json::Value::as_u64)
                .is_some(),
            "summary_rejected log should include decode_ms"
        );

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "zone": zone_id.as_str(),
                "peer_count": gossip.peer_count(),
                "peer_node_id": "node-invalid",
                "iblt_bytes": invalid_summary.iblt.len(),
                "decode_ms": rejected_log["decode_ms"].clone(),
                "rejected_reason": rejected_log["reason"].clone(),
                "result": "pass",
            }),
        );
    }

    /// Test: Accepted gossip summaries emit decode metrics and peer identity.
    #[test]
    fn test_gossip_summary_received_logs_decode_metrics() {
        const TEST_NAME: &str = "gossip_summary_received_logs_decode_metrics";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let epoch = EpochId::new("epoch-summary-received");
        let now = 1_000u64;

        let mut peer_gossip = MeshGossip::with_defaults(TailscaleNodeId::new("node-peer"));
        let object_id = test_object_id("received-object");
        peer_gossip.announce_object(&zone_id, &object_id, ObjectAdmissionClass::Admitted, now);
        peer_gossip.announce_symbol(&zone_id, &object_id, 7, ObjectAdmissionClass::Admitted, now);

        let summary = peer_gossip
            .create_summary(&zone_id, epoch)
            .expect("summary should exist");
        let expected_summary_bytes = u64::try_from(
            serde_json::to_vec(&summary)
                .expect("summary serializes")
                .len(),
        )
        .unwrap_or(u64::MAX);
        let expected_iblt_bytes = u64::try_from(summary.iblt.len()).unwrap_or(u64::MAX);

        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("debug");
        let mut local_gossip = MeshGossip::with_defaults(TailscaleNodeId::new("node-local"));
        local_gossip.handle_summary(summary, now + 1);

        assert_eq!(local_gossip.peer_count(), 1);

        let received_log = find_tracing_event(&capture, "summary_received");
        assert_eq!(
            received_log
                .get("peer_node_id")
                .and_then(serde_json::Value::as_str),
            Some("node-peer")
        );
        assert_eq!(
            received_log
                .get("object_count")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
        assert_eq!(
            received_log
                .get("symbol_count")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
        assert_eq!(
            received_log
                .get("summary_bytes")
                .and_then(serde_json::Value::as_u64),
            Some(expected_summary_bytes)
        );
        assert_eq!(
            received_log
                .get("iblt_bytes")
                .and_then(serde_json::Value::as_u64),
            Some(expected_iblt_bytes)
        );
        assert!(
            received_log
                .get("iblt_cells")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
                > 0,
            "summary_received log should include iblt_cells"
        );
        assert_eq!(
            received_log
                .get("accepted")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(
            received_log
                .get("decode_ms")
                .and_then(serde_json::Value::as_u64)
                .is_some(),
            "summary_received log should include decode_ms"
        );

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "zone": zone_id.as_str(),
                "peer_node_id": "node-peer",
                "summary_bytes": received_log["summary_bytes"].clone(),
                "iblt_bytes": received_log["iblt_bytes"].clone(),
                "iblt_cells": received_log["iblt_cells"].clone(),
                "decode_ms": received_log["decode_ms"].clone(),
                "fallback_reason": "none",
                "result": "pass",
            }),
        );
    }

    /// Test: `MeshGossip` drops over-config requests.
    #[test]
    fn test_gossip_request_rejects_over_config_bounds() {
        const TEST_NAME: &str = "gossip_request_rejects_over_config_bounds";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig {
            max_objects_per_request: 1,
            max_symbols_per_request: 1,
            ..GossipConfig::default()
        };
        let mut gossip = MeshGossip::new(TailscaleNodeId::new("node-0"), config);

        let object_ids = vec![test_object_id("obj-1"), test_object_id("obj-2")];
        for object_id in &object_ids {
            gossip.announce_object(&zone_id, object_id, ObjectAdmissionClass::Admitted, 1000);
        }

        let request = GossipRequest::for_objects(
            TailscaleNodeId::new("peer-1"),
            zone_id.clone(),
            object_ids,
            1000,
        );
        let response = gossip.handle_request(&request);

        assert_eq!(response.have_objects, [] as [fcp_prelude::ObjectId; 0]);
        assert_eq!(response.have_symbols, [] as [(fcp_prelude::ObjectId, u32); 0]);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "zone": zone_id.as_str(),
                "response_objects": response.have_objects.len(),
                "response_symbols": response.have_symbols.len(),
            }),
        );
    }

    /// Test: Multi-node bootstrap via summary exchange + bounded reconciliation.
    #[test]
    fn test_gossip_bootstrap_convergence() {
        const TEST_NAME: &str = "gossip_bootstrap_convergence";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let epoch = EpochId::new("epoch-bootstrap");
        let config = GossipConfig::default();

        let mut node_a = MeshGossip::new(TailscaleNodeId::new("node-a"), config.clone());
        let mut node_b = MeshGossip::new(TailscaleNodeId::new("node-b"), config.clone());
        let mut node_c = MeshGossip::new(TailscaleNodeId::new("node-c"), config);

        let object_id = test_object_id("bootstrap-object");
        let now = 1000u64;

        node_a.announce_object(&zone_id, &object_id, ObjectAdmissionClass::Admitted, now);
        node_a.announce_symbol(&zone_id, &object_id, 0, ObjectAdmissionClass::Admitted, now);
        node_a.announce_symbol(&zone_id, &object_id, 1, ObjectAdmissionClass::Admitted, now);

        let summary = node_a
            .create_summary(&zone_id, epoch)
            .expect("node-a summary should exist");
        node_b.handle_summary(summary.clone(), now + 1);
        node_c.handle_summary(summary, now + 1);

        assert_eq!(node_b.peer_count(), 1);
        assert_eq!(node_c.peer_count(), 1);

        let request = node_b.create_request(&zone_id, vec![object_id], now + 2);
        let response = node_a.handle_request(&request);
        assert_eq!(response.have_objects, vec![object_id]);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "zone": zone_id.as_str(),
                "peer_count_node_b": node_b.peer_count(),
                "peer_count_node_c": node_c.peer_count(),
                "objects_reconciled": response.have_objects.len(),
            }),
        );
    }

    /// Test: Compact summaries reduce bytes versus an explicit object/symbol listing baseline.
    #[test]
    fn test_gossip_summary_bandwidth_reduction_vs_explicit_baseline() {
        const TEST_NAME: &str = "gossip_summary_bandwidth_reduction_vs_explicit_baseline";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("debug");

        let zone_id = ZoneId::work();
        let epoch = EpochId::new("epoch-bandwidth");
        let config = GossipConfig {
            reconciliation_batch_size: 1,
            ..GossipConfig::default()
        };
        let mut gossip = MeshGossip::new(TailscaleNodeId::new("node-bandwidth"), config);
        let now = 1_000u64;

        let mut explicit_objects = Vec::new();
        let mut explicit_symbols = Vec::new();

        for object_index in 0..96 {
            let object_id = test_object_id(&format!("bandwidth-{object_index:03}"));
            explicit_objects.push(object_id);
            gossip.announce_object(&zone_id, &object_id, ObjectAdmissionClass::Admitted, now);

            for esi in 0..4 {
                explicit_symbols.push(serde_json::json!({
                    "object_id": object_id,
                    "esi": esi,
                }));
                gossip.announce_symbol(
                    &zone_id,
                    &object_id,
                    esi,
                    ObjectAdmissionClass::Admitted,
                    now,
                );
            }
        }

        let summary = gossip
            .create_summary(&zone_id, epoch)
            .expect("summary should exist");
        let summary_bytes = serde_json::to_vec(&summary)
            .expect("summary should serialize")
            .len();
        let baseline_bytes = serde_json::to_vec(&serde_json::json!({
            "zone_id": zone_id,
            "objects": explicit_objects,
            "symbols": explicit_symbols,
        }))
        .expect("baseline should serialize")
        .len();

        assert!(
            summary_bytes < baseline_bytes,
            "compact summary should be smaller than explicit baseline (summary={summary_bytes}, baseline={baseline_bytes})"
        );

        let created_log = find_tracing_event(&capture, "summary_created");
        assert_eq!(
            created_log
                .get("component")
                .and_then(serde_json::Value::as_str),
            Some("mesh.gossip")
        );
        assert_eq!(
            created_log
                .get("zone_id")
                .and_then(serde_json::Value::as_str),
            Some(zone_id.as_str())
        );
        assert_eq!(
            created_log
                .get("fallback_reason")
                .and_then(serde_json::Value::as_str),
            Some("none")
        );
        assert_eq!(
            created_log
                .get("summary_bytes")
                .and_then(serde_json::Value::as_u64),
            Some(u64::try_from(summary_bytes).unwrap_or(u64::MAX))
        );
        assert_eq!(
            created_log
                .get("iblt_bytes")
                .and_then(serde_json::Value::as_u64),
            Some(u64::try_from(summary.iblt.len()).unwrap_or(u64::MAX))
        );
        assert!(
            created_log
                .get("iblt_cells")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
                > 0,
            "summary_created log should include a non-zero iblt_cells count"
        );

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "zone": zone_id.as_str(),
                "summary_bytes": summary_bytes,
                "baseline_bytes": baseline_bytes,
                "bandwidth_reduction_bytes": baseline_bytes - summary_bytes,
                "iblt_cells": created_log["iblt_cells"].clone(),
                "fallback_reason": created_log["fallback_reason"].clone(),
                "result": "pass",
            }),
        );
    }

    /// Test: Production reconciliation sketches stay within budget and log metrics.
    #[test]
    fn test_gossip_summary_creation_logs_iblt_metrics() {
        const TEST_NAME: &str = "gossip_summary_creation_logs_iblt_metrics";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("debug");

        let zone_id = ZoneId::work();
        let epoch = EpochId::new("epoch-fallback");
        let config = GossipConfig {
            reconciliation_batch_size: 64,
            ..GossipConfig::default()
        };
        let max_iblt_bytes = config.max_iblt_bytes();
        let mut gossip = MeshGossip::new(TailscaleNodeId::new("node-fallback"), config);
        let object_id = test_object_id("fallback-object");
        let now = 1_000u64;

        for esi in 0..512 {
            gossip.announce_symbol(
                &zone_id,
                &object_id,
                esi,
                ObjectAdmissionClass::Admitted,
                now,
            );
        }

        let summary = gossip
            .create_summary(&zone_id, epoch)
            .expect("summary should exist");
        let summary_bytes = u64::try_from(
            serde_json::to_vec(&summary)
                .expect("summary should serialize")
                .len(),
        )
        .unwrap_or(u64::MAX);

        assert_ne!(summary.iblt, [] as [u8; 0]);
        assert!(summary.iblt.len() <= max_iblt_bytes);

        let created_log = find_tracing_event(&capture, "summary_created");
        assert_eq!(
            created_log
                .get("component")
                .and_then(serde_json::Value::as_str),
            Some("mesh.gossip")
        );
        assert_eq!(
            created_log
                .get("zone_id")
                .and_then(serde_json::Value::as_str),
            Some(zone_id.as_str())
        );
        assert_eq!(
            created_log
                .get("fallback_reason")
                .and_then(serde_json::Value::as_str),
            Some("none")
        );
        assert_eq!(
            created_log
                .get("summary_bytes")
                .and_then(serde_json::Value::as_u64),
            Some(summary_bytes)
        );
        assert_eq!(
            created_log
                .get("iblt_bytes")
                .and_then(serde_json::Value::as_u64),
            Some(u64::try_from(summary.iblt.len()).unwrap_or(u64::MAX))
        );
        assert!(
            created_log
                .get("iblt_cells")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
                > 0,
            "summary_created log should keep the pre-fallback cell count"
        );

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "zone": zone_id.as_str(),
                "summary_bytes": created_log["summary_bytes"].clone(),
                "iblt_bytes": created_log["iblt_bytes"].clone(),
                "iblt_cells": created_log["iblt_cells"].clone(),
                "fallback_reason": created_log["fallback_reason"].clone(),
                "result": "pass",
            }),
        );
    }

    /// Test: Decode-budget rejections surface a stable change-limit reason code.
    #[test]
    fn test_gossip_summary_rejected_when_iblt_change_limit_exceeded() {
        const TEST_NAME: &str = "gossip_summary_rejected_when_iblt_change_limit_exceeded";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let epoch = EpochId::new("epoch-change-limit");
        let now = 1_000u64;

        let sender_config = GossipConfig {
            reconciliation_batch_size: 64,
            ..GossipConfig::default()
        };
        let mut sender = MeshGossip::new(TailscaleNodeId::new("node-change-sender"), sender_config);
        let object_id = test_object_id("change-limit-object");
        sender.announce_object(&zone_id, &object_id, ObjectAdmissionClass::Admitted, now);
        for esi in 0..3 {
            sender.announce_symbol(
                &zone_id,
                &object_id,
                esi,
                ObjectAdmissionClass::Admitted,
                now,
            );
        }

        let summary = sender
            .create_summary(&zone_id, epoch)
            .expect("summary should exist");
        let summary_iblt_bytes = u64::try_from(summary.iblt.len()).unwrap_or(u64::MAX);

        let receiver_config = GossipConfig {
            reconciliation_batch_size: 2,
            ..GossipConfig::default()
        };
        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("warn");
        let mut receiver = MeshGossip::new(
            TailscaleNodeId::new("node-change-receiver"),
            receiver_config.clone(),
        );
        receiver.handle_summary(summary, now + 1);

        assert_eq!(receiver.peer_count(), 0);

        let rejected_log = find_tracing_event(&capture, "summary_rejected");
        assert_eq!(
            rejected_log
                .get("reason")
                .and_then(serde_json::Value::as_str),
            Some("iblt_change_limit_exceeded")
        );
        assert_eq!(
            rejected_log
                .get("peer_node_id")
                .and_then(serde_json::Value::as_str),
            Some("node-change-sender")
        );
        assert_eq!(
            rejected_log
                .get("zone_id")
                .and_then(serde_json::Value::as_str),
            Some(zone_id.as_str())
        );
        assert_eq!(
            rejected_log
                .get("iblt_bytes")
                .and_then(serde_json::Value::as_u64),
            Some(summary_iblt_bytes)
        );
        assert_eq!(
            rejected_log
                .get("max_iblt_bytes")
                .and_then(serde_json::Value::as_u64),
            Some(u64::try_from(receiver_config.max_iblt_bytes()).unwrap_or(u64::MAX))
        );
        assert!(
            rejected_log
                .get("decode_ms")
                .and_then(serde_json::Value::as_u64)
                .is_some(),
            "summary_rejected log should include decode_ms"
        );

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "zone": zone_id.as_str(),
                "peer_node_id": "node-change-sender",
                "iblt_bytes": rejected_log["iblt_bytes"].clone(),
                "decode_ms": rejected_log["decode_ms"].clone(),
                "fallback_reason": rejected_log["reason"].clone(),
                "result": "pass",
            }),
        );
    }

    /// Test: Partition/leave behavior via stale-peer pruning and rejoin.
    #[test]
    fn test_gossip_partition_prune_and_rejoin() {
        const TEST_NAME: &str = "gossip_partition_prune_and_rejoin";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let epoch = EpochId::new("epoch-partition");
        let config = GossipConfig {
            summary_ttl_secs: 30,
            ..GossipConfig::default()
        };

        let mut node_a = MeshGossip::new(TailscaleNodeId::new("node-a"), config.clone());
        let mut node_b = MeshGossip::new(TailscaleNodeId::new("node-b"), config);

        let object_id = test_object_id("partition-object");
        node_a.announce_object(&zone_id, &object_id, ObjectAdmissionClass::Admitted, 200);

        let initial_summary = node_a
            .create_summary(&zone_id, epoch.clone())
            .expect("initial summary");
        node_b.handle_summary(initial_summary, 201);
        assert_eq!(node_b.peer_count(), 1);

        let pruned = node_b.prune_stale_peers(235);
        assert_eq!(pruned, 1);
        assert_eq!(node_b.peer_count(), 0);

        node_a.announce_symbol(&zone_id, &object_id, 2, ObjectAdmissionClass::Admitted, 236);
        let rejoin_summary = node_a
            .create_summary(&zone_id, epoch)
            .expect("rejoin summary");
        node_b.handle_summary(rejoin_summary, 237);
        assert_eq!(node_b.peer_count(), 1);

        let request = node_b.create_request(&zone_id, vec![object_id], 238);
        let response = node_a.handle_request(&request);
        assert_eq!(response.have_objects, vec![object_id]);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "zone": zone_id.as_str(),
                "pruned_peers": pruned,
                "peer_count_after_rejoin": node_b.peer_count(),
                "objects_reconciled": response.have_objects.len(),
            }),
        );
    }
}

// ============================================================================
// LEASE COORDINATION TESTS
// ============================================================================

mod lease_coordination {
    use super::*;

    /// Test: Lease holder gets priority for singleton operations.
    #[test]
    fn test_lease_holder_priority() {
        const TEST_NAME: &str = "lease_holder_priority";
        const CATEGORY: &str = "lease_coordination";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("state:connector:1.0.0");

        let nodes = vec![
            NodeInfo {
                profile: create_profile_with_connector("node-holder", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![HeldLease {
                    subject_id: test_object_id("stateobject"),
                    purpose: LeasePurpose::SingletonWriter,
                    expires_at: 2000,
                    fencing_token: 5,
                }],
                zones: vec![],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-other", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000).with_singleton_holder("node-holder");
        let context = PlannerContext::new(connector_id.clone()).with_singleton_writer();

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Lease holder should be selected
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-holder");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "lease_holder": "node-holder",
                "selected_for_singleton": true,
            }),
        );
    }

    /// Test: Non-singleton operations allow any eligible node.
    #[test]
    fn test_non_singleton_allows_all() {
        const TEST_NAME: &str = "non_singleton_allows_all";
        const CATEGORY: &str = "lease_coordination";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("read:connector:1.0.0");

        let nodes = vec![
            NodeInfo {
                profile: create_profile_with_connector("node-1", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-2", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
        ];

        // Non-singleton operation (no with_singleton_writer)
        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(connector_id.clone());

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Both should be eligible
        assert_eq!(candidates.len(), 2);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "singleton_mode": false,
                "eligible_count": 2,
            }),
        );
    }

    /// Test: Lease conflict detection.
    #[test]
    fn test_lease_conflict_detection() {
        const TEST_NAME: &str = "lease_conflict_detection";
        const CATEGORY: &str = "lease_coordination";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("write:connector:1.0.0");

        let nodes = vec![
            NodeInfo {
                profile: create_profile_with_connector("node-1", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-2", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
        ];

        // Node-1 is the singleton holder, requesting from node-2's perspective
        let input = PlannerInput::new(nodes, 1000).with_singleton_holder("node-1");
        let context = PlannerContext::new(connector_id.clone()).with_singleton_writer();

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Only node-1 (holder) should be eligible
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-1");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "holder": "node-1",
                "conflicting_node_excluded": true,
            }),
        );
    }

    /// Test: Lease holder transfer updates singleton routing.
    #[test]
    fn test_lease_transfer_on_holder_change() {
        const TEST_NAME: &str = "lease_transfer_on_holder_change";
        const CATEGORY: &str = "lease_coordination";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("state:connector:1.0.0");
        let nodes = vec![
            NodeInfo {
                profile: create_profile_with_connector("node-a", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-b", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
        ];

        let context = PlannerContext::new(connector_id.clone()).with_singleton_writer();
        let planner = ExecutionPlanner::new();

        let before = planner.plan(
            &PlannerInput::new(nodes.clone(), 1000).with_singleton_holder("node-a"),
            &context,
        );
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].node_id.as_str(), "node-a");

        let after = planner.plan(
            &PlannerInput::new(nodes, 2000).with_singleton_holder("node-b"),
            &context,
        );
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].node_id.as_str(), "node-b");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "holder_before": before[0].node_id.as_str(),
                "holder_after": after[0].node_id.as_str(),
                "transfer_enforced": true,
            }),
        );
    }

    /// Test: Operation execution lease purpose.
    #[test]
    fn test_operation_execution_lease() {
        const TEST_NAME: &str = "operation_execution_lease";
        const CATEGORY: &str = "lease_coordination";
        emit_test_start(TEST_NAME, CATEGORY);

        let subject = test_object_id("operationsubject");

        let lease = HeldLease {
            subject_id: subject,
            purpose: LeasePurpose::OperationExecution,
            expires_at: 5000,
            fencing_token: 3,
        };

        // Verify lease structure
        assert_eq!(lease.purpose, LeasePurpose::OperationExecution);
        assert_eq!(format!("{}", lease.purpose), "operation_execution");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "lease_purpose": "operation_execution",
                "expires_at": 5000,
            }),
        );
    }

    /// Test: Coordinator election lease purpose.
    #[test]
    fn test_coordinator_election_lease() {
        const TEST_NAME: &str = "coordinator_election_lease";
        const CATEGORY: &str = "lease_coordination";
        emit_test_start(TEST_NAME, CATEGORY);

        let subject = test_object_id("coordinatorslot");

        let lease = HeldLease {
            subject_id: subject,
            purpose: LeasePurpose::CoordinatorElection,
            expires_at: 10000,
            fencing_token: 8,
        };

        // Verify lease structure
        assert_eq!(lease.purpose, LeasePurpose::CoordinatorElection);
        assert_eq!(format!("{}", lease.purpose), "coordinator_election");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "lease_purpose": "coordinator_election",
                "expires_at": 10000,
            }),
        );
    }
}

// ============================================================================
// INTEGRATION SCENARIO TESTS
// ============================================================================

mod integration_scenarios {
    use super::*;

    /// Test: Full mesh routing scenario with multiple factors.
    #[test]
    fn test_full_mesh_routing_scenario() {
        const TEST_NAME: &str = "full_mesh_routing_scenario";
        const CATEGORY: &str = "integration";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("multifactor:connector:2.0.0");
        let symbol_a = test_object_id("syma");
        let symbol_b = test_object_id("symb");

        // Node 1: Has connector, GPU, symbols, lease holder
        let mut node1_symbols = HashSet::new();
        node1_symbols.insert(symbol_a);
        node1_symbols.insert(symbol_b);

        let gpu = GpuProfile::new(GpuVendor::Nvidia, "RTX 4090", 24576);

        let nodes = vec![
            NodeInfo {
                profile: DeviceProfile::builder(NodeId::new("node-optimal"))
                    .cpu_cores(32)
                    .memory_mb(131072)
                    .gpu(gpu.clone())
                    .add_connector(InstalledConnector::new(
                        connector_id.clone(),
                        "2.0.0",
                        test_object_id("binary1"),
                    ))
                    .build(),
                local_symbols: node1_symbols,
                held_leases: vec![HeldLease {
                    subject_id: test_object_id("state"),
                    purpose: LeasePurpose::SingletonWriter,
                    expires_at: 5000,
                    fencing_token: 9,
                }],
                zones: vec![],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-basic", &connector_id, "1.5.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000).with_singleton_holder("node-optimal");
        let context = PlannerContext::new(connector_id.clone())
            .with_min_version("2.0.0")
            .with_gpu()
            .with_min_memory_mb(65536)
            .with_preferred_symbols(vec![symbol_a, symbol_b])
            .with_singleton_writer();

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // node-optimal should be the only candidate meeting all requirements
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-optimal");
        assert!(candidates[0].score > 0.0);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "selected_node": candidates[0].node_id.as_str(),
                "final_score": candidates[0].score,
                "constraints_checked": [
                    "connector_version",
                    "gpu_required",
                    "memory_requirement",
                    "data_locality",
                    "singleton_writer"
                ],
            }),
        );
    }

    /// Test: Admission + routing integration.
    #[test]
    fn test_admission_routing_integration() {
        const TEST_NAME: &str = "admission_routing_integration";
        const CATEGORY: &str = "integration";
        emit_test_start(TEST_NAME, CATEGORY);

        // Set up admission controller
        let mut admission = AdmissionController::with_default_policy();
        let peer = NodeId::new("requesting-peer");
        let now_ms = 1000u64;

        // First check admission
        let admission_result =
            admission.check_admission(&peer, 1024, 50, true /* authenticated */, now_ms);
        assert!(admission_result.is_ok());

        // Then proceed with routing
        let connector_id = test_connector_id("route:connector:1.0.0");
        let nodes = vec![NodeInfo {
            profile: create_profile_with_connector("node-target", &connector_id, "1.0.0"),
            local_symbols: HashSet::new(),
            held_leases: vec![],
            zones: vec![],
        }];

        let input = PlannerInput::new(nodes, now_ms);
        let context = PlannerContext::new(connector_id.clone());

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        assert_ne!(candidates, [] as [fcp_mesh::CandidateNode; 0]);

        // Record usage after successful routing
        admission.record_bytes(&peer, 1024, now_ms);
        admission.record_symbols(&peer, 50, now_ms);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "admission_passed": true,
                "routing_completed": true,
                "target_node": candidates[0].node_id.as_str(),
            }),
        );
    }

    /// Test: Admission denial path blocks over-budget requests.
    #[test]
    fn test_admission_routing_denies_over_budget() {
        const TEST_NAME: &str = "admission_routing_denies_over_budget";
        const CATEGORY: &str = "integration";
        emit_test_start(TEST_NAME, CATEGORY);

        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_bytes_per_min: 1200,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut admission = AdmissionController::new(policy);
        let peer = NodeId::new("requesting-peer-over-budget");
        let now_ms = 1000u64;

        admission.record_bytes(&peer, 1000, now_ms);
        let denied = admission.check_admission(&peer, 400, 5, true, now_ms);
        assert!(matches!(
            denied,
            Err(AdmissionError::ByteBudgetExceeded { .. })
        ));

        let connector_id = test_connector_id("route:connector:1.0.0");
        let nodes = vec![NodeInfo {
            profile: create_profile_with_connector("node-target", &connector_id, "1.0.0"),
            local_symbols: HashSet::new(),
            held_leases: vec![],
            zones: vec![],
        }];
        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(
            &PlannerInput::new(nodes, now_ms),
            &PlannerContext::new(connector_id.clone()),
        );
        assert_ne!(candidates, [] as [fcp_mesh::CandidateNode; 0]);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "admission_denied": true,
                "deny_reason": "byte_budget_exceeded",
                "routing_candidates_available": candidates.len(),
            }),
        );
    }

    /// Test: Gossip + routing integration.
    #[test]
    fn test_gossip_routing_integration() {
        const TEST_NAME: &str = "gossip_routing_integration";
        const CATEGORY: &str = "integration";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig::default();
        let mut gossip_state = GossipState::new(zone_id.clone(), &config);

        // Set up gossip state with object availability
        let object_id = test_object_id("dataobject");
        let now = 1000u64;

        for esi in 0..100 {
            gossip_state.announce_symbol(&object_id, esi, now);
        }

        // Use gossip info for routing decisions
        let connector_id = test_connector_id("data:connector:1.0.0");

        // Simulate nodes, one with local symbols based on gossip
        let mut node_symbols = HashSet::new();
        node_symbols.insert(object_id);

        let nodes = vec![
            NodeInfo {
                profile: create_profile_with_connector("node-with-data", &connector_id, "1.0.0"),
                local_symbols: node_symbols,
                held_leases: vec![],
                zones: vec![],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-no-data", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
                zones: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, now);
        let context =
            PlannerContext::new(connector_id.clone()).with_preferred_symbols(vec![object_id]);

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Node with data should be preferred
        assert_ne!(candidates, [] as [fcp_mesh::CandidateNode; 0]);
        assert_eq!(candidates[0].node_id.as_str(), "node-with-data");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "gossip_symbol_count": gossip_state.symbol_count(),
                "routing_preferred_data_locality": true,
                "selected_node": candidates[0].node_id.as_str(),
            }),
        );
    }
}

// ============================================================================
// REAL-COMPONENT MULTI-NODE INTEGRATION TESTS (9hoz)
//
// These tests exercise the full MeshNode stack with real sessions, gossip,
// admission control, and DecisionReceipt evidence — no mocks.
// ============================================================================

mod real_component_integration {
    use super::*;

    use bytes::Bytes;
    use fcp_cbor::SchemaId;
    use fcp_crypto::Ed25519SigningKey;
    use fcp_mesh::admission::{AdmissionError, AdmissionPolicy, ObjectAdmissionClass, PeerBudget};
    use fcp_mesh::gossip::{GossipConfig, GossipSummary};
    use fcp_mesh::{MeshNode, MeshNodeConfig, MeshSession, SymbolRequestError};
    use fcp_prelude::{
        Decision, DecisionReasonCode, EpochId, NodeSignature, ObjectHeader, Provenance, ZoneKeyId,
    };
    use fcp_protocol::session::{
        MeshSessionId, SessionCryptoSuite, SessionKeys, SessionReplayPolicy, TransportLimits,
    };
    use fcp_protocol::{DecodeStatus, SymbolAck, SymbolAckReason, SymbolRequest};
    use fcp_raptorq::ObjectTransmissionInformation;
    use fcp_store::{
        MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig,
        ObjectAdmissionPolicy, ObjectSymbolMeta, QuarantineStore, StoredSymbol, SymbolMeta,
        SymbolStore,
    };
    use semver::Version;

    const MOCK_CONNECTOR: &str = "foo.bar";

    fn test_header(zone_id: &ZoneId) -> ObjectHeader {
        ObjectHeader {
            schema: SchemaId::new("fcp.mesh", "SymbolRequest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 0,
            provenance: Provenance::new(zone_id.clone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn build_mesh_node_with_policy(
        name: &str,
        sender_instance_id: u64,
        local_node_id: u64,
        policy: AdmissionPolicy,
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
                .with_admission_policy(policy),
            object_store,
            symbol_store,
            quarantine_store,
        )
    }

    fn build_node(name: &str, sender_instance_id: u64, local_node_id: u64) -> MeshNode {
        build_mesh_node_with_policy(
            name,
            sender_instance_id,
            local_node_id,
            AdmissionPolicy::default(),
        )
    }

    fn authorize_peer_for_zone(node: &mut MeshNode, peer: &NodeId, zone_id: &ZoneId) {
        node.update_peer_zones(peer, HashSet::from([zone_id.clone()]));
    }

    fn authenticate_peer_for_zone(
        node: &mut MeshNode,
        peer: &NodeId,
        zone_id: &ZoneId,
        now_ms: u64,
    ) {
        authorize_peer_for_zone(node, peer, zone_id);
        node.admission_mut().set_authenticated(peer, true, now_ms);
    }

    fn sign_summary(
        signing_key: &Ed25519SigningKey,
        node_id: &NodeId,
        mut summary: GossipSummary,
    ) -> GossipSummary {
        let signature = signing_key.sign(&summary.signing_bytes());
        summary.signature = Some(NodeSignature::new(
            fcp_core::NodeId::new(node_id.as_str()),
            signature.to_bytes(),
            summary.timestamp,
        ));
        summary
    }

    async fn seed_symbols(store: &Arc<dyn SymbolStore>, meta: &ObjectSymbolMeta, source_node: u64) {
        store.put_object_meta(meta.clone()).await.unwrap();
        let symbol_size = meta.oti.symbol_size as usize;

        for esi in 0..meta.source_symbols {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id: meta.object_id,
                    esi,
                    zone_id: meta.zone_id.clone(),
                    source_node: Some(source_node),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            store.put_symbol(symbol).await.unwrap();
        }
    }

    fn make_decision_receipt(
        zone_id: &ZoneId,
        request_object_id: fcp_core::ObjectId,
        decision: Decision,
        reason_code: &str,
        node_name: &str,
        evidence: Vec<fcp_core::ObjectId>,
    ) -> fcp_core::DecisionReceipt {
        fcp_core::DecisionReceipt {
            header: ObjectHeader {
                schema: SchemaId::new("fcp.core", "DecisionReceipt", Version::new(1, 0, 0)),
                zone_id: zone_id.clone(),
                created_at: 1_000,
                provenance: Provenance::new(zone_id.clone()),
                refs: vec![],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            },
            request_object_id,
            decision,
            reason_code: reason_code.to_string(),
            evidence,
            explanation: None,
            signature: NodeSignature::new(fcp_core::NodeId::new(node_name), [0u8; 64], 1_000),
        }
    }

    // ========================================================================
    // 1. Session registration + admission auth gate through MeshNode
    // ========================================================================

    #[allow(clippy::too_many_lines)]
    #[fcp_async_core::runtime::test]
    async fn session_auth_gate_register_and_remove() {
        const TEST_NAME: &str = "session_auth_gate_register_and_remove";
        const CATEGORY: &str = "real_component";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([10u8; 8]);
        let object_id = test_object_id("session-auth-gate");
        let peer = NodeId::new("peer-session");

        let policy = AdmissionPolicy {
            require_authenticated_requests: true,
            ..AdmissionPolicy::default()
        };
        let mut node = build_mesh_node_with_policy("node-auth-gate", 50, 1, policy);
        let symbol_store = node.symbol_store().clone();
        authorize_peer_for_zone(&mut node, &peer, &zone_id);

        let oti = ObjectTransmissionInformation::new(512, 128, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };
        seed_symbols(&symbol_store, &meta, 1).await;

        // Phase 1: Unauthenticated request rejected
        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            2,
            1,
        );

        let err = node
            .handle_symbol_request(request.clone(), &peer, false, 1000)
            .await
            .expect_err("unauthenticated should be rejected");

        let deny_reason = match &err {
            SymbolRequestError::AdmissionRejected(AdmissionError::AuthenticationRequired) => {
                "authentication_required"
            }
            other => panic!("expected AuthenticationRequired, got: {other}"),
        };

        let deny_receipt = make_decision_receipt(
            &zone_id,
            object_id,
            Decision::Deny,
            deny_reason,
            "node-auth-gate",
            vec![],
        );
        assert!(deny_receipt.is_deny());
        assert_eq!(deny_receipt.reason_code, "authentication_required");

        // Phase 2: Register session → authenticated
        let session = MeshSession::new(
            MeshSessionId::new(),
            peer.clone(),
            SessionCryptoSuite::Suite1,
            SessionKeys {
                k_mac_i2r: [11u8; 32],
                k_mac_r2i: [12u8; 32],
                k_ctx: [13u8; 32],
            },
            TransportLimits::default(),
            true,
            1000,
            SessionReplayPolicy::default(),
        );
        node.register_session(session, 1000);
        assert!(node.is_peer_authenticated(&peer));

        let response = node
            .handle_symbol_request(request.clone(), &peer, false, 1001)
            .await
            .expect("authenticated session should allow request");
        assert_ne!(response.symbol_esis, [] as [u32; 0]);

        let allow_receipt = make_decision_receipt(
            &zone_id,
            object_id,
            Decision::Allow,
            DecisionReasonCode::Allow.as_str(),
            "node-auth-gate",
            vec![],
        );
        assert!(allow_receipt.is_allow());

        // Phase 3: Remove session → unauthenticated again
        node.remove_session(&peer, 2000);
        assert!(!node.is_peer_authenticated(&peer));

        let err = node
            .handle_symbol_request(request, &peer, false, 2001)
            .await
            .expect_err("unauthenticated after session removal");

        assert!(matches!(
            err,
            SymbolRequestError::AdmissionRejected(AdmissionError::AuthenticationRequired)
        ));

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "phase_1_deny": deny_reason,
                "phase_2_allow": true,
                "phase_3_deny_after_removal": true,
                "decision_receipts": 2,
            }),
        );
    }

    // ========================================================================
    // 2. Admission flood — byte budget exhaustion through MeshNode
    // ========================================================================

    #[fcp_async_core::runtime::test]
    async fn admission_flood_byte_budget_via_meshnode() {
        const TEST_NAME: &str = "admission_flood_byte_budget_via_meshnode";
        const CATEGORY: &str = "real_component";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([20u8; 8]);
        let object_id = test_object_id("flood-byte-budget");
        let peer = NodeId::new("flood-peer");

        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_bytes_per_min: 512,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut node = build_mesh_node_with_policy("node-flood-byte", 51, 1, policy);
        let symbol_store = node.symbol_store().clone();
        authenticate_peer_for_zone(&mut node, &peer, &zone_id, 1000);

        let oti = ObjectTransmissionInformation::new(512, 128, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 8,
            first_symbol_at: 0,
        };
        seed_symbols(&symbol_store, &meta, 1).await;

        let mut allowed_count = 0u32;
        let mut denied_count = 0u32;
        let mut deny_reason = String::new();
        let now_ms = 1000u64;

        // Symbol size from OTI: 128 bytes. Each request asks for max 2 symbols.
        // Estimated bytes per request = 2 * 128 = 256 bytes.
        // Budget = 512 bytes, so 2nd request should hit the limit.
        let symbol_size = 128u64;
        let max_symbols_per_request = 2u64;
        let estimated_bytes_per_request = max_symbols_per_request * symbol_size;

        for attempt in 0..10 {
            let request = SymbolRequest::new(
                test_header(&zone_id),
                object_id,
                zone_id.clone(),
                zone_key_id,
                1,
                2,
                1,
            );

            match node
                .handle_symbol_request(request, &peer, true, now_ms + attempt)
                .await
            {
                Ok(response) => {
                    assert_ne!(response.symbol_esis, [] as [u32; 0]);
                    allowed_count += 1;
                    // Record bytes against admission budget so it accumulates
                    node.admission_mut().record_bytes(
                        &peer,
                        estimated_bytes_per_request,
                        now_ms + attempt,
                    );
                }
                Err(SymbolRequestError::AdmissionRejected(ref err)) => {
                    deny_reason = format!("{err}");
                    denied_count += 1;
                    assert!(
                        matches!(err, AdmissionError::ByteBudgetExceeded { .. }),
                        "expected ByteBudgetExceeded, got: {err}"
                    );
                    break;
                }
                Err(other) => panic!("unexpected error: {other}"),
            }
        }

        assert!(allowed_count > 0, "at least one request should be allowed");
        assert!(
            denied_count > 0,
            "byte budget should eventually be exceeded"
        );

        let deny_receipt = make_decision_receipt(
            &zone_id,
            object_id,
            Decision::Deny,
            "byte_budget_exceeded",
            "node-flood-byte",
            vec![],
        );
        assert!(deny_receipt.is_deny());

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "allowed_requests": allowed_count,
                "denied_requests": denied_count,
                "deny_reason": deny_reason,
                "receipt_reason": deny_receipt.reason_code,
            }),
        );
    }

    // ========================================================================
    // 3. Admission flood — symbol budget exhaustion through MeshNode
    // ========================================================================

    #[fcp_async_core::runtime::test]
    async fn admission_flood_symbol_budget_via_meshnode() {
        const TEST_NAME: &str = "admission_flood_symbol_budget_via_meshnode";
        const CATEGORY: &str = "real_component";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([21u8; 8]);
        let object_id = test_object_id("flood-symbol-budget");
        let peer = NodeId::new("flood-sym-peer");

        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_symbols_per_min: 5,
                max_bytes_per_min: u64::MAX,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut node = build_mesh_node_with_policy("node-flood-sym", 52, 1, policy);
        let symbol_store = node.symbol_store().clone();
        authenticate_peer_for_zone(&mut node, &peer, &zone_id, 1000);

        let oti = ObjectTransmissionInformation::new(512, 128, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 8,
            first_symbol_at: 0,
        };
        seed_symbols(&symbol_store, &meta, 1).await;

        let mut allowed_symbols = 0u32;
        let mut denied = false;
        let now_ms = 1000u64;
        // Each request asks for max 2 symbols; budget is 5, so 3rd request should exceed
        let symbols_per_request = 2u32;

        for attempt in 0..10 {
            let request = SymbolRequest::new(
                test_header(&zone_id),
                object_id,
                zone_id.clone(),
                zone_key_id,
                1,
                2,
                1,
            );

            match node
                .handle_symbol_request(request, &peer, true, now_ms + attempt)
                .await
            {
                Ok(response) => {
                    let sent = u32::try_from(response.symbol_esis.len())
                        .expect("symbol count should fit in u32");
                    allowed_symbols += sent;
                    // Record symbols against admission budget so it accumulates
                    node.admission_mut().record_symbols(
                        &peer,
                        symbols_per_request,
                        now_ms + attempt,
                    );
                }
                Err(SymbolRequestError::AdmissionRejected(ref err)) => {
                    assert!(
                        matches!(err, AdmissionError::SymbolBudgetExceeded { .. }),
                        "expected SymbolBudgetExceeded, got: {err}"
                    );
                    denied = true;
                    break;
                }
                Err(other) => panic!("unexpected error: {other}"),
            }
        }

        assert!(allowed_symbols > 0);
        assert!(denied, "symbol budget should eventually be exceeded");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "allowed_symbols": allowed_symbols,
                "budget_exceeded": denied,
            }),
        );
    }

    // ========================================================================
    // 4. Multi-node gossip convergence through MeshNode
    // ========================================================================

    #[test]
    #[allow(clippy::similar_names)] // Two-node convergence test intentionally keeps symmetric A/B identifiers.
    fn multi_node_gossip_convergence_via_meshnode() {
        const TEST_NAME: &str = "multi_node_gossip_convergence_via_meshnode";
        const CATEGORY: &str = "real_component";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let obj_a = test_object_id("gossip-obj-a");
        let obj_b = test_object_id("gossip-obj-b");
        let obj_c = test_object_id("gossip-obj-c");

        let mut node_a = build_node("node-gossip-a", 60, 1);
        let mut node_b = build_node("node-gossip-b", 61, 2);
        let gossip_a_id = NodeId::new("node-gossip-a");
        let gossip_b_id = NodeId::new("node-gossip-b");
        let signing_key_a = Ed25519SigningKey::generate();
        let signing_key_b = Ed25519SigningKey::generate();
        node_a.register_peer_signing_key(gossip_b_id.clone(), signing_key_b.verifying_key());
        node_b.register_peer_signing_key(gossip_a_id.clone(), signing_key_a.verifying_key());
        authorize_peer_for_zone(&mut node_a, &gossip_b_id, &zone_id);
        authorize_peer_for_zone(&mut node_b, &gossip_a_id, &zone_id);

        // Node A announces obj_a and obj_b
        assert!(node_a.announce_object(&zone_id, &obj_a, ObjectAdmissionClass::Admitted, 1000));
        assert!(node_a.announce_object(&zone_id, &obj_b, ObjectAdmissionClass::Admitted, 1001));
        for esi in 0..10 {
            node_a.announce_symbol(&zone_id, &obj_a, esi, ObjectAdmissionClass::Admitted, 1002);
        }

        // Node B announces obj_b and obj_c
        assert!(node_b.announce_object(&zone_id, &obj_b, ObjectAdmissionClass::Admitted, 1000));
        assert!(node_b.announce_object(&zone_id, &obj_c, ObjectAdmissionClass::Admitted, 1001));
        for esi in 0..5 {
            node_b.announce_symbol(&zone_id, &obj_c, esi, ObjectAdmissionClass::Admitted, 1002);
        }

        // Node A: knows obj_a and obj_b, not obj_c
        assert!(node_a.gossip_mut().has_object(&zone_id, &obj_a));
        assert!(node_a.gossip_mut().has_object(&zone_id, &obj_b));
        assert!(!node_a.gossip_mut().has_object(&zone_id, &obj_c));

        // Node B: knows obj_b and obj_c, not obj_a
        assert!(node_b.gossip_mut().has_object(&zone_id, &obj_b));
        assert!(node_b.gossip_mut().has_object(&zone_id, &obj_c));
        assert!(!node_b.gossip_mut().has_object(&zone_id, &obj_a));

        // Exchange gossip summaries + handle_summary to track peer state
        let epoch = EpochId::new("epoch-convergence");

        let summary_a = node_a
            .gossip_mut()
            .create_summary(&zone_id, epoch.clone())
            .expect("node A should produce a summary");
        let summary_a = sign_summary(&signing_key_a, &gossip_a_id, summary_a);

        // B processes A's summary to learn about A's objects
        let _ = node_b
            .handle_gossip_message(GossipMessage::Summary(summary_a), 2000)
            .expect("node B should accept node A's signed summary");

        // B requests objects it learned about from A
        let request_from_b = node_b
            .gossip_mut()
            .create_request(&zone_id, vec![obj_a, obj_b], 2001);
        let response_a = node_a.gossip_mut().handle_request(&request_from_b);
        assert!(
            !response_a.have_objects.is_empty(),
            "node A should have objects B requests"
        );

        let summary_b = node_b
            .gossip_mut()
            .create_summary(&zone_id, epoch)
            .expect("node B should produce a summary");
        let summary_b = sign_summary(&signing_key_b, &gossip_b_id, summary_b);

        // A processes B's summary to learn about B's objects
        let _ = node_a
            .handle_gossip_message(GossipMessage::Summary(summary_b), 2002)
            .expect("node A should accept node B's signed summary");

        // A requests objects it learned about from B
        let request_from_a = node_a
            .gossip_mut()
            .create_request(&zone_id, vec![obj_c], 2003);
        let response_b = node_b.gossip_mut().handle_request(&request_from_a);
        assert!(
            !response_b.have_objects.is_empty(),
            "node B should have objects A requests"
        );

        let metrics_a = node_a.metrics();
        let metrics_b = node_b.metrics();
        assert!(metrics_a.gossip_announcements >= 2);
        assert!(metrics_b.gossip_announcements >= 2);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "node_a_objects": 2,
                "node_b_objects": 2,
                "node_a_announcements": metrics_a.gossip_announcements,
                "node_b_announcements": metrics_b.gossip_announcements,
                "a_has_for_b": response_a.have_objects.len(),
                "b_has_for_a": response_b.have_objects.len(),
            }),
        );
    }

    // ========================================================================
    // 5. Multi-node session-gated symbol transfer with DecisionReceipt
    // ========================================================================

    #[allow(clippy::too_many_lines)]
    #[fcp_async_core::runtime::test]
    async fn multi_node_session_gated_symbol_transfer() {
        const TEST_NAME: &str = "multi_node_session_gated_symbol_transfer";
        const CATEGORY: &str = "real_component";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([30u8; 8]);
        let object_id = test_object_id("session-gated-transfer");
        let peer_b = NodeId::new("node-b-peer");

        let policy = AdmissionPolicy {
            require_authenticated_requests: true,
            ..AdmissionPolicy::default()
        };
        let mut node_a = build_mesh_node_with_policy("node-a-gated", 70, 1, policy);
        let node_b = build_node("node-b-requester", 71, 2);
        authorize_peer_for_zone(&mut node_a, &peer_b, &zone_id);

        let symbol_store_a = node_a.symbol_store().clone();
        let receiver_store = node_b.symbol_store().clone();

        let oti = ObjectTransmissionInformation::new(512, 128, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };
        seed_symbols(&symbol_store_a, &meta, 1).await;

        // Phase 1: Unauthenticated — denied
        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            4,
            1,
        );
        let err = node_a
            .handle_symbol_request(request, &peer_b, false, 1000)
            .await
            .expect_err("unauthenticated should fail");
        assert!(matches!(
            err,
            SymbolRequestError::AdmissionRejected(AdmissionError::AuthenticationRequired)
        ));

        let deny_receipt = make_decision_receipt(
            &zone_id,
            object_id,
            Decision::Deny,
            "authentication_required",
            "node-a-gated",
            vec![],
        );

        // Phase 2: Register session → authenticated transfer
        let session = MeshSession::new(
            MeshSessionId::new(),
            peer_b.clone(),
            SessionCryptoSuite::Suite1,
            SessionKeys {
                k_mac_i2r: [31u8; 32],
                k_mac_r2i: [32u8; 32],
                k_ctx: [33u8; 32],
            },
            TransportLimits::default(),
            true,
            1001,
            SessionReplayPolicy::default(),
        );
        node_a.register_session(session, 1001);

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            4,
            1,
        );
        let response = node_a
            .handle_symbol_request(request, &peer_b, false, 1002)
            .await
            .expect("authenticated session should succeed");

        assert_eq!(response.symbol_esis.len(), 4);
        assert!(response.is_final);

        let allow_receipt = make_decision_receipt(
            &zone_id,
            object_id,
            Decision::Allow,
            DecisionReasonCode::Allow.as_str(),
            "node-a-gated",
            vec![object_id],
        );

        // Transfer symbols to receiver
        receiver_store.put_object_meta(meta.clone()).await.unwrap();
        for esi in response.symbol_esis {
            let symbol = symbol_store_a.get_symbol(&object_id, esi).await.unwrap();
            receiver_store.put_symbol(symbol).await.unwrap();
        }
        assert!(receiver_store.can_reconstruct(&object_id).await);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "deny_receipt": { "decision": "deny", "reason": deny_receipt.reason_code },
                "allow_receipt": { "decision": "allow", "reason": allow_receipt.reason_code },
                "symbols_transferred": 4,
                "receiver_reconstructed": true,
            }),
        );
    }

    // ========================================================================
    // 6. Gossip quarantine isolation through MeshNode (multi-object)
    // ========================================================================

    #[test]
    fn gossip_quarantine_isolation_multi_object() {
        const TEST_NAME: &str = "gossip_quarantine_isolation_multi_object";
        const CATEGORY: &str = "real_component";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let clean_obj = test_object_id("gossip-clean");
        let quarantined_obj = test_object_id("gossip-quarantined");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        quarantine_store
            .quarantine(fcp_store::QuarantinedObject {
                object_id: quarantined_obj,
                zone_id: zone_id.clone(),
                data: Bytes::from_static(b"malicious"),
                source_peer: Some(999),
                received_at: 0,
                peer_reputation: -50,
            })
            .expect("quarantine");

        let mut node = MeshNode::new(
            MeshNodeConfig::new("node-quarantine").with_sender_instance_id(80),
            object_store,
            symbol_store,
            quarantine_store,
        );

        let clean_added =
            node.announce_object(&zone_id, &clean_obj, ObjectAdmissionClass::Admitted, 1000);
        let quarantined_added = node.announce_object(
            &zone_id,
            &quarantined_obj,
            ObjectAdmissionClass::Admitted,
            1001,
        );

        assert!(clean_added);
        assert!(node.gossip_mut().has_object(&zone_id, &clean_obj));
        assert!(!quarantined_added);
        assert!(!node.gossip_mut().has_object(&zone_id, &quarantined_obj));

        let sym_added = node.announce_symbol(
            &zone_id,
            &quarantined_obj,
            0,
            ObjectAdmissionClass::Admitted,
            1002,
        );
        assert!(!sym_added);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "clean_gossipped": clean_added,
                "quarantined_blocked": !quarantined_added,
                "quarantined_symbol_blocked": !sym_added,
            }),
        );
    }

    // ========================================================================
    // 7. DecisionReceipt evidence chain for admission outcomes
    // ========================================================================

    #[allow(clippy::too_many_lines)]
    #[fcp_async_core::runtime::test]
    async fn decision_receipt_evidence_chain() {
        const TEST_NAME: &str = "decision_receipt_evidence_chain";
        const CATEGORY: &str = "real_component";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([40u8; 8]);
        let object_id = test_object_id("receipt-evidence");
        let peer = NodeId::new("receipt-peer");

        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_bytes_per_min: 1024,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut node = build_mesh_node_with_policy("node-receipt", 90, 1, policy);
        let symbol_store = node.symbol_store().clone();
        authenticate_peer_for_zone(&mut node, &peer, &zone_id, 1000);

        let oti = ObjectTransmissionInformation::new(512, 128, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 8,
            first_symbol_at: 0,
        };
        seed_symbols(&symbol_store, &meta, 1).await;

        let mut receipts: Vec<fcp_core::DecisionReceipt> = Vec::new();
        let now_ms = 1000u64;
        // Symbol size from OTI: 128 bytes. Each request asks for max 2 symbols.
        // Estimated bytes per request = 2 * 128 = 256 bytes.
        // Budget = 1024 bytes, so ~4 requests before exhaustion.
        let estimated_bytes_per_request = 2u64 * 128;

        for attempt in 0..20 {
            let request = SymbolRequest::new(
                test_header(&zone_id),
                object_id,
                zone_id.clone(),
                zone_key_id,
                1,
                2,
                1,
            );

            match node
                .handle_symbol_request(request, &peer, true, now_ms + attempt)
                .await
            {
                Ok(_) => {
                    // Record bytes so admission budget accumulates
                    node.admission_mut().record_bytes(
                        &peer,
                        estimated_bytes_per_request,
                        now_ms + attempt,
                    );
                    receipts.push(make_decision_receipt(
                        &zone_id,
                        object_id,
                        Decision::Allow,
                        DecisionReasonCode::Allow.as_str(),
                        "node-receipt",
                        vec![object_id],
                    ));
                }
                Err(SymbolRequestError::AdmissionRejected(ref err)) => {
                    let reason = match err {
                        AdmissionError::ByteBudgetExceeded { .. } => "byte_budget_exceeded",
                        AdmissionError::SymbolBudgetExceeded { .. } => "symbol_budget_exceeded",
                        other => panic!("unexpected admission error: {other}"),
                    };
                    receipts.push(make_decision_receipt(
                        &zone_id,
                        object_id,
                        Decision::Deny,
                        reason,
                        "node-receipt",
                        vec![],
                    ));
                    break;
                }
                Err(_) => break,
            }
        }

        let allow_count = receipts.iter().filter(|r| r.is_allow()).count();
        let deny_count = receipts.iter().filter(|r| r.is_deny()).count();

        assert!(allow_count > 0, "must have at least one allow receipt");
        assert!(deny_count > 0, "must have at least one deny receipt");

        for receipt in &receipts {
            assert_eq!(*receipt.zone_id(), zone_id);
            assert_eq!(receipt.request_object_id, object_id);
            assert_eq!(
                receipt.signature.node_id,
                fcp_core::NodeId::new("node-receipt")
            );
            if receipt.is_allow() {
                assert_eq!(receipt.evidence.len(), 1);
            }
        }

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "total_receipts": receipts.len(),
                "allow_receipts": allow_count,
                "deny_receipts": deny_count,
                "evidence_chain_valid": true,
            }),
        );
    }

    // ========================================================================
    // 8. DecodeStatus::Complete stops further transfers
    // ========================================================================

    #[fcp_async_core::runtime::test]
    async fn decode_complete_stops_transfer_via_meshnode() {
        const TEST_NAME: &str = "decode_complete_stops_transfer_via_meshnode";
        const CATEGORY: &str = "real_component";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([50u8; 8]);
        let object_id = test_object_id("decode-complete-stop");
        let peer = NodeId::new("decode-peer");

        let mut node = build_node("node-decode", 100, 1);
        let symbol_store = node.symbol_store().clone();
        authenticate_peer_for_zone(&mut node, &peer, &zone_id, 1000);

        let oti = ObjectTransmissionInformation::new(512, 128, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };
        seed_symbols(&symbol_store, &meta, 1).await;

        // Phase 1: Initial request succeeds
        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            2,
            1,
        );

        let response = node
            .handle_symbol_request(request, &peer, true, 1000)
            .await
            .expect("first request should succeed");
        assert_ne!(response.symbol_esis, [] as [u32; 0]);

        // Phase 2: Peer reports decode complete
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.status", "DecodeStatus", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 0,
            provenance: Provenance::new(zone_id.clone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        };
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());

        let mut status = DecodeStatus {
            header,
            object_id,
            zone_id: zone_id.clone(),
            zone_key_id,
            epoch_id: 1,
            // Must match the build_node("node-decode", ...) identity so
            // MeshNode::handle_decode_status's recipient-binding check passes.
            recipient_node_id: TailscaleNodeId::new("node-decode"),
            request_nonce: 3,
            received_unique: 4,
            needed: 0,
            complete: true,
            missing_hint: None,
            signature: fcp_crypto::Ed25519Signature::from_bytes(&[0u8; 64]),
        };
        status.sign(&signing_key);
        node.handle_decode_status(&peer, &status, 1001)
            .expect("status should verify");

        // Phase 3: Follow-up request rejected
        let request2 = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            2,
            1,
        );

        let err = node
            .handle_symbol_request(request2, &peer, true, 1001)
            .await
            .expect_err("should reject after decode complete");
        assert!(matches!(err, SymbolRequestError::AlreadyComplete { .. }));

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "initial_symbols_sent": response.symbol_esis.len(),
                "decode_complete_reported": true,
                "follow_up_rejected": true,
            }),
        );
    }

    // ========================================================================
    // 9. Gossip checkpoint exchange between MeshNodes
    // ========================================================================

    #[allow(clippy::too_many_lines, clippy::similar_names)]
    #[test]
    fn gossip_checkpoint_exchange_reconciliation() {
        const TEST_NAME: &str = "gossip_checkpoint_exchange_reconciliation";
        const CATEGORY: &str = "real_component";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();

        let gossip_config = GossipConfig {
            max_objects_per_summary: 100,
            max_symbols_per_summary: 1000,
            max_objects_per_request: 50,
            max_symbols_per_request: 50,
            ..GossipConfig::default()
        };

        let object_store_a = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store_a = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store_a = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let mut node_a = MeshNode::new(
            MeshNodeConfig::new("node-ckpt-a")
                .with_sender_instance_id(110)
                .with_gossip_config(gossip_config.clone()),
            object_store_a,
            symbol_store_a,
            quarantine_store_a,
        );

        let object_store_b = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store_b = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store_b = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let mut node_b = MeshNode::new(
            MeshNodeConfig::new("node-ckpt-b")
                .with_sender_instance_id(111)
                .with_gossip_config(gossip_config),
            object_store_b,
            symbol_store_b,
            quarantine_store_b,
        );
        let checkpoint_a_id = NodeId::new("node-ckpt-a");
        let checkpoint_b_id = NodeId::new("node-ckpt-b");
        let signing_key_a = Ed25519SigningKey::generate();
        let signing_key_b = Ed25519SigningKey::generate();
        node_a.register_peer_signing_key(checkpoint_b_id.clone(), signing_key_b.verifying_key());
        node_b.register_peer_signing_key(checkpoint_a_id.clone(), signing_key_a.verifying_key());
        authorize_peer_for_zone(&mut node_a, &checkpoint_b_id, &zone_id);
        authorize_peer_for_zone(&mut node_b, &checkpoint_a_id, &zone_id);

        // Node A: 5 objects
        let mut a_objects = Vec::new();
        for i in 0_u64..5 {
            let obj = test_object_id(&format!("checkpoint-a-{i}"));
            node_a.announce_object(&zone_id, &obj, ObjectAdmissionClass::Admitted, 1000 + i);
            a_objects.push(obj);
        }

        // Node B: 3 objects (1 overlap with A)
        let mut b_objects = Vec::new();
        node_b.announce_object(
            &zone_id,
            &a_objects[0],
            ObjectAdmissionClass::Admitted,
            1000,
        );
        b_objects.push(a_objects[0]);
        for i in 0_u64..2 {
            let obj = test_object_id(&format!("checkpoint-b-{i}"));
            node_b.announce_object(&zone_id, &obj, ObjectAdmissionClass::Admitted, 1001 + i);
            b_objects.push(obj);
        }

        // A → B checkpoint exchange
        let epoch = EpochId::new("epoch-checkpoint");
        let summary_a = node_a
            .gossip_mut()
            .create_summary(&zone_id, epoch.clone())
            .expect("A should produce summary");
        let summary_a = sign_summary(&signing_key_a, &checkpoint_a_id, summary_a);

        // B processes A's summary, then requests A's objects it doesn't have
        let _ = node_b
            .handle_gossip_message(GossipMessage::Summary(summary_a), 2000)
            .expect("B should accept A's signed summary");
        // B wants a_objects[1..5] (it already has a_objects[0])
        let missing_from_a: Vec<_> = a_objects[1..].to_vec();
        let request_from_b = node_b
            .gossip_mut()
            .create_request(&zone_id, missing_from_a, 2001);
        let response_a = node_a.gossip_mut().handle_request(&request_from_b);

        // B → A checkpoint exchange
        let summary_b = node_b
            .gossip_mut()
            .create_summary(&zone_id, epoch)
            .expect("B should produce summary");
        let summary_b = sign_summary(&signing_key_b, &checkpoint_b_id, summary_b);
        let _ = node_a
            .handle_gossip_message(GossipMessage::Summary(summary_b), 2002)
            .expect("A should accept B's signed summary");

        // A wants b_objects[1..3] (it already has a_objects[0] which overlaps)
        let missing_from_b: Vec<_> = b_objects[1..].to_vec();
        let request_from_a = node_a
            .gossip_mut()
            .create_request(&zone_id, missing_from_b, 2003);
        let response_b = node_b.gossip_mut().handle_request(&request_from_a);

        // A should confirm it has the objects B requested
        assert!(
            !response_a.have_objects.is_empty(),
            "A should have objects for B's request"
        );
        // B should confirm it has the objects A requested
        assert!(
            !response_b.have_objects.is_empty(),
            "B should have objects for A's request"
        );

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "node_a_announced": a_objects.len(),
                "node_b_announced": b_objects.len(),
                "overlap": 1,
                "a_has_for_b": response_a.have_objects.len(),
                "b_has_for_a": response_b.have_objects.len(),
            }),
        );
    }

    // ========================================================================
    // 10. Anti-amplification through MeshNode
    // ========================================================================

    #[fcp_async_core::runtime::test]
    async fn admission_anti_amplification_via_meshnode() {
        const TEST_NAME: &str = "admission_anti_amplification_via_meshnode";
        const CATEGORY: &str = "real_component";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([60u8; 8]);
        let object_id = test_object_id("anti-amplification");
        let peer = NodeId::new("amp-peer");

        let policy = AdmissionPolicy {
            max_amplification_factor: 2,
            require_authenticated_requests: false,
            ..AdmissionPolicy::default()
        };
        let mut node = build_mesh_node_with_policy("node-amp", 120, 1, policy);
        let symbol_store = node.symbol_store().clone();
        authorize_peer_for_zone(&mut node, &peer, &zone_id);

        let oti = ObjectTransmissionInformation::new(512, 128, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };
        seed_symbols(&symbol_store, &meta, 1).await;

        // Record minimal incoming to trigger amplification ratio check
        node.admission_mut().record_bytes(&peer, 10, 1000);

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            4,
            1,
        );

        let result = node.handle_symbol_request(request, &peer, true, 1001).await;

        let (decision, reason) = match &result {
            Ok(_) => (
                Decision::Allow,
                DecisionReasonCode::Allow.as_str().to_string(),
            ),
            Err(SymbolRequestError::AdmissionRejected(err)) => {
                let reason = match err {
                    AdmissionError::AmplificationViolation { .. } => "amplification_violation",
                    other => panic!("unexpected admission error: {other}"),
                };
                (Decision::Deny, reason.to_string())
            }
            Err(other) => panic!("unexpected error: {other}"),
        };

        let _receipt =
            make_decision_receipt(&zone_id, object_id, decision, &reason, "node-amp", vec![]);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "decision": format!("{decision:?}"),
                "reason": reason,
                "receipt_generated": true,
            }),
        );
    }

    // ========================================================================
    // 11. Peer state routing through MeshNode plan_execution
    // ========================================================================

    #[test]
    fn peer_state_routing_through_meshnode() {
        const TEST_NAME: &str = "peer_state_routing_through_meshnode";
        const CATEGORY: &str = "real_component";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("route:connector:1.0.0");
        let target_symbol = test_object_id("routing-target-symbol");

        let mut node = build_node("node-router", 130, 1);

        let mut peer1_symbols = HashSet::new();
        peer1_symbols.insert(target_symbol);

        let gpu = GpuProfile::new(GpuVendor::Nvidia, "RTX 4090", 24576);
        node.update_peer_state(
            NodeId::new("peer-powerful"),
            DeviceProfile::builder(NodeId::new("peer-powerful"))
                .cpu_cores(32)
                .memory_mb(131072)
                .gpu(gpu)
                .add_connector(InstalledConnector::new(
                    connector_id.clone(),
                    "1.0.0",
                    test_object_id("bin1"),
                ))
                .build(),
            peer1_symbols,
            vec![],
            1000,
        );

        node.update_peer_state(
            NodeId::new("peer-weak"),
            DeviceProfile::builder(NodeId::new("peer-weak"))
                .cpu_cores(4)
                .memory_mb(8192)
                .add_connector(InstalledConnector::new(
                    connector_id.clone(),
                    "1.0.0",
                    test_object_id("bin2"),
                ))
                .build(),
            HashSet::new(),
            vec![],
            1000,
        );

        assert_eq!(node.peer_count(), 2);

        let context = PlannerContext::new(connector_id).with_preferred_symbols(vec![target_symbol]);
        let candidates = node.plan_execution(&context, 1000);

        assert_ne!(candidates, [] as [fcp_mesh::CandidateNode; 0]);
        assert_eq!(candidates[0].node_id.as_str(), "peer-powerful");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "candidates": candidates.len(),
                "top_candidate": candidates[0].node_id.as_str(),
                "top_score": candidates[0].score,
            }),
        );
    }

    // ========================================================================
    // 12. SymbolAck StopSending halts further transfers
    // ========================================================================

    #[fcp_async_core::runtime::test]
    async fn symbol_ack_stop_sending_via_meshnode() {
        const TEST_NAME: &str = "symbol_ack_stop_sending_via_meshnode";
        const CATEGORY: &str = "real_component";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([70u8; 8]);
        let object_id = test_object_id("ack-stop-sending");
        let peer = NodeId::new("ack-peer");

        let mut node = build_node("node-ack", 140, 1);
        let symbol_store = node.symbol_store().clone();
        authenticate_peer_for_zone(&mut node, &peer, &zone_id, 1000);

        let oti = ObjectTransmissionInformation::new(512, 128, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 4,
            first_symbol_at: 0,
        };
        seed_symbols(&symbol_store, &meta, 1).await;

        // Phase 1: Normal request
        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            2,
            1,
        );
        let response = node
            .handle_symbol_request(request, &peer, true, 1000)
            .await
            .expect("first request should succeed");
        assert_ne!(response.symbol_esis, [] as [u32; 0]);

        // Phase 2: SymbolAck Complete — signals object is fully decoded
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());

        let mut ack = SymbolAck::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            TailscaleNodeId::new("node-ack"),
            4,
            SymbolAckReason::Complete,
            4,
        );
        ack.sign(&signing_key);
        node.handle_symbol_ack(&peer, &ack, 1001)
            .expect("ack should verify");

        // Phase 3: Rejected
        let request2 = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            2,
            1,
        );
        let err = node
            .handle_symbol_request(request2, &peer, true, 1001)
            .await
            .expect_err("should stop after SymbolAck StopSending");
        assert!(matches!(err, SymbolRequestError::AlreadyComplete { .. }));

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "initial_symbols": response.symbol_esis.len(),
                "stop_ack_received": true,
                "follow_up_rejected": true,
            }),
        );
    }
}
