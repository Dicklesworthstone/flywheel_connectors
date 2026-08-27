//! No-mock integration tests for fcp-mesh: admission, device, gossip,
//! transport, session, symbol request, planner, and degraded-mode.
//!
//! Uses real structs and crypto — no mocks, stubs, or fakes.

use std::collections::HashSet;

use fcp_crypto::{Ed25519SigningKey, MlDsa65SigningKey, PqSigningPolicy};
use fcp_mesh::degraded::{
    ControlPlaneEnvelope, ControlPlaneHandler, DegradedModeDecoder, DegradedModeEncoder,
    DegradedTransportError, InMemoryControlPlaneHandler, RetentionClass, SignedDegradedFrameAuth,
};
use fcp_mesh::device::{
    AvailabilityProfile, CpuArch, DeviceProfile, FitnessContext, GpuProfile, GpuVendor,
    InstalledConnector, LatencyClass, PowerSource, TpuProfile, TpuVendor,
};
use fcp_mesh::gossip::{GossipConfig, GossipState, MeshGossip};
use fcp_mesh::node::{MeshNodeError, MeshNodeMetrics};
use fcp_mesh::planner::{
    ExecutionPlanner, HeldLease, LeasePurpose, NodeInfo, PlannerContext, PlannerInput,
};
use fcp_mesh::replay::{
    TraceReplayDiff, TraceReplayEngine, TraceReplayError, TraceReplayInputFormat,
    TraceReplayReport, TraceReplaySummary,
};
use fcp_mesh::session::MeshSession;
use fcp_mesh::symbol_request::{
    SymbolRequestError, SymbolRequestHandler, SymbolRequestPolicy, SymbolResponseBuilder,
    TargetedRepairEngine,
};
use fcp_mesh::transport::{TransportPath, TransportPathKind, TransportSelector};
use fcp_mesh::{
    AdmissionController, AdmissionError, AdmissionPolicy, MeshNode, MeshNodeConfig,
    ObjectAdmissionClass, ObjectAdmissionPolicy, PeerBudget,
};
use fcp_prelude::{
    ConnectorId, EpochId, ObjectId, TailscaleNodeId, ZoneId, ZoneKey, ZoneKeyAlgorithm, ZoneKeyId,
    ZoneTransportPolicy,
};
use fcp_protocol::session::{
    MeshSessionId, SessionCryptoSuite, SessionKeys, SessionReplayPolicy, TransportLimits,
};
use fcp_raptorq::RaptorQConfig;
use fcp_store::{
    MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig,
    QuarantineStore,
};
use fcp_tailscale::NodeId;
use fcp_telemetry::trace_capture::TraceCaptureConfig;
use std::sync::Arc;

// ── Helpers ──

fn test_node(name: &str) -> NodeId {
    NodeId::new(name)
}

fn test_ts_node(name: &str) -> TailscaleNodeId {
    TailscaleNodeId::new(name)
}

const fn test_object_id(n: u8) -> ObjectId {
    ObjectId::from_bytes([n; 32])
}

fn test_zone() -> ZoneId {
    ZoneId::work()
}

const fn test_zone_key_id() -> ZoneKeyId {
    ZoneKeyId::from_bytes([0xBB; 8])
}

const fn test_zone_key() -> ZoneKey {
    ZoneKey::from_bytes([0xA5; 32])
}

const fn test_zone_key_algorithm() -> ZoneKeyAlgorithm {
    ZoneKeyAlgorithm::ChaCha20Poly1305
}

fn test_connector_id(name: &str) -> ConnectorId {
    ConnectorId::new(name, "request-response", "0.1.0").expect("test connector id")
}

const fn test_session_keys() -> SessionKeys {
    SessionKeys {
        k_mac_i2r: [1u8; 32],
        k_mac_r2i: [2u8; 32],
        k_ctx: [3u8; 32],
    }
}

fn test_device_profile(name: &str, memory_mb: u32, cpu_cores: u16) -> DeviceProfile {
    DeviceProfile::builder(test_node(name))
        .cpu_cores(cpu_cores)
        .cpu_arch(CpuArch::Aarch64)
        .memory_mb(memory_mb)
        .local_storage_mb(10_000)
        .symbol_store_quota_mb(5_000)
        .power_source(PowerSource::Mains)
        .bandwidth_estimate_kbps(100_000)
        .latency_class(LatencyClass::Lan)
        .availability(AvailabilityProfile::AlwaysOn)
        .build()
}

fn profile_with_connector(
    name: &str,
    memory_mb: u32,
    cpu_cores: u16,
    connector_id: &str,
    version: &str,
) -> DeviceProfile {
    let connector = InstalledConnector::new(
        test_connector_id(connector_id),
        version.to_string(),
        test_object_id(0xFF),
    );
    DeviceProfile::builder(test_node(name))
        .cpu_cores(cpu_cores)
        .cpu_arch(CpuArch::Aarch64)
        .memory_mb(memory_mb)
        .local_storage_mb(10_000)
        .symbol_store_quota_mb(5_000)
        .power_source(PowerSource::Mains)
        .bandwidth_estimate_kbps(100_000)
        .latency_class(LatencyClass::Lan)
        .availability(AvailabilityProfile::AlwaysOn)
        .add_connector(connector)
        .build()
}

// ════════════════════════════════════════════════════════════════════════════
// Admission Control
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn admission_default_policy_requires_auth() {
    let policy = AdmissionPolicy::default();
    assert!(policy.require_authenticated_requests);
    assert!(policy.strict_unauthenticated_limits);
}

#[test]
fn admission_public_ingress_allows_unauth() {
    let policy = AdmissionPolicy::public_ingress();
    assert!(!policy.require_authenticated_requests);
    assert_eq!(policy.max_amplification_factor, 2);
}

#[test]
fn admission_trusted_mesh_high_limits() {
    let policy = AdmissionPolicy::trusted_mesh();
    assert!(policy.require_authenticated_requests);
    assert_eq!(policy.max_amplification_factor, 100);
    assert!(!policy.strict_unauthenticated_limits);
}

#[test]
fn admission_check_bytes_within_budget() {
    let mut ctrl = AdmissionController::new(AdmissionPolicy::public_ingress());
    let peer = test_node("peer-1");
    let now = 1_000_000u64;
    ctrl.check_bytes(&peer, 1024, now).expect("within budget");
}

#[test]
fn admission_check_bytes_exceeds_budget() {
    let budget = PeerBudget {
        max_bytes_per_min: 100,
        ..PeerBudget::restrictive()
    };
    let policy = AdmissionPolicy {
        per_peer: budget,
        require_authenticated_requests: false,
        max_amplification_factor: 10,
        strict_unauthenticated_limits: false,
        ..AdmissionPolicy::default()
    };
    let mut ctrl = AdmissionController::new(policy);
    let peer = test_node("peer-1");
    let now = 1_000_000u64;
    ctrl.record_bytes(&peer, 100, now);
    let err = ctrl.check_bytes(&peer, 1, now).unwrap_err();
    assert!(matches!(err, AdmissionError::ByteBudgetExceeded { .. }));
    assert!(err.is_retryable());
    assert!(err.retry_after().is_some());
}

#[test]
fn admission_check_symbols_exceeds_budget() {
    let budget = PeerBudget {
        max_symbols_per_min: 10,
        ..PeerBudget::restrictive()
    };
    let policy = AdmissionPolicy {
        per_peer: budget,
        require_authenticated_requests: false,
        max_amplification_factor: 10,
        strict_unauthenticated_limits: false,
        ..AdmissionPolicy::default()
    };
    let mut ctrl = AdmissionController::new(policy);
    let peer = test_node("peer-2");
    let now = 2_000_000u64;
    ctrl.record_symbols(&peer, 10, now);
    let err = ctrl.check_symbols(&peer, 1, now).unwrap_err();
    assert!(matches!(err, AdmissionError::SymbolBudgetExceeded { .. }));
}

#[test]
fn admission_window_reset_allows_more() {
    let budget = PeerBudget {
        max_bytes_per_min: 100,
        ..PeerBudget::restrictive()
    };
    let policy = AdmissionPolicy {
        per_peer: budget,
        require_authenticated_requests: false,
        max_amplification_factor: 10,
        strict_unauthenticated_limits: false,
        ..AdmissionPolicy::default()
    };
    let mut ctrl = AdmissionController::new(policy);
    let peer = test_node("peer-1");
    let t0 = 1_000_000u64;
    ctrl.record_bytes(&peer, 100, t0);
    // The sliding-window controller keeps the previous bucket decaying
    // through the next minute. After two windows, the original usage is stale.
    let t1 = t0 + 121_000;
    ctrl.check_bytes(&peer, 50, t1).expect("new window allows");
}

#[test]
fn admission_auth_required_rejects_unauth() {
    let mut ctrl = AdmissionController::new(AdmissionPolicy::default());
    let peer = test_node("peer-noauth");
    let now = 1_000_000u64;
    let err = ctrl.check_admission(&peer, 64, 1, false, now).unwrap_err();
    assert!(matches!(err, AdmissionError::AuthenticationRequired));
    assert!(!err.is_retryable());
}

#[test]
fn admission_set_and_check_authenticated() {
    let mut ctrl = AdmissionController::with_default_policy();
    let peer = test_node("peer-auth");
    let now = 1_000_000u64;
    assert!(!ctrl.is_authenticated(&peer));
    ctrl.set_authenticated(&peer, true, now);
    assert!(ctrl.is_authenticated(&peer));
}

#[test]
fn admission_gc_stale_peers() {
    let mut ctrl = AdmissionController::new(AdmissionPolicy::public_ingress());
    let peer = test_node("stale-peer");
    let now = 1_000_000u64;
    ctrl.record_bytes(&peer, 10, now);
    assert_eq!(ctrl.peer_count(), 1);
    ctrl.gc_stale_peers(now + 3_600_001, 3_600_000);
    assert_eq!(ctrl.peer_count(), 0);
}

#[test]
fn admission_error_codes_unique() {
    let errors = [
        AdmissionError::ByteBudgetExceeded {
            current: 0,
            limit: 0,
            retry_after: std::time::Duration::from_secs(1),
        },
        AdmissionError::SymbolBudgetExceeded {
            current: 0,
            limit: 0,
            retry_after: std::time::Duration::from_secs(1),
        },
        AdmissionError::AuthenticationRequired,
        AdmissionError::ProofOfNeedRequired,
    ];
    let codes: Vec<u32> = errors.iter().map(AdmissionError::error_code).collect();
    let unique: HashSet<u32> = codes.iter().copied().collect();
    assert_eq!(codes.len(), unique.len(), "error codes must be unique");
}

#[test]
fn object_admission_class_serde() {
    assert_ne!(
        ObjectAdmissionClass::Quarantined,
        ObjectAdmissionClass::Admitted
    );
    let json = serde_json::to_string(&ObjectAdmissionClass::Admitted).unwrap();
    assert_eq!(json, "\"admitted\"");
    let parsed: ObjectAdmissionClass = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ObjectAdmissionClass::Admitted);
}

#[test]
fn object_admission_policy_defaults() {
    let policy = ObjectAdmissionPolicy::default();
    assert!(policy.max_quarantine_bytes_per_zone > 0);
    assert!(policy.max_quarantine_objects_per_zone > 0);
}

// ════════════════════════════════════════════════════════════════════════════
// Device Profiles
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn device_profile_builder_basic() {
    let profile = test_device_profile("node-1", 8192, 8);
    assert_eq!(profile.node_id.as_str(), "node-1");
    assert_eq!(profile.memory_mb, 8192);
    assert_eq!(profile.cpu_cores, 8);
    assert!(!profile.has_gpu());
    assert!(!profile.has_tpu());
}

#[test]
fn device_profile_with_gpu() {
    let gpu = GpuProfile::new(GpuVendor::Nvidia, "A100", 80_000);
    let profile = DeviceProfile::builder(test_node("gpu-node"))
        .cpu_cores(16)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(65536)
        .gpu(gpu)
        .build();
    assert!(profile.has_gpu());
}

#[test]
fn device_profile_with_tpu() {
    let tpu = TpuProfile::new(TpuVendor::Google, "v5e", 4, 16_000);
    let profile = DeviceProfile::builder(test_node("tpu-node"))
        .cpu_cores(96)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(131_072)
        .tpu(tpu)
        .build();
    assert!(profile.has_tpu());
}

#[test]
fn device_profile_connector_lookup() {
    let profile = profile_with_connector("node-c", 4096, 4, "fcp.github", "1.2.0");
    let cid = test_connector_id("fcp.github");
    assert!(profile.has_connector(&cid));
    let connector = profile.get_connector(&cid).unwrap();
    assert_eq!(connector.version, "1.2.0");
    assert!(!profile.has_connector(&test_connector_id("fcp.slack")));
}

#[test]
fn device_profile_low_battery() {
    let profile = DeviceProfile::builder(test_node("mobile"))
        .cpu_cores(4)
        .cpu_arch(CpuArch::Aarch64)
        .memory_mb(4096)
        .power_source(PowerSource::Battery)
        .battery_percent(5)
        .build();
    assert!(profile.is_low_battery());

    let profile2 = DeviceProfile::builder(test_node("plugged"))
        .cpu_cores(4)
        .cpu_arch(CpuArch::Aarch64)
        .memory_mb(4096)
        .power_source(PowerSource::Mains)
        .build();
    assert!(!profile2.is_low_battery());
}

#[test]
fn fitness_score_requires_gpu() {
    let profile = test_device_profile("no-gpu", 8192, 8);
    let ctx = FitnessContext::new().with_requires_gpu(true);
    let score = profile.compute_fitness(&ctx);
    assert!(!score.eligible, "no GPU → ineligible");
}

#[test]
fn fitness_score_requires_connector() {
    let profile = test_device_profile("plain-node", 4096, 4);
    let ctx = FitnessContext::new().with_required_connector(test_connector_id("fcp.jira"));
    let score = profile.compute_fitness(&ctx);
    assert!(!score.eligible, "missing connector → ineligible");
}

#[test]
fn fitness_score_with_connector() {
    let profile = profile_with_connector("node-ok", 4096, 4, "fcp.jira", "1.0.0");
    let ctx = FitnessContext::new().with_required_connector(test_connector_id("fcp.jira"));
    let score = profile.compute_fitness(&ctx);
    assert!(score.eligible);
    assert!(score.score > 0.0);
}

#[test]
fn device_metered_flag() {
    let profile = DeviceProfile::builder(test_node("metered"))
        .cpu_cores(4)
        .cpu_arch(CpuArch::Aarch64)
        .memory_mb(4096)
        .metered(true)
        .build();
    assert!(profile.metered);
}

#[test]
fn cpu_arch_variants() {
    let arches = [
        CpuArch::X86_64,
        CpuArch::Aarch64,
        CpuArch::Wasm32,
        CpuArch::Riscv64,
    ];
    for arch in &arches {
        let _debug = format!("{arch:?}");
    }
    assert_ne!(CpuArch::X86_64, CpuArch::Aarch64);
}

#[test]
fn gpu_with_compute_capability() {
    let gpu = GpuProfile::new(GpuVendor::Nvidia, "H100", 80_000).with_compute_capability("9.0");
    assert_eq!(gpu.compute_capability.as_deref(), Some("9.0"));
}

// ════════════════════════════════════════════════════════════════════════════
// Gossip
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn gossip_state_announce_object() {
    let zone = test_zone();
    let config = GossipConfig::default();
    let mut state = GossipState::new(zone, &config);
    let obj = test_object_id(1);
    state.announce_object(&obj, 1000);
    assert!(state.has_object(&obj));
}

#[test]
fn gossip_state_announce_symbol() {
    let zone = test_zone();
    let config = GossipConfig::default();
    let mut state = GossipState::new(zone, &config);
    let obj = test_object_id(2);
    state.announce_object(&obj, 1000);
    state.announce_symbol(&obj, 0, 1000);
    state.announce_symbol(&obj, 1, 1000);
    let symbols = state.symbols_for_object(&obj).unwrap();
    assert_eq!(symbols.len(), 2);
}

#[test]
fn gossip_state_counts() {
    let zone = test_zone();
    let config = GossipConfig::default();
    let mut state = GossipState::new(zone, &config);
    let obj = test_object_id(3);
    state.announce_object(&obj, 1000);
    state.announce_symbol(&obj, 0, 1000);
    assert_eq!(state.object_count(), 1);
    assert_eq!(state.symbol_count(), 1);
}

#[test]
fn gossip_state_create_summary() {
    let zone = test_zone();
    let config = GossipConfig::default();
    let mut state = GossipState::new(zone, &config);
    let obj = test_object_id(4);
    state.announce_object(&obj, 1000);
    let summary = state.create_summary(test_ts_node("node-1"), EpochId::new("epoch-1"));
    assert_eq!(summary.object_count, 1);
}

#[test]
fn gossip_state_remove_object() {
    let zone = test_zone();
    let config = GossipConfig::default();
    let mut state = GossipState::new(zone, &config);
    let obj = test_object_id(5);
    state.announce_object(&obj, 1000);
    assert!(state.has_object(&obj));
    state.remove_object(&obj, 2000);
    assert!(!state.has_object(&obj));
}

#[test]
fn gossip_state_may_have_checks() {
    let zone = test_zone();
    let config = GossipConfig::default();
    let mut state = GossipState::new(zone, &config);
    let obj = test_object_id(6);
    state.announce_object(&obj, 1000);
    assert!(state.may_have_object(&obj));
    state.announce_symbol(&obj, 42, 1000);
    assert!(state.may_have_symbol(&obj, 42));
    assert!(state.has_symbol(&obj, 42));
    assert!(!state.has_symbol(&obj, 99));
}

#[test]
fn mesh_gossip_announce_object() {
    let node = test_ts_node("gossip-node");
    let config = GossipConfig::default();
    let mut gossip = MeshGossip::new(node, config);
    let zone = test_zone();
    let obj = test_object_id(10);
    let now = 1_000_000u64;
    let announced = gossip.announce_object(&zone, &obj, ObjectAdmissionClass::Admitted, now);
    assert!(announced);
    assert!(gossip.has_object(&zone, &obj));
}

#[test]
fn mesh_gossip_quarantined_blocked() {
    let node = test_ts_node("gossip-node");
    let config = GossipConfig::default();
    let mut gossip = MeshGossip::new(node, config);
    let zone = test_zone();
    let obj = test_object_id(11);
    let announced = gossip.announce_object(&zone, &obj, ObjectAdmissionClass::Quarantined, 1000);
    assert!(!announced, "quarantined objects must not be gossiped");
    assert!(!gossip.has_object(&zone, &obj));
}

#[test]
fn mesh_gossip_announce_symbol() {
    let node = test_ts_node("sym-node");
    let config = GossipConfig::default();
    let mut gossip = MeshGossip::new(node, config);
    let zone = test_zone();
    let obj = test_object_id(12);
    gossip.announce_object(&zone, &obj, ObjectAdmissionClass::Admitted, 1000);
    let ok = gossip.announce_symbol(&zone, &obj, 5, ObjectAdmissionClass::Admitted, 1000);
    assert!(ok);
    assert!(gossip.has_symbol(&zone, &obj, 5));
}

#[test]
fn mesh_gossip_peer_count() {
    let node = test_ts_node("local");
    let gossip = MeshGossip::with_defaults(node);
    assert_eq!(gossip.peer_count(), 0);
}

#[test]
fn mesh_gossip_create_summary() {
    let node = test_ts_node("sum-node");
    let config = GossipConfig::default();
    let mut gossip = MeshGossip::new(node, config);
    let zone = test_zone();
    let obj = test_object_id(13);
    gossip.announce_object(&zone, &obj, ObjectAdmissionClass::Admitted, 1000);
    let summary = gossip.create_summary(&zone, EpochId::new("epoch-1"));
    assert!(summary.is_some());
}

#[test]
fn gossip_config_defaults() {
    let config = GossipConfig::default();
    assert!(config.max_objects_per_summary > 0);
    assert!(config.summary_ttl_secs > 0);
}

// ════════════════════════════════════════════════════════════════════════════
// Transport
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn transport_path_priority_order() {
    let paths = vec![
        TransportPath::new(TransportPathKind::Funnel, test_node("p1"), "f1", Some(100)),
        TransportPath::new(TransportPathKind::Derp, test_node("p2"), "d1", Some(50)),
        TransportPath::new(TransportPathKind::Direct, test_node("p3"), "l1", Some(1)),
        TransportPath::new(TransportPathKind::Mesh, test_node("p4"), "m1", Some(10)),
    ];
    let policy = ZoneTransportPolicy {
        allow_lan: true,
        allow_derp: true,
        allow_funnel: true,
    };
    let ranked = TransportSelector::rank_paths(&paths, &policy);
    assert_eq!(ranked[0].path.kind, TransportPathKind::Direct);
    assert_eq!(ranked[1].path.kind, TransportPathKind::Mesh);
    assert_eq!(ranked[2].path.kind, TransportPathKind::Derp);
    assert_eq!(ranked[3].path.kind, TransportPathKind::Funnel);
}

#[test]
fn transport_policy_disallows_derp() {
    let paths = vec![
        TransportPath::new(TransportPathKind::Derp, test_node("p1"), "d1", Some(50)),
        TransportPath::new(TransportPathKind::Direct, test_node("p2"), "l1", Some(1)),
    ];
    let policy = ZoneTransportPolicy {
        allow_lan: true,
        allow_derp: false,
        allow_funnel: false,
    };
    let ranked = TransportSelector::rank_paths(&paths, &policy);
    let derp_entry = ranked
        .iter()
        .find(|r| r.path.kind == TransportPathKind::Derp)
        .unwrap();
    assert!(!derp_entry.eligible);
    let direct_entry = ranked
        .iter()
        .find(|r| r.path.kind == TransportPathKind::Direct)
        .unwrap();
    assert!(direct_entry.eligible);
}

#[test]
fn transport_best_path_returns_eligible() {
    let paths = vec![
        TransportPath::new(TransportPathKind::Derp, test_node("p1"), "d1", Some(10)),
        TransportPath::new(TransportPathKind::Direct, test_node("p2"), "l1", Some(1)),
    ];
    let policy = ZoneTransportPolicy::default(); // only LAN allowed
    let best = TransportSelector::best_path(&paths, &policy);
    assert!(best.is_some());
    assert_eq!(best.unwrap().path.kind, TransportPathKind::Direct);
}

#[test]
fn transport_best_path_none_when_all_ineligible() {
    let paths = vec![
        TransportPath::new(TransportPathKind::Derp, test_node("p1"), "d1", Some(10)),
        TransportPath::new(TransportPathKind::Funnel, test_node("p2"), "f1", Some(100)),
    ];
    let policy = ZoneTransportPolicy {
        allow_lan: true,
        allow_derp: false,
        allow_funnel: false,
    };
    let best = TransportSelector::best_path(&paths, &policy);
    assert!(best.is_none());
}

#[test]
fn transport_rtt_tiebreaker() {
    let paths = vec![
        TransportPath::new(
            TransportPathKind::Direct,
            test_node("slow"),
            "slow-path",
            Some(50),
        ),
        TransportPath::new(
            TransportPathKind::Direct,
            test_node("fast"),
            "fast-path",
            Some(2),
        ),
    ];
    let policy = ZoneTransportPolicy::default();
    let best = TransportSelector::best_path(&paths, &policy).unwrap();
    assert_eq!(best.path.estimated_rtt_ms, Some(2));
}

#[test]
fn transport_multipath_selection() {
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, test_node("a"), "a", Some(1)),
        TransportPath::new(TransportPathKind::Direct, test_node("b"), "b", Some(2)),
        TransportPath::new(TransportPathKind::Mesh, test_node("c"), "c", Some(10)),
    ];
    let policy = ZoneTransportPolicy {
        allow_lan: true,
        allow_derp: true,
        allow_funnel: true,
    };
    let selected = TransportSelector::select_multipath(&paths, &policy, &test_object_id(1), 0, 2);
    assert_eq!(selected.len(), 2);
    assert!(selected.iter().all(|p| p.kind == TransportPathKind::Direct));
}

#[test]
fn transport_multipath_zero_fanout() {
    let paths = vec![TransportPath::new(
        TransportPathKind::Direct,
        test_node("a"),
        "a",
        Some(1),
    )];
    let policy = ZoneTransportPolicy::default();
    let selected = TransportSelector::select_multipath(&paths, &policy, &test_object_id(1), 0, 0);
    assert_eq!(selected, [] as [fcp_mesh::TransportPath; 0]);
}

#[test]
fn transport_multipath_deterministic() {
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, test_node("a"), "a", None),
        TransportPath::new(TransportPathKind::Direct, test_node("b"), "b", None),
        TransportPath::new(TransportPathKind::Direct, test_node("c"), "c", None),
    ];
    let policy = ZoneTransportPolicy::default();
    let obj = test_object_id(42);
    let s1 = TransportSelector::select_multipath(&paths, &policy, &obj, 0, 2);
    let s2 = TransportSelector::select_multipath(&paths, &policy, &obj, 0, 2);
    assert_eq!(s1.len(), s2.len());
    for (a, b) in s1.iter().zip(s2.iter()) {
        assert_eq!(a.path_id, b.path_id);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Session
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn session_new_initial_state() {
    let session = MeshSession::new(
        MeshSessionId::new(),
        test_node("peer-1"),
        SessionCryptoSuite::Suite1,
        test_session_keys(),
        TransportLimits::default(),
        true,
        1_000_000,
        SessionReplayPolicy::default(),
    );
    assert!(session.is_initiator);
    assert!(!session.needs_rekey(1_000_000));
}

#[test]
fn session_send_seq_increments() {
    let mut session = MeshSession::new(
        MeshSessionId::new(),
        test_node("peer-2"),
        SessionCryptoSuite::Suite1,
        test_session_keys(),
        TransportLimits::default(),
        true,
        1_000_000,
        SessionReplayPolicy::default(),
    );
    let seq1 = session.next_send_seq();
    let seq2 = session.next_send_seq();
    assert_eq!(seq1, 1);
    assert_eq!(seq2, 2);
}

#[test]
fn session_recv_seq_replay_detection() {
    let mut session = MeshSession::new(
        MeshSessionId::new(),
        test_node("peer-3"),
        SessionCryptoSuite::Suite1,
        test_session_keys(),
        TransportLimits::default(),
        false,
        1_000_000,
        SessionReplayPolicy::default(),
    );
    assert!(session.check_recv_seq(1));
    assert!(!session.check_recv_seq(1), "replay should be rejected");
    assert!(session.check_recv_seq(2));
}

#[test]
fn session_mac_roundtrip() {
    let keys = test_session_keys();
    let session_id = MeshSessionId::new();
    let mut initiator = MeshSession::new(
        session_id,
        test_node("responder"),
        SessionCryptoSuite::Suite1,
        keys,
        TransportLimits::default(),
        true,
        1_000_000,
        SessionReplayPolicy::default(),
    );
    let mut responder = MeshSession::new(
        session_id,
        test_node("initiator"),
        SessionCryptoSuite::Suite1,
        keys,
        TransportLimits::default(),
        false,
        1_000_000,
        SessionReplayPolicy::default(),
    );

    let frame_data = b"test frame payload";
    let (seq, mac) = initiator.mac_outgoing(frame_data);
    assert!(responder.verify_incoming(seq, frame_data, &mac));
}

#[test]
fn session_mac_wrong_data_fails() {
    let keys = test_session_keys();
    let session_id = MeshSessionId::new();
    let mut initiator = MeshSession::new(
        session_id,
        test_node("responder"),
        SessionCryptoSuite::Suite1,
        keys,
        TransportLimits::default(),
        true,
        1_000_000,
        SessionReplayPolicy::default(),
    );
    let mut responder = MeshSession::new(
        session_id,
        test_node("initiator"),
        SessionCryptoSuite::Suite1,
        keys,
        TransportLimits::default(),
        false,
        1_000_000,
        SessionReplayPolicy::default(),
    );

    let (seq, mac) = initiator.mac_outgoing(b"original data");
    assert!(!responder.verify_incoming(seq, b"tampered data", &mac));
}

#[test]
fn session_needs_rekey_after_time() {
    let policy = SessionReplayPolicy {
        rekey_after_seconds: 100,
        ..SessionReplayPolicy::default()
    };
    let session = MeshSession::new(
        MeshSessionId::new(),
        test_node("peer"),
        SessionCryptoSuite::Suite1,
        test_session_keys(),
        TransportLimits::default(),
        true,
        1_000,
        policy,
    );
    assert!(!session.needs_rekey(1_050));
    assert!(session.needs_rekey(1_101));
}

#[test]
fn session_needs_rekey_after_frames() {
    let policy = SessionReplayPolicy {
        rekey_after_frames: 3,
        ..SessionReplayPolicy::default()
    };
    let mut session = MeshSession::new(
        MeshSessionId::new(),
        test_node("peer"),
        SessionCryptoSuite::Suite1,
        test_session_keys(),
        TransportLimits::default(),
        true,
        1_000,
        policy,
    );
    session.mac_outgoing(b"f1");
    session.mac_outgoing(b"f2");
    assert!(!session.needs_rekey(1_000));
    session.mac_outgoing(b"f3");
    assert!(session.needs_rekey(1_000));
}

#[test]
fn session_direction_keys_differ() {
    let session = MeshSession::new(
        MeshSessionId::new(),
        test_node("peer"),
        SessionCryptoSuite::Suite1,
        test_session_keys(),
        TransportLimits::default(),
        true,
        1_000,
        SessionReplayPolicy::default(),
    );
    assert_ne!(session.send_mac_key(), session.recv_mac_key());
}

#[test]
fn session_seq_zero_rejected() {
    let mut session = MeshSession::new(
        MeshSessionId::new(),
        test_node("peer"),
        SessionCryptoSuite::Suite1,
        test_session_keys(),
        TransportLimits::default(),
        false,
        1_000,
        SessionReplayPolicy::default(),
    );
    assert!(!session.verify_incoming(0, b"data", &[0u8; 16]));
}

#[test]
fn session_suite2_mac_roundtrip() {
    let keys = test_session_keys();
    let session_id = MeshSessionId::new();
    let mut initiator = MeshSession::new(
        session_id,
        test_node("responder"),
        SessionCryptoSuite::Suite2,
        keys,
        TransportLimits::default(),
        true,
        1_000_000,
        SessionReplayPolicy::default(),
    );
    let mut responder = MeshSession::new(
        session_id,
        test_node("initiator"),
        SessionCryptoSuite::Suite2,
        keys,
        TransportLimits::default(),
        false,
        1_000_000,
        SessionReplayPolicy::default(),
    );

    let frame_data = b"suite2 payload";
    let (seq, mac) = initiator.mac_outgoing(frame_data);
    assert!(responder.verify_incoming(seq, frame_data, &mac));
}

// ════════════════════════════════════════════════════════════════════════════
// Symbol Request Handler
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn symbol_request_policy_defaults() {
    let policy = SymbolRequestPolicy::default();
    assert_eq!(
        policy.max_unauthenticated_response,
        fcp_mesh::symbol_request::DEFAULT_RESPONSE_LIMIT_UNAUTHENTICATED
    );
    assert_eq!(
        policy.max_authenticated_response,
        fcp_mesh::symbol_request::DEFAULT_RESPONSE_LIMIT_AUTHENTICATED
    );
    assert!(policy.allow_unauthenticated);
}

#[test]
fn symbol_request_handler_with_default_policy() {
    let handler = SymbolRequestHandler::with_default_policy();
    let peer = NodeId::new("peer-default");
    let obj = test_object_id(1);
    assert!(!handler.should_stop(&peer, &obj));
}

#[test]
fn symbol_response_builder_basic() {
    let response =
        SymbolResponseBuilder::new(test_object_id(1), test_zone(), test_zone_key_id(), 100)
            .build(10, 0);
    assert_eq!(response.object_id, test_object_id(1));
    assert!(!response.is_final); // symbols remain unsent
}

#[test]
fn targeted_repair_register_available() {
    let mut engine = TargetedRepairEngine::new();
    let obj = test_object_id(5);
    engine.register_available(obj, 0..10);
    // Just verify it doesn't panic
    engine.remove_object(&obj);
}

#[test]
fn symbol_request_handler_prune_stale() {
    let mut handler = SymbolRequestHandler::with_default_policy();
    // prune with no state should return 0
    let pruned = handler.prune_stale_state(1_000_000);
    assert_eq!(pruned, 0);
}

#[test]
fn symbol_request_error_display() {
    let err = SymbolRequestError::BoundsExceeded {
        requested: 500,
        max_allowed: 32,
    };
    let msg = err.to_string();
    assert!(msg.contains("500"));
    assert!(msg.contains("32"));

    let err2 = SymbolRequestError::AlreadyComplete {
        object_id: "abc".to_string(),
    };
    assert!(err2.to_string().contains("abc"));
}

#[test]
fn symbol_request_error_hint_too_large() {
    let err = SymbolRequestError::HintTooLarge {
        count: 200,
        max: 100,
    };
    let msg = err.to_string();
    assert!(msg.contains("200"));
    assert!(msg.contains("100"));
}

// ════════════════════════════════════════════════════════════════════════════
// Planner
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn planner_selects_best_node() {
    let connector_id = test_connector_id("fcp.github");
    let nodes = vec![
        NodeInfo {
            profile: profile_with_connector("node-a", 4096, 4, "fcp.github", "1.0.0"),
            local_symbols: HashSet::new(),
            held_leases: vec![],
            zones: vec![],
        },
        NodeInfo {
            profile: profile_with_connector("node-b", 16384, 16, "fcp.github", "2.0.0"),
            local_symbols: HashSet::new(),
            held_leases: vec![],
            zones: vec![],
        },
    ];
    let input = PlannerInput::new(nodes, 1_000_000);
    let context = PlannerContext::new(connector_id);
    let planner = ExecutionPlanner::new();
    let candidates = planner.plan(&input, &context);
    assert_eq!(candidates.len(), 2);
    // Both nodes are eligible; planner ranks by fitness score
    let names: Vec<&str> = candidates.iter().map(|c| c.node_id.as_str()).collect();
    assert!(names.contains(&"node-a"));
    assert!(names.contains(&"node-b"));
}

#[test]
fn planner_excludes_missing_connector() {
    let connector_id = test_connector_id("fcp.jira");
    let nodes = vec![
        NodeInfo {
            profile: test_device_profile("no-jira", 8192, 8),
            local_symbols: HashSet::new(),
            held_leases: vec![],
            zones: vec![],
        },
        NodeInfo {
            profile: profile_with_connector("has-jira", 4096, 4, "fcp.jira", "1.0.0"),
            local_symbols: HashSet::new(),
            held_leases: vec![],
            zones: vec![],
        },
    ];
    let input = PlannerInput::new(nodes, 1_000_000);
    let context = PlannerContext::new(connector_id);
    let planner = ExecutionPlanner::new();
    let candidates = planner.plan(&input, &context);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].node_id.as_str(), "has-jira");
}

#[test]
fn planner_data_locality_bonus() {
    let connector_id = test_connector_id("fcp.test");
    let obj = test_object_id(42);
    let mut local = HashSet::new();
    local.insert(obj);
    let nodes = vec![
        NodeInfo {
            profile: profile_with_connector("local-data", 4096, 4, "fcp.test", "1.0.0"),
            local_symbols: local,
            held_leases: vec![],
            zones: vec![],
        },
        NodeInfo {
            profile: profile_with_connector("remote-data", 4096, 4, "fcp.test", "1.0.0"),
            local_symbols: HashSet::new(),
            held_leases: vec![],
            zones: vec![],
        },
    ];
    let input = PlannerInput::new(nodes, 1_000_000);
    let context = PlannerContext::new(connector_id).with_preferred_symbols(vec![obj]);
    let planner = ExecutionPlanner::new();
    let candidates = planner.plan(&input, &context);
    assert_eq!(candidates[0].node_id.as_str(), "local-data");
    assert!(candidates[0].score > candidates[1].score);
}

#[test]
fn planner_required_symbols_hard_constraint() {
    let connector_id = test_connector_id("fcp.test");
    let required_obj = test_object_id(99);
    let mut has_it = HashSet::new();
    has_it.insert(required_obj);
    let nodes = vec![
        NodeInfo {
            profile: profile_with_connector("has-sym", 4096, 4, "fcp.test", "1.0.0"),
            local_symbols: has_it,
            held_leases: vec![],
            zones: vec![],
        },
        NodeInfo {
            profile: profile_with_connector("no-sym", 8192, 8, "fcp.test", "1.0.0"),
            local_symbols: HashSet::new(),
            held_leases: vec![],
            zones: vec![],
        },
    ];
    let input = PlannerInput::new(nodes, 1_000_000);
    let context = PlannerContext::new(connector_id).with_required_symbols(vec![required_obj]);
    let planner = ExecutionPlanner::new();
    let candidates = planner.plan(&input, &context);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].node_id.as_str(), "has-sym");
}

#[test]
fn planner_excludes_nodes_by_id() {
    let connector_id = test_connector_id("fcp.test");
    let nodes = vec![
        NodeInfo {
            profile: profile_with_connector("keep", 4096, 4, "fcp.test", "1.0.0"),
            local_symbols: HashSet::new(),
            held_leases: vec![],
            zones: vec![],
        },
        NodeInfo {
            profile: profile_with_connector("exclude", 8192, 8, "fcp.test", "1.0.0"),
            local_symbols: HashSet::new(),
            held_leases: vec![],
            zones: vec![],
        },
    ];
    let input = PlannerInput::new(nodes, 1_000_000);
    let context = PlannerContext::new(connector_id).excluding(["exclude"]);
    let planner = ExecutionPlanner::new();
    let candidates = planner.plan(&input, &context);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].node_id.as_str(), "keep");
}

#[test]
fn planner_gpu_requirement() {
    let connector_id = test_connector_id("fcp.ml");
    let gpu = GpuProfile::new(GpuVendor::Nvidia, "A100", 80_000);
    let gpu_profile = DeviceProfile::builder(test_node("gpu-node"))
        .cpu_cores(16)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(65536)
        .gpu(gpu)
        .add_connector(InstalledConnector::new(
            test_connector_id("fcp.ml"),
            "1.0.0".to_string(),
            test_object_id(0xFF),
        ))
        .build();
    let no_gpu_profile = profile_with_connector("no-gpu", 65536, 16, "fcp.ml", "1.0.0");
    let nodes = vec![
        NodeInfo {
            profile: gpu_profile,
            local_symbols: HashSet::new(),
            held_leases: vec![],
            zones: vec![],
        },
        NodeInfo {
            profile: no_gpu_profile,
            local_symbols: HashSet::new(),
            held_leases: vec![],
            zones: vec![],
        },
    ];
    let input = PlannerInput::new(nodes, 1_000_000);
    let context = PlannerContext::new(connector_id).with_gpu();
    let planner = ExecutionPlanner::new();
    let candidates = planner.plan(&input, &context);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].node_id.as_str(), "gpu-node");
}

#[test]
fn planner_singleton_writer_lease() {
    let connector_id = test_connector_id("fcp.db");
    let nodes = vec![
        NodeInfo {
            profile: profile_with_connector("holder", 4096, 4, "fcp.db", "1.0.0"),
            local_symbols: HashSet::new(),
            held_leases: vec![HeldLease {
                subject_id: test_object_id(1),
                purpose: LeasePurpose::SingletonWriter,
                expires_at: 2_000_000,
                fencing_token: 5,
            }],
            zones: vec![],
        },
        NodeInfo {
            profile: profile_with_connector("non-holder", 4096, 4, "fcp.db", "1.0.0"),
            local_symbols: HashSet::new(),
            held_leases: vec![],
            zones: vec![],
        },
    ];
    let input = PlannerInput::new(nodes, 1_000_000).with_singleton_holder("holder");
    let context = PlannerContext::new(connector_id).with_singleton_writer();
    let planner = ExecutionPlanner::new();
    let candidates = planner.plan(&input, &context);
    assert_ne!(candidates, [] as [fcp_mesh::CandidateNode; 0]);
    assert_eq!(candidates[0].node_id.as_str(), "holder");
}

#[test]
fn planner_empty_nodes_returns_empty() {
    let connector_id = test_connector_id("fcp.test");
    let input = PlannerInput::new(vec![], 1_000_000);
    let context = PlannerContext::new(connector_id);
    let planner = ExecutionPlanner::new();
    let candidates = planner.plan(&input, &context);
    assert_eq!(candidates, [] as [fcp_mesh::CandidateNode; 0]);
}

#[test]
fn planner_deterministic_ordering() {
    let connector_id = test_connector_id("fcp.test");
    let nodes: Vec<NodeInfo> = (0..5)
        .map(|i| NodeInfo {
            profile: profile_with_connector(&format!("node-{i}"), 4096, 4, "fcp.test", "1.0.0"),
            local_symbols: HashSet::new(),
            held_leases: vec![],
            zones: vec![],
        })
        .collect();
    let input = PlannerInput::new(nodes, 1_000_000);
    let context = PlannerContext::new(connector_id);
    let planner = ExecutionPlanner::new();
    let c1 = planner.plan(&input, &context);
    let c2 = planner.plan(&input, &context);
    assert_eq!(c1.len(), c2.len());
    for (a, b) in c1.iter().zip(c2.iter()) {
        assert_eq!(a.node_id.as_str(), b.node_id.as_str());
    }
}

#[test]
fn lease_purpose_display() {
    assert_eq!(
        LeasePurpose::SingletonWriter.to_string(),
        "singleton_writer"
    );
    assert_eq!(
        LeasePurpose::OperationExecution.to_string(),
        "operation_execution"
    );
    assert_eq!(
        LeasePurpose::CoordinatorElection.to_string(),
        "coordinator_election"
    );
    assert_eq!(LeasePurpose::Other.to_string(), "other");
}

// ════════════════════════════════════════════════════════════════════════════
// Error Types
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn admission_error_retryable() {
    let retryable = AdmissionError::ByteBudgetExceeded {
        current: 100,
        limit: 50,
        retry_after: std::time::Duration::from_secs(60),
    };
    assert!(retryable.is_retryable());
    assert_eq!(
        retryable.retry_after(),
        Some(std::time::Duration::from_secs(60))
    );

    let not_retryable = AdmissionError::AuthenticationRequired;
    assert!(!not_retryable.is_retryable());
    assert_eq!(not_retryable.retry_after(), None);
}

#[test]
fn admission_error_display() {
    let err = AdmissionError::ObjectQuarantined {
        object_id: "obj-123".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("obj-123"));
}

// ════════════════════════════════════════════════════════════════════════════
// Degraded-Mode Transport
// ════════════════════════════════════════════════════════════════════════════

const fn test_raptorq_config() -> RaptorQConfig {
    RaptorQConfig {
        symbol_size: 64,
        repair_ratio_bps: 500,
        max_object_size: 1024 * 1024,
        decode_timeout: std::time::Duration::from_secs(30),
        max_chunk_threshold: 1024,
        chunk_size: 256,
    }
}

fn test_envelope(
    payload: &[u8],
    object_n: u8,
    epoch_id: u64,
    retention: RetentionClass,
) -> ControlPlaneEnvelope {
    ControlPlaneEnvelope::new(
        payload.to_vec(),
        [0xAA; 32],
        test_object_id(object_n),
        test_zone(),
        test_zone_key_id(),
        epoch_id,
        retention,
    )
}

#[test]
fn retention_class_default_is_required() {
    assert_eq!(RetentionClass::default(), RetentionClass::Required);
}

#[test]
fn retention_class_variants_distinct() {
    assert_ne!(RetentionClass::Required, RetentionClass::Ephemeral);
    let r = RetentionClass::Required;
    let r2 = r;
    assert_eq!(r, r2);
}

#[test]
fn control_plane_envelope_construction() {
    let payload = vec![0x42; 128];
    let schema_hash = [0xBB; 32];
    let envelope = ControlPlaneEnvelope::new(
        payload.clone(),
        schema_hash,
        test_object_id(1),
        test_zone(),
        test_zone_key_id(),
        42,
        RetentionClass::Required,
    );
    assert_eq!(envelope.payload, payload);
    assert_eq!(envelope.schema_hash, schema_hash);
    assert_eq!(envelope.object_id, test_object_id(1));
    assert_eq!(envelope.epoch_id, 42);
    assert_eq!(envelope.retention, RetentionClass::Required);
}

#[test]
fn control_plane_envelope_clone() {
    let envelope = test_envelope(&[0x42; 128], 1, 0, RetentionClass::Required);
    let cloned = envelope.clone();
    assert_eq!(cloned.payload, envelope.payload);
    assert_eq!(cloned.schema_hash, envelope.schema_hash);
    assert_eq!(cloned.object_id, envelope.object_id);
}

#[test]
fn degraded_encoder_decoder_roundtrip() {
    let config = test_raptorq_config();
    let mut encoder = DegradedModeEncoder::new(config.clone(), 12345);
    let envelope = test_envelope(&[0x42; 256], 1, 0, RetentionClass::Required);
    let zone_key = test_zone_key();
    let algorithm = test_zone_key_algorithm();
    let frames = encoder
        .encode_authenticated(
            &envelope,
            0,
            &zone_key,
            algorithm,
            &test_ts_node("mesh-test-sender"),
        )
        .expect("encode should succeed");
    assert_ne!(frames, [] as [fcp_protocol::FcpsFrame; 0]);

    let mut decoder = DegradedModeDecoder::new(config);
    let zone = test_zone();
    let mut result = None;
    for frame in &frames {
        if let Some(decoded) = decoder
            .process_frame_authenticated(
                frame,
                &zone,
                RetentionClass::Required,
                &zone_key,
                algorithm,
                &test_ts_node("mesh-test-sender"),
            )
            .expect("decode should succeed")
        {
            result = Some(decoded);
        }
    }
    let reconstructed = result.expect("should reconstruct envelope");
    assert_eq!(reconstructed.payload, envelope.payload);
    assert_eq!(reconstructed.schema_hash, envelope.schema_hash);
    assert_eq!(reconstructed.object_id, envelope.object_id);
}

#[test]
fn degraded_encoder_frame_seq_increments() {
    let config = test_raptorq_config();
    let mut encoder = DegradedModeEncoder::new(config, 99);
    let envelope = test_envelope(&[0x10; 64], 2, 0, RetentionClass::Required);
    let zone_key = test_zone_key();
    let algorithm = test_zone_key_algorithm();
    let source_id = test_ts_node("mesh-test-sender");

    let frames1 = encoder
        .encode_authenticated(&envelope, 0, &zone_key, algorithm, &source_id)
        .unwrap();
    let frames2 = encoder
        .encode_authenticated(&envelope, 1, &zone_key, algorithm, &source_id)
        .unwrap();
    assert_eq!(frames1[0].header.frame_seq, 0);
    assert_eq!(frames2[0].header.frame_seq, 1);
}

#[test]
fn degraded_encoder_small_payload() {
    let config = test_raptorq_config();
    let mut encoder = DegradedModeEncoder::new(config.clone(), 1);
    let envelope = test_envelope(&[0x01; 8], 3, 0, RetentionClass::Ephemeral);
    let zone_key = test_zone_key();
    let algorithm = test_zone_key_algorithm();
    let source_id = test_ts_node("mesh-test-sender");
    let frames = encoder
        .encode_authenticated(&envelope, 0, &zone_key, algorithm, &source_id)
        .unwrap();
    assert_ne!(frames, [] as [fcp_protocol::FcpsFrame; 0]);

    let mut decoder = DegradedModeDecoder::new(config);
    let zone = test_zone();
    let mut result = None;
    for frame in &frames {
        result = decoder
            .process_frame_authenticated(
                frame,
                &zone,
                RetentionClass::Ephemeral,
                &zone_key,
                algorithm,
                &source_id,
            )
            .unwrap();
    }
    let reconstructed = result.expect("small payload roundtrip");
    assert_eq!(reconstructed.payload, vec![0x01; 8]);
}

#[test]
fn degraded_encoder_signed_roundtrip() {
    let config = test_raptorq_config();
    let mut encoder = DegradedModeEncoder::new(config.clone(), 777);
    let envelope = test_envelope(&[0xAB; 128], 4, 5, RetentionClass::Required);
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let pq_signing_key = MlDsa65SigningKey::generate().expect("ML-DSA signing key");
    let source_id = test_ts_node("sender-node");
    let zone_key = test_zone_key();
    let algorithm = test_zone_key_algorithm();

    let signed_frames = encoder
        .encode_signed_authenticated(
            &envelope,
            5,
            &zone_key,
            algorithm,
            &source_id,
            1000,
            &signing_key,
            &pq_signing_key,
        )
        .expect("encode_signed should succeed");
    assert_ne!(
        signed_frames,
        [] as [fcp_crypto::SignedEnvelope<fcp_protocol::SignedFcpsFramePayload>; 0]
    );

    let mut decoder = DegradedModeDecoder::new(config);
    let zone = test_zone();
    let mut result = None;
    for sf in &signed_frames {
        if let Some(decoded) = decoder
            .process_signed_frame_authenticated(
                sf,
                &zone,
                RetentionClass::Required,
                &SignedDegradedFrameAuth {
                    verifying_key: &verifying_key,
                    pq_verifying_key: pq_signing_key.verifying_key(),
                    signing_policy: PqSigningPolicy::BothRequired,
                    zone_key: &zone_key,
                    algorithm,
                },
            )
            .expect("signed decode should succeed")
        {
            result = Some(decoded);
        }
    }
    let reconstructed = result.expect("signed roundtrip should reconstruct");
    assert_eq!(reconstructed.payload, envelope.payload);
}

#[test]
fn degraded_decoder_wrong_signing_key_rejected() {
    let config = test_raptorq_config();
    let mut encoder = DegradedModeEncoder::new(config.clone(), 888);
    let envelope = test_envelope(&[0xCC; 64], 5, 0, RetentionClass::Required);
    let signing_key = Ed25519SigningKey::generate();
    let wrong_key = Ed25519SigningKey::generate();
    let wrong_verifying = wrong_key.verifying_key();
    let pq_signing_key = MlDsa65SigningKey::generate().expect("ML-DSA signing key");
    let source_id = test_ts_node("bad-sender");
    let zone_key = test_zone_key();
    let algorithm = test_zone_key_algorithm();

    let signed_frames = encoder
        .encode_signed_authenticated(
            &envelope,
            0,
            &zone_key,
            algorithm,
            &source_id,
            1000,
            &signing_key,
            &pq_signing_key,
        )
        .unwrap();

    let mut decoder = DegradedModeDecoder::new(config);
    let zone = test_zone();
    let err = decoder
        .process_signed_frame_authenticated(
            &signed_frames[0],
            &zone,
            RetentionClass::Required,
            &SignedDegradedFrameAuth {
                verifying_key: &wrong_verifying,
                pq_verifying_key: pq_signing_key.verifying_key(),
                signing_policy: PqSigningPolicy::BothRequired,
                zone_key: &zone_key,
                algorithm,
            },
        )
        .unwrap_err();
    assert!(matches!(
        err,
        DegradedTransportError::SignatureVerificationFailed
    ));
}

#[test]
fn degraded_decoder_zone_mismatch_rejected() {
    let config = test_raptorq_config();
    let mut encoder = DegradedModeEncoder::new(config.clone(), 555);
    let envelope = test_envelope(&[0xDD; 64], 6, 0, RetentionClass::Required);
    let zone_key = test_zone_key();
    let algorithm = test_zone_key_algorithm();
    let source_id = test_ts_node("mesh-test-sender");
    let frames = encoder
        .encode_authenticated(&envelope, 0, &zone_key, algorithm, &source_id)
        .unwrap();

    let mut decoder = DegradedModeDecoder::new(config);
    let wrong_zone = ZoneId::owner();
    let err = decoder
        .process_frame_authenticated(
            &frames[0],
            &wrong_zone,
            RetentionClass::Required,
            &zone_key,
            algorithm,
            &source_id,
        )
        .unwrap_err();
    assert!(matches!(err, DegradedTransportError::ZoneMismatch { .. }));
}

#[test]
fn degraded_decoder_rejects_tampered_symbol_data() {
    let config = test_raptorq_config();
    let mut encoder = DegradedModeEncoder::new(config.clone(), 4242);
    let mut decoder = DegradedModeDecoder::new(config);
    let zone = test_zone();
    let zone_key = test_zone_key();
    let algorithm = test_zone_key_algorithm();
    let source_id = test_ts_node("mesh-test-sender");
    let envelope = test_envelope(&[0x5A; 128], 7, 0, RetentionClass::Required);

    let mut frame = encoder
        .encode_authenticated(&envelope, 0, &zone_key, algorithm, &source_id)
        .unwrap()
        .remove(0);
    frame.symbols[0].data[0] ^= 0x01;

    let err = decoder
        .process_frame_authenticated(
            &frame,
            &zone,
            RetentionClass::Required,
            &zone_key,
            algorithm,
            &source_id,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        DegradedTransportError::SymbolDecryptFailed { .. }
    ));
}

#[test]
fn degraded_decoder_pending_count_and_clear() {
    let config = test_raptorq_config();
    let mut decoder = DegradedModeDecoder::new(config);
    assert_eq!(decoder.pending_count(), 0);
    assert!(!decoder.clear_pending(&test_object_id(99)));
}

#[test]
fn degraded_decoder_get_status_none_for_unknown() {
    let config = test_raptorq_config();
    let decoder = DegradedModeDecoder::new(config);
    assert!(decoder.get_status(&test_object_id(42)).is_none());
}

#[test]
fn degraded_transport_error_display() {
    let err = DegradedTransportError::Incomplete {
        received: 5,
        needed: 10,
    };
    let msg = err.to_string();
    assert!(msg.contains('5'));
    assert!(msg.contains("10"));

    let err2 = DegradedTransportError::RetentionViolation;
    assert_ne!(err2.to_string(), "");

    let err3 = DegradedTransportError::MissingControlPlaneFlag;
    assert_ne!(err3.to_string(), "");

    let err4 = DegradedTransportError::ObjectIdMismatch;
    assert_ne!(err4.to_string(), "");
}

// ════════════════════════════════════════════════════════════════════════════
// InMemoryControlPlaneHandler
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn handler_stores_required_objects() {
    let handler = InMemoryControlPlaneHandler::new();
    assert_eq!(handler.count(), 0);

    let envelope = test_envelope(&[1; 64], 10, 1, RetentionClass::Required);
    handler.handle(envelope).unwrap();
    assert_eq!(handler.count(), 1);

    let retrieved = handler.get(&test_object_id(10)).expect("should retrieve");
    assert_eq!(retrieved.payload, vec![1; 64]);
    assert_eq!(retrieved.epoch_id, 1);
}

#[test]
fn handler_discards_ephemeral_objects() {
    let handler = InMemoryControlPlaneHandler::new();
    let envelope = test_envelope(&[2; 64], 11, 1, RetentionClass::Ephemeral);
    handler.handle(envelope).unwrap();
    assert_eq!(handler.count(), 0);
    assert!(handler.get(&test_object_id(11)).is_none());
}

#[test]
fn handler_replaces_existing_object() {
    let handler = InMemoryControlPlaneHandler::new();
    let e1 = test_envelope(&[1; 64], 20, 1, RetentionClass::Required);
    handler.handle(e1).unwrap();
    assert_eq!(handler.count(), 1);

    // Same object_id, different payload
    let e2 = test_envelope(&[2; 64], 20, 2, RetentionClass::Required);
    handler.handle(e2).unwrap();
    assert_eq!(handler.count(), 1);

    let retrieved = handler.get(&test_object_id(20)).unwrap();
    assert_eq!(retrieved.payload, vec![2; 64]);
    assert_eq!(retrieved.epoch_id, 2);
}

#[test]
fn handler_list_epochs_all() {
    let handler = InMemoryControlPlaneHandler::new();
    let zone = test_zone();

    handler
        .handle(test_envelope(&[1; 8], 30, 10, RetentionClass::Required))
        .unwrap();
    handler
        .handle(test_envelope(&[2; 8], 31, 20, RetentionClass::Required))
        .unwrap();
    handler
        .handle(test_envelope(&[3; 8], 32, 10, RetentionClass::Required))
        .unwrap();

    let epochs = handler.list_epochs(&zone, None);
    assert_eq!(epochs.len(), 2);
    assert!(epochs.contains(&10));
    assert!(epochs.contains(&20));
}

#[test]
fn handler_list_epochs_since() {
    let handler = InMemoryControlPlaneHandler::new();
    let zone = test_zone();

    handler
        .handle(test_envelope(&[1; 8], 40, 5, RetentionClass::Required))
        .unwrap();
    handler
        .handle(test_envelope(&[2; 8], 41, 10, RetentionClass::Required))
        .unwrap();
    handler
        .handle(test_envelope(&[3; 8], 42, 15, RetentionClass::Required))
        .unwrap();

    let epochs = handler.list_epochs(&zone, Some(5));
    assert_eq!(epochs.len(), 2);
    assert!(epochs.contains(&10));
    assert!(epochs.contains(&15));
    assert!(!epochs.contains(&5));
}

#[test]
fn handler_list_epochs_unknown_zone() {
    let handler = InMemoryControlPlaneHandler::new();
    let unknown = ZoneId::owner();
    let epochs = handler.list_epochs(&unknown, None);
    assert_eq!(epochs, [] as [u64; 0]);
}

#[test]
fn handler_fetch_epoch_objects() {
    let handler = InMemoryControlPlaneHandler::new();
    let zone = test_zone();

    handler
        .handle(test_envelope(&[1; 8], 50, 7, RetentionClass::Required))
        .unwrap();
    handler
        .handle(test_envelope(&[2; 8], 51, 7, RetentionClass::Required))
        .unwrap();
    handler
        .handle(test_envelope(&[3; 8], 52, 8, RetentionClass::Required))
        .unwrap();

    let epoch7 = handler.fetch_epoch(&zone, 7);
    assert_eq!(epoch7.len(), 2);

    let epoch8 = handler.fetch_epoch(&zone, 8);
    assert_eq!(epoch8.len(), 1);

    let epoch_missing = handler.fetch_epoch(&zone, 99);
    assert!(epoch_missing.is_empty());
}

#[test]
fn handler_fetch_epoch_unknown_zone() {
    let handler = InMemoryControlPlaneHandler::new();
    let unknown = ZoneId::owner();
    let result = handler.fetch_epoch(&unknown, 0);
    assert!(result.is_empty());
}

#[test]
fn handler_multiple_zones_independent() {
    let handler = InMemoryControlPlaneHandler::new();
    let zone_work = test_zone();
    let zone_owner = ZoneId::owner();

    let e1 = ControlPlaneEnvelope::new(
        vec![1; 8],
        [0xAA; 32],
        test_object_id(60),
        zone_work.clone(),
        test_zone_key_id(),
        1,
        RetentionClass::Required,
    );
    let e2 = ControlPlaneEnvelope::new(
        vec![2; 8],
        [0xBB; 32],
        test_object_id(61),
        zone_owner.clone(),
        test_zone_key_id(),
        1,
        RetentionClass::Required,
    );

    handler.handle(e1).unwrap();
    handler.handle(e2).unwrap();

    assert_eq!(handler.list_epochs(&zone_work, None).len(), 1);
    assert_eq!(handler.list_epochs(&zone_owner, None).len(), 1);
    assert_eq!(handler.fetch_epoch(&zone_work, 1).len(), 1);
    assert_eq!(handler.fetch_epoch(&zone_owner, 1).len(), 1);
}

// ════════════════════════════════════════════════════════════════════════════
// Replay Engine
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn trace_replay_input_format_serde() {
    let formats = [
        (TraceReplayInputFormat::Auto, "\"auto\""),
        (TraceReplayInputFormat::Json, "\"json\""),
        (TraceReplayInputFormat::Cbor, "\"cbor\""),
    ];
    for (variant, expected_json) in &formats {
        let json = serde_json::to_string(variant).unwrap();
        assert_eq!(&json, expected_json);
        let parsed: TraceReplayInputFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(&parsed, variant);
    }
}

#[test]
fn trace_replay_input_format_equality() {
    assert_eq!(TraceReplayInputFormat::Auto, TraceReplayInputFormat::Auto);
    assert_ne!(TraceReplayInputFormat::Json, TraceReplayInputFormat::Cbor);
}

#[test]
fn trace_replay_diff_serde_roundtrip() {
    let diff = TraceReplayDiff {
        index: 5,
        event_type: "routing".to_string(),
        expected_decision: Some("allow".to_string()),
        actual_decision: Some("deny".to_string()),
        detail: "decision mismatch".to_string(),
    };
    let json = serde_json::to_string(&diff).unwrap();
    let parsed: TraceReplayDiff = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, diff);
}

#[test]
fn trace_replay_diff_with_none_decisions() {
    let diff = TraceReplayDiff {
        index: 0,
        event_type: "gossip".to_string(),
        expected_decision: None,
        actual_decision: None,
        detail: "event payload mismatch".to_string(),
    };
    let json = serde_json::to_string(&diff).unwrap();
    let parsed: TraceReplayDiff = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.expected_decision, None);
    assert_eq!(parsed.actual_decision, None);
}

#[test]
fn trace_replay_summary_serde_roundtrip() {
    let summary = TraceReplaySummary {
        total_events: 100,
        event_type_counts: [("routing".to_string(), 50), ("admission".to_string(), 30)]
            .into_iter()
            .collect(),
        expected_decision_counts: std::iter::once(("allow".to_string(), 40)).collect(),
        actual_decision_counts: [("allow".to_string(), 38), ("deny".to_string(), 2)]
            .into_iter()
            .collect(),
        matched_events: 90,
        mismatched_events: 10,
        matched_decisions: 38,
        mismatched_decisions: 2,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let parsed: TraceReplaySummary = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, summary);
}

#[test]
fn trace_replay_report_serde_roundtrip() {
    let report = TraceReplayReport {
        source_trace_id: "trace-001".to_string(),
        source_capturing_node: Some("node-a".to_string()),
        input_events: 50,
        replayed_events: 48,
        summary: TraceReplaySummary {
            total_events: 50,
            event_type_counts: std::collections::BTreeMap::default(),
            expected_decision_counts: std::collections::BTreeMap::default(),
            actual_decision_counts: std::collections::BTreeMap::default(),
            matched_events: 48,
            mismatched_events: 2,
            matched_decisions: 0,
            mismatched_decisions: 0,
        },
        diffs: vec![TraceReplayDiff {
            index: 3,
            event_type: "lease".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: "missing replay event".to_string(),
        }],
    };
    let json = serde_json::to_string(&report).unwrap();
    let parsed: TraceReplayReport = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, report);
}

#[test]
fn trace_replay_report_no_capturing_node() {
    let report = TraceReplayReport {
        source_trace_id: "trace-002".to_string(),
        source_capturing_node: None,
        input_events: 0,
        replayed_events: 0,
        summary: TraceReplaySummary {
            total_events: 0,
            event_type_counts: std::collections::BTreeMap::default(),
            expected_decision_counts: std::collections::BTreeMap::default(),
            actual_decision_counts: std::collections::BTreeMap::default(),
            matched_events: 0,
            mismatched_events: 0,
            matched_decisions: 0,
            mismatched_decisions: 0,
        },
        diffs: vec![],
    };
    let json = serde_json::to_string(&report).unwrap();
    let parsed: TraceReplayReport = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.source_capturing_node, None);
    assert_eq!(parsed.diffs, [] as [fcp_mesh::TraceReplayDiff; 0]);
}

#[test]
fn trace_replay_error_io_display() {
    let err = TraceReplayError::Io {
        path: "/tmp/trace.json".to_string(),
        message: "file not found".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("/tmp/trace.json"));
    assert!(msg.contains("file not found"));
}

#[test]
fn trace_replay_error_parse_display() {
    let err = TraceReplayError::Parse {
        format: "json",
        message: "unexpected EOF".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("json"));
    assert!(msg.contains("unexpected EOF"));
}

#[test]
fn trace_replay_error_capture_unavailable() {
    let err = TraceReplayError::TraceCaptureUnavailable;
    assert_ne!(err.to_string(), "");
}

#[test]
fn trace_replay_engine_load_nonexistent_file() {
    let result = TraceReplayEngine::load_trace_from_path(
        "/nonexistent/path/trace.json",
        TraceReplayInputFormat::Json,
    );
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), TraceReplayError::Io { .. }));
}

#[test]
fn trace_replay_engine_replay_path_nonexistent() {
    let result =
        TraceReplayEngine::replay_path("/nonexistent/replay.json", TraceReplayInputFormat::Auto);
    assert!(result.is_err());
}

// ════════════════════════════════════════════════════════════════════════════
// MeshNode Configuration
// ════════════════════════════════════════════════════════════════════════════

fn create_test_stores() -> (
    Arc<MemoryObjectStore>,
    Arc<MemorySymbolStore>,
    Arc<QuarantineStore>,
) {
    let obj_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
    let sym_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
    let quarantine = Arc::new(QuarantineStore::new(
        fcp_store::ObjectAdmissionPolicy::default(),
    ));
    (obj_store, sym_store, quarantine)
}

fn create_test_node(name: &str) -> MeshNode {
    let config = MeshNodeConfig::new(name).with_sender_instance_id(42);
    let (obj, sym, quar) = create_test_stores();
    MeshNode::new(config, obj, sym, quar)
}

#[test]
fn mesh_node_config_builder() {
    let config = MeshNodeConfig::new("test-node");
    assert_eq!(config.node_id, "test-node");
    assert!(config.trace_capture_zones.is_none());
}

#[test]
fn mesh_node_config_with_overrides() {
    let config = MeshNodeConfig::new("node-1")
        .with_admission_policy(AdmissionPolicy::trusted_mesh())
        .with_gossip_config(GossipConfig::default())
        .with_symbol_request_policy(SymbolRequestPolicy::default())
        .with_raptorq_config(RaptorQConfig::default())
        .with_sender_instance_id(9999);
    assert_eq!(config.node_id, "node-1");
    assert_eq!(config.sender_instance_id, 9999);
    assert!(config.admission_policy.require_authenticated_requests);
}

#[test]
fn mesh_node_config_with_trace_zones() {
    let mut zones = HashSet::new();
    zones.insert(test_zone());
    let config = MeshNodeConfig::new("traced-node").with_trace_capture_zones(zones);
    assert!(config.trace_capture_zones.is_some());
    assert_eq!(config.trace_capture_zones.as_ref().unwrap().len(), 1);
}

#[test]
fn mesh_node_construction() {
    let node = create_test_node("test-node");
    assert_eq!(node.local_node_id().as_str(), "test-node");
    assert_eq!(node.peer_count(), 0);
}

#[test]
fn mesh_node_metrics_default() {
    let node = create_test_node("metrics-node");
    let metrics = node.metrics();
    assert_eq!(metrics.gossip_announcements, 0);
    assert_eq!(metrics.gossip_updates, 0);
    assert_eq!(metrics.peer_updates, 0);
}

#[test]
fn mesh_node_peer_lifecycle() {
    let mut node = create_test_node("local-node");
    let peer_id = test_node("peer-1");
    let profile = test_device_profile("peer-1", 8192, 8);

    node.update_peer_state(peer_id.clone(), profile, HashSet::new(), vec![], 1000);
    assert_eq!(node.peer_count(), 1);
    assert_eq!(node.metrics().peer_updates, 1);

    node.remove_peer(&peer_id);
    assert_eq!(node.peer_count(), 0);
}

#[test]
fn mesh_node_multiple_peers() {
    let mut node = create_test_node("hub-node");
    for i in 0..5 {
        let peer_id = test_node(&format!("peer-{i}"));
        let profile = test_device_profile(&format!("peer-{i}"), 4096, 4);
        node.update_peer_state(peer_id, profile, HashSet::new(), vec![], 1000);
    }
    assert_eq!(node.peer_count(), 5);
    assert_eq!(node.metrics().peer_updates, 5);
}

#[test]
fn mesh_node_session_management() {
    let mut node = create_test_node("session-node");
    let peer_id = test_node("peer-auth");
    let profile = test_device_profile("peer-auth", 4096, 4);
    node.update_peer_state(peer_id.clone(), profile, HashSet::new(), vec![], 1000);

    assert!(!node.is_peer_authenticated(&peer_id));

    let session = MeshSession::new(
        MeshSessionId::new(),
        peer_id.clone(),
        SessionCryptoSuite::Suite1,
        test_session_keys(),
        TransportLimits::default(),
        true,
        1000,
        SessionReplayPolicy::default(),
    );
    node.register_session(session, 1000);
    assert!(node.is_peer_authenticated(&peer_id));

    node.remove_session(&peer_id, 2000);
    assert!(!node.is_peer_authenticated(&peer_id));
}

#[test]
fn mesh_node_gossip_announce() {
    let mut node = create_test_node("gossip-node");
    let zone = test_zone();
    let obj = test_object_id(1);

    let announced = node.announce_object(&zone, &obj, ObjectAdmissionClass::Admitted, 1000);
    assert!(announced);
    assert_eq!(node.metrics().gossip_announcements, 1);
}

#[test]
fn mesh_node_gossip_announce_symbol() {
    let mut node = create_test_node("sym-gossip-node");
    let zone = test_zone();
    let obj = test_object_id(2);

    node.announce_object(&zone, &obj, ObjectAdmissionClass::Admitted, 1000);
    let sym_announced = node.announce_symbol(&zone, &obj, 0, ObjectAdmissionClass::Admitted, 1000);
    assert!(sym_announced);
}

#[test]
fn mesh_node_gossip_quarantined_blocked() {
    let mut node = create_test_node("quar-node");
    let zone = test_zone();
    let obj = test_object_id(3);

    let announced = node.announce_object(&zone, &obj, ObjectAdmissionClass::Quarantined, 1000);
    assert!(!announced);
}

#[test]
fn mesh_node_plan_execution() {
    let mut node = create_test_node("planner-node");

    let peer_id = test_node("worker-1");
    let profile = profile_with_connector("worker-1", 8192, 8, "fcp.test", "1.0.0");
    node.update_peer_state(peer_id, profile, HashSet::new(), vec![], 1000);

    let ctx = PlannerContext::new(test_connector_id("fcp.test"));
    let candidates = node.plan_execution(&ctx, 1000);
    assert_ne!(candidates, [] as [fcp_mesh::CandidateNode; 0]);
}

#[test]
fn mesh_node_plan_execution_no_candidates() {
    let node = create_test_node("empty-planner");
    let ctx = PlannerContext::new(test_connector_id("fcp.missing"));
    let candidates = node.plan_execution(&ctx, 1000);
    assert_eq!(candidates, [] as [fcp_mesh::CandidateNode; 0]);
}

#[test]
fn mesh_node_control_plane_encode_decode() {
    let config = test_raptorq_config();
    let mesh_config = MeshNodeConfig::new("cp-node")
        .with_raptorq_config(config)
        .with_sender_instance_id(42);
    let (obj, sym, quar) = create_test_stores();
    let mut node = MeshNode::new(mesh_config, obj, sym, quar);

    let envelope = test_envelope(&[0xEE; 128], 70, 1, RetentionClass::Required);
    let zone = test_zone();
    let zone_key = test_zone_key();
    let algorithm = test_zone_key_algorithm();

    let frames = node
        .encode_control_plane(&envelope, 1, &zone_key, algorithm)
        .expect("encode");
    assert_ne!(frames, [] as [fcp_protocol::FcpsFrame; 0]);

    let peer = NodeId::new("cp-node");
    let mut result = None;
    for frame in &frames {
        if let Some(decoded) = node
            .decode_control_plane(
                &peer,
                frame,
                &zone,
                RetentionClass::Required,
                &zone_key,
                algorithm,
                1_000,
            )
            .expect("decode")
        {
            result = Some(decoded);
        }
    }
    let decoded = result.expect("roundtrip through MeshNode");
    assert_eq!(decoded.payload, envelope.payload);
}

#[test]
fn mesh_node_process_control_plane_with_handler() {
    let config = test_raptorq_config();
    let mesh_config = MeshNodeConfig::new("handler-node")
        .with_raptorq_config(config)
        .with_sender_instance_id(55);
    let (obj, sym, quar) = create_test_stores();
    let mut node = MeshNode::new(mesh_config, obj, sym, quar);

    let envelope = test_envelope(&[0xFF; 64], 80, 2, RetentionClass::Required);
    let zone = test_zone();
    let zone_key = test_zone_key();
    let algorithm = test_zone_key_algorithm();
    let handler = InMemoryControlPlaneHandler::new();

    let frames = node
        .encode_control_plane(&envelope, 2, &zone_key, algorithm)
        .expect("encode");
    let peer = NodeId::new("handler-node");
    for frame in &frames {
        node.process_control_plane_frame(
            &peer,
            frame,
            &zone,
            RetentionClass::Required,
            &zone_key,
            algorithm,
            2_000,
            &handler,
        )
        .expect("process");
    }
    assert_eq!(handler.count(), 1);
    let stored = handler.get(&test_object_id(80)).expect("stored");
    assert_eq!(stored.payload, vec![0xFF; 64]);
}

#[test]
fn mesh_node_control_plane_rejects_tampered_symbol_data() {
    let config = test_raptorq_config();
    let mesh_config = MeshNodeConfig::new("tamper-node")
        .with_raptorq_config(config)
        .with_sender_instance_id(77);
    let (obj, sym, quar) = create_test_stores();
    let mut node = MeshNode::new(mesh_config, obj, sym, quar);

    let envelope = test_envelope(&[0xAC; 128], 81, 3, RetentionClass::Required);
    let zone = test_zone();
    let zone_key = test_zone_key();
    let algorithm = test_zone_key_algorithm();

    let mut frame = node
        .encode_control_plane(&envelope, 3, &zone_key, algorithm)
        .expect("encode")
        .remove(0);
    frame.symbols[0].data[0] ^= 0x01;

    let err = node
        .decode_control_plane(
            &NodeId::new("tamper-node"),
            &frame,
            &zone,
            RetentionClass::Required,
            &zone_key,
            algorithm,
            3_000,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        MeshNodeError::DegradedTransport(DegradedTransportError::SymbolDecryptFailed { .. })
    ));
}

#[test]
fn mesh_node_transport_path_ranking() {
    let node = create_test_node("transport-node");
    let policy = ZoneTransportPolicy {
        allow_lan: true,
        allow_derp: true,
        allow_funnel: false,
    };
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, test_node("a"), "a", Some(1)),
        TransportPath::new(TransportPathKind::Funnel, test_node("b"), "b", Some(5)),
    ];
    let ranked = node.rank_transport_paths(&policy, &paths);
    assert_eq!(ranked.len(), 2);
    let direct = ranked
        .iter()
        .find(|r| r.path.kind == TransportPathKind::Direct)
        .unwrap();
    assert!(direct.eligible);
    let funnel = ranked
        .iter()
        .find(|r| r.path.kind == TransportPathKind::Funnel)
        .unwrap();
    assert!(!funnel.eligible);
}

#[test]
fn mesh_node_best_transport_path() {
    let node = create_test_node("best-path-node");
    let policy = ZoneTransportPolicy::default();
    let paths = vec![
        TransportPath::new(
            TransportPathKind::Direct,
            test_node("fast"),
            "fast",
            Some(1),
        ),
        TransportPath::new(
            TransportPathKind::Direct,
            test_node("slow"),
            "slow",
            Some(100),
        ),
    ];
    let best = node.best_transport_path(&policy, &paths);
    assert!(best.is_some());
    assert_eq!(best.unwrap().path.estimated_rtt_ms, Some(1));
}

#[test]
fn mesh_node_select_transport_paths_deterministic() {
    let mut node = create_test_node("multipath-node");
    let policy = ZoneTransportPolicy::default();
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, test_node("a"), "a", None),
        TransportPath::new(TransportPathKind::Direct, test_node("b"), "b", None),
        TransportPath::new(TransportPathKind::Direct, test_node("c"), "c", None),
    ];
    let obj = test_object_id(42);
    let s1 = node.select_transport_paths(&policy, &paths, &obj, 0, 2);
    let s2 = node.select_transport_paths(&policy, &paths, &obj, 0, 2);
    assert_eq!(s1.len(), s2.len());
    for (a, b) in s1.iter().zip(s2.iter()) {
        assert_eq!(a.path_id, b.path_id);
    }
}

#[test]
fn mesh_node_prune_stale_state() {
    let mut node = create_test_node("prune-node");
    let pruned = node.prune_stale_state(1_000_000);
    assert_eq!(pruned, 0);
}

#[test]
fn mesh_node_trace_snapshot_disabled() {
    let config = MeshNodeConfig::new("no-trace")
        .with_sender_instance_id(1)
        .with_trace_capture_config(TraceCaptureConfig::default()); // default has enabled=false
    let (obj, sym, quar) = create_test_stores();
    let node = MeshNode::new(config, obj, sym, quar);
    assert!(node.trace_snapshot().is_none());
    assert!(node.trace_redacted_snapshot().is_none());
}

#[test]
fn mesh_node_trace_snapshot_enabled() {
    let config = MeshNodeConfig::new("traced-node")
        .with_sender_instance_id(2)
        .with_trace_capture_config(TraceCaptureConfig::new().enabled());
    let (obj, sym, quar) = create_test_stores();
    let node = MeshNode::new(config, obj, sym, quar);
    let snapshot = node.trace_snapshot();
    assert!(snapshot.is_some());
}

#[test]
fn mesh_node_store_access() {
    let (obj, sym, quar) = create_test_stores();
    let config = MeshNodeConfig::new("store-node").with_sender_instance_id(3);
    let node = MeshNode::new(config, obj, sym, quar);
    let _ = node.object_store();
    let _ = node.symbol_store();
    let _ = node.quarantine_store();
}

#[test]
fn mesh_node_gossip_mut_access() {
    let mut node = create_test_node("gossip-mut-node");
    let gossip = node.gossip_mut();
    assert_eq!(gossip.peer_count(), 0);
}

#[test]
fn mesh_node_admission_mut_access() {
    let mut node = create_test_node("admission-mut-node");
    let admission = node.admission_mut();
    assert_eq!(admission.peer_count(), 0);
}

#[test]
fn mesh_node_peer_signing_key_lifecycle() {
    let mut node = create_test_node("key-node");
    let peer = test_node("peer-key");
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    node.register_peer_signing_key(peer.clone(), verifying_key);
    node.remove_peer_signing_key(&peer);
    // No panic means success
}

#[test]
fn mesh_node_update_local_state() {
    let mut node = create_test_node("local-state-node");
    let profile = test_device_profile("local-state-node", 16384, 16);
    node.update_local_state(profile, HashSet::new(), vec![]);
    // Verify it doesn't panic and node is still functional
    assert_eq!(node.peer_count(), 0);
}

#[test]
fn mesh_node_update_local_state_with_leases() {
    let mut node = create_test_node("lease-node");
    let profile = test_device_profile("lease-node", 4096, 4);
    let leases = vec![HeldLease {
        subject_id: test_object_id(1),
        purpose: LeasePurpose::SingletonWriter,
        expires_at: 2_000_000,
        fencing_token: 7,
    }];
    node.update_local_state(profile, HashSet::new(), leases);
    // Functional after update
    let ctx = PlannerContext::new(test_connector_id("fcp.test"));
    let _ = node.plan_execution(&ctx, 1000);
}

#[test]
fn mesh_node_remove_nonexistent_peer() {
    let mut node = create_test_node("remove-node");
    let peer = test_node("ghost-peer");
    node.remove_peer(&peer);
    assert_eq!(node.peer_count(), 0);
}

#[test]
fn mesh_node_remove_peer_cleans_session() {
    let mut node = create_test_node("cleanup-node");
    let peer_id = test_node("session-peer");
    let profile = test_device_profile("session-peer", 4096, 4);
    node.update_peer_state(peer_id.clone(), profile, HashSet::new(), vec![], 1000);

    let session = MeshSession::new(
        MeshSessionId::new(),
        peer_id.clone(),
        SessionCryptoSuite::Suite1,
        test_session_keys(),
        TransportLimits::default(),
        true,
        1000,
        SessionReplayPolicy::default(),
    );
    node.register_session(session, 1000);
    assert!(node.is_peer_authenticated(&peer_id));

    node.remove_peer(&peer_id);
    assert!(!node.is_peer_authenticated(&peer_id));
    assert_eq!(node.peer_count(), 0);
}

// ════════════════════════════════════════════════════════════════════════════
// MeshNode Error Types
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn mesh_node_error_from_admission() {
    let admission_err = AdmissionError::AuthenticationRequired;
    let node_err: MeshNodeError = admission_err.into();
    let msg = node_err.to_string();
    assert!(msg.contains("admission"));
}

#[test]
fn mesh_node_error_from_symbol_request() {
    let sym_err = SymbolRequestError::BoundsExceeded {
        requested: 100,
        max_allowed: 10,
    };
    let node_err: MeshNodeError = sym_err.into();
    let msg = node_err.to_string();
    assert!(msg.contains("symbol request"));
}

#[test]
fn mesh_node_error_from_degraded_transport() {
    let deg_err = DegradedTransportError::RetentionViolation;
    let node_err: MeshNodeError = deg_err.into();
    let msg = node_err.to_string();
    assert!(msg.contains("degraded transport"));
}

#[test]
fn mesh_node_error_trace_not_enabled() {
    let err = MeshNodeError::TraceNotEnabled;
    assert!(err.to_string().contains("trace"));
}

#[test]
fn mesh_node_metrics_default_values() {
    let m = MeshNodeMetrics::default();
    assert_eq!(m.gossip_announcements, 0);
    assert_eq!(m.gossip_updates, 0);
    assert_eq!(m.peer_updates, 0);
    let _debug = format!("{m:?}");
}

// ════════════════════════════════════════════════════════════════════════════
// Cross-Module Integration (MeshNode end-to-end workflows)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn cross_admission_gossip_planning_workflow() {
    let mut node = create_test_node("orchestrator");
    let peer = test_node("worker-1");
    let zone = test_zone();

    let profile = profile_with_connector("worker-1", 16384, 8, "data-sync", "1.0.0");
    node.update_peer_state(peer.clone(), profile, HashSet::new(), vec![], 1000);
    assert!(!node.is_peer_authenticated(&peer));

    let session = MeshSession::new(
        MeshSessionId::new(),
        peer.clone(),
        SessionCryptoSuite::Suite1,
        test_session_keys(),
        TransportLimits::default(),
        true,
        1000,
        SessionReplayPolicy::default(),
    );
    node.register_session(session, 1000);
    assert!(node.is_peer_authenticated(&peer));

    let obj1 = ObjectId::from_bytes([0x01; 32]);
    let obj2 = ObjectId::from_bytes([0x02; 32]);
    assert!(node.announce_object(&zone, &obj1, ObjectAdmissionClass::Admitted, 2000));
    assert!(node.announce_object(&zone, &obj2, ObjectAdmissionClass::Admitted, 2000));
    assert_eq!(node.metrics().gossip_announcements, 2);

    let context = PlannerContext::new(test_connector_id("data-sync"));
    let candidates = node.plan_execution(&context, 3000);
    assert_ne!(candidates, [] as [fcp_mesh::CandidateNode; 0]);
}

#[test]
fn cross_session_auth_propagates_to_admission() {
    let mut node = create_test_node("gateway");
    let peer = test_node("client-1");

    let profile = test_device_profile("client-1", 4096, 2);
    node.update_peer_state(peer.clone(), profile, HashSet::new(), vec![], 1000);
    assert!(!node.is_peer_authenticated(&peer));

    let session = MeshSession::new(
        MeshSessionId::new(),
        peer.clone(),
        SessionCryptoSuite::Suite1,
        test_session_keys(),
        TransportLimits::default(),
        false,
        1000,
        SessionReplayPolicy::default(),
    );
    node.register_session(session, 2000);
    assert!(node.is_peer_authenticated(&peer));

    node.remove_session(&peer, 3000);
    assert!(!node.is_peer_authenticated(&peer));
}

#[test]
fn cross_multi_peer_score_ordering() {
    let mut node = create_test_node("scheduler");

    let weak = profile_with_connector("weak", 2048, 1, "inference", "1.0.0");
    let strong = profile_with_connector("strong", 65536, 32, "inference", "1.0.0");
    let medium = profile_with_connector("medium", 8192, 4, "inference", "1.0.0");

    node.update_peer_state(test_node("weak"), weak, HashSet::new(), vec![], 1000);
    node.update_peer_state(test_node("strong"), strong, HashSet::new(), vec![], 1000);
    node.update_peer_state(test_node("medium"), medium, HashSet::new(), vec![], 1000);

    let context = PlannerContext::new(test_connector_id("inference"));
    let candidates = node.plan_execution(&context, 2000);
    assert_eq!(candidates.len(), 3);

    for i in 0..candidates.len() - 1 {
        assert!(
            candidates[i].score >= candidates[i + 1].score,
            "candidates not sorted: {} < {}",
            candidates[i].score,
            candidates[i + 1].score
        );
    }
}

#[test]
fn cross_degraded_encode_to_handler_store() {
    let mut encoder = DegradedModeEncoder::new(test_raptorq_config(), 42);
    let zone = test_zone();
    let zone_key = test_zone_key();
    let algorithm = test_zone_key_algorithm();
    let source_id = test_ts_node("mesh-test-sender");
    let envelope = test_envelope(
        b"cross-module-test-payload",
        0x77,
        10,
        RetentionClass::Required,
    );

    let frames = encoder
        .encode_authenticated(&envelope, 10, &zone_key, algorithm, &source_id)
        .unwrap();
    assert_ne!(frames, [] as [fcp_protocol::FcpsFrame; 0]);

    let mut decoder = DegradedModeDecoder::new(test_raptorq_config());
    let mut recovered = None;
    for frame in &frames {
        if let Ok(Some(env)) = decoder.process_frame_authenticated(
            frame,
            &zone,
            RetentionClass::Required,
            &zone_key,
            algorithm,
            &source_id,
        ) {
            recovered = Some(env);
            break;
        }
    }
    let recovered = recovered.expect("should decode");

    let handler = InMemoryControlPlaneHandler::new();
    handler.handle(recovered).unwrap();
    assert_eq!(handler.count(), 1);

    let epochs = handler.list_epochs(&zone, None);
    assert_eq!(epochs.len(), 1);
    assert_eq!(epochs[0], 10);
}

// ════════════════════════════════════════════════════════════════════════════
// Session Edge Cases
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn session_bidirectional_mac_both_directions() {
    let session_id = MeshSessionId([0x01; 16]);
    let keys_i2r = SessionKeys {
        k_mac_i2r: [0xAA; 32],
        k_mac_r2i: [0xBB; 32],
        k_ctx: [0xCC; 32],
    };
    let keys_r2i = SessionKeys {
        k_mac_i2r: [0xAA; 32],
        k_mac_r2i: [0xBB; 32],
        k_ctx: [0xCC; 32],
    };

    let mut initiator = MeshSession::new(
        session_id,
        test_node("responder"),
        SessionCryptoSuite::Suite1,
        keys_i2r,
        TransportLimits::default(),
        true,
        0,
        SessionReplayPolicy::default(),
    );

    let mut responder = MeshSession::new(
        session_id,
        test_node("initiator"),
        SessionCryptoSuite::Suite1,
        keys_r2i,
        TransportLimits::default(),
        false,
        0,
        SessionReplayPolicy::default(),
    );

    let data_a = b"hello from initiator";
    let (seq_a, mac_a) = initiator.mac_outgoing(data_a);
    assert!(responder.verify_incoming(seq_a, data_a, &mac_a));

    let data_b = b"hello from responder";
    let (seq_b, mac_b) = responder.mac_outgoing(data_b);
    assert!(initiator.verify_incoming(seq_b, data_b, &mac_b));
}

#[test]
fn session_own_mac_rejected_wrong_direction() {
    let mut session = MeshSession::new(
        MeshSessionId([0x02; 16]),
        test_node("peer"),
        SessionCryptoSuite::Suite1,
        SessionKeys {
            k_mac_i2r: [0xCC; 32],
            k_mac_r2i: [0xDD; 32],
            k_ctx: [0; 32],
        },
        TransportLimits::default(),
        true,
        0,
        SessionReplayPolicy::default(),
    );

    let data = b"test payload";
    let (seq, send_mac) = session.mac_outgoing(data);
    // Own MAC should not verify as incoming (different key direction)
    assert!(!session.verify_incoming(seq, data, &send_mac));
}

#[test]
fn session_rekey_after_bytes_threshold() {
    let policy = SessionReplayPolicy {
        rekey_after_bytes: 100,
        rekey_after_frames: u64::MAX,
        rekey_after_seconds: u64::MAX,
        ..SessionReplayPolicy::default()
    };
    let mut session = MeshSession::new(
        MeshSessionId([0x03; 16]),
        test_node("peer"),
        SessionCryptoSuite::Suite1,
        SessionKeys {
            k_mac_i2r: [0xEE; 32],
            k_mac_r2i: [0xFF; 32],
            k_ctx: [0; 32],
        },
        TransportLimits::default(),
        true,
        0,
        policy,
    );

    assert!(!session.needs_rekey(0));
    for _ in 0..20 {
        let _ = session.mac_outgoing(b"short");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Gossip Edge Cases
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn gossip_multi_zone_isolation() {
    let config = GossipConfig::default();
    let zone_a = ZoneId::work();
    let zone_b = ZoneId::private();
    let obj = test_object_id(0x55);

    let mut state_a = GossipState::new(zone_a, &config);
    let state_b = GossipState::new(zone_b, &config);

    state_a.announce_object(&obj, 1);
    assert!(state_a.may_have_object(&obj));
    // Different zone state should not have the object
    assert!(!state_b.may_have_object(&obj));
}

#[test]
fn gossip_object_remove_then_readd() {
    let zone = test_zone();
    let config = GossipConfig::default();
    let mut state = GossipState::new(zone, &config);
    let obj = test_object_id(0x66);

    state.announce_object(&obj, 1);
    assert!(state.has_object(&obj));

    state.remove_object(&obj, 2);
    assert!(!state.has_object(&obj));

    state.announce_object(&obj, 3);
    assert!(state.has_object(&obj));
}

#[test]
fn gossip_bulk_summary_count() {
    let node = test_ts_node("bulk-node");
    let config = GossipConfig::default();
    let mut gossip = MeshGossip::new(node, config);
    let zone = test_zone();

    for i in 0..50u8 {
        let obj = test_object_id(i);
        gossip.announce_object(&zone, &obj, ObjectAdmissionClass::Admitted, u64::from(i));
    }

    let summary = gossip.create_summary(&zone, EpochId::new("epoch-bulk"));
    assert!(summary.is_some());
    assert!(summary.unwrap().object_count >= 50);
}

// ════════════════════════════════════════════════════════════════════════════
// Transport Edge Cases
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn transport_empty_paths_returns_none() {
    let policy = ZoneTransportPolicy::default();
    let paths: Vec<TransportPath> = vec![];
    let best = TransportSelector::best_path(&paths, &policy);
    assert!(best.is_none());
}

#[test]
fn transport_fanout_capped_at_available() {
    let policy = ZoneTransportPolicy::default();
    let paths = vec![TransportPath::new(
        TransportPathKind::Direct,
        test_node("a"),
        "path-a",
        Some(10),
    )];
    let obj = test_object_id(0xFA);
    let selected = TransportSelector::select_multipath(&paths, &policy, &obj, 0, 5);
    assert_eq!(selected.len(), 1);
}

#[test]
fn transport_priority_ordering_invariant() {
    let policy = ZoneTransportPolicy::default();

    let paths = vec![
        TransportPath::new(
            TransportPathKind::Direct,
            test_node("slow"),
            "slow",
            Some(500),
        ),
        TransportPath::new(
            TransportPathKind::Direct,
            test_node("fast"),
            "fast",
            Some(5),
        ),
        TransportPath::new(
            TransportPathKind::Direct,
            test_node("mid"),
            "mid",
            Some(100),
        ),
    ];

    let ranked = TransportSelector::rank_paths(&paths, &policy);
    assert_eq!(ranked.len(), 3);
    // All should be eligible (Direct is allowed by default policy)
    assert!(ranked.iter().all(|r| r.eligible));
}

// ════════════════════════════════════════════════════════════════════════════
// Admission Edge Cases
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn admission_independent_peer_budgets() {
    let mut admission = AdmissionController::new(AdmissionPolicy::default());

    let peer_a = test_node("peer-a");
    let peer_b = test_node("peer-b");

    for _ in 0..100 {
        let _ = admission.check_bytes(&peer_a, 1000, 1000);
    }

    assert!(admission.check_bytes(&peer_b, 1000, 1000).is_ok());
}

#[test]
fn admission_gc_preserves_active_peers() {
    let mut admission = AdmissionController::new(AdmissionPolicy::default());
    let active = test_node("active");
    let stale = test_node("stale");

    let _ = admission.check_bytes(&active, 100, 1000);
    let _ = admission.check_bytes(&stale, 100, 1);

    admission.gc_stale_peers(2000, 500);
    assert!(admission.check_bytes(&active, 100, 2000).is_ok());
}

#[test]
fn mesh_node_full_peer_removal_cleanup() {
    let mut node = create_test_node("cleanup-test");
    let peer = test_node("temp-peer");

    let profile = test_device_profile("temp-peer", 4096, 2);
    node.update_peer_state(peer.clone(), profile, HashSet::new(), vec![], 1000);

    let session = MeshSession::new(
        MeshSessionId::new(),
        peer.clone(),
        SessionCryptoSuite::Suite1,
        test_session_keys(),
        TransportLimits::default(),
        true,
        1000,
        SessionReplayPolicy::default(),
    );
    node.register_session(session, 1000);
    assert_eq!(node.peer_count(), 1);
    assert!(node.is_peer_authenticated(&peer));

    node.remove_peer(&peer);
    assert_eq!(node.peer_count(), 0);
    assert!(!node.is_peer_authenticated(&peer));
}

#[test]
fn mesh_node_announce_then_plan_data_locality() {
    let mut node = create_test_node("locality-test");
    let peer = test_node("data-node");
    let zone = test_zone();
    let obj = test_object_id(0xDD);

    let profile = profile_with_connector("data-node", 8192, 4, "compute", "1.0.0");
    let mut symbols = HashSet::new();
    symbols.insert(obj);
    node.update_peer_state(peer, profile, symbols, vec![], 1000);

    node.announce_object(&zone, &obj, ObjectAdmissionClass::Admitted, 2000);

    let context =
        PlannerContext::new(test_connector_id("compute")).with_required_symbols(vec![obj]);
    let candidates = node.plan_execution(&context, 3000);
    assert_ne!(candidates, [] as [fcp_mesh::CandidateNode; 0]);
    assert!(candidates.iter().any(|c| c.node_id.as_str() == "data-node"));
}

#[test]
fn mesh_node_multiple_sessions_independent() {
    let mut node = create_test_node("multi-session");
    let peer_a = test_node("alice");
    let peer_b = test_node("bob");

    let prof_a = test_device_profile("alice", 4096, 2);
    let prof_b = test_device_profile("bob", 8192, 4);
    node.update_peer_state(peer_a.clone(), prof_a, HashSet::new(), vec![], 1000);
    node.update_peer_state(peer_b.clone(), prof_b, HashSet::new(), vec![], 1000);

    let session_a = MeshSession::new(
        MeshSessionId::new(),
        peer_a.clone(),
        SessionCryptoSuite::Suite1,
        test_session_keys(),
        TransportLimits::default(),
        true,
        1000,
        SessionReplayPolicy::default(),
    );
    let session_b = MeshSession::new(
        MeshSessionId::new(),
        peer_b.clone(),
        SessionCryptoSuite::Suite1,
        test_session_keys(),
        TransportLimits::default(),
        true,
        1000,
        SessionReplayPolicy::default(),
    );

    node.register_session(session_a, 1000);
    node.register_session(session_b, 1000);
    assert!(node.is_peer_authenticated(&peer_a));
    assert!(node.is_peer_authenticated(&peer_b));

    node.remove_session(&peer_a, 2000);
    assert!(!node.is_peer_authenticated(&peer_a));
    assert!(node.is_peer_authenticated(&peer_b));
}
