//! End-to-end verification of I-CONFLUENCE operation classification and
//! `MeshInvokeTransport` dispatch throughput (`flywheel_connectors-angoc.11.1.1`).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fcp_core::{
    AgentHint, CapabilityId, CoordinationClass, IdempotencyClass, OperationId, OperationInfo,
    RiskLevel, SafetyTier,
};
use fcp_mesh::{
    MeshDispatchRequest, MeshInvokeTransport, MeshLeaseEntry, MeshLeaseTable,
};
use serde_json::json;
use tracing::Subscriber;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt};

fn sample_op(id: &str, safety_tier: SafetyTier, idempotency: IdempotencyClass) -> OperationInfo {
    OperationInfo {
        id: OperationId::new(id).expect("valid operation id"),
        summary: format!("Operation {id}"),
        description: None,
        input_schema: json!({"type": "object"}),
        output_schema: json!({"type": "object"}),
        capability: CapabilityId::new("stripe.cap").expect("valid capability id"),
        risk_level: RiskLevel::Low,
        safety_tier,
        idempotency,
        ai_hints: AgentHint::default(),
        rate_limit: None,
        requires_approval: None,
    }
}

fn synthetic_five_peer_table() -> MeshLeaseTable {
    let mut table = MeshLeaseTable::new();
    table.register_connector_peers(
        "stripe",
        vec![
            MeshLeaseEntry::new("peer-a", 1),
            MeshLeaseEntry::new("peer-b", 1),
            MeshLeaseEntry::new("peer-c", 1),
            MeshLeaseEntry::new("peer-d", 1),
            MeshLeaseEntry::new("peer-e", 1),
        ],
    );
    table
}

fn synthetic_workload(total_ops: usize, read_ratio: f64) -> Vec<MeshDispatchRequest> {
    let read_op = sample_op("stripe.get_charge", SafetyTier::Safe, IdempotencyClass::Strict);
    let write_op = sample_op(
        "stripe.create_charge",
        SafetyTier::Risky,
        IdempotencyClass::Strict,
    );
    let read_cutoff = (total_ops as f64 * read_ratio).round() as usize;

    (0..total_ops)
        .map(|idx| {
            let op = if idx < read_cutoff {
                read_op.clone()
            } else {
                write_op.clone()
            };
            MeshDispatchRequest::new("stripe", op, json!({"seq": idx}))
        })
        .collect()
}

struct QuorumRoundCounter {
    quorum_rounds: Arc<AtomicUsize>,
    dispatch_spans: Arc<AtomicUsize>,
}

impl<S: Subscriber> Layer<S> for QuorumRoundCounter {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &tracing::span::Id,
        _ctx: Context<'_, S>,
    ) {
        match attrs.metadata().name() {
            "fcp.mesh.quorum.round" => {
                self.quorum_rounds.fetch_add(1, Ordering::SeqCst);
            }
            "fcp.mesh.dispatch" => {
                self.dispatch_spans.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
    }
}

#[test]
fn test_iconfluent_read_3x_throughput_vs_quorum() {
    let workload = synthetic_workload(1000, 0.5);
    assert_eq!(workload.len(), 1000);

    let base_overhead = Duration::from_micros(60);

    // (a) All ops forced to RequiresQuorum (emergency override active).
    let forced_transport = MeshInvokeTransport::new(synthetic_five_peer_table(), 3)
        .with_quorum_round_overhead(base_overhead)
        .with_force_quorum_override(Some(true));
    let start_quorum = Instant::now();
    for req in &workload {
        let outcome = forced_transport
            .dispatch(req)
            .expect("forced quorum dispatch succeeds");
        assert_eq!(
            outcome.trace.effective_class,
            CoordinationClass::RequiresQuorum
        );
        assert!(outcome.trace.quorum_round_emitted);
    }
    let elapsed_quorum = start_quorum.elapsed();

    // (b) Reads classified as IConfluent bypass quorum coordination.
    let classified_transport = MeshInvokeTransport::new(synthetic_five_peer_table(), 3)
        .with_quorum_round_overhead(base_overhead)
        .with_force_quorum_override(Some(false));
    let start_classified = Instant::now();
    let mut iconfluent_count = 0usize;
    for req in &workload {
        let outcome = classified_transport
            .dispatch(req)
            .expect("classified dispatch succeeds");
        if outcome.trace.effective_class == CoordinationClass::IConfluent {
            iconfluent_count += 1;
            assert!(!outcome.trace.quorum_round_emitted);
            assert!(outcome.trace.quorum_round_skipped);
        }
    }
    let elapsed_classified = start_classified.elapsed();

    assert_eq!(iconfluent_count, 500);

    let throughput_quorum = workload.len() as f64 / elapsed_quorum.as_secs_f64();
    let throughput_classified = workload.len() as f64 / elapsed_classified.as_secs_f64();

    assert!(
        throughput_classified >= 3.0 * throughput_quorum,
        "I-confluent classification must yield >=3x throughput; classified={throughput_classified:.1}/s vs forced-quorum={throughput_quorum:.1}/s"
    );
}

#[test]
fn test_iconfluent_does_not_emit_quorum_round() {
    let quorum_rounds = Arc::new(AtomicUsize::new(0));
    let dispatch_spans = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry().with(QuorumRoundCounter {
        quorum_rounds: Arc::clone(&quorum_rounds),
        dispatch_spans: Arc::clone(&dispatch_spans),
    });

    let transport = MeshInvokeTransport::new(synthetic_five_peer_table(), 3)
        .with_force_quorum_override(Some(false));
    let read_op = sample_op(
        "stripe.list_charges",
        SafetyTier::Safe,
        IdempotencyClass::Strict,
    );
    let req = MeshDispatchRequest::new("stripe", read_op, json!({"limit": 10}));

    tracing::subscriber::with_default(subscriber, || {
        let outcome = transport.dispatch(&req).expect("dispatch succeeds");
        assert_eq!(outcome.trace.effective_class, CoordinationClass::IConfluent);
        assert!(!outcome.trace.quorum_round_emitted);
        assert!(outcome.trace.quorum_round_skipped);
    });

    assert_eq!(
        dispatch_spans.load(Ordering::SeqCst),
        1,
        "expected exactly 1 fcp.mesh.dispatch span"
    );
    assert_eq!(
        quorum_rounds.load(Ordering::SeqCst),
        0,
        "IConfluent dispatch must NOT emit any fcp.mesh.quorum.round span"
    );
}

#[test]
fn test_force_quorum_env_overrides() {
    let quorum_rounds = Arc::new(AtomicUsize::new(0));
    let dispatch_spans = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry().with(QuorumRoundCounter {
        quorum_rounds: Arc::clone(&quorum_rounds),
        dispatch_spans: Arc::clone(&dispatch_spans),
    });

    let transport = MeshInvokeTransport::new(synthetic_five_peer_table(), 3)
        .with_force_quorum_override(Some(true));
    let read_op = sample_op(
        "stripe.get_charge",
        SafetyTier::Safe,
        IdempotencyClass::Strict,
    );
    let req = MeshDispatchRequest::new("stripe", read_op, json!({"id": "ch_123"}));

    tracing::subscriber::with_default(subscriber, || {
        let outcome = transport.dispatch(&req).expect("dispatch succeeds");
        assert_eq!(outcome.trace.declared_class, CoordinationClass::IConfluent);
        assert_eq!(
            outcome.trace.effective_class,
            CoordinationClass::RequiresQuorum
        );
        assert!(outcome.trace.forced_quorum_override);
        assert!(outcome.trace.quorum_round_emitted);
    });

    assert_eq!(
        quorum_rounds.load(Ordering::SeqCst),
        1,
        "forced-quorum override must emit fcp.mesh.quorum.round span even for IConfluent ops"
    );
}
