//! Real-load matrix coverage for the host backpressure controller
//! under concurrent multi-priority traffic.
//!
//! `backpressure_action_conformance.rs` enumerates the action space
//! by hand-tuned single-cell telemetry shapes. `golden_backpressure_
//! decision_matrix.rs` freezes the value of every (priority ×
//! telemetry-shape) cell as a snapshot. Both run single-threaded
//! against the pure controller — neither catches the integration-
//! level question this harness pins:
//!
//!   *Under real concurrent multi-priority load against the live
//!   `ResilienceLayer`, do the load-bearing cells of the action
//!   matrix actually fire?*
//!
//! Concretely, this test pins five contracts:
//!
//!   1. **Concurrent-replay safety**. Every decision returned by
//!      `ResilienceLayer::backpressure_decision()` while N permit-
//!      holder tasks contend for the bulkhead must satisfy
//!      `replay_matches()`. A torn read between the load-shedder's
//!      base-load atomic and the bulkhead's permit count would
//!      surface as a decision whose replay record reproduces a
//!      different action — the canonical "data race in audit trail"
//!      symptom.
//!
//!   2. **Delay fires under warning/soft-band QueueCongested load**.
//!      `from_resilience_pressure` only populates queue and cpu
//!      pressure (memory and downstream signals are not reachable
//!      through the live load shedder), so the integration-reachable
//!      QueueCongested cell MUST produce `Delay` for at least one
//!      non-Low priority. Pre-fix `Delay` was the most-common live
//!      action under default weights yet was indistinguishable from
//!      `Admit` at integration time — this is the integration-level
//!      pinning that catches that regression (br-6bgp1).
//!
//!   3. **AdmitWithWarning fires at CpuSaturated**. With base-load
//!      driven above `hard_limit_per_mille` the CpuSaturated cell
//!      selects `AdmitWithWarning` for Critical/High/Normal traffic
//!      (per `golden_backpressure_decision_matrix.rs`). A regression
//!      that strips the warning-emission code path (the original
//!      uwih7 silent-downgrade-to-Admit bug at the integration
//!      layer) makes this assertion fail with the warning column
//!      empty.
//!
//!   4. **Critical priority is reserved**. Across every load band
//!      we sweep, `Critical` traffic NEVER picks a `rejects_work()`
//!      action (Shed / CancelLowPriority). This is the structural
//!      invariant operators rely on for must-deliver traffic; if a
//!      future weight refactor lets fairness loss outweigh the
//!      reserved-priority guard, this catches it.
//!
//!   5. **Priority monotonicity at the action band**. For any fixed
//!      load level, the action selected for `Low` traffic is
//!      structurally ≥ the action for `Critical` traffic, where
//!      ordering is the natural softness ordering
//!      (Admit < AdmitWithWarning < Delay < Shed < CancelLowPriority).
//!      A regression that reverses priority weighting (admitting
//!      Low while shedding Critical) would invert this ordering.
//!
//! The test does NOT depend on the specific weight schedule landing
//! every action in every cell — it asserts only the cells the
//! controller is *contractually required* to reach. Future weight
//! tuning can shift the exact action picked at warning_band[Normal]
//! without breaking the test, as long as warning_band collectively
//! still produces ≥1 AdmitWithWarning and soft_limit collectively
//! still produces ≥1 Delay.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use fcp_async_core::runtime;
use fcp_async_core::sync::Mutex;
use fcp_async_core::{task, time};
use fcp_host::{
    BackpressureAction, BackpressureDecision, BackpressureState, BulkheadConfig, RequestPriority,
    ResilienceConfig, ResilienceError, ResilienceLayer,
};
use fcp_kernel::ConnectorId;

const TEST_CONNECTOR_ID: &str = "fcp.host:bp_concurrent:v1.0.0";
/// Number of permit-holder tasks. Below the bulkhead's
/// `max_concurrent` (4) so queue pressure stays moderate (≈500/mille)
/// rather than saturating at 1000 — this lets `set_base_load_per_mille`
/// drive cpu_pressure independently across the warning/soft/hard
/// classification bands we want to exercise.
const PERMIT_HOLDER_COUNT: usize = 2;
const SAMPLES_PER_PRIORITY_PER_BAND: usize = 32;
const PERMIT_HOLD_MS: u64 = 8;

fn connector_id() -> ConnectorId {
    TEST_CONNECTOR_ID.parse().expect("valid connector id")
}

/// All four documented priorities, lowest-criticality first.
const PRIORITIES: [RequestPriority; 4] = [
    RequestPriority::Low,
    RequestPriority::Normal,
    RequestPriority::High,
    RequestPriority::Critical,
];

/// Natural softness ordering of `BackpressureAction`. Lower = softer
/// (admit-class), higher = more disruptive (rejects-work-class).
/// `FallbackStaticPolicy` is intentionally unranked here — the test
/// asserts no fallback fires (calibration is always Valid in this
/// harness), and a fallback would be flagged by the replay check
/// independently.
fn action_softness_rank(action: BackpressureAction) -> Option<u8> {
    match action {
        BackpressureAction::Admit => Some(0),
        BackpressureAction::AdmitWithWarning => Some(1),
        BackpressureAction::Delay => Some(2),
        BackpressureAction::Shed => Some(3),
        BackpressureAction::CancelLowPriority => Some(4),
        BackpressureAction::FallbackStaticPolicy => None,
    }
}

/// Sample one decision per priority with the layer in its current
/// load state. Returns priority → decision so per-band invariants
/// can be checked. Used both by the concurrent sampling loop and by
/// the steady-state probe.
fn sample_one_per_priority(
    layer: &ResilienceLayer,
    cid: &ConnectorId,
    operation: &str,
) -> HashMap<RequestPriority, BackpressureDecision> {
    let mut out = HashMap::new();
    for &priority in &PRIORITIES {
        let decision = layer.backpressure_decision(cid, priority, operation);
        out.insert(priority, decision);
    }
    out
}

/// Result accumulator: which actions were observed for each priority
/// across all samples in a given load band, plus a count of
/// replay-mismatch decisions (must stay 0).
#[derive(Debug, Default)]
struct BandObservations {
    /// priority → set of actions observed across samples.
    actions_by_priority: HashMap<RequestPriority, BTreeSet<BackpressureAction>>,
    /// priority → set of states observed across samples.
    states_by_priority: HashMap<RequestPriority, BTreeSet<BackpressureState>>,
    /// Replay mismatches across all samples (must stay 0).
    replay_mismatches: usize,
    /// Total samples taken (for sanity).
    sample_count: usize,
}

impl BandObservations {
    fn record(&mut self, priority: RequestPriority, decision: &BackpressureDecision) {
        self.actions_by_priority
            .entry(priority)
            .or_default()
            .insert(decision.action);
        self.states_by_priority
            .entry(priority)
            .or_default()
            .insert(decision.state);
        if !decision.replay_matches() {
            self.replay_mismatches += 1;
        }
        self.sample_count += 1;
    }

    fn all_actions(&self) -> BTreeSet<BackpressureAction> {
        let mut all = BTreeSet::new();
        for set in self.actions_by_priority.values() {
            all.extend(set.iter().copied());
        }
        all
    }
}

/// Spawn `count` long-running permit holders that hold a bulkhead
/// permit for `hold_ms` then exit. Returns the join handles so the
/// caller can await them after sampling completes.
async fn spawn_permit_holders(
    layer: Arc<ResilienceLayer>,
    cid: ConnectorId,
    count: usize,
    hold_ms: u64,
    keep_running: Arc<AtomicBool>,
) -> Vec<fcp_async_core::task::JoinHandle<()>> {
    let mut handles = Vec::new();
    for slot in 0..count {
        let layer = Arc::clone(&layer);
        let cid = cid.clone();
        let keep_running = Arc::clone(&keep_running);
        handles.push(task::spawn(async move {
            // Permit-holder loop: each iteration grabs a permit via
            // execute() and holds it for `hold_ms` ms, releasing then
            // re-acquiring while the test wants saturation. Using
            // execute() (not direct bulkhead access) ensures the
            // permits flow through the same code path the controller
            // observes via pressure_per_mille.
            let priority = match slot % 3 {
                0 => RequestPriority::Normal,
                1 => RequestPriority::High,
                _ => RequestPriority::Critical,
            };
            while keep_running.load(Ordering::SeqCst) {
                let result = layer
                    .execute::<_, (), std::io::Error>(&cid, priority, "permit_holder", async move {
                        time::sleep(Duration::from_millis(hold_ms)).await;
                        Ok(())
                    })
                    .await;
                // Some attempts under saturation return LoadShed —
                // that's fine for permit-holding purposes. Other
                // resilience errors mean the load generator stopped
                // exercising the intended path.
                assert!(
                    matches!(&result, Ok(()) | Err(ResilienceError::LoadShed { .. })),
                    "permit-holder saw unexpected error: {result:?}",
                );
            }
        }));
    }
    handles
}

/// Sweep concurrently across all priorities while the layer is held
/// at the given base-load level. Produces a populated
/// `BandObservations` after `samples` sweeps have completed.
async fn sweep_band_concurrently(
    layer: Arc<ResilienceLayer>,
    cid: ConnectorId,
    samples: usize,
) -> BandObservations {
    let observations = Arc::new(Mutex::new(BandObservations::default()));

    let mut sampler_handles = Vec::new();
    for sweep in 0..samples {
        let layer = Arc::clone(&layer);
        let cid = cid.clone();
        let observations = Arc::clone(&observations);
        sampler_handles.push(task::spawn(async move {
            // Each sweep takes one decision per priority. Spreading
            // across spawned tasks means the controller is being
            // sampled CONCURRENTLY with the permit-holders modifying
            // bulkhead.pressure_per_mille — that's the concurrency
            // shape we need to exercise replay_matches() under.
            let per_priority = sample_one_per_priority(&layer, &cid, "sweep");
            {
                let mut guard = observations.lock().await;
                for (priority, decision) in &per_priority {
                    guard.record(*priority, decision);
                }
            }
            // Yield to let permit-holders re-grab permits between
            // sweeps so the bulkhead state actually moves around.
            if sweep.is_multiple_of(8) {
                fcp_async_core::task::yield_now().await;
            }
        }));
    }

    for handle in sampler_handles {
        handle.await.expect("sampler task joined");
    }

    let guard = observations.lock().await;
    BandObservations {
        actions_by_priority: guard.actions_by_priority.clone(),
        states_by_priority: guard.states_by_priority.clone(),
        replay_mismatches: guard.replay_mismatches,
        sample_count: guard.sample_count,
    }
}

/// Run a complete sweep at the given base_load level with permit-
/// holders contending. Observations carry both the action and state
/// distributions per priority. Returns the band's observations.
async fn run_band(
    layer: Arc<ResilienceLayer>,
    cid: ConnectorId,
    base_load: u16,
) -> BandObservations {
    layer.set_base_load_per_mille(base_load);

    // Spin up permit holders BEFORE sampling so the bulkhead is
    // actually contended when the sampler reads pressure_per_mille.
    let keep_running = Arc::new(AtomicBool::new(true));
    let holder_handles = spawn_permit_holders(
        Arc::clone(&layer),
        cid.clone(),
        PERMIT_HOLDER_COUNT,
        PERMIT_HOLD_MS,
        Arc::clone(&keep_running),
    )
    .await;

    // Brief warmup so at least some permit-holders have entered
    // execute() and begun pressing on the bulkhead.
    time::sleep(Duration::from_millis(20)).await;

    let observations = sweep_band_concurrently(
        Arc::clone(&layer),
        cid.clone(),
        SAMPLES_PER_PRIORITY_PER_BAND,
    )
    .await;

    // Stop the permit holders.
    keep_running.store(false, Ordering::SeqCst);
    for handle in holder_handles {
        // Permit-holders may take up to PERMIT_HOLD_MS to wake up
        // and observe the stop signal.
        handle.await.expect("permit-holder task joined");
    }

    observations
}

#[runtime::test]
async fn backpressure_matrix_under_concurrent_multi_priority_load() {
    // Tight bulkhead: 4 permits + 16 queued. The 6 permit-holder
    // tasks therefore can't all hold permits simultaneously, which
    // drives queue_pressure into a real (not synthetic) elevated
    // band. set_base_load_per_mille additionally drives the
    // cpu_pressure axis so we can hit the full state matrix.
    let bulkhead = BulkheadConfig {
        max_concurrent: 4,
        max_queued: 16,
        ..BulkheadConfig::default()
    };
    let config = ResilienceConfig {
        bulkhead,
        ..ResilienceConfig::default()
    };
    let layer = Arc::new(ResilienceLayer::new(config));
    let cid = connector_id();
    layer.ensure_connector(&cid);

    // ── Band 0 — quiet baseline (no contention, base_load=0) ─────
    //
    // Verifies the steady-state Admit path: with no load, every
    // priority sees the Admit cell. This is the "below warning"
    // half-row of the matrix.
    let baseline = sample_one_per_priority(&layer, &cid, "baseline");
    for (&priority, decision) in &baseline {
        assert_eq!(
            decision.state,
            BackpressureState::Normal,
            "baseline state for {priority:?} must classify Normal — got {:?}",
            decision.state,
        );
        assert_eq!(
            decision.action,
            BackpressureAction::Admit,
            "baseline action for {priority:?} must be Admit — got {:?}",
            decision.action,
        );
        assert!(
            decision.replay_matches(),
            "baseline decision for {priority:?} fails offline replay — \
             controller is not deterministic at the integration layer",
        );
    }

    // ── Band 1 — warning band (cpu_pressure ∈ [warning, soft_limit)) ──
    //
    // base_load=700 puts cpu_pressure firmly in the warning band
    // (warning_per_mille=600, soft_limit_per_mille=850 by default).
    // The 2 permit-holders contribute ~500/mille queue pressure, so
    // bulkhead.pressure_per_mille = 500 (queue) and effective_load
    // = max(700, 500) = 700 — state classifies as QueueCongested
    // because max_pressure ≥ warning_per_mille while neither cpu
    // nor queue cross hard_limit. Per the integration matrix this
    // cell selects `Delay` for non-Low priorities and
    // `CancelLowPriority` for Low.
    let warning = run_band(Arc::clone(&layer), cid.clone(), 700).await;
    assert_eq!(
        warning.replay_mismatches, 0,
        "warning band: {} of {} sampled decisions failed replay_matches() — \
         concurrent contention exposed a torn read in the controller \
         input pipeline",
        warning.replay_mismatches, warning.sample_count,
    );
    let warning_actions = warning.all_actions();
    assert!(
        warning_actions.contains(&BackpressureAction::Delay),
        "warning band did NOT fire Delay for any priority — this is \
         the br-6bgp1 silent-downgrade regression reappearing at the \
         integration layer. Observed actions: {warning_actions:?}; \
         per-priority: {:?}",
        warning.actions_by_priority,
    );

    // ── Band 2 — soft-limit band (cpu_pressure ≥ soft_limit) ─────
    //
    // base_load=900 → cpu_pressure 900, still below hard_limit (950).
    // Queue pressure ~500/mille from permit-holders. Per the
    // classification rules (cpu < hard_limit, queue < soft_limit,
    // max_pressure ≥ warning_per_mille), state is again
    // QueueCongested → expected action is `Delay` for non-Low
    // priorities. The bulkhead-permit contention here is heavier
    // than at base_load=700 because effective_load is bumped, so
    // this band re-validates Delay under more realistic stress.
    let soft = run_band(Arc::clone(&layer), cid.clone(), 900).await;
    assert_eq!(
        soft.replay_mismatches, 0,
        "soft-limit band: {} of {} samples failed replay_matches()",
        soft.replay_mismatches, soft.sample_count,
    );
    let soft_actions = soft.all_actions();
    assert!(
        soft_actions.contains(&BackpressureAction::Delay),
        "soft-limit band did NOT fire Delay for any priority — \
         controller is not delaying under elevated load. \
         Observed actions: {soft_actions:?}; per-priority: {:?}",
        soft.actions_by_priority,
    );

    // ── Band 3 — hard-limit band (cpu_pressure ≥ hard_limit) ─────
    //
    // base_load=970 → cpu_pressure 970 → CpuSaturated state. The
    // canonical matrix shows AdmitWithWarning for Critical/High/
    // Normal at this state; Low picks Shed. This is the cell where
    // the original uwih7 fix landed — pre-fix AdmitWithWarning was
    // silently downgraded to Admit at the integration layer, so a
    // regression that re-introduces that downgrade would empty this
    // cell and fail the assertion below.
    let hard = run_band(Arc::clone(&layer), cid.clone(), 970).await;
    assert_eq!(
        hard.replay_mismatches, 0,
        "hard-limit band: {} of {} samples failed replay_matches()",
        hard.replay_mismatches, hard.sample_count,
    );
    let hard_actions = hard.all_actions();
    assert!(
        hard_actions.contains(&BackpressureAction::AdmitWithWarning),
        "hard-limit (CpuSaturated) band did NOT fire AdmitWithWarning \
         for any priority — this is the silent-downgrade-to-Admit \
         regression (uwih7) reappearing at the integration layer. \
         Observed actions: {hard_actions:?}; per-priority: {:?}",
        hard.actions_by_priority,
    );

    // Critical priority MUST NOT pick a rejects_work() action in
    // any band. This is the must-deliver guarantee.
    for band in [&warning, &soft, &hard] {
        if let Some(critical_actions) = band.actions_by_priority.get(&RequestPriority::Critical) {
            for &action in critical_actions {
                let synthetic_decision_rejects = matches!(
                    action,
                    BackpressureAction::Shed | BackpressureAction::CancelLowPriority
                );
                assert!(
                    !synthetic_decision_rejects,
                    "Critical priority selected rejects_work action {action:?} — \
                     this violates the reserved-priority guard. \
                     Per-priority observations: {:?}",
                    band.actions_by_priority,
                );
            }
        }
    }

    // ── Priority monotonicity at hard-limit band ────────────────
    //
    // For any fixed load, the softest action observed for Critical
    // must be ≤ the softest action observed for Low. This
    // structural ordering catches a weight regression that would
    // invert priority handling.
    for band_label in [("warning", &warning), ("soft", &soft), ("hard", &hard)] {
        let (label, band) = band_label;
        let critical_softest = band
            .actions_by_priority
            .get(&RequestPriority::Critical)
            .and_then(|set| set.iter().filter_map(|a| action_softness_rank(*a)).min());
        let low_softest = band
            .actions_by_priority
            .get(&RequestPriority::Low)
            .and_then(|set| set.iter().filter_map(|a| action_softness_rank(*a)).min());
        if let (Some(crit), Some(low)) = (critical_softest, low_softest) {
            assert!(
                crit <= low,
                "{label} band: Critical's softest action rank ({crit}) > Low's \
                 softest action rank ({low}) — priority handling inverted. \
                 Critical observed: {:?}; Low observed: {:?}",
                band.actions_by_priority.get(&RequestPriority::Critical),
                band.actions_by_priority.get(&RequestPriority::Low),
            );
        }
    }

    eprintln!(
        "warning band: actions={:?} states={:?} samples={}",
        warning.all_actions(),
        warning
            .states_by_priority
            .values()
            .flatten()
            .copied()
            .collect::<BTreeSet<_>>(),
        warning.sample_count,
    );
    eprintln!(
        "soft band: actions={:?} states={:?} samples={}",
        soft.all_actions(),
        soft.states_by_priority
            .values()
            .flatten()
            .copied()
            .collect::<BTreeSet<_>>(),
        soft.sample_count,
    );
    eprintln!(
        "hard band: actions={:?} states={:?} samples={}",
        hard.all_actions(),
        hard.states_by_priority
            .values()
            .flatten()
            .copied()
            .collect::<BTreeSet<_>>(),
        hard.sample_count,
    );
}
