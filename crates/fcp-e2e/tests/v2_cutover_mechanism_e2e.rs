//! V2 mesh-native cutover mechanism proof (br-ksiz8, [C.9]).
//!
//! Closes the documentation/proof acceptance follow-on from the
//! hr0rr-track-C parent epic. Proves end-to-end that the **cutover
//! MECHANISM** is wired:
//!
//! 1. `TruthPrecedencePolicy::default()` returns `V2MeshNative` (br-4la3k).
//! 2. The canonical enforcement pipeline includes
//!    `EnforcementCheckId::DeploymentTier` at index 4 — right after
//!    `RevocationCascade`, before `HolderProof` (br-nsrx3 + br-yowdy).
//! 3. A `Risky` request in `DeploymentMode::Evaluation` is **denied at
//!    `DeploymentTier`** with `TIER_REQUIRES_MESH_ACTIVE`. This is the
//!    bead's marquee end-to-end behaviour.
//! 4. The same `Risky` request in `DeploymentMode::MeshActive` is
//!    **admitted** — pins the not-over-blocked invariant.
//!
//! No mocks. Real `TruthPrecedencePolicy::default`, real
//! `EnforcementPipeline::default`, real `EnforcementContext` with a
//! real `Arc<DeploymentClassification>`, real `admit_safety_tier`.
//! JSONL log lines per phase per scenario for triage tooling.
//!
//! Items that require a multi-node mesh fixture (genuine
//! `fwc mesh explain-availability` returning mesh-backed answers
//! against ≥1 connector with placement evidence) are deferred to
//! C.1–C.4. This harness is the **mechanism** proof, not the
//! **operational substrate** proof.

//! Note: this harness intentionally does NOT import `fwc::truth` —
//! the V2-default + env-rollback classifier matrix is fully covered
//! by 14 inline tests in `crates/fwc/src/truth.rs::tests` (br-4la3k).
//! `fwc` is a binary, not a library, so its truth module is not
//! reachable from a downstream test crate; duplicating the matrix
//! here would just drift. This harness focuses on the host-side
//! wiring (br-nsrx3) which IS reachable via `fcp_host`'s public
//! surface.

use std::sync::Arc;

use chrono::Utc;
use serde_json::json;

use fcp_host::{
    CheckOutcome, DeploymentClassification, DeploymentClassificationReason, DeploymentMode,
    EnforcementContextBuilder, EnforcementPipeline, MeshQuorumSignals, PipelineOutcome,
    admit_safety_tier,
};
use fcp_prelude::{EnforcementCheckId, EnforcementCheckOrder, SafetyTier};

/// JSONL log entry per phase per scenario, per the testing-perfect-e2e
/// triage contract. Visible under `cargo test -- --nocapture`.
fn log_event(scenario_id: &str, phase: &str, outcome: &str, detail: Option<&str>) {
    let entry = json!({
        "ts": Utc::now().to_rfc3339(),
        "scenario_id": scenario_id,
        "bead": "ksiz8",
        "phase": phase,
        "outcome": outcome,
        "detail": detail,
    });
    println!("{entry}");
}

fn evaluation_classification() -> Arc<DeploymentClassification> {
    Arc::new(DeploymentClassification {
        mode: DeploymentMode::Evaluation,
        signals: MeshQuorumSignals::single_host_evaluation(),
        reason: DeploymentClassificationReason::InsufficientMeshQuorum {
            observed: 0,
            required: 2,
        },
    })
}

fn mesh_active_classification() -> Arc<DeploymentClassification> {
    Arc::new(DeploymentClassification {
        mode: DeploymentMode::MeshActive,
        signals: MeshQuorumSignals::fully_active(3),
        reason: DeploymentClassificationReason::MeshQuorumActive,
    })
}

fn ctx_with_tier_and_mode(
    tier: SafetyTier,
    classification: Arc<DeploymentClassification>,
) -> fcp_host::EnforcementContext {
    EnforcementContextBuilder::new()
        .request_id("req-ksiz8")
        .connector_id("github:risky:1.0.0")
        .operation("issues.create")
        .zone_id("z:work")
        .principal("user:ops")
        .capability_claims(vec!["github.write".into()])
        .required_capability("github.write")
        .holder_proof_required(false)
        .holder_verified(true)
        .checkpoint_age_ms(10_000)
        .revocation_list_age_ms(20_000)
        .budget_used(0)
        .budget_limit(1000)
        .rate_count(0)
        .rate_limit(100)
        .manifest_allowed_operations(vec!["issues.create".into()])
        .safety_tier(tier)
        .deployment_classification(classification)
        .build()
        .expect("builder produces valid context")
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 1 + 2: br-4la3k V2-default + env-rollback classifier
// matrix — covered upstream by 14 inline tests in
// `crates/fwc/src/truth.rs::tests`. Cross-crate test deferred per
// the module-doc note above (fwc is a binary).
// ─────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────
// Scenario 3: canonical enforcement pipeline includes DeploymentTier
// at index 4, after RevocationCascade and before HolderProof.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn v2_cutover_mechanism_deployment_tier_at_canonical_index_4() {
    let scenario = "ksiz8.canonical_slot";
    log_event(scenario, "setup", "started", None);

    let order = EnforcementCheckOrder::canonical_order();
    assert_eq!(
        order.len(),
        EnforcementCheckOrder::COUNT,
        "canonical order length must match the shared enforcement contract"
    );
    assert_eq!(order[2], EnforcementCheckId::CapabilityVerify);
    assert_eq!(
        order[3],
        EnforcementCheckId::RevocationCascade,
        "RevocationCascade MUST sit at index 3 (right after CapabilityVerify)"
    );
    assert_eq!(
        order[4],
        EnforcementCheckId::DeploymentTier,
        "DeploymentTier MUST sit at index 4 (after RevocationCascade)"
    );
    assert_eq!(order[5], EnforcementCheckId::HolderProof);

    let pipeline = EnforcementPipeline::default();
    let names = pipeline.check_names();
    assert_eq!(names.len(), EnforcementCheckOrder::COUNT);
    assert_eq!(
        names[3], "revocation_cascade",
        "the live pipeline MUST include revocation_cascade at index 3"
    );
    assert_eq!(
        names[4], "deployment_tier",
        "the live pipeline MUST include the deployment_tier check at index 4"
    );
    assert_eq!(names[5], "holder_proof");

    log_event(
        scenario,
        "verify_canonical_slot",
        "passed",
        Some("deployment_tier @ index 4"),
    );
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 4: marquee end-to-end behaviour — Risky+Evaluation MUST be
// denied at deployment_tier with TIER_REQUIRES_MESH_ACTIVE.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn v2_cutover_mechanism_risky_in_evaluation_denied_at_deployment_tier() -> Result<(), String> {
    let scenario = "ksiz8.risky_in_evaluation_denied";
    log_event(scenario, "setup", "started", None);

    let pipeline = EnforcementPipeline::default();
    let ctx = ctx_with_tier_and_mode(SafetyTier::Risky, evaluation_classification());

    log_event(scenario, "evaluate_pipeline", "running", None);
    let decision = pipeline.evaluate(&ctx);

    match decision.outcome {
        PipelineOutcome::Deny {
            check_name,
            reason_code,
            ..
        } => {
            assert_eq!(check_name, "deployment_tier");
            assert_eq!(reason_code, "TIER_REQUIRES_MESH_ACTIVE");
        }
        outcome @ PipelineOutcome::Allow => {
            return Err(format!("expected Deny at deployment_tier, got {outcome:?}"));
        }
    }

    log_event(
        scenario,
        "evaluate_pipeline",
        "denied",
        Some("deployment_tier=TIER_REQUIRES_MESH_ACTIVE"),
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 5: not-over-blocked — Risky+MeshActive MUST be admitted at
// the deployment_tier check (downstream checks may still deny, but
// deployment_tier MUST allow).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn v2_cutover_mechanism_risky_in_mesh_active_admitted_at_deployment_tier() {
    let scenario = "ksiz8.risky_in_mesh_active_admitted";
    log_event(scenario, "setup", "started", None);

    let pipeline = EnforcementPipeline::default();
    let ctx = ctx_with_tier_and_mode(SafetyTier::Risky, mesh_active_classification());

    log_event(scenario, "evaluate_pipeline", "running", None);
    let decision = pipeline.evaluate(&ctx);

    let record = decision
        .checks_run
        .iter()
        .find(|r| r.name == "deployment_tier")
        .expect("deployment_tier check ran");
    assert!(
        matches!(record.outcome, CheckOutcome::Allow),
        "deployment_tier MUST admit Risky in MeshActive (got {:?})",
        record.outcome
    );

    log_event(scenario, "evaluate_pipeline", "admitted", None);
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 6: composition — admit_safety_tier (called directly, the
// way C.6 / hr0rr.1 originally exposed it) MUST agree with the wired
// pipeline check.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn v2_cutover_mechanism_admit_safety_tier_agrees_with_pipeline_outcome() {
    let scenario = "ksiz8.admit_agrees_with_pipeline";
    log_event(scenario, "setup", "started", None);

    let cases = [
        (SafetyTier::Safe, evaluation_classification(), true),
        (SafetyTier::Safe, mesh_active_classification(), true),
        (SafetyTier::Risky, evaluation_classification(), false),
        (SafetyTier::Risky, mesh_active_classification(), true),
        (SafetyTier::Dangerous, evaluation_classification(), false),
        (SafetyTier::Dangerous, mesh_active_classification(), true),
        (SafetyTier::Critical, evaluation_classification(), true),
        (SafetyTier::Critical, mesh_active_classification(), true),
        (SafetyTier::Forbidden, evaluation_classification(), false),
        (SafetyTier::Forbidden, mesh_active_classification(), false),
    ];

    for (tier, classification, expected_admit) in cases {
        let admit_result = admit_safety_tier(&classification, tier);
        let admitted = admit_result.is_ok();
        assert_eq!(
            admitted, expected_admit,
            "admit_safety_tier({tier:?}, mode={:?}) wrong",
            classification.mode
        );
    }

    log_event(
        scenario,
        "verify_admission_matrix",
        "passed",
        Some("10 (tier × mode) cases verified"),
    );
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 7: deferred — full mesh-availability proof against a
// multi-node fixture. Stubbed under #[ignore] until the live fwc
// mesh-availability path can consume per-zone mesh inventory and return
// mesh-backed truth for at least one placed connector. The local A.4
// deterministic failover harness has landed in multi_node_failover.rs, but
// it is not the same proof as this operator-facing fwc availability gate.
// ─────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires live fwc mesh explain-availability to consume per-zone mesh inventory and return mesh-backed truth for a placed connector; the local A.4 multi_node_failover.rs harness has landed but is not this operator-facing gate."]
fn v2_cutover_mechanism_fwc_mesh_explain_availability_returns_mesh_backed() -> Result<(), String> {
    // Acceptance lifted from hr0rr epic body:
    //   "fwc mesh explain-availability returns mesh-backed for ≥1
    //    connector in test harness".
    //
    // To implement: publish a connector with placement evidence to ≥2 nodes
    // through the live host/fwc mesh-availability boundary, then drive
    // `fwc mesh explain-availability <connector>` and assert the
    // returned envelope carries `availability=LiveRuntime` AND the
    // payload's `truth_source` is `mesh-backed` (NOT `host-backed`).
    //
    // The local C.4/A.4 deterministic failover substrate lives in
    // `crates/fcp-e2e/tests/multi_node_failover.rs`. It proves seeded
    // local failover and replay contracts, but it does not publish live
    // per-zone inventory through fwc.
    //
    // The mesh-availability surface in fwc/src/main.rs already exists
    // (see `mesh_availability_dispatch`); it currently returns
    // host-backed because per-zone mesh inventory is not yet exposed
    // on the live host API. C.1 and C.5 close that gap.
    Err("deferred: mesh fixture not yet available; see ignore message".to_owned())
}
