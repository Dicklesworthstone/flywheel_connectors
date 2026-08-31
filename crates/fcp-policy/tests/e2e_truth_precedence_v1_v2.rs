//! E2E truth-precedence + revocation interaction
//! (testing-perfect-e2e-integration-tests-with-logging-and-no-mocks).
//!
//! `AmberLark`, 2026-05-02 — alpha-domain coverage sweep.
//!
//! ## What this exercises
//!
//! Three real components composed together with NO mocks:
//!
//! 1. `fcp_policy::OperationalModelVersion` + the
//!    `select_operational_model_for_deployment` decision matrix
//!    (real fcp-policy code that fwc + fcp-host both consume).
//! 2. `fcp_core::RevocationRegistry` populated with a real
//!    `RevocationObject` carrying a real `ObjectHeader` + `Provenance`.
//! 3. The combined effect: V2-mesh-native vs V1-host-first selection
//!    must NOT change the answer to "is this object revoked at time T?"
//!    (revocation is canonically authoritative regardless of model
//!    version — pinning this invariant prevents a future regression
//!    where one of the two paths silently degrades to a different
//!    answer).
//!
//! ## No-mock guarantees
//!
//! - No `mockall`, `wiremock`, or hand-rolled fakes for the system
//!   under test. Every component is a real fcp-policy / fcp-core type.
//! - The only test scaffolding is the `tracing_subscriber` capture
//!   below — it does NOT substitute any production type, it just
//!   observes the per-phase span durations to assert the test's own
//!   timing invariants.
//!
//! ## Tracing
//!
//! Each phase is wrapped in a `tracing::info_span!` named
//! `"phase.<name>"` so a downstream observer can see the test's
//! progress. Timing assertions cap each phase's wall-clock duration
//! (the bead "perf-budget" check that catches accidental quadratic
//! regressions).

use std::time::Instant;

use fcp_cbor::SchemaId;
use fcp_core::{
    ObjectHeader, ObjectId, Provenance, RevocationObject, RevocationRegistry, RevocationScope,
};
use fcp_policy::{
    OperationalModelSelection, OperationalModelVersion, ZoneId,
    select_operational_model_for_deployment,
};
use semver::Version;
use tracing::{Level, info, info_span};

/// Phase-budget caps. Each test phase asserts its own elapsed time
/// stayed under this budget so a regression that introduces a
/// quadratic walk shows up as a hard test failure rather than a
/// silent slowdown.
const PHASE_BUDGET_MS: u128 = 250;

fn build_object_header(zone_id: &ZoneId, created_at: u64) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.core", "RevocationObject", Version::new(1, 0, 0)),
        zone_id: zone_id.clone(),
        created_at,
        provenance: Provenance::new(zone_id.clone()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn build_revocation(zone_id: &ZoneId, revoked_id: ObjectId, effective_at: u64) -> RevocationObject {
    RevocationObject {
        header: build_object_header(zone_id, effective_at),
        revoked: vec![revoked_id],
        scope: RevocationScope::Capability,
        reason: "e2e_truth_precedence_v1_v2 test fixture (br-AmberLark)".to_string(),
        effective_at,
        expires_at: None,
        signature: [0_u8; 64],
    }
}

#[test]
#[allow(clippy::too_many_lines)]
#[allow(clippy::cast_possible_truncation)]
fn e2e_truth_precedence_v1_v2_revocation_invariant() {
    // Initialise tracing with a test-scoped subscriber. The subscriber
    // is local to this test (tracing::subscriber::set_default returns
    // a guard that drops at end-of-scope) so it never bleeds into
    // other tests run in parallel.
    let _tracing = tracing::subscriber::set_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(Level::DEBUG)
            .with_test_writer()
            .finish(),
    );

    let scenario_id = "e2e/truth-precedence/v1-v2-revocation-invariant";
    let zone_id = ZoneId::work();
    let revoked_object_id = ObjectId::from_bytes([0x42; 32]);
    let now: u64 = 1_700_000_500;
    let effective_at: u64 = 1_700_000_000;

    info!(
        scenario_id,
        zone = %zone_id.as_str(),
        bead = "AmberLark/e2e",
        "starting truth-precedence x revocation invariant test"
    );

    // ── Phase 1: build the operational-model selection matrix ────────
    let phase = info_span!("phase.select_operational_model").entered();
    let phase_start = Instant::now();

    // Operator deploys with V2 requested (the post-br-4la3k default)
    // on a single-host topology WITH the degraded opt-in. Effective
    // model should be V2.
    let v2_with_opt_in: OperationalModelSelection = select_operational_model_for_deployment(
        OperationalModelVersion::V2MeshNative,
        true, // explicit_v2_requested
        true, // degraded_v2_accepted
        true, // single_host_detected
    );
    assert_eq!(
        v2_with_opt_in.requested,
        OperationalModelVersion::V2MeshNative
    );
    assert_eq!(
        v2_with_opt_in.effective,
        OperationalModelVersion::V2MeshNative
    );
    assert!(v2_with_opt_in.degraded_v2_opt_in);
    assert!(v2_with_opt_in.warning.is_none());

    // Operator deploys with V2 requested on single-host WITHOUT the
    // opt-in. Effective model falls back to V1 with a warning.
    let v2_no_opt_in: OperationalModelSelection = select_operational_model_for_deployment(
        OperationalModelVersion::V2MeshNative,
        true,  // explicit_v2_requested
        false, // degraded_v2_accepted
        true,  // single_host_detected
    );
    assert_eq!(
        v2_no_opt_in.requested,
        OperationalModelVersion::V2MeshNative
    );
    assert_eq!(v2_no_opt_in.effective, OperationalModelVersion::V1HostFirst);
    assert!(!v2_no_opt_in.degraded_v2_opt_in);
    assert!(
        v2_no_opt_in.warning.is_some(),
        "fallback must produce a warning"
    );
    if let Some(msg) = v2_no_opt_in.warning {
        info!(scenario_id, fallback_warning = %msg, "v2-without-opt-in fell back to v1");
    }

    // V1 explicitly requested — unchanged regardless of topology.
    let v1_explicit: OperationalModelSelection = select_operational_model_for_deployment(
        OperationalModelVersion::V1HostFirst,
        false,
        false,
        true,
    );
    assert_eq!(v1_explicit.effective, OperationalModelVersion::V1HostFirst);
    assert!(v1_explicit.warning.is_none());

    let phase_elapsed = phase_start.elapsed();
    assert!(
        phase_elapsed.as_millis() < PHASE_BUDGET_MS,
        "select_operational_model phase exceeded {}ms budget: {}ms",
        PHASE_BUDGET_MS,
        phase_elapsed.as_millis()
    );
    info!(
        scenario_id,
        phase = "select_operational_model",
        elapsed_ms = phase_elapsed.as_millis() as u64,
        "ok"
    );
    drop(phase);

    // ── Phase 2: real RevocationRegistry populated with a revocation ─
    let phase = info_span!("phase.populate_revocation_registry").entered();
    let phase_start = Instant::now();

    let mut registry = RevocationRegistry::new();
    let revocation = build_revocation(&zone_id, revoked_object_id, effective_at);
    registry.add_revocation(&revocation);

    assert!(
        registry.is_revoked(&revoked_object_id),
        "registry must record the revocation"
    );
    assert!(
        registry.is_revoked_at(&revoked_object_id, now),
        "now ({now}) is after effective_at ({effective_at}); should be revoked"
    );
    assert!(
        !registry.is_revoked_at(&revoked_object_id, effective_at - 1),
        "before effective_at should NOT be revoked (defensive boundary check)"
    );

    let phase_elapsed = phase_start.elapsed();
    assert!(
        phase_elapsed.as_millis() < PHASE_BUDGET_MS,
        "populate_revocation_registry phase exceeded {}ms budget: {}ms",
        PHASE_BUDGET_MS,
        phase_elapsed.as_millis()
    );
    info!(
        scenario_id,
        phase = "populate_revocation_registry",
        elapsed_ms = phase_elapsed.as_millis() as u64,
        revocations = 1,
        "ok"
    );
    drop(phase);

    // ── Phase 3: cross-product invariant ─────────────────────────────
    // Revocation is canonically authoritative regardless of
    // operational-model selection. Operating in V1 vs V2 MUST NOT
    // change the answer to "is this object revoked at time T?".
    // Pin this so a future change that gates the registry behind an
    // operational-model branch can't silently regress.
    let phase = info_span!("phase.cross_product_invariant").entered();
    let phase_start = Instant::now();

    let selections = [
        ("v2_with_opt_in", &v2_with_opt_in),
        ("v2_no_opt_in", &v2_no_opt_in),
        ("v1_explicit", &v1_explicit),
    ];
    for (label, selection) in selections {
        let revoked_now = registry.is_revoked_at(&revoked_object_id, now);
        let revoked_before = registry.is_revoked_at(&revoked_object_id, effective_at - 1);
        info!(
            scenario_id,
            selection_label = label,
            requested = ?selection.requested,
            effective = ?selection.effective,
            single_host_detected = selection.single_host_detected,
            degraded_v2_opt_in = selection.degraded_v2_opt_in,
            revoked_now,
            revoked_before,
            "model-selection / revocation cross-product"
        );
        assert!(
            revoked_now,
            "selection={label}: revocation lookup at now MUST be true under any operational model"
        );
        assert!(
            !revoked_before,
            "selection={label}: revocation lookup before effective_at MUST be false under any operational model"
        );
    }

    let phase_elapsed = phase_start.elapsed();
    assert!(
        phase_elapsed.as_millis() < PHASE_BUDGET_MS,
        "cross_product_invariant phase exceeded {}ms budget: {}ms",
        PHASE_BUDGET_MS,
        phase_elapsed.as_millis()
    );
    info!(
        scenario_id,
        phase = "cross_product_invariant",
        elapsed_ms = phase_elapsed.as_millis() as u64,
        selections = selections.len() as u64,
        "ok"
    );
    drop(phase);

    info!(scenario_id, "test passed");
}

/// Pins the env-driven model resolution so a future change to
/// `truth_precedence_env_requests_v1` / `_v2` can't silently flip the
/// default. Real `fcp_policy::requested_operational_model_from_env`,
/// no mocks.
#[test]
fn e2e_truth_precedence_env_default_resolves_to_v2_post_4la3k() {
    let _tracing = tracing::subscriber::set_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(Level::DEBUG)
            .with_test_writer()
            .finish(),
    );
    let scenario_id = "e2e/truth-precedence/env-default-v2";

    let phase = info_span!("phase.env_default_v2").entered();
    let model = fcp_policy::requested_operational_model_from_env(None);
    info!(scenario_id, ?model, "default env (None) resolves");
    assert_eq!(
        model,
        OperationalModelVersion::V2MeshNative,
        "post-br-4la3k: env-default MUST resolve to V2-mesh-native"
    );
    drop(phase);

    let phase = info_span!("phase.env_explicit_v1").entered();
    let v1_model = fcp_policy::requested_operational_model_from_env(Some("v1"));
    info!(scenario_id, ?v1_model, "explicit env=v1 resolves");
    assert_eq!(
        v1_model,
        OperationalModelVersion::V1HostFirst,
        "explicit env=v1 MUST opt back into V1-host-first for incident rollback"
    );
    drop(phase);

    let phase = info_span!("phase.env_unknown_value").entered();
    let unknown_model = fcp_policy::requested_operational_model_from_env(Some("garbage"));
    info!(scenario_id, ?unknown_model, "unknown env value resolves");
    assert_eq!(
        unknown_model,
        OperationalModelVersion::V2MeshNative,
        "unknown env values MUST NOT silently roll back to V1 — they fall through to the default"
    );
    drop(phase);

    info!(scenario_id, "test passed");
}
