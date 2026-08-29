//! Integrated massive-swarm gauntlet smoke lane.
//!
//! This is intentionally offline and deterministic: it exercises the same
//! replay/evidence contracts that a host-backed 10k soak must emit, without
//! depending on live connector services.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use chrono::Utc;
use fcp_host::{
    BatchExecutor, BatchInvokeRequest, BatchOperation, BatchOperationError, BatchOperationPriority,
    BatchOptions, BatchScheduleHint, BatchScheduleReport, BatchScheduleWaitPercentiles,
    BatchSchedulerMode, BatchSchedulerOptions, ConnectorPrewarmConfig, OperationResultStatus,
    PrewarmCheckoutDecision, PrewarmCheckoutObservation, PrewarmCredentialState,
    PrewarmHealthState, PrewarmManifestState, PrewarmPoolState, PrewarmSandboxState,
    PrewarmStrategy, PrewarmZoneBinding, ProcessExit, ResourceLedgerInput, ResourceLedgerOutcome,
    ResourceLedgerRecord, ResourceLedgerRecordKind, ResourceLedgerSamples, ResourceTelemetryState,
};
use fcp_testkit::evidence_helpers::{
    LatencyBreakdown, SWARM_ADVERSARIAL_REVOCATION_SCHEMA_VERSION,
    SWARM_BASELINE_PROMOTION_SCHEMA_VERSION, SWARM_BATCH_MORSELIZATION_SCHEMA_VERSION,
    SWARM_CONTROLLER_SAFETY_SCHEMA_VERSION, SWARM_PREWARM_COLD_START_SCHEMA_VERSION,
    SwarmAdversarialAdmissionOutcome, SwarmAdversarialBackpressureAction,
    SwarmAdversarialCleanupOutcome, SwarmAdversarialLatencyPercentiles,
    SwarmAdversarialRevocationEvent, SwarmAdversarialRevocationEventInput,
    SwarmAdversarialRevocationOutcome, SwarmAdversarialRevocationReport,
    SwarmAdversarialRevocationThresholds, SwarmBaselineArtifactDigests, SwarmBaselinePathKind,
    SwarmBaselinePromotionManifest, SwarmBatchFairnessBucket, SwarmBatchMorselizationEvidence,
    SwarmBatchResourceSample, SwarmBatchWaitPercentiles, SwarmCalibrationStatus,
    SwarmControllerInteractionScenario, SwarmControllerMode, SwarmControllerModeEvidence,
    SwarmControllerModeMetrics, SwarmControllerSafetyOutcome, SwarmControllerSafetyReport,
    SwarmControllerSafetyThresholds, SwarmDecisionAction, SwarmDecisionCard,
    SwarmDecisionCounterfactual, SwarmDecisionDomain, SwarmDecisionEvidencePointer,
    SwarmDecisionFallback, SwarmDecisionLossTerm, SwarmEvidenceArtifact, SwarmEvidenceArtifactKind,
    SwarmEvidenceArtifactManifest, SwarmEvidenceExecutionMode, SwarmEvidenceRedactionPolicy,
    SwarmEvidenceSourceKind, SwarmGauntletCounters, SwarmGauntletEvidenceBundle,
    SwarmGauntletManifest, SwarmGauntletPhase, SwarmGauntletPhaseEvidence,
    SwarmLatencyEvidenceBundle, SwarmLatencySample, SwarmLatencyScenario,
    SwarmPrewarmColdStartEvidence, SwarmPrewarmLatencyPercentiles, SwarmPromotionEnvelope,
    SwarmPromotionQualification, SwarmPromotionSkipArtifact, SwarmPromotionTopology,
    SwarmRegressionGateThresholds, SwarmRegressionMetricSnapshot, SwarmRegressionResourceMetrics,
    SwarmRunEnvironment, SwarmStatisticalGateInput, SwarmStatisticalGateOutcome,
    SwarmStatisticalGateReasonKind, SwarmStatisticalGateReport, SwarmStatisticalGateTuning,
    SwarmStatisticalTraceQuality, SwarmWorkloadKind,
    validate_swarm_prewarm_cold_start_evidence_bundle,
};
use serde_json::{Value, json};

fn smoke_environment() -> SwarmRunEnvironment {
    SwarmRunEnvironment {
        worker_id: "offline-e2e-runner".to_string(),
        cpu_count: 64,
        physical_cpu_count: Some(32),
        numa_node_count: Some(2),
        memory_bytes: Some(256 * 1024 * 1024 * 1024),
        cargo_target_dir: Some("/tmp/fcp-swarm-gauntlet-e2e".to_string()),
        command_line: vec![
            "cargo".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "fcp-e2e".to_string(),
            "--test".to_string(),
            "swarm_gauntlet_e2e".to_string(),
        ],
        source_revision: Some("e2e-smoke-revision".to_string()),
        captured_at: Utc::now(),
    }
}

fn promotion_skip_environment() -> SwarmRunEnvironment {
    SwarmRunEnvironment {
        worker_id: "offline-e2e-small-worker".to_string(),
        cpu_count: 12,
        physical_cpu_count: None,
        numa_node_count: None,
        memory_bytes: None,
        cargo_target_dir: Some("/tmp/fcp-swarm-promotion-skip".to_string()),
        command_line: vec![
            "cargo".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "fcp-e2e".to_string(),
            "--test".to_string(),
            "swarm_gauntlet_e2e".to_string(),
        ],
        source_revision: Some("e2e-promotion-skip-revision".to_string()),
        captured_at: Utc::now(),
    }
}

fn required_artifacts() -> Vec<SwarmEvidenceArtifact> {
    SwarmEvidenceArtifactKind::REQUIRED
        .into_iter()
        .map(|kind| SwarmEvidenceArtifact::new(kind, format!("blake3:{}", kind.as_str()), true))
        .collect()
}

fn phase_evidence() -> Vec<SwarmGauntletPhaseEvidence> {
    vec![
        SwarmGauntletPhaseEvidence::new(
            SwarmGauntletPhase::Fwc,
            "fwc",
            "command_log.txt#fwc-bench",
        ),
        SwarmGauntletPhaseEvidence::new(SwarmGauntletPhase::Host, "fcp-host", "summary.json#host"),
        SwarmGauntletPhaseEvidence::new(SwarmGauntletPhase::Mesh, "fcp-mesh", "summary.json#mesh"),
        SwarmGauntletPhaseEvidence::new(
            SwarmGauntletPhase::ConnectorTestkit,
            "fcp-testkit",
            "raw_samples.jsonl#connector",
        ),
        SwarmGauntletPhaseEvidence::new(
            SwarmGauntletPhase::Scheduler,
            "fcp-host",
            "decision-card:scheduler",
        ),
        SwarmGauntletPhaseEvidence::new(
            SwarmGauntletPhase::Placement,
            "fcp-mesh",
            "decision-card:placement",
        ),
        SwarmGauntletPhaseEvidence::new(
            SwarmGauntletPhase::Backpressure,
            "fcp-host",
            "decision-card:backpressure",
        ),
        SwarmGauntletPhaseEvidence::new(
            SwarmGauntletPhase::Audit,
            "fcp-host",
            "raw_samples.jsonl#audit",
        ),
        SwarmGauntletPhaseEvidence::new(
            SwarmGauntletPhase::Store,
            "fcp-store",
            "raw_samples.jsonl#sparse-high-k",
        ),
        SwarmGauntletPhaseEvidence::new(
            SwarmGauntletPhase::EvidenceBundle,
            "fcp-testkit",
            "manifest.json",
        ),
    ]
}

fn decision_cards(scenario_id: &str) -> Vec<SwarmDecisionCard> {
    [
        (
            "e2e-card:scheduler",
            SwarmDecisionDomain::Scheduler,
            SwarmDecisionAction::Dispatch,
            "queue_congested",
            "p99_queueing",
        ),
        (
            "e2e-card:placement",
            SwarmDecisionDomain::Placement,
            SwarmDecisionAction::Place,
            "numa_pressure",
            "rss_headroom",
        ),
        (
            "e2e-card:backpressure",
            SwarmDecisionDomain::Backpressure,
            SwarmDecisionAction::Delay,
            "downstream_throttled",
            "retry_amplification",
        ),
    ]
    .into_iter()
    .map(|(card_id, domain, action, state, loss_term)| {
        SwarmDecisionCard::new(
            card_id,
            domain,
            "connector:offline-gauntlet",
            state,
            action,
            100,
            SwarmDecisionFallback::available(SwarmDecisionAction::Fallback),
        )
        .with_scenario(scenario_id)
        .with_loss_terms(vec![SwarmDecisionLossTerm::new(
            loss_term, 10, 1_000_000, "score",
        )])
        .with_counterfactual(SwarmDecisionCounterfactual::new(
            SwarmDecisionAction::Fallback,
            120,
            "fallback remains replayable",
        ))
        .with_evidence_pointers(vec![SwarmDecisionEvidencePointer::bundle_artifact(
            format!("raw_samples.jsonl#{scenario_id}"),
            "blake3:raw",
            true,
        )])
        .with_replay_inputs(BTreeMap::from([
            ("scenario_id".to_string(), json!(scenario_id)),
            ("queue_depth".to_string(), json!(64)),
        ]))
    })
    .collect()
}

fn controller_safety_card(
    card_id: &str,
    domain: SwarmDecisionDomain,
    action: SwarmDecisionAction,
    scenario: SwarmControllerInteractionScenario,
) -> SwarmDecisionCard {
    SwarmDecisionCard::new(
        card_id,
        domain,
        "connector:offline-controller-safety",
        scenario.as_str(),
        action,
        100,
        SwarmDecisionFallback::available(SwarmDecisionAction::Fallback),
    )
    .with_scenario(scenario.as_str())
    .with_loss_terms(vec![
        SwarmDecisionLossTerm::new("p99_queueing", 100, 1_000_000, "ns"),
        SwarmDecisionLossTerm::new("audit_visibility", 1, 2_000_000, "events"),
    ])
    .with_counterfactual(SwarmDecisionCounterfactual::new(
        SwarmDecisionAction::Fallback,
        140,
        "fallback is safe but lower-throughput",
    ))
    .with_evidence_pointers(vec![SwarmDecisionEvidencePointer::bundle_artifact(
        format!("controller_safety.jsonl#{}", scenario.as_str()),
        "blake3:controller-safety",
        true,
    )])
    .with_replay_inputs(BTreeMap::from([
        ("scenario".to_string(), json!(scenario.as_str())),
        ("queue_depth".to_string(), json!(128)),
        (
            "zone".to_string(),
            json!("z:project:offline-controller-safety"),
        ),
    ]))
}

fn controller_safety_cards(scenario: SwarmControllerInteractionScenario) -> Vec<SwarmDecisionCard> {
    vec![
        controller_safety_card(
            "e2e-card:scheduler-safety",
            SwarmDecisionDomain::Scheduler,
            SwarmDecisionAction::Dispatch,
            scenario,
        ),
        controller_safety_card(
            "e2e-card:placement-safety",
            SwarmDecisionDomain::Placement,
            SwarmDecisionAction::Place,
            scenario,
        ),
        controller_safety_card(
            "e2e-card:backpressure-safety",
            SwarmDecisionDomain::Backpressure,
            SwarmDecisionAction::Delay,
            scenario,
        ),
        controller_safety_card(
            "e2e-card:fallback-safety",
            SwarmDecisionDomain::Backpressure,
            SwarmDecisionAction::Fallback,
            scenario,
        ),
    ]
}

fn controller_safety_metrics(
    submitted_ops: u64,
    decision_card_count: u64,
) -> SwarmControllerModeMetrics {
    SwarmControllerModeMetrics {
        submitted_ops,
        accounted_ops: submitted_ops,
        audit_event_count: submitted_ops,
        max_starvation_ms: 300,
        zone_fairness_skew_microunits: 10_000,
        principal_fairness_skew_microunits: 10_000,
        counterfactual_count: decision_card_count,
        decision_card_count,
        ..SwarmControllerModeMetrics::default()
    }
}

fn controller_safety_modes(
    scenario: SwarmControllerInteractionScenario,
) -> Vec<SwarmControllerModeEvidence> {
    let scheduler = controller_safety_metrics(256, 1);
    let placement = controller_safety_metrics(256, 1);
    let mut backpressure = controller_safety_metrics(256, 1);
    backpressure.delayed_ops = 16;
    let mut audit = controller_safety_metrics(256, 0);
    audit.counterfactual_count = 0;
    let mut combined = controller_safety_metrics(256, 3);
    combined.delayed_ops = 16;
    combined.shed_ops = 2;
    let mut fallback = controller_safety_metrics(256, 1);
    fallback.fallback_invocations = 1;

    vec![
        SwarmControllerModeEvidence::new(
            scenario,
            SwarmControllerMode::SchedulerOnly,
            scheduler,
            vec!["e2e-card:scheduler-safety".to_string()],
        ),
        SwarmControllerModeEvidence::new(
            scenario,
            SwarmControllerMode::PlacementOnly,
            placement,
            vec!["e2e-card:placement-safety".to_string()],
        ),
        SwarmControllerModeEvidence::new(
            scenario,
            SwarmControllerMode::BackpressureOnly,
            backpressure,
            vec!["e2e-card:backpressure-safety".to_string()],
        ),
        SwarmControllerModeEvidence::new(
            scenario,
            SwarmControllerMode::AuditOnly,
            audit,
            Vec::new(),
        ),
        SwarmControllerModeEvidence::new(
            scenario,
            SwarmControllerMode::CombinedController,
            combined,
            vec![
                "e2e-card:scheduler-safety".to_string(),
                "e2e-card:placement-safety".to_string(),
                "e2e-card:backpressure-safety".to_string(),
            ],
        ),
        SwarmControllerModeEvidence::new(
            scenario,
            SwarmControllerMode::ConservativeFallback,
            fallback,
            vec!["e2e-card:fallback-safety".to_string()],
        ),
    ]
}

fn adversarial_revocation_event(
    operation_id: &str,
    admission_outcome: SwarmAdversarialAdmissionOutcome,
    denial_reason: Option<&str>,
) -> SwarmAdversarialRevocationEvent {
    SwarmAdversarialRevocationEvent::new(SwarmAdversarialRevocationEventInput {
        scenario_id: "adversarial_revocation_overload_e2e_smoke".to_string(),
        operation_id: operation_id.to_string(),
        node_count: 8,
        request_count: 2_048,
        zone: "z:project:adversarial-swarm".to_string(),
        principal_ref: "principal:blake3:e2e0123456789abcdef".to_string(),
        token_ref: "token:blake3:e2e0123456789abcdef".to_string(),
        admission_outcome,
        revocation_seq: 99,
        revocation_head: "revocation-head:blake3:e2e0123456789abcdef".to_string(),
        backpressure_state: "overloaded_zone".to_string(),
        backpressure_action: SwarmAdversarialBackpressureAction::Delay,
        audit_receipt_id: format!("audit-receipt-{operation_id}"),
        latency_percentiles: SwarmAdversarialLatencyPercentiles::new(14, 52, 144),
        denial_reason: denial_reason.map(str::to_string),
        cleanup_outcome: SwarmAdversarialCleanupOutcome::Completed,
        skip_reason: None,
        emergency_revocation_witness: false,
        revoked_work: false,
        stale_revocation: false,
        malformed_revocation: false,
        retry_count: 0,
        fallback_count: 0,
    })
}

fn adversarial_revocation_events() -> Vec<SwarmAdversarialRevocationEvent> {
    let mut revoked = adversarial_revocation_event(
        "op-e2e-revoked-token",
        SwarmAdversarialAdmissionOutcome::Denied,
        Some("revoked_token"),
    );
    revoked.revoked_work = true;
    revoked.retry_count = 4;

    let mut emergency_a = adversarial_revocation_event(
        "op-e2e-emergency-revocation-a",
        SwarmAdversarialAdmissionOutcome::Delayed,
        None,
    );
    emergency_a.emergency_revocation_witness = true;
    emergency_a.backpressure_action = SwarmAdversarialBackpressureAction::EmergencyPropagate;
    emergency_a.latency_percentiles = SwarmAdversarialLatencyPercentiles::new(8, 24, 81);

    let mut emergency_b = adversarial_revocation_event(
        "op-e2e-emergency-revocation-b",
        SwarmAdversarialAdmissionOutcome::Delayed,
        None,
    );
    emergency_b.emergency_revocation_witness = true;
    emergency_b.backpressure_action = SwarmAdversarialBackpressureAction::Fallback;
    emergency_b.fallback_count = 1;
    emergency_b.latency_percentiles = SwarmAdversarialLatencyPercentiles::new(12, 38, 112);

    let mut stale = adversarial_revocation_event(
        "op-e2e-stale-revocation",
        SwarmAdversarialAdmissionOutcome::Denied,
        Some("stale_revocation"),
    );
    stale.stale_revocation = true;

    let mut malformed = adversarial_revocation_event(
        "op-e2e-malformed-revocation",
        SwarmAdversarialAdmissionOutcome::Denied,
        Some("malformed_revocation"),
    );
    malformed.malformed_revocation = true;

    vec![revoked, emergency_a, emergency_b, stale, malformed]
}

fn latency_bundle() -> Result<SwarmLatencyEvidenceBundle, Box<dyn Error>> {
    let scenarios = vec![
        SwarmLatencyScenario::new(SwarmWorkloadKind::FwcHostConnector, 1_000),
        SwarmLatencyScenario::new(SwarmWorkloadKind::HostBatchInvoke, 1_000),
        SwarmLatencyScenario::new(SwarmWorkloadKind::MeshGossipUpdate, 1_000),
        SwarmLatencyScenario::new(SwarmWorkloadKind::AuditEvidenceRecording, 1_000),
    ];
    let samples: Vec<_> = scenarios
        .iter()
        .enumerate()
        .flat_map(|(scenario_index, scenario)| {
            (0_u64..4).map(move |sample_index| {
                let offset = u64::try_from(scenario_index).unwrap_or(u64::MAX) * 10;
                SwarmLatencySample::new(
                    scenario.id.clone(),
                    format!("agent-{sample_index}"),
                    format!("op-{scenario_index}-{sample_index}"),
                    sample_index,
                    LatencyBreakdown::new(
                        100 + offset + sample_index,
                        200 + offset,
                        30,
                        sample_index,
                        40,
                        10,
                    ),
                )
            })
        })
        .collect();
    let environment = smoke_environment();
    let artifact_manifest = SwarmEvidenceArtifactManifest::from_environment(
        "gauntlet-e2e-smoke",
        SwarmEvidenceSourceKind::HostBacked,
        SwarmEvidenceExecutionMode::Smoke,
        &environment,
        required_artifacts(),
        SwarmEvidenceRedactionPolicy::conservative(),
    )?;

    Ok(
        SwarmLatencyEvidenceBundle::from_samples(environment, scenarios, samples)?
            .with_artifact_manifest(artifact_manifest)?,
    )
}

fn resource_snapshots(bundle: &SwarmLatencyEvidenceBundle) -> Vec<SwarmRegressionMetricSnapshot> {
    bundle
        .summaries
        .iter()
        .map(|summary| {
            SwarmRegressionMetricSnapshot::from_summary(
                summary,
                SwarmRegressionResourceMetrics {
                    throughput_ops_per_second: 10_000,
                    cpu_microunits: 4_000_000,
                    rss_bytes: 128 * 1024 * 1024,
                    max_queue_depth: 64,
                    retry_amplification_microunits: 100_000,
                },
            )
        })
        .collect()
}

#[allow(clippy::too_many_lines)] // linear evidence-record builder for the gauntlet; emission order is the artifact contract
fn resource_ledger_records(
    command_line: &[String],
    git_revision: &str,
    worker_identity: &str,
) -> Result<Vec<Value>, serde_json::Error> {
    [
        (
            "invoke",
            ResourceLedgerRecordKind::Invoke,
            ResourceLedgerOutcome::Admitted,
            ResourceLedgerSamples {
                state: ResourceTelemetryState::Observed,
                queue_pressure_per_mille: Some(120),
                cpu_pressure_per_mille: Some(180),
                memory_pressure_per_mille: Some(210),
                in_flight: Some(8),
                queue_depth: Some(2),
                retry_after_ms: None,
            },
            vec![10_000, 12_000, 15_000, 20_000],
        ),
        (
            "batch",
            ResourceLedgerRecordKind::Batch,
            ResourceLedgerOutcome::Admitted,
            ResourceLedgerSamples {
                state: ResourceTelemetryState::Observed,
                queue_pressure_per_mille: Some(240),
                cpu_pressure_per_mille: Some(360),
                memory_pressure_per_mille: Some(300),
                in_flight: Some(64),
                queue_depth: Some(8),
                retry_after_ms: None,
            },
            vec![30_000, 32_000, 40_000],
        ),
        (
            "backpressure",
            ResourceLedgerRecordKind::Backpressure,
            ResourceLedgerOutcome::Delayed,
            ResourceLedgerSamples {
                state: ResourceTelemetryState::Observed,
                queue_pressure_per_mille: Some(820),
                cpu_pressure_per_mille: Some(760),
                memory_pressure_per_mille: Some(650),
                in_flight: Some(64),
                queue_depth: Some(31),
                retry_after_ms: Some(25),
            },
            vec![20_000, 22_000, 30_000],
        ),
        (
            "placement",
            ResourceLedgerRecordKind::Placement,
            ResourceLedgerOutcome::Admitted,
            ResourceLedgerSamples {
                state: ResourceTelemetryState::Observed,
                queue_pressure_per_mille: Some(100),
                cpu_pressure_per_mille: Some(440),
                memory_pressure_per_mille: Some(390),
                in_flight: Some(16),
                queue_depth: Some(4),
                retry_after_ms: None,
            },
            vec![8_000, 9_000, 11_000],
        ),
        (
            "retry",
            ResourceLedgerRecordKind::Retry,
            ResourceLedgerOutcome::Retried,
            ResourceLedgerSamples {
                state: ResourceTelemetryState::Observed,
                queue_pressure_per_mille: Some(400),
                cpu_pressure_per_mille: Some(500),
                memory_pressure_per_mille: None,
                in_flight: Some(14),
                queue_depth: Some(7),
                retry_after_ms: Some(100),
            },
            vec![30_000, 50_000, 80_000],
        ),
        (
            "audit",
            ResourceLedgerRecordKind::Audit,
            ResourceLedgerOutcome::Admitted,
            ResourceLedgerSamples {
                state: ResourceTelemetryState::NotApplicable,
                ..ResourceLedgerSamples::default()
            },
            Vec::new(),
        ),
    ]
    .into_iter()
    .map(|(suffix, kind, outcome, samples, latency_samples_ns)| {
        let audit_receipt_id = if kind == ResourceLedgerRecordKind::Audit {
            Some("audit-receipt-resource-ledger-e2e".to_string())
        } else {
            None
        };
        ResourceLedgerRecord::new(ResourceLedgerInput {
            scenario_id: "swarm.resource-ledger.e2e-gauntlet".to_string(),
            operation_id: format!("op-proof-{suffix}"),
            kind,
            outcome,
            command_line: command_line.to_vec(),
            git_revision: git_revision.to_string(),
            worker_identity: worker_identity.to_string(),
            zone_id: Some("z:work".to_string()),
            principal_id: Some("principal:resource-ledger-e2e".to_string()),
            connector_id: Some("fcp.synthetic-gauntlet".to_string()),
            controller_decision: Some(suffix.to_string()),
            samples,
            latency_samples_ns,
            audit_receipt_id,
            fallback_reason: None,
            skip_reason: None,
        })
        .to_jsonl_value()
    })
    .collect()
}

fn batch_morselization_command_line() -> Vec<String> {
    vec![
        "rch".to_string(),
        "exec".to_string(),
        "--".to_string(),
        "cargo".to_string(),
        "test".to_string(),
        "-p".to_string(),
        "fcp-e2e".to_string(),
        "--no-default-features".to_string(),
        "--test".to_string(),
        "swarm_gauntlet_e2e".to_string(),
        "batch_morselization".to_string(),
        "--".to_string(),
        "--nocapture".to_string(),
    ]
}

fn batch_operation(index: usize, root_dependency: Option<&str>) -> BatchOperation {
    let is_long = index % 25 == 0;
    let fairness_key = if index % 3 == 0 {
        "zone:hot".to_string()
    } else {
        format!("zone:tenant:{}", index % 127)
    };
    BatchOperation {
        id: format!("op_{index:05}"),
        tool: "fcp.host.synthetic_batch".to_string(),
        input: json!({"shape": "redacted-fixture"}),
        depends_on: root_dependency.into_iter().map(str::to_string).collect(),
        zone: None,
        scheduler: BatchScheduleHint {
            priority: if index % 257 == 0 {
                BatchOperationPriority::Critical
            } else {
                BatchOperationPriority::Normal
            },
            estimated_duration_ms: Some(if is_long {
                20_000
            } else {
                2 + u64::try_from(index % 13).unwrap_or(u64::MAX)
            }),
            fairness_key: Some(fairness_key),
        },
    }
}

fn batch_morselization_request(operation_count: usize) -> BatchInvokeRequest {
    let mut operations = Vec::with_capacity(operation_count);
    for index in 0..operation_count {
        let root_dependency = (index >= operation_count / 2).then_some("op_00000");
        operations.push(batch_operation(index, root_dependency));
    }
    BatchInvokeRequest {
        operations,
        options: BatchOptions {
            max_parallelism: 256,
            timeout_ms: 30_000,
            scheduler: BatchSchedulerOptions {
                mode: BatchSchedulerMode::Adaptive,
                max_consecutive_per_fairness_key: 2,
            },
            ..Default::default()
        },
    }
}

fn batch_failure_request(timeout_ms: u64) -> BatchInvokeRequest {
    BatchInvokeRequest {
        operations: vec![
            batch_operation(0, None),
            batch_operation(1, Some("op_00000")),
        ],
        options: BatchOptions {
            max_parallelism: 2,
            timeout_ms,
            scheduler: BatchSchedulerOptions {
                mode: BatchSchedulerMode::Adaptive,
                max_consecutive_per_fairness_key: 2,
            },
            ..Default::default()
        },
    }
}

fn injected_batch_error() -> BatchOperationError {
    BatchOperationError {
        code: "INJECTED_FAILURE".to_string(),
        message: "redacted downstream failure".to_string(),
        retry_after_ms: Some(250),
    }
}

fn batch_failure_modes(
    executor: &BatchExecutor,
) -> Result<(String, String, String), Box<dyn Error>> {
    let failure = executor.execute_sync(&batch_failure_request(30_000), |operation| {
        if operation.id == "op_00000" {
            Err(injected_batch_error())
        } else {
            Ok(json!({"ok": true}))
        }
    })?;
    let error_kind = failure
        .results
        .iter()
        .find(|result| result.status == OperationResultStatus::Error)
        .and_then(|result| result.error.as_ref())
        .map(|error| format!("downstream_error:{}", error.code))
        .ok_or("failure scenario should include an error result")?;
    let skip_reason = failure
        .results
        .iter()
        .find(|result| result.status == OperationResultStatus::Skipped)
        .and_then(|result| result.error.as_ref())
        .map(|error| format!("dependency_failed:{}", error.code))
        .ok_or("failure scenario should include dependency skip")?;

    let timeout = executor.execute_sync(&batch_failure_request(0), |_| Ok(json!({"ok": true})))?;
    let cancellation_reason = timeout
        .results
        .iter()
        .find(|result| result.status == OperationResultStatus::Skipped)
        .and_then(|result| result.error.as_ref())
        .map(|error| format!("timeout:{}", error.code))
        .ok_or("timeout scenario should include a skipped operation")?;

    Ok((error_kind, cancellation_reason, skip_reason))
}

fn batch_wait_percentiles(wait: BatchScheduleWaitPercentiles) -> SwarmBatchWaitPercentiles {
    SwarmBatchWaitPercentiles {
        p50_ms: wait.p50_ms,
        p95_ms: wait.p95_ms,
        p99_ms: wait.p99_ms,
        p999_ms: wait.p999_ms,
        max_ms: wait.max_ms,
        mean_ms: wait.mean_ms,
    }
}

fn redacted_fairness_key(key: &str) -> String {
    format!("blake3:{}", blake3::hash(key.as_bytes()))
}

fn fairness_distribution(report: &BatchScheduleReport) -> Vec<SwarmBatchFairnessBucket> {
    let mut operation_counts = BTreeMap::<String, usize>::new();
    for decision in &report.decisions {
        let key = decision.fairness_key.as_deref().unwrap_or("unclassified");
        *operation_counts
            .entry(redacted_fairness_key(key))
            .or_default() += 1;
    }

    let mut morsel_counts = BTreeMap::<String, usize>::new();
    if let Some(morselization) = &report.morselization {
        for morsel in &morselization.morsels {
            for key in &morsel.fairness_keys {
                *morsel_counts.entry(redacted_fairness_key(key)).or_default() += 1;
            }
        }
    }

    operation_counts
        .into_iter()
        .map(
            |(fairness_key_hash, operation_count)| SwarmBatchFairnessBucket {
                morsel_count: morsel_counts.get(&fairness_key_hash).copied().unwrap_or(1),
                fairness_key_hash,
                operation_count,
            },
        )
        .collect()
}

fn batch_morselization_evidence(
    operation_count: usize,
    dependency_depth: usize,
    report: &BatchScheduleReport,
    error_kind: String,
    cancellation_reason: String,
    skip_reason: String,
) -> Result<SwarmBatchMorselizationEvidence, Box<dyn Error>> {
    let queueing = report
        .queueing_summary
        .as_ref()
        .ok_or("batch report should include queueing summary")?;
    let fifo_wait = queueing.fifo_wait;
    let scheduled_wait = queueing.scheduled_wait;
    let morselization = report
        .morselization
        .as_ref()
        .ok_or("batch report should include morselization")?;
    let operation_count_u64 = u64::try_from(operation_count).unwrap_or(u64::MAX);

    Ok(SwarmBatchMorselizationEvidence {
        schema_version: SWARM_BATCH_MORSELIZATION_SCHEMA_VERSION.to_string(),
        scenario_id: format!("host_batch_morselization_{operation_count}"),
        batch_id: format!("batch:offline:{operation_count}"),
        command_line: batch_morselization_command_line(),
        git_revision: "e2e-smoke-revision".to_string(),
        worker_id: "offline-e2e-runner".to_string(),
        scheduler_mode: format!("{:?}", report.mode).to_ascii_lowercase(),
        operation_count,
        dependency_depth,
        morsel_size: morselization.max_operations_per_morsel,
        total_morsels: morselization.total_morsels,
        split_tiers: morselization.split_tiers,
        largest_morsel_operations: morselization.largest_morsel_operations,
        fairness_distribution: fairness_distribution(report),
        fifo_wait: batch_wait_percentiles(fifo_wait),
        scheduled_wait: batch_wait_percentiles(scheduled_wait),
        resources: SwarmBatchResourceSample {
            rss_bytes: 128 * 1024 * 1024 + operation_count_u64.saturating_mul(512),
            cpu_microunits: 64_000_000,
            max_queue_depth: u64::try_from(morselization.max_operations_per_morsel)
                .unwrap_or(u64::MAX),
            retry_amplification_microunits: 0,
        },
        fallback_reason: morselization.fallback_reason.clone(),
        error_kind: Some(error_kind),
        cancellation_reason: Some(cancellation_reason),
        skip_reason: Some(skip_reason),
    })
}

fn maybe_write_batch_morselization_jsonl_artifact(jsonl: &str) -> std::io::Result<()> {
    let Some(path) = std::env::var_os("FCP_BATCH_MORSELIZATION_JSONL_OUT") else {
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

fn prewarm_cargo_target_dir() -> String {
    std::env::var("PREWARM_EVIDENCE_CARGO_TARGET_DIR")
        .or_else(|_| std::env::var("PREWARM_CARGO_TARGET_DIR"))
        .or_else(|_| std::env::var("CARGO_TARGET_DIR"))
        .unwrap_or_else(|_| "/tmp/fcp-prewarm-e2e".to_string())
}

fn prewarm_cargo_target_dir_class(cargo_target_dir: &str) -> &'static str {
    if cargo_target_dir == "/tmp"
        || cargo_target_dir.starts_with("/tmp/")
        || cargo_target_dir == "/private/tmp"
        || cargo_target_dir.starts_with("/private/tmp/")
    {
        "tmp"
    } else if cargo_target_dir.starts_with("/Users/")
        || cargo_target_dir.starts_with("/private/var/")
    {
        "private_absolute"
    } else if Path::new(cargo_target_dir).is_absolute() {
        "absolute"
    } else {
        "relative"
    }
}

fn prewarm_cargo_target_dir_hash(cargo_target_dir: &str) -> String {
    format!(
        "blake3:{}",
        blake3::hash(cargo_target_dir.as_bytes()).to_hex()
    )
}

fn prewarm_manifest_hash() -> String {
    format!(
        "blake3:{}",
        blake3::hash(b"fcp-test-connector:request-response:strict-prewarm").to_hex()
    )
}

fn prewarm_zone_hash() -> String {
    format!(
        "blake3:{}",
        blake3::hash(b"z:project:swarm-prewarm").to_hex()
    )
}

fn prewarm_command_line(cargo_target_dir: &str) -> Vec<String> {
    vec![
        "rch".to_string(),
        "exec".to_string(),
        "--".to_string(),
        "env".to_string(),
        format!("CARGO_TARGET_DIR={cargo_target_dir}"),
        "cargo".to_string(),
        "test".to_string(),
        "-p".to_string(),
        "fcp-e2e".to_string(),
        "--no-default-features".to_string(),
        "--test".to_string(),
        "swarm_gauntlet_e2e".to_string(),
        "prewarm_cold_start".to_string(),
        "--".to_string(),
        "--nocapture".to_string(),
    ]
}

fn serde_label<T: serde::Serialize>(value: &T) -> Result<String, Box<dyn Error>> {
    let value = serde_json::to_value(value)?;
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "serialized enum label should be a string".into())
}

fn prewarm_observation(
    pool_state: PrewarmPoolState,
    manifest: PrewarmManifestState,
    health: PrewarmHealthState,
    previous_exit: Option<ProcessExit>,
) -> PrewarmCheckoutObservation {
    PrewarmCheckoutObservation {
        pool_state,
        manifest,
        zone_binding: PrewarmZoneBinding::Bound,
        sandbox: PrewarmSandboxState::LimitsActive,
        credential: PrewarmCredentialState::Deferred,
        health,
        entry_age: Duration::from_millis(20),
        previous_exit,
    }
}

fn prewarm_sandbox_gap_observation() -> PrewarmCheckoutObservation {
    let mut observation = prewarm_observation(
        PrewarmPoolState::WarmHit,
        PrewarmManifestState::Current,
        PrewarmHealthState::Ready,
        None,
    );
    observation.sandbox = PrewarmSandboxState::LimitsUnavailable;
    observation
}

fn prewarm_latency(
    p50_ms: u64,
    p95_ms: u64,
    p99_ms: u64,
    p999_percentile_ms: u64,
    max_ms: u64,
    mean_ms: u64,
) -> SwarmPrewarmLatencyPercentiles {
    SwarmPrewarmLatencyPercentiles {
        p50_ms,
        p95_ms,
        p99_ms,
        p999_ms: p999_percentile_ms,
        max_ms,
        mean_ms,
    }
}

fn prewarm_decision_label(decision: &PrewarmCheckoutDecision) -> &'static str {
    match decision {
        PrewarmCheckoutDecision::AdmitWarm { .. } => "admit_warm",
        PrewarmCheckoutDecision::FallbackOnDemand { .. } => "fallback_on_demand",
        PrewarmCheckoutDecision::RejectUnsafe { .. } => "reject_unsafe",
    }
}

fn prewarm_decision_reasons(
    decision: &PrewarmCheckoutDecision,
) -> Result<(Option<String>, Option<String>), Box<dyn Error>> {
    match decision {
        PrewarmCheckoutDecision::AdmitWarm { .. } => Ok((None, None)),
        PrewarmCheckoutDecision::FallbackOnDemand { reason } => {
            Ok((Some(serde_label(reason)?), None))
        }
        PrewarmCheckoutDecision::RejectUnsafe { reason } => Ok((None, Some(serde_label(reason)?))),
    }
}

struct PrewarmEvidenceCase<'a> {
    scenario_id: &'a str,
    config: &'a ConnectorPrewarmConfig,
    observation: PrewarmCheckoutObservation,
    activation_latency_ms: u64,
    baseline_on_demand_latency_ms: u64,
    latency: SwarmPrewarmLatencyPercentiles,
    baseline_latency: SwarmPrewarmLatencyPercentiles,
    process_count: u32,
    concurrent_startups: u32,
    restart_reason: Option<&'a str>,
    skip_reason: Option<&'a str>,
    shutdown_cleanup_verified: bool,
}

fn prewarm_evidence(
    case: PrewarmEvidenceCase<'_>,
) -> Result<SwarmPrewarmColdStartEvidence, Box<dyn Error>> {
    let decision = case.config.decide_checkout(&case.observation);
    let (fallback_reason, unsafe_rejection_reason) = prewarm_decision_reasons(&decision)?;
    let cargo_target_dir = prewarm_cargo_target_dir();
    let cargo_target_dir_class = prewarm_cargo_target_dir_class(&cargo_target_dir).to_string();
    let cargo_target_dir_hash = prewarm_cargo_target_dir_hash(&cargo_target_dir);
    let error_mapping = match (&fallback_reason, &unsafe_rejection_reason) {
        (Some(reason), None) => format!("fallback_on_demand:{reason}"),
        (None, Some(reason)) => format!("reject_unsafe:{reason}"),
        (None, None) => "ok".to_string(),
        (Some(fallback), Some(rejection)) => format!("ambiguous:{fallback}:{rejection}"),
    };

    Ok(SwarmPrewarmColdStartEvidence {
        schema_version: SWARM_PREWARM_COLD_START_SCHEMA_VERSION.to_string(),
        execution_mode: SwarmEvidenceExecutionMode::Smoke,
        source_kind: SwarmEvidenceSourceKind::Offline,
        scenario_id: case.scenario_id.to_string(),
        connector_id: "fcp.github:utility:1.0.0".to_string(),
        command_line: prewarm_command_line(&cargo_target_dir),
        git_revision: "abc1234".to_string(),
        worker_id: "offline-e2e-runner".to_string(),
        cargo_target_dir,
        cargo_target_dir_class,
        cargo_target_dir_hash,
        connector_fixture_id: "fcp-test-connector:request-response".to_string(),
        host_boundary: "fcp-host::supervisor::ConnectorPrewarmConfig::decide_checkout".to_string(),
        manifest_hash: prewarm_manifest_hash(),
        zone: prewarm_zone_hash(),
        strategy: serde_label(&case.config.strategy)?,
        pool_state: serde_label(&case.observation.pool_state)?,
        pool_size: case.config.max_idle,
        admission_decision: prewarm_decision_label(&decision).to_string(),
        warm_checkout: decision.admits_warm_entry(),
        activation_latency_ms: case.activation_latency_ms,
        baseline_on_demand_latency_ms: case.baseline_on_demand_latency_ms,
        latency: case.latency,
        baseline_latency: case.baseline_latency,
        sandbox_layer: serde_label(&case.observation.sandbox)?,
        sandbox_profile: "strict".to_string(),
        sandbox_boundary: "fcp-sandbox::strict-profile-limits".to_string(),
        credential_mode: serde_label(&case.observation.credential)?,
        rss_bytes: 96 * 1024 * 1024 + u64::from(case.concurrent_startups).saturating_mul(4096),
        process_count: case.process_count,
        concurrent_startups: case.concurrent_startups,
        error_mapping,
        cleanup_result: if case.shutdown_cleanup_verified {
            "verified".to_string()
        } else {
            "not_verified".to_string()
        },
        restart_reason: case.restart_reason.map(str::to_string),
        fallback_reason,
        unsafe_rejection_reason,
        skip_reason: case.skip_reason.map(str::to_string),
        shutdown_cleanup_verified: case.shutdown_cleanup_verified,
    })
}

fn maybe_write_prewarm_jsonl_artifact(jsonl: &str) -> std::io::Result<()> {
    let Some(path) = std::env::var_os("FCP_PREWARM_COLD_START_JSONL_OUT") else {
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

fn emit_prewarm_jsonl_stdout(jsonl: &str) {
    for line in jsonl.lines() {
        println!("FCP_PREWARM_COLD_START_JSONL {line}");
    }
}

fn statistical_baseline_snapshot() -> SwarmRegressionMetricSnapshot {
    SwarmRegressionMetricSnapshot {
        scenario_id: "host_batch_invoke_10000".to_string(),
        sample_count: 120,
        p99_ns: 100_000,
        p999_ns: 125_000,
        throughput_ops_per_second: 1_000_000,
        cpu_microunits: 64_000_000,
        rss_bytes: 8 * 1024 * 1024 * 1024,
        max_queue_depth: 1_000,
        retry_amplification_microunits: 100_000,
    }
}

fn statistical_baseline_manifest(
    scenario_id: &str,
    expires_at: chrono::DateTime<Utc>,
) -> SwarmBaselinePromotionManifest {
    SwarmBaselinePromotionManifest {
        schema_version: SWARM_BASELINE_PROMOTION_SCHEMA_VERSION.to_string(),
        baseline_id: format!("baseline:{scenario_id}:e2e"),
        scenario_id: scenario_id.to_string(),
        execution_mode: SwarmEvidenceExecutionMode::Smoke,
        source_revision: "e2e-baseline-revision".to_string(),
        rch_worker_id: "offline-e2e-runner".to_string(),
        required_paths: SwarmBaselinePathKind::REQUIRED.to_vec(),
        artifact_digests: SwarmBaselineArtifactDigests::new(
            "blake3:e2e-raw-samples",
            "blake3:e2e-summary",
            "blake3:e2e-gate-report",
            "blake3:e2e-proof-notes",
            "blake3:e2e-manifest",
        ),
        redaction_policy: SwarmEvidenceRedactionPolicy::conservative(),
        operator_notes: "offline e2e baseline promoted from controlled traces".to_string(),
        promoted_at: Utc::now(),
        expires_at,
    }
}

fn statistical_report(
    candidate: SwarmRegressionMetricSnapshot,
    candidate_quality: SwarmStatisticalTraceQuality,
    audit_event_count: u64,
    decision_card_replay_matches: bool,
    expires_at: chrono::DateTime<Utc>,
) -> SwarmStatisticalGateReport {
    let baseline = statistical_baseline_snapshot();
    SwarmStatisticalGateReport::evaluate(SwarmStatisticalGateInput {
        baseline_manifest: statistical_baseline_manifest(&baseline.scenario_id, expires_at),
        baseline: baseline.clone(),
        candidate,
        thresholds: SwarmRegressionGateThresholds::smoke(),
        execution_mode: SwarmEvidenceExecutionMode::Smoke,
        tuning: SwarmStatisticalGateTuning::smoke(),
        baseline_quality: SwarmStatisticalTraceQuality::controlled(baseline.sample_count),
        candidate_quality,
        audit_event_count,
        decision_card_replay_matches,
        operator_notes: "offline e2e statistical gate proof".to_string(),
        generated_at: Utc::now(),
    })
}

fn record_types(records: &[Value]) -> BTreeSet<&str> {
    records
        .iter()
        .filter_map(|record| record["record_type"].as_str())
        .collect()
}

#[test]
fn integrated_swarm_gauntlet_smoke_emits_replayable_jsonl() -> Result<(), Box<dyn Error>> {
    let manifest = SwarmGauntletManifest::smoke(vec![
        "cargo".to_string(),
        "test".to_string(),
        "-p".to_string(),
        "fcp-e2e".to_string(),
        "--test".to_string(),
        "swarm_gauntlet_e2e".to_string(),
    ]);
    let latency_bundle = latency_bundle()?;
    let resources = resource_snapshots(&latency_bundle);
    let first_scenario = latency_bundle.summaries[0].scenario_id.clone();
    let resource_ledger_records = resource_ledger_records(
        &latency_bundle.environment.command_line,
        latency_bundle
            .environment
            .source_revision
            .as_deref()
            .unwrap_or("unknown"),
        &latency_bundle.environment.worker_id,
    )?;
    let gauntlet = SwarmGauntletEvidenceBundle::new(
        manifest,
        latency_bundle,
        resources,
        decision_cards(&first_scenario),
        phase_evidence(),
        SwarmGauntletCounters {
            audit_event_count: 4,
            same_zone_audit_appends: 512,
            sparse_high_k_metadata_events: 3,
        },
        None,
    )?
    .with_resource_ledger_records(resource_ledger_records)?;

    let records = gauntlet.to_jsonl_values()?;
    let types = record_types(&records);
    let log_record = records
        .iter()
        .find(|record| record["record_type"] == "swarm_gauntlet_log")
        .ok_or("gauntlet log record should be present")?;
    let jsonl = records
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");

    assert!(types.contains("swarm_gauntlet_manifest"));
    assert!(types.contains("swarm_latency_bundle"));
    assert!(types.contains("swarm_latency_sample"));
    assert!(types.contains("swarm_decision_card"));
    assert!(types.contains("resource_ledger"));
    assert!(types.contains("swarm_gauntlet_phase_evidence"));
    assert!(types.contains("swarm_gauntlet_summary"));
    assert!(types.contains("swarm_gauntlet_log"));
    assert_eq!(log_record["git_revision"], "e2e-smoke-revision");
    assert_eq!(log_record["worker_id"], "offline-e2e-runner");
    assert_eq!(log_record["evidence_bundle_id"], "gauntlet-e2e-smoke");
    assert!(log_record["decision_card_ids"].is_array());
    assert_eq!(log_record["resource_ledger_record_count"], 6);
    assert_eq!(log_record["resource_ledger_record_type"], "resource_ledger");
    assert!(log_record["resource_ledger_operation_ids"].is_array());
    assert!(log_record["p99_ns"].is_u64());
    assert!(log_record["throughput_ops_per_second"].is_u64());
    let ledger_record = records
        .iter()
        .find(|record| record["record_type"] == "resource_ledger")
        .ok_or("resource ledger record should be present")?;
    assert_eq!(ledger_record["schema_version"], "resource-ledger/v1");
    assert!(
        ledger_record["ledger"]["worker_ref"]
            .as_str()
            .is_some_and(|worker| worker.starts_with("worker:blake3:"))
    );
    assert!(
        ledger_record["ledger"]["principal_ref"]
            .as_str()
            .is_some_and(|principal| principal.starts_with("principal:blake3:"))
    );
    for line in jsonl.lines() {
        serde_json::from_str::<Value>(line)?;
    }
    assert!(!jsonl.contains("sk-live-"));
    assert!(!jsonl.contains("Bearer test-token"));
    assert!(!jsonl.contains("super-secret-value"));
    assert!(!jsonl.contains("principal:resource-ledger-e2e"));
    Ok(())
}

#[test]
fn batch_morselization_e2e_emits_replayable_jsonl() -> Result<(), Box<dyn Error>> {
    let executor = BatchExecutor::new();
    let (error_kind, cancellation_reason, skip_reason) = batch_failure_modes(&executor)?;
    let mut records = Vec::new();

    for operation_count in [1_000_usize, 10_000] {
        let request = batch_morselization_request(operation_count);
        let (plan, report) = executor.plan_with_schedule_report(&request)?;
        let evidence = batch_morselization_evidence(
            operation_count,
            plan.tiers.len(),
            &report,
            error_kind.clone(),
            cancellation_reason.clone(),
            skip_reason.clone(),
        )?;

        evidence.validate()?;
        records.push(evidence.to_jsonl_value()?);
    }

    let jsonl = records
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    maybe_write_batch_morselization_jsonl_artifact(&jsonl)?;
    let types = record_types(&records);
    let tenk_record = records
        .iter()
        .find(|record| record["scenario_id"] == "host_batch_morselization_10000")
        .ok_or("10k batch morselization record should be present")?;

    assert!(types.contains("swarm_batch_morselization_evidence"));
    assert_eq!(
        tenk_record["schema_version"],
        SWARM_BATCH_MORSELIZATION_SCHEMA_VERSION
    );
    assert_eq!(tenk_record["operation_count"], 10_000);
    assert_eq!(tenk_record["dependency_depth"], 2);
    assert_eq!(tenk_record["morsel_size"], 256);
    assert!(
        tenk_record["evidence"]["total_morsels"]
            .as_u64()
            .is_some_and(|total| total > 1)
    );
    assert!(
        tenk_record["evidence"]["split_tiers"]
            .as_u64()
            .is_some_and(|tiers| tiers > 0)
    );
    assert_eq!(
        tenk_record["evidence"]["largest_morsel_operations"],
        tenk_record["morsel_size"]
    );
    assert!(
        tenk_record["evidence"]["fairness_distribution"]
            .as_array()
            .is_some_and(|distribution| distribution.len() > 8)
    );
    assert!(tenk_record["p50_wait_ms"].is_u64());
    assert!(tenk_record["p95_wait_ms"].is_u64());
    assert!(tenk_record["p99_wait_ms"].is_u64());
    assert!(tenk_record["p999_wait_ms"].is_u64());
    assert!(tenk_record["rss_bytes"].is_u64());
    assert!(tenk_record["max_queue_depth"].is_u64());
    assert_eq!(
        tenk_record["error_kind"],
        "downstream_error:INJECTED_FAILURE"
    );
    assert_eq!(tenk_record["cancellation_reason"], "timeout:BATCH_TIMEOUT");
    assert_eq!(tenk_record["skip_reason"], "dependency_failed:DEP_FAILED");
    for line in jsonl.lines() {
        serde_json::from_str::<Value>(line)?;
    }
    assert!(!jsonl.contains("sk-live-"));
    assert!(!jsonl.contains("Bearer test-token"));
    assert!(!jsonl.contains("super-secret-value"));
    Ok(())
}

#[allow(clippy::too_many_lines)] // end-to-end scenario script; steps are sequential evidence emissions, not reusable logic
#[test]
fn prewarm_cold_start_e2e_emits_replayable_jsonl() -> Result<(), Box<dyn Error>> {
    let config = ConnectorPrewarmConfig::warm_pool(
        1,
        256,
        Duration::from_secs(30),
        Duration::from_millis(25),
    );
    let zygote_config = ConnectorPrewarmConfig {
        strategy: PrewarmStrategy::Zygote,
        min_idle: 1,
        max_idle: 1,
        max_age: Duration::from_secs(30),
        checkout_timeout: Duration::from_millis(25),
    };
    let evidence = vec![
        prewarm_evidence(PrewarmEvidenceCase {
            scenario_id: "prewarm_empty_pool",
            config: &config,
            observation: prewarm_observation(
                PrewarmPoolState::Empty,
                PrewarmManifestState::Current,
                PrewarmHealthState::Ready,
                None,
            ),
            activation_latency_ms: 96,
            baseline_on_demand_latency_ms: 96,
            latency: prewarm_latency(96, 96, 96, 96, 96, 96),
            baseline_latency: prewarm_latency(96, 96, 96, 96, 96, 96),
            process_count: 1,
            concurrent_startups: 1,
            restart_reason: None,
            skip_reason: None,
            shutdown_cleanup_verified: true,
        })?,
        prewarm_evidence(PrewarmEvidenceCase {
            scenario_id: "prewarm_warm_hit",
            config: &config,
            observation: prewarm_observation(
                PrewarmPoolState::WarmHit,
                PrewarmManifestState::Current,
                PrewarmHealthState::Ready,
                None,
            ),
            activation_latency_ms: 18,
            baseline_on_demand_latency_ms: 96,
            latency: prewarm_latency(18, 22, 26, 29, 30, 20),
            baseline_latency: prewarm_latency(90, 96, 112, 125, 130, 95),
            process_count: 1,
            concurrent_startups: 1,
            restart_reason: None,
            skip_reason: None,
            shutdown_cleanup_verified: true,
        })?,
        prewarm_evidence(PrewarmEvidenceCase {
            scenario_id: "prewarm_stale_entry",
            config: &config,
            observation: prewarm_observation(
                PrewarmPoolState::Stale,
                PrewarmManifestState::Current,
                PrewarmHealthState::Ready,
                None,
            ),
            activation_latency_ms: 96,
            baseline_on_demand_latency_ms: 96,
            latency: prewarm_latency(96, 96, 96, 96, 96, 96),
            baseline_latency: prewarm_latency(96, 96, 96, 96, 96, 96),
            process_count: 1,
            concurrent_startups: 1,
            restart_reason: None,
            skip_reason: None,
            shutdown_cleanup_verified: true,
        })?,
        prewarm_evidence(PrewarmEvidenceCase {
            scenario_id: "prewarm_crash_before_checkout",
            config: &config,
            observation: prewarm_observation(
                PrewarmPoolState::CrashBeforeCheckout,
                PrewarmManifestState::Current,
                PrewarmHealthState::Ready,
                Some(ProcessExit::with_code(1)),
            ),
            activation_latency_ms: 96,
            baseline_on_demand_latency_ms: 96,
            latency: prewarm_latency(96, 96, 96, 96, 96, 96),
            baseline_latency: prewarm_latency(96, 96, 96, 96, 96, 96),
            process_count: 1,
            concurrent_startups: 1,
            restart_reason: Some("exit_code_1"),
            skip_reason: None,
            shutdown_cleanup_verified: true,
        })?,
        prewarm_evidence(PrewarmEvidenceCase {
            scenario_id: "prewarm_shutdown_cleanup",
            config: &config,
            observation: prewarm_observation(
                PrewarmPoolState::WarmHit,
                PrewarmManifestState::Current,
                PrewarmHealthState::Ready,
                None,
            ),
            activation_latency_ms: 21,
            baseline_on_demand_latency_ms: 96,
            latency: prewarm_latency(21, 24, 28, 31, 32, 23),
            baseline_latency: prewarm_latency(90, 96, 112, 125, 130, 95),
            process_count: 1,
            concurrent_startups: 1,
            restart_reason: None,
            skip_reason: None,
            shutdown_cleanup_verified: true,
        })?,
        prewarm_evidence(PrewarmEvidenceCase {
            scenario_id: "prewarm_concurrent_swarm_startup",
            config: &config,
            observation: prewarm_observation(
                PrewarmPoolState::WarmHit,
                PrewarmManifestState::Current,
                PrewarmHealthState::Ready,
                None,
            ),
            activation_latency_ms: 24,
            baseline_on_demand_latency_ms: 112,
            latency: prewarm_latency(24, 31, 42, 50, 55, 28),
            baseline_latency: prewarm_latency(96, 112, 148, 180, 200, 118),
            process_count: 256,
            concurrent_startups: 10_000,
            restart_reason: None,
            skip_reason: None,
            shutdown_cleanup_verified: true,
        })?,
        prewarm_evidence(PrewarmEvidenceCase {
            scenario_id: "prewarm_exhausted_under_burst",
            config: &config,
            observation: prewarm_observation(
                PrewarmPoolState::Empty,
                PrewarmManifestState::Current,
                PrewarmHealthState::Ready,
                None,
            ),
            activation_latency_ms: 128,
            baseline_on_demand_latency_ms: 128,
            latency: prewarm_latency(128, 128, 128, 128, 128, 128),
            baseline_latency: prewarm_latency(128, 128, 128, 128, 128, 128),
            process_count: 256,
            concurrent_startups: 4_096,
            restart_reason: None,
            skip_reason: Some("pool_exhausted_by_burst"),
            shutdown_cleanup_verified: true,
        })?,
        prewarm_evidence(PrewarmEvidenceCase {
            scenario_id: "prewarm_sandbox_limits_unavailable",
            config: &config,
            observation: prewarm_sandbox_gap_observation(),
            activation_latency_ms: 96,
            baseline_on_demand_latency_ms: 96,
            latency: prewarm_latency(96, 96, 96, 96, 96, 96),
            baseline_latency: prewarm_latency(96, 96, 96, 96, 96, 96),
            process_count: 1,
            concurrent_startups: 1,
            restart_reason: None,
            skip_reason: Some("sandbox_limits_unverified"),
            shutdown_cleanup_verified: true,
        })?,
        prewarm_evidence(PrewarmEvidenceCase {
            scenario_id: "prewarm_checkout_cancelled_before_admit",
            config: &config,
            observation: prewarm_observation(
                PrewarmPoolState::WarmHit,
                PrewarmManifestState::Current,
                PrewarmHealthState::Starting,
                None,
            ),
            activation_latency_ms: 96,
            baseline_on_demand_latency_ms: 96,
            latency: prewarm_latency(96, 96, 96, 96, 96, 96),
            baseline_latency: prewarm_latency(96, 96, 96, 96, 96, 96),
            process_count: 1,
            concurrent_startups: 1,
            restart_reason: None,
            skip_reason: Some("checkout_cancelled_before_admit"),
            shutdown_cleanup_verified: true,
        })?,
        prewarm_evidence(PrewarmEvidenceCase {
            scenario_id: "prewarm_zygote_rejected_without_security_proof",
            config: &zygote_config,
            observation: prewarm_observation(
                PrewarmPoolState::WarmHit,
                PrewarmManifestState::Current,
                PrewarmHealthState::Ready,
                None,
            ),
            activation_latency_ms: 96,
            baseline_on_demand_latency_ms: 96,
            latency: prewarm_latency(96, 96, 96, 96, 96, 96),
            baseline_latency: prewarm_latency(96, 96, 96, 96, 96, 96),
            process_count: 1,
            concurrent_startups: 1,
            restart_reason: None,
            skip_reason: None,
            shutdown_cleanup_verified: true,
        })?,
    ];

    validate_swarm_prewarm_cold_start_evidence_bundle(&evidence, false)?;
    let records = evidence
        .into_iter()
        .map(|record| -> Result<Value, Box<dyn Error>> {
            record.validate()?;
            Ok(record.to_jsonl_value()?)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let jsonl = records
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    maybe_write_prewarm_jsonl_artifact(&jsonl)?;
    emit_prewarm_jsonl_stdout(&jsonl);
    let types = record_types(&records);
    let warm_hit = records
        .iter()
        .find(|record| record["scenario_id"] == "prewarm_warm_hit")
        .ok_or("warm-hit prewarm record should be present")?;
    let empty_pool = records
        .iter()
        .find(|record| record["scenario_id"] == "prewarm_empty_pool")
        .ok_or("empty-pool prewarm record should be present")?;
    let stale_entry = records
        .iter()
        .find(|record| record["scenario_id"] == "prewarm_stale_entry")
        .ok_or("stale-entry prewarm record should be present")?;
    let crash = records
        .iter()
        .find(|record| record["scenario_id"] == "prewarm_crash_before_checkout")
        .ok_or("crash-before-checkout prewarm record should be present")?;
    let cleanup = records
        .iter()
        .find(|record| record["scenario_id"] == "prewarm_shutdown_cleanup")
        .ok_or("shutdown-cleanup prewarm record should be present")?;
    let concurrent = records
        .iter()
        .find(|record| record["scenario_id"] == "prewarm_concurrent_swarm_startup")
        .ok_or("concurrent-swarm prewarm record should be present")?;
    let exhausted = records
        .iter()
        .find(|record| record["scenario_id"] == "prewarm_exhausted_under_burst")
        .ok_or("burst-exhaustion prewarm record should be present")?;
    let sandbox_gap = records
        .iter()
        .find(|record| record["scenario_id"] == "prewarm_sandbox_limits_unavailable")
        .ok_or("sandbox-gap prewarm record should be present")?;
    let cancelled = records
        .iter()
        .find(|record| record["scenario_id"] == "prewarm_checkout_cancelled_before_admit")
        .ok_or("cancelled-checkout prewarm record should be present")?;
    let zygote = records
        .iter()
        .find(|record| record["scenario_id"] == "prewarm_zygote_rejected_without_security_proof")
        .ok_or("zygote-rejection prewarm record should be present")?;

    assert!(types.contains("swarm_prewarm_cold_start_evidence"));
    assert_eq!(
        warm_hit["schema_version"],
        SWARM_PREWARM_COLD_START_SCHEMA_VERSION
    );
    assert_eq!(warm_hit["execution_mode"], "smoke");
    assert_eq!(warm_hit["source_kind"], "offline");
    assert_eq!(warm_hit["connector_id"], "fcp.github:utility:1.0.0");
    assert_eq!(warm_hit["git_revision"], "abc1234");
    assert_eq!(warm_hit["worker_id"], "offline-e2e-runner");
    let cargo_target_dir = warm_hit["cargo_target_dir"]
        .as_str()
        .ok_or("cargo target dir should be recorded")?;
    assert!(!cargo_target_dir.is_empty());
    assert_eq!(
        warm_hit["cargo_target_dir_class"],
        prewarm_cargo_target_dir_class(cargo_target_dir)
    );
    assert!(
        warm_hit["cargo_target_dir_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("blake3:"))
    );
    assert_eq!(
        warm_hit["connector_fixture_id"],
        "fcp-test-connector:request-response"
    );
    assert_eq!(
        warm_hit["host_boundary"],
        "fcp-host::supervisor::ConnectorPrewarmConfig::decide_checkout"
    );
    let warm_manifest_hash = warm_hit["manifest_hash"]
        .as_str()
        .ok_or("manifest hash should be recorded")?;
    let warm_manifest_hash_hex = warm_manifest_hash
        .strip_prefix("blake3:")
        .ok_or("manifest hash should use blake3 prefix")?;
    assert_eq!(warm_manifest_hash_hex.len(), 64);
    assert!(
        warm_manifest_hash_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    let warm_zone = warm_hit["zone"]
        .as_str()
        .ok_or("zone hash should be recorded")?;
    let warm_zone_hex = warm_zone
        .strip_prefix("blake3:")
        .ok_or("zone hash should use blake3 prefix")?;
    assert_eq!(warm_zone_hex.len(), 64);
    assert!(
        warm_zone_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_eq!(warm_hit["strategy"], "warm_pool");
    assert_eq!(warm_hit["pool_state"], "warm_hit");
    assert_eq!(warm_hit["pool_size"], 256);
    assert_eq!(warm_hit["admission_decision"], "admit_warm");
    assert_eq!(warm_hit["warm_checkout"], true);
    assert_eq!(warm_hit["sandbox_layer"], "limits_active");
    assert_eq!(warm_hit["sandbox_profile"], "strict");
    assert_eq!(
        warm_hit["sandbox_boundary"],
        "fcp-sandbox::strict-profile-limits"
    );
    assert_eq!(warm_hit["credential_mode"], "deferred");
    assert_eq!(warm_hit["error_mapping"], "ok");
    assert_eq!(warm_hit["cleanup_result"], "verified");
    let cargo_target_arg = format!("CARGO_TARGET_DIR={cargo_target_dir}");
    assert!(warm_hit["command_line"].as_array().is_some_and(|args| {
        args.iter()
            .any(|arg| arg.as_str() == Some(cargo_target_arg.as_str()))
    }));
    assert!(
        warm_hit["p99_activation_latency_ms"]
            .as_u64()
            .zip(warm_hit["baseline_on_demand_latency_ms"].as_u64())
            .is_some_and(|(p99, baseline)| p99 < baseline)
    );
    assert!(
        warm_hit["p50_activation_latency_ms"].is_u64()
            && warm_hit["p95_activation_latency_ms"].is_u64()
            && warm_hit["p99_activation_latency_ms"].is_u64()
    );
    let warm_p50 = warm_hit["p50_activation_latency_ms"]
        .as_u64()
        .ok_or("warm p50 should be recorded")?;
    let warm_p95 = warm_hit["p95_activation_latency_ms"]
        .as_u64()
        .ok_or("warm p95 should be recorded")?;
    let warm_p99 = warm_hit["p99_activation_latency_ms"]
        .as_u64()
        .ok_or("warm p99 should be recorded")?;
    let warm_baseline_p50 = warm_hit["baseline_p50_activation_latency_ms"]
        .as_u64()
        .ok_or("warm baseline p50 should be recorded")?;
    let warm_baseline_p95 = warm_hit["baseline_p95_activation_latency_ms"]
        .as_u64()
        .ok_or("warm baseline p95 should be recorded")?;
    let warm_baseline_p99 = warm_hit["baseline_p99_activation_latency_ms"]
        .as_u64()
        .ok_or("warm baseline p99 should be recorded")?;
    assert_eq!(warm_baseline_p50, 90);
    assert_eq!(warm_baseline_p95, 96);
    assert_eq!(warm_baseline_p99, 112);
    assert_eq!(
        warm_hit["p50_activation_latency_improvement_ms"].as_u64(),
        Some(warm_baseline_p50 - warm_p50)
    );
    assert_eq!(
        warm_hit["p95_activation_latency_improvement_ms"].as_u64(),
        Some(warm_baseline_p95 - warm_p95)
    );
    assert_eq!(
        warm_hit["p99_activation_latency_improvement_ms"].as_u64(),
        Some(warm_baseline_p99 - warm_p99)
    );
    assert!(
        warm_hit["p50_activation_latency_improvement_ms"]
            .as_u64()
            .is_some_and(|improvement| improvement > 0)
            && warm_hit["p95_activation_latency_improvement_ms"]
                .as_u64()
                .is_some_and(|improvement| improvement > 0)
            && warm_hit["p99_activation_latency_improvement_ms"]
                .as_u64()
                .is_some_and(|improvement| improvement > 0)
    );
    assert_eq!(empty_pool["fallback_reason"], "empty_pool");
    assert_eq!(empty_pool["admission_decision"], "fallback_on_demand");
    assert_eq!(empty_pool["warm_checkout"], false);
    assert_eq!(empty_pool["error_mapping"], "fallback_on_demand:empty_pool");
    assert_eq!(stale_entry["fallback_reason"], "warm_entry_stale");
    assert_eq!(crash["fallback_reason"], "crash_before_checkout");
    assert_eq!(crash["restart_reason"], "exit_code_1");
    assert_eq!(
        zygote["unsafe_rejection_reason"],
        "zygote_without_security_proof"
    );
    assert_eq!(zygote["admission_decision"], "reject_unsafe");
    assert_eq!(
        zygote["error_mapping"],
        "reject_unsafe:zygote_without_security_proof"
    );
    assert!(
        cleanup["shutdown_cleanup_verified"]
            .as_bool()
            .unwrap_or(false)
    );
    assert_eq!(concurrent["concurrent_startups"], 10_000);
    assert_eq!(concurrent["process_count"], 256);
    assert!(
        concurrent["p99_activation_latency_ms"]
            .as_u64()
            .zip(concurrent["baseline_on_demand_latency_ms"].as_u64())
            .is_some_and(|(p99, baseline)| p99 < baseline)
    );
    assert!(
        concurrent["p50_activation_latency_ms"].is_u64()
            && concurrent["p95_activation_latency_ms"].is_u64()
            && concurrent["p99_activation_latency_ms"].is_u64()
    );
    let concurrent_p99 = concurrent["p99_activation_latency_ms"]
        .as_u64()
        .ok_or("concurrent p99 should be recorded")?;
    let concurrent_baseline_p99 = concurrent["baseline_p99_activation_latency_ms"]
        .as_u64()
        .ok_or("concurrent baseline p99 should be recorded")?;
    assert_eq!(concurrent_baseline_p99, 148);
    assert_eq!(
        concurrent["p99_activation_latency_improvement_ms"].as_u64(),
        Some(concurrent_baseline_p99 - concurrent_p99)
    );
    assert!(
        concurrent["p99_activation_latency_improvement_ms"]
            .as_u64()
            .is_some_and(|improvement| improvement > 0)
    );
    assert_eq!(exhausted["fallback_reason"], "empty_pool");
    assert_eq!(exhausted["error_mapping"], "fallback_on_demand:empty_pool");
    assert_eq!(exhausted["skip_reason"], "pool_exhausted_by_burst");
    assert_eq!(exhausted["warm_checkout"], false);
    assert_eq!(exhausted["concurrent_startups"], 4_096);
    assert_eq!(sandbox_gap["fallback_reason"], "sandbox_limits_unavailable");
    assert_eq!(
        sandbox_gap["error_mapping"],
        "fallback_on_demand:sandbox_limits_unavailable"
    );
    assert_eq!(sandbox_gap["sandbox_layer"], "limits_unavailable");
    assert_eq!(sandbox_gap["skip_reason"], "sandbox_limits_unverified");
    assert_eq!(sandbox_gap["warm_checkout"], false);
    assert_eq!(cancelled["fallback_reason"], "warm_entry_still_starting");
    assert_eq!(
        cancelled["error_mapping"],
        "fallback_on_demand:warm_entry_still_starting"
    );
    assert_eq!(cancelled["skip_reason"], "checkout_cancelled_before_admit");
    assert_eq!(cancelled["warm_checkout"], false);
    for line in jsonl.lines() {
        serde_json::from_str::<Value>(line)?;
    }
    assert!(!jsonl.contains("sk-live-"));
    assert!(!jsonl.contains("Bearer test-token"));
    assert!(!jsonl.contains("super-secret-value"));
    Ok(())
}

#[allow(clippy::too_many_lines)] // end-to-end scenario script; steps are sequential evidence emissions, not reusable logic
#[test]
fn swarm_statistical_gate_e2e_emits_pass_fail_and_indeterminate_logs() -> Result<(), Box<dyn Error>>
{
    let baseline = statistical_baseline_snapshot();
    let future_expiry = Utc::now() + chrono::Duration::days(30);
    let pass_report = statistical_report(
        SwarmRegressionMetricSnapshot {
            p99_ns: 104_000,
            p999_ns: 131_000,
            throughput_ops_per_second: 970_000,
            cpu_microunits: 66_000_000,
            max_queue_depth: 1_050,
            retry_amplification_microunits: 105_000,
            ..baseline.clone()
        },
        SwarmStatisticalTraceQuality::controlled(120),
        4,
        true,
        future_expiry,
    );
    let fail_report = statistical_report(
        SwarmRegressionMetricSnapshot {
            p99_ns: 115_000,
            p999_ns: 145_000,
            throughput_ops_per_second: 900_000,
            cpu_microunits: 72_000_000,
            max_queue_depth: 1_250,
            retry_amplification_microunits: 125_000,
            ..baseline.clone()
        },
        SwarmStatisticalTraceQuality::controlled(120),
        0,
        false,
        future_expiry,
    );
    let mut noisy_quality = SwarmStatisticalTraceQuality::controlled(120);
    noisy_quality.worker_drift_percent = 25;
    let indeterminate_report = statistical_report(
        baseline,
        noisy_quality,
        4,
        true,
        Utc::now() + chrono::Duration::days(30),
    );
    let reports = [
        ("pass", pass_report),
        ("fail", fail_report),
        ("indeterminate", indeterminate_report),
    ];
    let outcomes: BTreeMap<_, _> = reports
        .iter()
        .map(|(name, report)| (*name, report.outcome))
        .collect();
    let mut records = Vec::new();
    for (_, report) in &reports {
        records.extend(report.to_jsonl_values()?);
    }
    let jsonl = records
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    let gate_records = records
        .iter()
        .filter(|record| record["record_type"] == "swarm_statistical_gate_report")
        .collect::<Vec<_>>();
    let fail_record = gate_records
        .iter()
        .find(|record| record["outcome"] == "fail")
        .ok_or("fail record should be present")?;
    let indeterminate_record = gate_records
        .iter()
        .find(|record| record["outcome"] == "indeterminate")
        .ok_or("indeterminate record should be present")?;

    assert_eq!(
        outcomes.get("pass"),
        Some(&SwarmStatisticalGateOutcome::Pass)
    );
    assert_eq!(
        outcomes.get("fail"),
        Some(&SwarmStatisticalGateOutcome::Fail)
    );
    assert_eq!(
        outcomes.get("indeterminate"),
        Some(&SwarmStatisticalGateOutcome::Indeterminate)
    );
    assert_eq!(gate_records.len(), 3);
    assert!(
        fail_record["reason_codes"]
            .as_array()
            .ok_or("fail reason codes should be an array")?
            .iter()
            .any(|code| code == SwarmStatisticalGateReasonKind::P99Regression.code())
    );
    assert!(
        fail_record["reason_codes"]
            .as_array()
            .ok_or("fail reason codes should be an array")?
            .iter()
            .any(|code| code == SwarmStatisticalGateReasonKind::AuditLoss.code())
    );
    assert!(
        indeterminate_record["reason_codes"]
            .as_array()
            .ok_or("indeterminate reason codes should be an array")?
            .iter()
            .any(|code| code == SwarmStatisticalGateReasonKind::NoisyWorker.code())
    );
    assert!(jsonl.contains("swarm_baseline_promotion_manifest"));
    assert!(jsonl.contains("blake3:e2e-raw-samples"));
    for line in jsonl.lines() {
        serde_json::from_str::<Value>(line)?;
    }
    assert!(!jsonl.contains("sk-live-"));
    assert!(!jsonl.contains("Bearer test-token"));
    assert!(!jsonl.contains("super-secret-value"));
    Ok(())
}

#[allow(clippy::too_many_lines)] // end-to-end scenario script; steps are sequential evidence emissions, not reusable logic
#[test]
fn swarm_controller_safety_e2e_emits_pass_fail_and_fallback_logs() -> Result<(), Box<dyn Error>> {
    let pass_scenario = SwarmControllerInteractionScenario::MixedPriority;
    let pass_report = SwarmControllerSafetyReport::evaluate(
        pass_scenario,
        SwarmControllerSafetyThresholds::smoke(),
        controller_safety_modes(pass_scenario),
        controller_safety_cards(pass_scenario),
    );

    let fail_scenario = SwarmControllerInteractionScenario::SameZoneAuditStorm;
    let mut fail_modes = controller_safety_modes(fail_scenario);
    let combined = fail_modes
        .iter_mut()
        .find(|mode| mode.mode == SwarmControllerMode::CombinedController)
        .ok_or("combined controller mode should be present")?;
    combined.metrics.accounted_ops = 252;
    combined.metrics.hidden_drop_count = 4;
    combined.metrics.audit_event_count = 240;
    combined.metrics.max_starvation_ms = 10_000;
    combined.metrics.zone_fairness_skew_microunits = 300_000;
    combined.metrics.replay_mismatch_count = 1;
    let fail_report = SwarmControllerSafetyReport::evaluate(
        fail_scenario,
        SwarmControllerSafetyThresholds::smoke(),
        fail_modes,
        controller_safety_cards(fail_scenario),
    );

    let fallback_scenario = SwarmControllerInteractionScenario::DownstreamThrottled;
    let mut fallback_cards = controller_safety_cards(fallback_scenario);
    fallback_cards[2] = fallback_cards[2]
        .clone()
        .with_calibration(SwarmCalibrationStatus::ReplayMismatch);
    let mut fallback_modes = controller_safety_modes(fallback_scenario);
    let backpressure = fallback_modes
        .iter_mut()
        .find(|mode| mode.mode == SwarmControllerMode::BackpressureOnly)
        .ok_or("backpressure mode should be present")?;
    backpressure.metrics.fallback_invocations = 1;
    backpressure.fallback_reason = Some("replay_mismatch".to_string());
    let fallback_report = SwarmControllerSafetyReport::evaluate(
        fallback_scenario,
        SwarmControllerSafetyThresholds::smoke(),
        fallback_modes,
        fallback_cards,
    );

    let reports = [
        ("pass", pass_report),
        ("fail", fail_report),
        ("fallback_required", fallback_report),
    ];
    let outcomes: BTreeMap<_, _> = reports
        .iter()
        .map(|(name, report)| (*name, report.outcome))
        .collect();
    let mut records = Vec::new();
    for (_, report) in &reports {
        records.extend(report.to_jsonl_values()?);
    }
    let jsonl = records
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    let report_records = records
        .iter()
        .filter(|record| record["record_type"] == "swarm_controller_safety_report")
        .collect::<Vec<_>>();
    let failure_records = records
        .iter()
        .filter(|record| record["record_type"] == "swarm_controller_safety_failure")
        .collect::<Vec<_>>();
    let fallback_record = report_records
        .iter()
        .find(|record| record["outcome"] == "fallback_required")
        .ok_or("fallback-required report should be present")?;
    let pass_record = report_records
        .iter()
        .find(|record| record["outcome"] == "pass")
        .ok_or("pass report should be present")?;

    assert_eq!(
        outcomes.get("pass"),
        Some(&SwarmControllerSafetyOutcome::Pass)
    );
    assert_eq!(
        outcomes.get("fail"),
        Some(&SwarmControllerSafetyOutcome::Fail)
    );
    assert_eq!(
        outcomes.get("fallback_required"),
        Some(&SwarmControllerSafetyOutcome::FallbackRequired)
    );
    assert_eq!(report_records.len(), 3);
    assert_eq!(
        pass_record["schema_version"],
        SWARM_CONTROLLER_SAFETY_SCHEMA_VERSION
    );
    assert!(
        pass_record["decision_card_ids"]
            .as_array()
            .ok_or("decision card ids should be an array")?
            .iter()
            .any(|id| id == "e2e-card:backpressure-safety")
    );
    assert!(failure_records.iter().any(|record| {
        record["invariant"] == "work_conservation" && record["reason"] == "hidden_drop"
    }));
    assert!(failure_records.iter().any(|record| {
        record["invariant"] == "no_audit_loss" && record["reason"] == "audit_event_shortfall"
    }));
    assert!(
        fallback_record["fallback_reasons"]
            .as_array()
            .ok_or("fallback reasons should be an array")?
            .iter()
            .any(|reason| reason
                .as_str()
                .is_some_and(|value| value.contains("replay_mismatch")))
    );
    assert!(jsonl.contains("swarm_controller_safety_mode_evidence"));
    assert!(jsonl.contains("swarm_decision_card"));
    for line in jsonl.lines() {
        serde_json::from_str::<Value>(line)?;
    }
    assert!(!jsonl.contains("sk-live-"));
    assert!(!jsonl.contains("Bearer test-token"));
    assert!(!jsonl.contains("super-secret-value"));
    Ok(())
}

#[test]
fn adversarial_revocation_swarm_e2e_emits_fail_closed_jsonl() -> Result<(), Box<dyn Error>> {
    let report = SwarmAdversarialRevocationReport::evaluate(
        "adversarial_revocation_overload_e2e_smoke",
        SwarmAdversarialRevocationThresholds::smoke(),
        adversarial_revocation_events(),
    );
    let records = report.to_jsonl_values()?;
    let jsonl = records
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    let report_record = records
        .iter()
        .find(|record| record["record_type"] == "swarm_adversarial_revocation_report")
        .ok_or("adversarial revocation report should be present")?;
    let revoked_record = records
        .iter()
        .find(|record| record["operation_id"] == "op-e2e-revoked-token")
        .ok_or("revoked token row should be present")?;
    let stale_record = records
        .iter()
        .find(|record| record["operation_id"] == "op-e2e-stale-revocation")
        .ok_or("stale revocation row should be present")?;

    assert_eq!(report.outcome, SwarmAdversarialRevocationOutcome::Pass);
    assert!(report.failures.is_empty());
    assert_eq!(
        report_record["schema_version"],
        SWARM_ADVERSARIAL_REVOCATION_SCHEMA_VERSION
    );
    assert_eq!(report_record["node_count"], 8);
    assert_eq!(report_record["request_count"], 2_048);
    assert_eq!(report_record["revoked_denial_count"], 1);
    assert_eq!(report_record["emergency_revocation_witness_count"], 2);
    assert_eq!(report_record["stale_rejection_count"], 1);
    assert_eq!(report_record["malformed_rejection_count"], 1);
    assert_eq!(report_record["retry_count"], 4);
    assert_eq!(report_record["fallback_count"], 1);
    assert_eq!(revoked_record["admission_outcome"], "denied");
    assert_eq!(revoked_record["denial_reason"], "revoked_token");
    assert_eq!(revoked_record["backpressure_state"], "overloaded_zone");
    assert_eq!(revoked_record["cleanup_outcome"], "completed");
    assert_eq!(revoked_record["latency_percentiles"]["p99_ms"], 144);
    assert_eq!(stale_record["denial_reason"], "stale_revocation");
    assert!(jsonl.contains("swarm_adversarial_revocation_event"));
    assert!(jsonl.contains("swarm_adversarial_revocation_report"));
    for line in jsonl.lines() {
        serde_json::from_str::<Value>(line)?;
    }
    assert!(!jsonl.contains("Bearer test-token"));
    assert!(!jsonl.contains("super-secret-value"));
    assert!(!jsonl.contains("principal:raw:"));
    assert!(!jsonl.contains("token:raw:"));
    Ok(())
}

#[test]
fn swarm_promotion_skip_emits_exact_rerun_artifact() -> Result<(), Box<dyn Error>> {
    let envelope = SwarmPromotionEnvelope::high_core_256gib(vec![
        "rch".to_string(),
        "exec".to_string(),
        "--".to_string(),
        "cargo".to_string(),
        "test".to_string(),
        "-p".to_string(),
        "fcp-e2e".to_string(),
        "--test".to_string(),
        "swarm_gauntlet_e2e".to_string(),
        "--".to_string(),
        "--nocapture".to_string(),
    ]);
    let topology = SwarmPromotionTopology::from_environment(
        &promotion_skip_environment(),
        "macos 15.4",
        "24.4.0",
        Some("automatic".to_string()),
        Some("local-ssd".to_string()),
    );
    let qualification = SwarmPromotionQualification::evaluate(envelope, topology)?;
    let skip_artifact = SwarmPromotionSkipArtifact::from_qualification(qualification)
        .ok_or("small offline worker should emit a hardware promotion skip")?;

    let records = skip_artifact.to_jsonl_values()?;
    let types = record_types(&records);
    let skip_record = records
        .iter()
        .find(|record| record["record_type"] == "swarm_promotion_skip")
        .ok_or("promotion skip record should be present")?;
    let jsonl = records
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");

    assert!(types.contains("swarm_promotion_envelope"));
    assert!(types.contains("swarm_promotion_topology"));
    assert!(types.contains("swarm_promotion_skip"));
    assert_eq!(
        skip_record["artifact"]["qualification"]["topology"]["worker_id"],
        "offline-e2e-small-worker"
    );
    assert!(
        skip_record["skip_reason_codes"]
            .as_array()
            .ok_or("skip reason codes should be an array")?
            .iter()
            .any(|code| code == "insufficient_logical_cpus")
    );
    assert!(
        skip_record["skip_reason_codes"]
            .as_array()
            .ok_or("skip reason codes should be an array")?
            .iter()
            .any(|code| code == "missing_memory_measurement")
    );
    assert!(jsonl.contains("\"rerun_command\""));
    assert!(jsonl.contains("swarm_gauntlet_e2e"));
    for line in jsonl.lines() {
        serde_json::from_str::<Value>(line)?;
    }
    assert!(!jsonl.contains("sk-live-"));
    assert!(!jsonl.contains("Bearer test-token"));
    assert!(!jsonl.contains("super-secret-value"));
    Ok(())
}
