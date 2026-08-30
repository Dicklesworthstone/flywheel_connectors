//! Emit a local resource-ledger JSONL smoke bundle.
//!
//! This runner intentionally emits deterministic, redaction-safe records for
//! the ledger contract. It does not claim a live high-scale host+mesh swarm run;
//! unavailable production prerequisites must be represented by structured skip
//! records rather than by silent success.

use std::env;
use std::process::{Command, ExitCode};
use std::time::Duration;

use fcp_host::{
    BackpressureCalibration, BackpressureController, BackpressureControllerInput,
    BackpressureFairnessContext, BackpressureFairnessContextInput, BackpressureTelemetry,
    ConnectorSnapshotResumeConfig, FairnessLoadSheddingEvidenceInput,
    FairnessLoadSheddingEvidenceRecord, PrewarmCredentialState, PrewarmManifestState,
    PrewarmSandboxState, PrewarmZoneBinding, RequestPriority, ResourceLedgerInput,
    ResourceLedgerOutcome, ResourceLedgerRecord, ResourceLedgerRecordKind, ResourceLedgerSamples,
    ResourceTelemetryState, SnapshotCapabilityState, SnapshotCredentialMode, SnapshotPlatformState,
    SnapshotResumeEvidence, SnapshotResumeEvidenceInput, SnapshotResumeObservation,
    SnapshotResumeState, SnapshotSecurityProofState,
};

const USAGE: &str = "\
Usage: fcp-resource-ledger-evidence [OPTIONS]

Options:
  --scenario-id <id>               Stable scenario id
  --operation-id <id>              Base operation id
  --worker <id>                    Worker/node identity to hash
  --git-revision <rev>             Git revision under test
  --skip-host-mesh <reason>        Emit only a structured skip record
  --fairness-load-shed             Emit k3zfl.13 fairness load-shedding proof records
  --snapshot-resume                Emit k3zfl.12 snapshot/resume spike proof records
  -h, --help                       Print this help

Environment:
  FCP_RESOURCE_LEDGER_GIT_REVISION Fallback for --git-revision
";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cli {
    scenario_id: String,
    operation_id: String,
    worker_identity: String,
    git_revision: Option<String>,
    skip_host_mesh_reason: Option<String>,
    fairness_load_shed: bool,
    snapshot_resume: bool,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            scenario_id: "swarm.resource-ledger.local-smoke".to_string(),
            operation_id: "resource-ledger-smoke".to_string(),
            worker_identity: "local-worker".to_string(),
            git_revision: None,
            skip_host_mesh_reason: None,
            fairness_load_shed: false,
            snapshot_resume: false,
        }
    }
}

fn main() -> ExitCode {
    let command_line = env::args().collect::<Vec<_>>();
    let cli = match parse_cli(&command_line) {
        Ok(Some(cli)) => cli,
        Ok(None) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("{error}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let git_revision = cli
        .git_revision
        .clone()
        .or_else(|| env::var("FCP_RESOURCE_LEDGER_GIT_REVISION").ok())
        .unwrap_or_else(detect_git_revision);

    if cli.fairness_load_shed {
        let records = if let Some(reason) = cli.skip_host_mesh_reason.as_deref() {
            vec![FairnessLoadSheddingEvidenceRecord::structured_skip(
                &cli.scenario_id,
                "request_response_saas",
                "z:work",
                "saas.write",
                reason,
            )]
        } else {
            fairness_load_shed_records(&cli)
        };
        for record in records {
            match record.to_jsonl_line() {
                Ok(line) => println!("{line}"),
                Err(error) => {
                    eprintln!("failed to serialize fairness load-shedding evidence: {error}");
                    return ExitCode::FAILURE;
                }
            }
        }
        return ExitCode::SUCCESS;
    }

    if cli.snapshot_resume {
        let records = snapshot_resume_records(&cli);
        for record in records {
            match record.to_jsonl_line() {
                Ok(line) => println!("{line}"),
                Err(error) => {
                    eprintln!("failed to serialize snapshot/resume evidence: {error}");
                    return ExitCode::FAILURE;
                }
            }
        }
        return ExitCode::SUCCESS;
    }

    let records = if let Some(reason) = cli.skip_host_mesh_reason {
        vec![ResourceLedgerRecord::structured_skip(
            cli.scenario_id,
            cli.operation_id,
            command_line,
            git_revision,
            cli.worker_identity,
            reason,
        )]
    } else {
        local_smoke_records(&cli, &command_line, &git_revision)
    };

    for record in records {
        match record.to_jsonl_line() {
            Ok(line) => println!("{line}"),
            Err(error) => {
                eprintln!("failed to serialize resource ledger evidence: {error}");
                return ExitCode::FAILURE;
            }
        }
    }

    ExitCode::SUCCESS
}

fn parse_cli(args: &[String]) -> Result<Option<Cli>, String> {
    let mut cli = Cli::default();
    let mut iter = args.iter().skip(1);

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--scenario-id" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--scenario-id requires a value".to_string())?;
                cli.scenario_id.clone_from(value);
            }
            "--operation-id" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--operation-id requires a value".to_string())?;
                cli.operation_id.clone_from(value);
            }
            "--worker" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--worker requires a value".to_string())?;
                cli.worker_identity.clone_from(value);
            }
            "--git-revision" => {
                cli.git_revision = Some(
                    iter.next()
                        .ok_or_else(|| "--git-revision requires a value".to_string())?
                        .clone(),
                );
            }
            "--fairness-load-shed" => {
                cli.fairness_load_shed = true;
            }
            "--snapshot-resume" => {
                cli.snapshot_resume = true;
            }
            "--skip-host-mesh" => {
                cli.skip_host_mesh_reason = Some(
                    iter.next()
                        .ok_or_else(|| "--skip-host-mesh requires a value".to_string())?
                        .clone(),
                );
            }
            value if value.starts_with("--scenario-id=") => {
                cli.scenario_id = split_value(value, "--scenario-id")?.to_string();
            }
            value if value.starts_with("--operation-id=") => {
                cli.operation_id = split_value(value, "--operation-id")?.to_string();
            }
            value if value.starts_with("--worker=") => {
                cli.worker_identity = split_value(value, "--worker")?.to_string();
            }
            value if value.starts_with("--git-revision=") => {
                cli.git_revision = Some(split_value(value, "--git-revision")?.to_string());
            }
            value if value.starts_with("--skip-host-mesh=") => {
                cli.skip_host_mesh_reason =
                    Some(split_value(value, "--skip-host-mesh")?.to_string());
            }
            other => return Err(format!("unknown option '{other}'")),
        }
    }

    if cli.fairness_load_shed && cli.snapshot_resume {
        return Err(
            "--fairness-load-shed and --snapshot-resume are mutually exclusive".to_string(),
        );
    }

    Ok(Some(cli))
}

fn split_value<'a>(value: &'a str, option: &str) -> Result<&'a str, String> {
    value
        .split_once('=')
        .map(|(_, raw)| raw)
        .filter(|raw| !raw.is_empty())
        .ok_or_else(|| format!("{option} requires a value"))
}

fn local_smoke_records(
    cli: &Cli,
    command_line: &[String],
    git_revision: &str,
) -> Vec<ResourceLedgerRecord> {
    let base = |suffix: &str, kind, outcome, samples, latency_samples_ns| ResourceLedgerInput {
        scenario_id: cli.scenario_id.clone(),
        operation_id: format!("{}-{suffix}", cli.operation_id),
        kind,
        outcome,
        command_line: command_line.to_vec(),
        git_revision: git_revision.to_string(),
        worker_identity: cli.worker_identity.clone(),
        zone_id: Some("z:work".to_string()),
        principal_id: Some("principal:resource-ledger-smoke".to_string()),
        connector_id: Some("fcp.synthetic-smoke".to_string()),
        controller_decision: Some(outcome_label(outcome).to_string()),
        samples,
        latency_samples_ns,
        audit_receipt_id: None,
        fallback_reason: None,
        skip_reason: None,
    };

    vec![
        ResourceLedgerRecord::new(base(
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
        )),
        ResourceLedgerRecord::new(base(
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
        )),
        ResourceLedgerRecord::new(base(
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
        )),
        ResourceLedgerRecord::new(ResourceLedgerInput {
            audit_receipt_id: Some("audit-receipt-resource-ledger-smoke".to_string()),
            ..base(
                "audit",
                ResourceLedgerRecordKind::Audit,
                ResourceLedgerOutcome::Admitted,
                ResourceLedgerSamples {
                    state: ResourceTelemetryState::NotApplicable,
                    ..ResourceLedgerSamples::default()
                },
                Vec::new(),
            )
        }),
    ]
}

fn fairness_load_shed_records(cli: &Cli) -> Vec<FairnessLoadSheddingEvidenceRecord> {
    let controller = BackpressureController::default();
    vec![
        fairness_record(
            "normal_traffic",
            &controller,
            RequestPriority::Normal,
            BackpressureTelemetry {
                queue_pressure_per_mille: Some(120),
                cpu_pressure_per_mille: Some(180),
                useful_work_per_mille: Some(800),
                ..BackpressureTelemetry::default()
            },
            fairness_context(
                "request_response_saas",
                "z:work",
                "saas.read",
                250,
                240,
                220,
                (120, 0),
            ),
            2,
            vec![4, 5, 7, 8, 9],
        ),
        fairness_record(
            "single_connector_saturation",
            &controller,
            RequestPriority::Low,
            BackpressureTelemetry {
                queue_pressure_per_mille: Some(920),
                cpu_pressure_per_mille: Some(800),
                useful_work_per_mille: Some(100),
                ..BackpressureTelemetry::default()
            },
            fairness_context(
                "request_response_saas",
                "z:work",
                "saas.write",
                980,
                860,
                840,
                (80, 20),
            ),
            31,
            vec![8, 13, 21, 34, 55],
        ),
        fairness_record(
            "multi_zone_contention",
            &controller,
            RequestPriority::Normal,
            BackpressureTelemetry {
                queue_pressure_per_mille: Some(910),
                cpu_pressure_per_mille: Some(610),
                useful_work_per_mille: Some(700),
                ..BackpressureTelemetry::default()
            },
            fairness_context(
                "request_response_saas",
                "z:project:alpha",
                "saas.write",
                930,
                780,
                760,
                (64, 16),
            ),
            24,
            vec![10, 16, 24, 39, 63],
        ),
        fairness_record(
            "high_priority_emergency_work",
            &controller,
            RequestPriority::Critical,
            BackpressureTelemetry {
                queue_pressure_per_mille: Some(980),
                cpu_pressure_per_mille: Some(980),
                useful_work_per_mille: Some(1_000),
                ..BackpressureTelemetry::default()
            },
            fairness_context(
                "request_response_saas",
                "z:work",
                "incident.respond",
                990,
                900,
                880,
                (20, 0),
            ),
            38,
            vec![12, 18, 26, 40, 65],
        ),
        FairnessLoadSheddingEvidenceRecord::structured_skip(
            "revoked_principal",
            "request_response_saas",
            "z:work",
            "saas.write",
            "revoked principals are denied by enforcement before resilience load shedding",
        ),
        fairness_record(
            "downstream_throttling",
            &controller,
            RequestPriority::Normal,
            BackpressureTelemetry {
                queue_pressure_per_mille: Some(400),
                cpu_pressure_per_mille: Some(300),
                downstream_retry_after_ms: Some(2_000),
                retry_amplification_per_mille: Some(900),
                useful_work_per_mille: Some(700),
                ..BackpressureTelemetry::default()
            },
            fairness_context(
                "request_response_saas",
                "z:community",
                "saas.read",
                700,
                520,
                510,
                (96, 4),
            ),
            7,
            vec![25, 40, 60, 90, 120],
        ),
        fairness_record(
            "shutdown_cancellation",
            &controller,
            RequestPriority::Low,
            BackpressureTelemetry {
                queue_pressure_per_mille: Some(300),
                cpu_pressure_per_mille: Some(350),
                memory_pressure_per_mille: Some(970),
                useful_work_per_mille: Some(250),
                ..BackpressureTelemetry::default()
            },
            fairness_context(
                "request_response_saas",
                "z:public",
                "saas.bulk_export",
                900,
                720,
                700,
                (40, 35),
            ),
            18,
            vec![30, 55, 89, 144, 233],
        ),
    ]
    .into_iter()
    .map(|mut record| {
        record.scenario_id = format!("{}.{}", cli.scenario_id, record.scenario_id);
        record
    })
    .collect()
}

fn fairness_context(
    connector_class: &str,
    zone_id: &str,
    capability: &str,
    connector_class_pressure_per_mille: u16,
    zone_share_per_mille: u16,
    capability_share_per_mille: u16,
    window_counts: (u64, u64),
) -> BackpressureFairnessContext {
    let (admitted_count, shed_count) = window_counts;
    BackpressureFairnessContext::new(BackpressureFairnessContextInput {
        connector_class: connector_class.to_string(),
        zone_id: zone_id.to_string(),
        capability: capability.to_string(),
        connector_class_pressure_per_mille,
        zone_share_per_mille,
        capability_share_per_mille,
        target_share_per_mille: 500,
        admitted_count,
        shed_count,
    })
}

fn fairness_record(
    scenario_suffix: &str,
    controller: &BackpressureController,
    priority: RequestPriority,
    telemetry: BackpressureTelemetry,
    fairness: BackpressureFairnessContext,
    queue_depth: u64,
    latency_samples_ms: Vec<u64>,
) -> FairnessLoadSheddingEvidenceRecord {
    let decision = controller.decide(
        BackpressureControllerInput::new(
            format!(
                "fcp.host:{}:{}/invoke",
                fairness.connector_class, fairness.capability
            ),
            priority,
            telemetry,
            BackpressureCalibration::valid(),
        )
        .with_fairness(fairness.clone()),
    );

    FairnessLoadSheddingEvidenceRecord::new(FairnessLoadSheddingEvidenceInput {
        scenario_id: scenario_suffix.to_string(),
        decision,
        fairness,
        queue_depth,
        latency_samples_ms,
        audit_receipt_id: Some(format!("audit-receipt-k3zfl-13-{scenario_suffix}")),
        cleanup_result: "no_remote_state_created".to_string(),
        skip_reason: None,
    })
}

#[allow(clippy::too_many_lines)]
fn snapshot_resume_records(cli: &Cli) -> Vec<SnapshotResumeEvidence> {
    let config = ConnectorSnapshotResumeConfig::wasmtime_snapshot(
        Duration::from_secs(30),
        Duration::from_millis(50),
    );
    let base = SnapshotResumeObservation {
        snapshot_state: SnapshotResumeState::WarmCandidate,
        manifest: PrewarmManifestState::Current,
        zone_binding: PrewarmZoneBinding::Bound,
        capability: SnapshotCapabilityState::Bound,
        sandbox: PrewarmSandboxState::LimitsActive,
        credential: PrewarmCredentialState::Deferred,
        platform: SnapshotPlatformState::Supported,
        proof: SnapshotSecurityProofState::Absent,
        snapshot_age: Duration::from_secs(5),
        cow_dirty_pages: None,
        previous_exit: None,
    };

    let mut empty_store = base.clone();
    empty_store.snapshot_state = SnapshotResumeState::EmptySnapshotStore;
    empty_store.manifest = PrewarmManifestState::Missing;

    let mut warm_resume = base.clone();
    warm_resume.cow_dirty_pages = Some(0);

    let mut stale_manifest = base.clone();
    stale_manifest.snapshot_state = SnapshotResumeState::StaleManifest;
    stale_manifest.manifest = PrewarmManifestState::Stale;

    let mut revoked_capability = base.clone();
    revoked_capability.snapshot_state = SnapshotResumeState::RevokedCapability;
    revoked_capability.capability = SnapshotCapabilityState::Revoked;

    let mut crash_before_checkout = base.clone();
    crash_before_checkout.snapshot_state = SnapshotResumeState::CrashBeforeCheckout;
    crash_before_checkout.previous_exit = Some(fcp_host::ProcessExit::with_code(1));

    let mut concurrent_swarm_startup = base.clone();
    concurrent_swarm_startup.snapshot_state = SnapshotResumeState::ConcurrentStartup;

    let mut unsupported_platform = base;
    unsupported_platform.snapshot_state = SnapshotResumeState::UnsupportedPlatform;
    unsupported_platform.platform = SnapshotPlatformState::Unsupported;

    vec![
        snapshot_record(
            cli,
            "empty_snapshot_store",
            &config,
            empty_store,
            None,
            Some(82),
            Some(59 * 1024 * 1024),
            "snapshot_store_empty_on_demand_activation_verified",
        ),
        snapshot_record(
            cli,
            "warm_resume",
            &config,
            warm_resume,
            Some("blake3:snapshot-current"),
            Some(41),
            Some(61 * 1024 * 1024),
            "snapshot_not_checked_out_missing_security_proof",
        ),
        snapshot_record(
            cli,
            "stale_manifest",
            &config,
            stale_manifest,
            Some("blake3:snapshot-stale"),
            Some(91),
            Some(62 * 1024 * 1024),
            "stale_snapshot_rejected_on_demand_activation_required",
        ),
        snapshot_record(
            cli,
            "revoked_capability",
            &config,
            revoked_capability,
            Some("blake3:snapshot-current"),
            Some(88),
            Some(62 * 1024 * 1024),
            "revoked_snapshot_not_checked_out",
        ),
        snapshot_record(
            cli,
            "crash_before_checkout",
            &config,
            crash_before_checkout,
            Some("blake3:snapshot-current"),
            Some(96),
            Some(63 * 1024 * 1024),
            "crash_marker_reaped_on_demand_activation_required",
        ),
        snapshot_record(
            cli,
            "concurrent_swarm_startup",
            &config,
            concurrent_swarm_startup,
            Some("blake3:snapshot-current"),
            Some(123),
            Some(68 * 1024 * 1024),
            "snapshot_lease_contention_fell_back_to_on_demand",
        ),
        snapshot_record(
            cli,
            "unsupported_platform",
            &config,
            unsupported_platform,
            Some("blake3:snapshot-current"),
            None,
            None,
            "not_applicable",
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn snapshot_record(
    cli: &Cli,
    scenario_suffix: &str,
    config: &ConnectorSnapshotResumeConfig,
    observation: SnapshotResumeObservation,
    manifest_hash: Option<&str>,
    activation_latency_ms: Option<u64>,
    memory_rss_bytes: Option<u64>,
    cleanup_result: &str,
) -> SnapshotResumeEvidence {
    let decision = config.decide_resume(&observation);
    SnapshotResumeEvidence::new(SnapshotResumeEvidenceInput {
        scenario_id: format!("{}.{}", cli.scenario_id, scenario_suffix),
        connector_id: "fcp.synthetic.snapshot:utility:1.0.0".to_string(),
        manifest_hash: manifest_hash.map(str::to_string),
        zone: "z:project:snapshot-spike".to_string(),
        snapshot_state: observation.snapshot_state,
        cow_dirty_pages: observation.cow_dirty_pages,
        activation_latency_ms,
        memory_rss_bytes,
        sandbox_profile: "strict".to_string(),
        credential_mode: snapshot_credential_mode(observation.credential),
        cleanup_result: cleanup_result.to_string(),
        decision,
    })
}

const fn snapshot_credential_mode(credential: PrewarmCredentialState) -> SnapshotCredentialMode {
    match credential {
        PrewarmCredentialState::Deferred => SnapshotCredentialMode::Deferred,
        PrewarmCredentialState::MaterialLoaded => SnapshotCredentialMode::RedactedMaterialPresent,
    }
}

fn outcome_label(outcome: ResourceLedgerOutcome) -> &'static str {
    match outcome {
        ResourceLedgerOutcome::Admitted => "admitted",
        ResourceLedgerOutcome::Warned => "warned",
        ResourceLedgerOutcome::Delayed => "delayed",
        ResourceLedgerOutcome::Denied => "denied",
        ResourceLedgerOutcome::Cancelled => "cancelled",
        ResourceLedgerOutcome::Retried => "retried",
        ResourceLedgerOutcome::Skipped => "skipped",
        ResourceLedgerOutcome::Unknown => "unknown",
    }
}

fn detect_git_revision() -> String {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|revision| revision.trim().to_string())
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn parse_cli_uses_documented_defaults() {
        let cli = parse_cli(&args(&["fcp-resource-ledger-evidence"]))
            .expect("parse")
            .expect("not help");

        assert_eq!(cli.scenario_id, "swarm.resource-ledger.local-smoke");
        assert_eq!(cli.operation_id, "resource-ledger-smoke");
        assert_eq!(cli.worker_identity, "local-worker");
    }

    #[test]
    fn parse_cli_accepts_inline_and_split_options() {
        let cli = parse_cli(&args(&[
            "fcp-resource-ledger-evidence",
            "--scenario-id=custom.scenario",
            "--operation-id",
            "op42",
            "--worker=worker-secret-name",
            "--git-revision",
            "abc123",
            "--skip-host-mesh=missing live mesh fixture",
        ]))
        .expect("parse")
        .expect("not help");

        assert_eq!(cli.scenario_id, "custom.scenario");
        assert_eq!(cli.operation_id, "op42");
        assert_eq!(cli.worker_identity, "worker-secret-name");
        assert_eq!(cli.git_revision.as_deref(), Some("abc123"));
        assert_eq!(
            cli.skip_host_mesh_reason.as_deref(),
            Some("missing live mesh fixture")
        );
    }

    #[test]
    fn parse_cli_accepts_fairness_load_shed_flag() {
        let cli = parse_cli(&args(&[
            "fcp-resource-ledger-evidence",
            "--fairness-load-shed",
        ]))
        .expect("parse")
        .expect("not help");

        assert!(cli.fairness_load_shed);
    }

    #[test]
    fn parse_cli_accepts_snapshot_resume_flag() {
        let cli = parse_cli(&args(&[
            "fcp-resource-ledger-evidence",
            "--snapshot-resume",
        ]))
        .expect("parse")
        .expect("not help");

        assert!(cli.snapshot_resume);
    }

    #[test]
    fn parse_cli_rejects_conflicting_evidence_modes() {
        let err = parse_cli(&args(&[
            "fcp-resource-ledger-evidence",
            "--snapshot-resume",
            "--fairness-load-shed",
        ]))
        .expect_err("conflicting modes should fail");

        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn parse_cli_rejects_unknown_options() {
        let err = parse_cli(&args(&["fcp-resource-ledger-evidence", "--wat"]))
            .expect_err("unknown option should fail");
        assert!(err.contains("unknown option"));
    }

    #[test]
    fn local_smoke_records_cover_core_decision_surfaces() {
        let cli = Cli::default();
        let records = local_smoke_records(&cli, &args(&["fcp-resource-ledger-evidence"]), "abc123");

        assert_eq!(records.len(), 4);
        assert!(
            records
                .iter()
                .any(|record| record.kind == ResourceLedgerRecordKind::Backpressure)
        );
        assert!(
            records
                .iter()
                .any(|record| record.kind == ResourceLedgerRecordKind::Audit
                    && record.audit_receipt_id.is_some())
        );
        assert!(
            records
                .iter()
                .all(|record| record.worker_ref.starts_with("worker:blake3:"))
        );
    }

    #[test]
    fn fairness_load_shed_records_cover_required_scenarios() {
        let cli = Cli::default();
        let records = fairness_load_shed_records(&cli);

        assert_eq!(records.len(), 7);
        assert!(
            records
                .iter()
                .any(|record| record.scenario_id.ends_with("normal_traffic")
                    && record.backpressure_action == "admit")
        );
        assert!(records.iter().any(|record| {
            record.scenario_id.ends_with("single_connector_saturation")
                && record.backpressure_action == "shed"
                && record.denial_reason.is_some()
        }));
        assert!(records.iter().any(|record| {
            record.scenario_id.ends_with("high_priority_emergency_work")
                && record.backpressure_action != "shed"
                && record.backpressure_action != "cancel_low_priority"
        }));
        assert!(
            records
                .iter()
                .any(|record| record.scenario_id.ends_with("revoked_principal")
                    && record.skip_reason.is_some())
        );
        assert!(
            records
                .iter()
                .all(|record| record.cleanup_result == "no_remote_state_created"
                    || record.cleanup_result == "not_applicable")
        );
        assert!(
            records
                .iter()
                .all(|record| !record.operator_guidance.is_empty())
        );
        assert!(
            records
                .iter()
                .filter(|record| record.skip_reason.is_none())
                .all(|record| record.decision_replay_matches)
        );
        assert!(records.iter().any(|record| {
            record.scenario_id.ends_with("downstream_throttling")
                && record.downstream_retry_after_ms == Some(2_000)
                && record.retry_amplification_per_mille == Some(900)
        }));
    }

    #[test]
    fn fairness_load_shed_records_serialize_required_jsonl_fields() {
        let cli = Cli::default();
        let line = fairness_load_shed_records(&cli)[1]
            .to_jsonl_line()
            .expect("serialize");

        for field in [
            "scenario_id",
            "connector_class",
            "zone",
            "capability",
            "queue_depth",
            "admitted_count",
            "shed_count",
            "denial_reason",
            "backpressure_action",
            "latency_percentiles",
            "fairness_score",
            "decision_replay_matches",
            "operator_guidance",
            "audit_receipt_id",
            "cleanup_result",
        ] {
            assert!(line.contains(field), "missing {field} in {line}");
        }
    }

    #[test]
    fn snapshot_resume_records_cover_required_fail_closed_scenarios() {
        let cli = Cli::default();
        let records = snapshot_resume_records(&cli);

        assert_eq!(records.len(), 7);
        for suffix in [
            "empty_snapshot_store",
            "warm_resume",
            "stale_manifest",
            "revoked_capability",
            "crash_before_checkout",
            "concurrent_swarm_startup",
            "unsupported_platform",
        ] {
            assert!(
                records
                    .iter()
                    .any(|record| record.scenario_id.ends_with(suffix)),
                "missing {suffix}"
            );
        }

        assert!(records.iter().any(|record| {
            record.scenario_id.ends_with("warm_resume")
                && record.admission_decision == "reject_unsafe"
                && record.rejection_reason.as_deref() == Some("snapshot_resume_proof_unavailable")
                && !record.resume_checkout
                && record.cow_dirty_pages == Some(0)
        }));
        assert!(records.iter().any(|record| {
            record.scenario_id.ends_with("stale_manifest")
                && record.fallback_reason.as_deref() == Some("stale_manifest")
        }));
        assert!(records.iter().any(|record| {
            record.scenario_id.ends_with("revoked_capability")
                && record.rejection_reason.as_deref() == Some("revoked_capability")
        }));
        assert!(records.iter().any(|record| {
            record.scenario_id.ends_with("unsupported_platform")
                && record.skip_reason.as_deref() == Some("platform_unsupported")
                && record.activation_latency_ms.is_none()
        }));
        assert!(records.iter().all(|record| {
            record.schema_version == fcp_host::SNAPSHOT_RESUME_SCHEMA_VERSION
                && record.bead_id == fcp_host::SNAPSHOT_RESUME_BEAD
                && record.sandbox_profile == "strict"
                && record.credential_mode == SnapshotCredentialMode::Deferred
                && !record.operator_guidance.is_empty()
                && !record.resume_checkout
        }));
    }

    #[test]
    fn snapshot_resume_records_serialize_required_jsonl_fields() {
        let cli = Cli::default();
        let line = snapshot_resume_records(&cli)[1]
            .to_jsonl_line()
            .expect("serialize");

        for field in [
            "scenario_id",
            "connector_id",
            "manifest_hash",
            "zone",
            "snapshot_state",
            "cow_dirty_pages",
            "activation_latency_ms",
            "memory_rss_bytes",
            "sandbox_profile",
            "credential_mode",
            "fallback_reason",
            "rejection_reason",
            "skip_reason",
            "cleanup_result",
            "operator_guidance",
            "decision",
        ] {
            assert!(line.contains(field), "missing {field} in {line}");
        }
        assert!(!line.contains("secret"));
        assert!(!line.contains("token"));
    }
}
