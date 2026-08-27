//! Proof-readiness report behavior coverage.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use fwc::proof_readiness::{
    MissingPrerequisiteKind, ProofClass, ProofReadinessReportOptions, ProofReadinessStatus,
    build_readiness_report, load_targets_manifest, system_time_from_unix_secs,
};
use jsonschema::Validator;
use serde_json::{Value, json};
use tempfile::tempdir;

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_root() -> PathBuf {
    crate_root().join("../..")
}

fn repo_manifest() -> PathBuf {
    repo_root().join("docs/proof/evidence_targets.toml")
}

fn schema_validator() -> Validator {
    let schema_text = fs::read_to_string(crate_root().join("schemas/proof_readiness.schema.json"))
        .expect("proof readiness schema should load");
    let schema: Value =
        serde_json::from_str(&schema_text).expect("proof readiness schema should parse");
    Validator::new(&schema).expect("proof readiness schema should compile")
}

fn build_report_for(repo_root: &Path, target: &str) -> fwc::proof_readiness::ProofReadinessReport {
    build_report_for_at(repo_root, target, SystemTime::now())
}

fn build_report_for_at(
    repo_root: &Path,
    target: &str,
    now: SystemTime,
) -> fwc::proof_readiness::ProofReadinessReport {
    let manifest = load_targets_manifest(repo_manifest()).expect("repository manifest loads");
    build_readiness_report(
        &manifest,
        &ProofReadinessReportOptions {
            repo_root: repo_root.to_path_buf(),
            now,
            generated_at: Some("2026-06-07T12:00:00Z".to_owned()),
            target_filter: Some(target.to_owned()),
            only_missing: false,
        },
    )
    .expect("report builds")
}

fn write_json_artifact(repo_root: &Path, relative_path: &str, value: &Value) {
    let path = repo_root.join(relative_path);
    fs::create_dir_all(path.parent().expect("artifact should have parent"))
        .expect("artifact directory should be created");
    fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("artifact should serialize"),
    )
    .expect("artifact should be written");
}

fn assert_schema_valid(payload: &Value) {
    let validator = schema_validator();
    let errors = validator
        .iter_errors(payload)
        .map(|error| format!("{} at {}", error, error.instance_path()))
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "proof readiness report should validate against schema: {errors:?}"
    );
}

#[test]
fn test_reports_missing_pq_machine_classes_without_artifacts() {
    let temp = tempdir().expect("temp repo root");
    let report = build_report_for(temp.path(), "pq_signing_csd");

    assert_eq!(report.status, ProofReadinessStatus::MissingPrerequisites);
    assert_eq!(report.summary.target_count, 1);
    let target = &report.targets[0];
    assert_eq!(target.target_id, "pq_signing_csd");
    assert_eq!(target.status, ProofReadinessStatus::MissingPrerequisites);
    assert_eq!(
        target.satisfied_artifacts,
        [] as [fwc::proof_readiness::SatisfiedArtifact; 0]
    );
    assert!(target.missing.iter().any(|item| {
        item.kind == MissingPrerequisiteKind::Artifact
            && item.id == "artifacts/perf/pq_signing/csd-*.json"
    }));
    assert!(
        target
            .missing
            .iter()
            .any(|item| { item.kind == MissingPrerequisiteKind::MachineClass && item.id == "csd" })
    );
}

#[test]
fn test_reports_contabo_satisfied_when_valid_statpack_exists() {
    let temp = tempdir().expect("temp repo root");
    write_json_artifact(
        temp.path(),
        "artifacts/perf/pq_signing/contabo-good.json",
        &json!({
            "schema_version": "fcp.pq-signing-overhead.v1",
            "machine_class": "contabo",
            "git_sha": "0123456789abcdef0123456789abcdef01234567",
            "sample_count": 10000,
            "summary": { "p50_us": 10, "p99_us": 20 }
        }),
    );

    let report = build_report_for(temp.path(), "pq_signing_contabo");
    assert_eq!(report.status, ProofReadinessStatus::Ready);
    let target = &report.targets[0];
    assert_eq!(target.status, ProofReadinessStatus::Ready);
    assert_eq!(
        target.missing,
        [] as [fwc::proof_readiness::MissingPrerequisite; 0]
    );
    assert_eq!(target.satisfied_artifacts.len(), 1);
    assert_eq!(
        target.satisfied_artifacts[0].machine_class.as_deref(),
        Some("contabo")
    );
    assert!(target.satisfied_artifacts[0].digest.starts_with("blake3:"));
    assert!(target.satisfied_artifacts[0].redacted);
}

#[test]
fn test_reports_cutover_hosts_redacted_and_missing_when_hashes_absent() {
    let temp = tempdir().expect("temp repo root");
    let report = build_report_for(temp.path(), "mesh_cutover_three_host_green");
    let target = &report.targets[0];

    assert_eq!(target.status, ProofReadinessStatus::MissingPrerequisites);
    assert_eq!(target.command.proof_class, ProofClass::LiveHost);
    assert!(
        target
            .command
            .argv_template
            .iter()
            .any(|arg| arg == "<redacted host list>")
    );
    assert!(!target.command.argv_template.join(" ").contains("http://"));
    assert!(!target.command.argv_template.join(" ").contains("localhost"));
    assert!(
        target
            .redaction_notes
            .iter()
            .any(|note| note == "hash_host_ids")
    );
    for role in ["active", "standby-a", "standby-b"] {
        assert!(
            target
                .missing
                .iter()
                .any(|item| { item.kind == MissingPrerequisiteKind::HostRole && item.id == role })
        );
    }
}

#[test]
fn test_rejects_stale_or_wrong_schema_artifact() {
    let temp = tempdir().expect("temp repo root");
    write_json_artifact(
        temp.path(),
        "artifacts/perf/pq_signing/contabo-wrong-schema.json",
        &json!({
            "schema_version": "fcp.other-schema.v1",
            "machine_class": "contabo",
            "git_sha": "0123456789abcdef0123456789abcdef01234567",
            "sample_count": 10000,
            "summary": { "p50_us": 10, "p99_us": 20 }
        }),
    );
    write_json_artifact(
        temp.path(),
        "artifacts/perf/pq_signing/contabo-stale.json",
        &json!({
            "schema_version": "fcp.pq-signing-overhead.v1",
            "machine_class": "contabo",
            "git_sha": "0123456789abcdef0123456789abcdef01234567",
            "sample_count": 10000,
            "summary": { "p50_us": 10, "p99_us": 20 }
        }),
    );

    let report = build_report_for_at(
        temp.path(),
        "pq_signing_contabo",
        SystemTime::now() + Duration::from_secs(365 * 24 * 60 * 60),
    );
    let target = &report.targets[0];
    assert_eq!(target.status, ProofReadinessStatus::MissingPrerequisites);
    assert_eq!(
        target.satisfied_artifacts,
        [] as [fwc::proof_readiness::SatisfiedArtifact; 0]
    );
    assert!(
        target
            .missing
            .iter()
            .any(|item| item.kind == MissingPrerequisiteKind::Schema)
    );
    assert!(
        target
            .missing
            .iter()
            .any(|item| item.kind == MissingPrerequisiteKind::Freshness)
    );
}

#[test]
fn test_committed_filename_date_marks_stale_proof_despite_fresh_mtime() {
    // Regression (fz3ux): a committed proof whose filename date is far in the
    // past must be reported stale even though its filesystem mtime is "now"
    // (which is exactly the state after a fresh clone or CI checkout). Under the
    // old mtime-only check this artifact would look freshly generated.
    let temp = tempdir().expect("temp repo root");
    write_json_artifact(
        temp.path(),
        "artifacts/perf/pq_signing/csd-2020-01-01-abcdef0.json",
        &json!({
            "schema_version": "fcp.pq-signing-overhead.v1",
            "machine_class": "csd",
            "git_sha": "0123456789abcdef0123456789abcdef01234567",
            "sample_count": 10000,
            "summary": { "p50_us": 10, "p99_us": 20 }
        }),
    );

    // `now` is the real wall clock (always years after 2020-01-01), while the
    // just-written file's mtime is the current instant.
    let report = build_report_for_at(temp.path(), "pq_signing_csd", SystemTime::now());
    let target = &report.targets[0];
    assert_eq!(target.status, ProofReadinessStatus::MissingPrerequisites);
    assert_eq!(
        target.satisfied_artifacts,
        [] as [fwc::proof_readiness::SatisfiedArtifact; 0]
    );
    assert!(
        target
            .missing
            .iter()
            .any(|item| item.kind == MissingPrerequisiteKind::Freshness),
        "committed filename date must drive the freshness verdict, not fs mtime"
    );
}

#[test]
fn test_committed_filename_date_within_window_is_fresh() {
    // A committed proof whose filename date falls inside the freshness window is
    // satisfied — the date parser must not over-reject valid recent artifacts.
    let temp = tempdir().expect("temp repo root");
    write_json_artifact(
        temp.path(),
        "artifacts/perf/pq_signing/csd-2026-06-20-abcdef0.json",
        &json!({
            "schema_version": "fcp.pq-signing-overhead.v1",
            "machine_class": "csd",
            "git_sha": "0123456789abcdef0123456789abcdef01234567",
            "sample_count": 10000,
            "summary": { "p50_us": 10, "p99_us": 20 }
        }),
    );

    // 2026-06-25T00:00:00Z — five days after the filename date, inside the
    // 30-day window for the csd target.
    let now = system_time_from_unix_secs(1_782_345_600);
    let report = build_report_for_at(temp.path(), "pq_signing_csd", now);
    let target = &report.targets[0];
    assert_eq!(target.status, ProofReadinessStatus::Ready);
    assert!(
        target
            .missing
            .iter()
            .all(|item| item.kind != MissingPrerequisiteKind::Freshness),
        "recent committed filename date must be treated as fresh"
    );
    assert_eq!(target.satisfied_artifacts.len(), 1);
}

#[test]
fn test_json_validates_against_proof_readiness_schema() {
    let temp = tempdir().expect("temp repo root");
    write_json_artifact(
        temp.path(),
        "artifacts/perf/pq_signing/contabo-good.json",
        &json!({
            "schema_version": "fcp.pq-signing-overhead.v1",
            "machine_class": "contabo",
            "git_sha": "0123456789abcdef0123456789abcdef01234567",
            "sample_count": 10000,
            "summary": { "p50_us": 10, "p99_us": 20 }
        }),
    );

    let report = build_report_for(temp.path(), "pq_signing_contabo");
    let payload = serde_json::to_value(report).expect("report serializes");
    assert_schema_valid(&payload);
}

#[test]
fn test_cli_reports_unknown_target_as_typed_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_fwc"))
        .args([
            "--json",
            "proof",
            "readiness",
            "--manifest",
            repo_manifest().to_str().expect("manifest path is utf8"),
            "--repo-root",
            repo_root().to_str().expect("repo path is utf8"),
            "--target",
            "not_a_real_target",
        ])
        .output()
        .expect("fwc should run");

    assert!(!output.status.success());
    let payload: Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be JSON payload");
    assert_eq!(payload["status"], "error");
    assert_eq!(payload["error"]["type"], "unknown-proof-target");
    assert!(payload["availability"].is_object());
}

#[test]
fn test_cli_only_missing_suppresses_satisfied_target() {
    let temp = tempdir().expect("temp repo root");
    write_json_artifact(
        temp.path(),
        "artifacts/perf/pq_signing/contabo-good.json",
        &json!({
            "schema_version": "fcp.pq-signing-overhead.v1",
            "machine_class": "contabo",
            "git_sha": "0123456789abcdef0123456789abcdef01234567",
            "sample_count": 10000,
            "summary": { "p50_us": 10, "p99_us": 20 }
        }),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_fwc"))
        .args([
            "--json",
            "proof",
            "readiness",
            "--manifest",
            repo_manifest().to_str().expect("manifest path is utf8"),
            "--repo-root",
            temp.path().to_str().expect("repo path is utf8"),
            "--target",
            "pq_signing_contabo",
            "--only-missing",
        ])
        .output()
        .expect("fwc should run");

    assert!(output.status.success());
    let payload: Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be JSON payload");
    assert_eq!(payload["status"], "ready");
    // The summary describes the full evaluated set; only the listed targets
    // are narrowed by --only-missing.
    assert_eq!(payload["summary"]["target_count"], 1);
    assert_eq!(payload["summary"]["ready_count"], 1);
    assert_eq!(
        payload["targets"].as_array().expect("targets array").len(),
        0
    );
    assert_schema_valid(&payload);
}

#[test]
fn test_future_timestamped_artifact_is_not_fresh() {
    let temp = tempdir().expect("temp repo root");
    write_json_artifact(
        temp.path(),
        "artifacts/perf/pq_signing/contabo-good.json",
        &json!({
            "schema_version": "fcp.pq-signing-overhead.v1",
            "machine_class": "contabo",
            "git_sha": "0123456789abcdef0123456789abcdef01234567",
            "sample_count": 10000,
            "summary": { "p50_us": 10, "p99_us": 20 }
        }),
    );

    // Evaluate at a point in the past so the artifact's modification time sits
    // in the future. A future timestamp cannot prove freshness; the artifact
    // must fail closed instead of counting as fresh evidence.
    let report = build_report_for_at(
        temp.path(),
        "pq_signing_contabo",
        SystemTime::now() - Duration::from_secs(2 * 24 * 60 * 60),
    );
    let target = &report.targets[0];
    assert_eq!(target.status, ProofReadinessStatus::MissingPrerequisites);
    assert_eq!(
        target.satisfied_artifacts,
        [] as [fwc::proof_readiness::SatisfiedArtifact; 0]
    );
    assert!(
        target
            .missing
            .iter()
            .any(|item| item.kind == MissingPrerequisiteKind::Freshness)
    );
}
