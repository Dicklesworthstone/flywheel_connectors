//! Proof request bundle behavior coverage.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use fwc::proof_readiness::{
    ProofReadinessReportOptions, build_readiness_report, load_targets_manifest,
    parse_targets_manifest_str,
};
use fwc::proof_request::{ProofRequestBundleStatus, build_proof_request_bundle};
use serde_json::Value;
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

fn build_report(
    repo_root: &Path,
    target: Option<&str>,
    only_missing: bool,
) -> fwc::proof_readiness::ProofReadinessReport {
    let manifest = load_targets_manifest(repo_manifest()).expect("repository manifest loads");
    build_readiness_report(
        &manifest,
        &ProofReadinessReportOptions {
            repo_root: repo_root.to_path_buf(),
            now: SystemTime::now(),
            generated_at: Some("2026-06-07T12:00:00Z".to_owned()),
            target_filter: target.map(ToOwned::to_owned),
            only_missing,
        },
    )
    .expect("readiness report builds")
}

fn assert_no_forbidden_material(text: &str) {
    for forbidden in forbidden_material_markers() {
        assert!(
            !text.contains(&forbidden),
            "proof request bundle should not contain forbidden marker {forbidden}"
        );
    }
}

fn forbidden_material_markers() -> Vec<String> {
    vec![
        scheme_marker("http"),
        scheme_marker("https"),
        ipv4_marker([127, 0, 0, 1]),
        ipv4_marker([10, 0, 0, 1]),
        format!("{}.{}.", 192, 168),
        header_marker("Author", "ization"),
        spaced_marker("Bear", "er"),
        header_marker("cook", "ie"),
        assignment_marker("pass", "word"),
        assignment_marker("tok", "en"),
        format!("/{}/", "Users"),
    ]
}

fn scheme_marker(scheme: &str) -> String {
    format!("{scheme}:{}", "//")
}

fn ipv4_marker(octets: [u8; 4]) -> String {
    octets
        .into_iter()
        .map(|octet| octet.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

fn header_marker(prefix: &str, suffix: &str) -> String {
    format!("{prefix}{suffix}:")
}

fn spaced_marker(prefix: &str, suffix: &str) -> String {
    format!("{prefix}{suffix} ")
}

fn assignment_marker(prefix: &str, suffix: &str) -> String {
    format!("{prefix}{suffix}=")
}

#[test]
fn test_request_bundle_mentions_all_missing_targets() {
    let temp = tempdir().expect("temp repo root");
    let manifest = load_targets_manifest(repo_manifest()).expect("repository manifest loads");
    let report = build_report(temp.path(), None, true);
    let bundle =
        build_proof_request_bundle(&manifest, &report).expect("proof request bundle builds");

    assert_eq!(bundle.status, ProofRequestBundleStatus::MissingRequests);
    assert_eq!(bundle.target_count, manifest.targets.len());
    let requested_ids = bundle
        .requests
        .iter()
        .map(|request| request.target_id.as_str())
        .collect::<BTreeSet<_>>();
    for target in &manifest.targets {
        assert!(
            requested_ids.contains(target.target_id.as_str()),
            "bundle should include missing target {}",
            target.target_id
        );
        assert!(bundle.markdown.contains(&target.target_id));
        for bead in &target.blocked_beads {
            assert!(bundle.markdown.contains(bead));
        }
    }
}

#[test]
fn test_request_bundle_omits_raw_urls_private_ips_and_tokens() {
    let temp = tempdir().expect("temp repo root");
    let manifest = load_targets_manifest(repo_manifest()).expect("repository manifest loads");
    let report = build_report(temp.path(), Some("mesh_cutover_three_host_green"), true);
    let bundle =
        build_proof_request_bundle(&manifest, &report).expect("proof request bundle builds");

    let rendered = serde_json::to_string_pretty(&bundle).expect("bundle serializes");
    assert_no_forbidden_material(&rendered);
    assert!(rendered.contains("<redacted host list>"));
    assert!(rendered.contains("hash_host_ids"));
}

#[test]
fn test_request_bundle_includes_exact_artifact_schema_and_threshold() {
    let manifest = parse_targets_manifest_str(
        r#"
schema_version = "fcp.fwc.proof-readiness-targets.v1"

[[targets]]
target_id = "threshold_target"
title = "Threshold target"
blocked_beads = ["flywheel_connectors-qeg89.3"]
artifact_schema = "fcp.threshold-proof.v1"
artifact_root = "artifacts/proof/threshold"
artifact_globs = ["artifacts/proof/threshold/*.json"]
freshness_days = 9
machine_classes = ["csd"]
host_roles = []
required_artifact_fields = ["schema_version", "git_sha", "sample_count", "summary"]
command_template = "cargo bench -p fcp-crypto --bench hybrid_verify -- --samples 10000 --statpack-out artifacts/proof/threshold/csd-<date>-<sha>.json"
redaction_policy = ["no_raw_hostnames", "no_private_ips", "no_tokens"]
evidence_notes = ["Threshold fixture contains summarized benchmark output only."]

[targets.thresholds]
sample_count = "10000"
"#,
    )
    .expect("threshold manifest parses");
    let temp = tempdir().expect("temp repo root");
    let report = build_readiness_report(
        &manifest,
        &ProofReadinessReportOptions {
            repo_root: temp.path().to_path_buf(),
            now: SystemTime::now(),
            generated_at: Some("2026-06-07T12:00:00Z".to_owned()),
            target_filter: Some("threshold_target".to_owned()),
            only_missing: true,
        },
    )
    .expect("readiness report builds");
    let bundle =
        build_proof_request_bundle(&manifest, &report).expect("proof request bundle builds");
    let request = &bundle.requests[0];

    assert_eq!(
        request.artifact_requirements.artifact_schema,
        "fcp.threshold-proof.v1"
    );
    assert_eq!(request.artifact_requirements.freshness_days, 9);
    assert!(
        request
            .artifact_requirements
            .required_fields
            .iter()
            .any(|field| field == "sample_count")
    );
    assert_eq!(
        request
            .artifact_requirements
            .thresholds
            .get("sample_count")
            .map(String::as_str),
        Some("10000")
    );
    assert!(request.message_markdown.contains("fcp.threshold-proof.v1"));
    assert!(request.message_markdown.contains("sample_count"));
    assert!(request.message_markdown.contains("10000"));
}

#[test]
fn test_request_bundle_escapes_markdown_in_title_and_messages() {
    let manifest = parse_targets_manifest_str(
        r#"
schema_version = "fcp.fwc.proof-readiness-targets.v1"

[[targets]]
target_id = "markdown_injection_target"
title = "Injection [click](//evil.example) *title* `fence`"
blocked_beads = ["flywheel_connectors-qeg89.3"]
artifact_schema = "fcp.threshold-proof.v1"
artifact_root = "artifacts/proof/threshold"
artifact_globs = ["artifacts/proof/threshold/*.json"]
freshness_days = 9
machine_classes = ["csd"]
host_roles = []
required_artifact_fields = ["schema_version", "git_sha", "summary"]
command_template = "cargo bench -p fcp-crypto --bench hybrid_verify -- --statpack-out artifacts/proof/threshold/csd-<date>-<sha>.json"
redaction_policy = ["no_raw_hostnames", "no_private_ips", "no_tokens"]
evidence_notes = ["Fixture for markdown escaping."]
"#,
    )
    .expect("injection manifest parses");
    let temp = tempdir().expect("temp repo root");
    let report = build_readiness_report(
        &manifest,
        &ProofReadinessReportOptions {
            repo_root: temp.path().to_path_buf(),
            now: SystemTime::now(),
            generated_at: Some("2026-06-12T12:00:00Z".to_owned()),
            target_filter: Some("markdown_injection_target".to_owned()),
            only_missing: true,
        },
    )
    .expect("readiness report builds");
    let bundle =
        build_proof_request_bundle(&manifest, &report).expect("proof request bundle builds");
    let markdown = &bundle.requests[0].message_markdown;

    // The protocol-relative link and emphasis/code metacharacters from the
    // title must arrive backslash-escaped, never as live markdown.
    assert!(!markdown.contains("[click](//evil.example)"));
    assert!(markdown.contains("\\[click\\]\\(//evil.example\\)"));
    assert!(markdown.contains("\\*title\\*"));
    assert!(markdown.contains("\\`fence\\`"));
}

#[test]
fn test_request_bundle_is_stable_for_same_report() {
    let temp = tempdir().expect("temp repo root");
    let manifest = load_targets_manifest(repo_manifest()).expect("repository manifest loads");
    let report = build_report(temp.path(), Some("pq_signing_csd"), true);

    let first =
        build_proof_request_bundle(&manifest, &report).expect("first request bundle builds");
    let second =
        build_proof_request_bundle(&manifest, &report).expect("second request bundle builds");

    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_string_pretty(&first).expect("first serializes"),
        serde_json::to_string_pretty(&second).expect("second serializes")
    );
}

#[test]
fn test_cli_generates_json_request_bundle_for_missing_target() {
    let temp = tempdir().expect("temp repo root");
    let output = Command::new(env!("CARGO_BIN_EXE_fwc"))
        .args([
            "--json",
            "proof",
            "request",
            "--manifest",
            repo_manifest().to_str().expect("manifest path is utf8"),
            "--repo-root",
            temp.path().to_str().expect("repo path is utf8"),
            "--target",
            "mesh_cutover_three_host_green",
            "--now-unix-secs",
            "1780848000",
        ])
        .output()
        .expect("fwc should run");

    assert!(output.status.success());
    let payload: Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be JSON payload");
    assert_eq!(payload["schema_version"], "fcp.fwc.proof-request-bundle.v1");
    assert_eq!(payload["status"], "missing-requests");
    assert_eq!(payload["target_count"], 1);
    assert_eq!(
        payload["requests"][0]["target_id"],
        "mesh_cutover_three_host_green"
    );
    assert!(payload["availability"].is_object());
    assert_no_forbidden_material(&String::from_utf8_lossy(&output.stdout));
}
