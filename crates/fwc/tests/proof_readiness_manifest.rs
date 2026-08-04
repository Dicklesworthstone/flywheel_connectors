//! Proof-readiness target manifest and report schema coverage.

use std::collections::BTreeSet;
use std::path::PathBuf;

use fwc::proof_readiness::{
    PROOF_READINESS_REPORT_SCHEMA_VERSION, load_targets_manifest, parse_targets_manifest_str,
};
use jsonschema::Validator;
use serde_json::{Value, json};

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_root() -> PathBuf {
    crate_root().join("../..")
}

fn fixture(name: &str) -> PathBuf {
    crate_root()
        .join("tests")
        .join("fixtures")
        .join("proof_readiness")
        .join(name)
}

fn schema_validator() -> Validator {
    let schema_path = crate_root()
        .join("schemas")
        .join("proof_readiness.schema.json");
    let schema_text =
        std::fs::read_to_string(schema_path).expect("proof readiness schema should load");
    let schema: Value =
        serde_json::from_str(&schema_text).expect("proof readiness schema should parse");
    Validator::new(&schema).expect("proof readiness schema should compile")
}

fn assert_schema_valid(validator: &Validator, payload: &Value) {
    let errors = validator
        .iter_errors(payload)
        .map(|error| format!("{} at {}", error, error.instance_path()))
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "proof readiness report should validate against schema: {errors:?}"
    );
}

fn assert_schema_invalid(validator: &Validator, payload: &Value, reason: &str) {
    assert!(
        !validator.is_valid(payload),
        "proof readiness report should be invalid: {reason}"
    );
}

#[test]
fn test_valid_manifest_loads_targets() {
    let manifest =
        load_targets_manifest(fixture("evidence_targets_valid.toml")).expect("valid fixture loads");

    assert_eq!(
        manifest.schema_version,
        "fcp.fwc.proof-readiness-targets.v1"
    );
    assert_eq!(manifest.targets.len(), 1);
    let target = &manifest.targets[0];
    assert_eq!(target.target_id, "fixture_target");
    assert_eq!(target.blocked_beads, ["flywheel_connectors-qeg89.1"]);
    assert_eq!(target.redaction_policy.len(), 3);
}

#[test]
fn test_repository_manifest_contains_required_initial_targets() {
    let manifest = load_targets_manifest(repo_root().join("docs/proof/evidence_targets.toml"))
        .expect("repository proof target manifest loads");
    let ids = manifest
        .targets
        .iter()
        .map(|target| target.target_id.as_str())
        .collect::<BTreeSet<_>>();

    for expected in [
        "pq_signing_csd",
        "pq_signing_contabo",
        "pq_signing_laptop",
        "mesh_cutover_three_host_green",
        "multi_machine_failover_gauntlet",
        "blake3_avx512_statpack",
        "chacha20_avx2_statpack",
    ] {
        assert!(
            ids.contains(expected),
            "repository manifest must include {expected}"
        );
    }
}

#[test]
fn test_manifest_rejects_raw_private_endpoint() {
    let error = format!(
        "{:#}",
        load_targets_manifest(fixture("evidence_targets_bad_raw_endpoint.toml"))
            .expect_err("raw endpoints must fail closed")
    );

    assert!(
        error.contains("raw endpoint") || error.contains("private or local endpoint"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_manifest_rejects_target_without_blocked_bead() {
    let error = format!(
        "{:#}",
        load_targets_manifest(fixture("evidence_targets_missing_blocked_bead.toml"))
            .expect_err("missing blocked beads must fail closed")
    );

    assert!(error.contains("blocked bead"), "unexpected error: {error}");
}

#[test]
fn test_manifest_requires_redaction_policy_per_target() {
    let manifest = r#"
schema_version = "fcp.fwc.proof-readiness-targets.v1"

[[targets]]
target_id = "missing_redaction"
title = "Missing redaction"
blocked_beads = ["flywheel_connectors-qeg89.1"]
artifact_schema = "fcp.fixture-proof.v1"
artifact_root = "artifacts/proof/fixture"
artifact_globs = ["artifacts/proof/fixture/*.json"]
freshness_days = 7
machine_classes = ["fixture"]
host_roles = []
required_artifact_fields = ["schema_version", "git_sha"]
command_template = "cargo test -p fwc proof_readiness_fixture -- --nocapture"
redaction_policy = []
evidence_notes = ["Fixture target contains no live endpoints."]
"#;

    let error = parse_targets_manifest_str(manifest)
        .expect_err("missing redaction policy must fail closed")
        .to_string();

    assert!(
        error.contains("redaction policy"),
        "unexpected error: {error}"
    );
}

#[test]
fn proof_readiness_report_schema_accepts_missing_target_payload() {
    let validator = schema_validator();
    let payload = json!({
        "schema_version": PROOF_READINESS_REPORT_SCHEMA_VERSION,
        "status": "missing-prerequisites",
        "generated_at": "2026-06-07T12:00:00Z",
        "targets": [{
            "target_id": "pq_signing_csd",
            "blocked_beads": ["flywheel_connectors-angoc.8.3"],
            "status": "missing-prerequisites",
            "missing": [{
                "kind": "artifact",
                "id": "artifacts/perf/pq_signing/csd-*.json",
                "message": "No fresh csd StatPack artifact is available."
            }],
            "satisfied_artifacts": [],
            "command": {
                "argv_template": [
                    "cargo",
                    "bench",
                    "-p",
                    "fcp-crypto",
                    "--bench",
                    "hybrid_verify"
                ],
                "requires_remote": true,
                "proof_class": "remote-cargo"
            },
            "redaction_notes": ["Do not include raw hostnames or private endpoints."],
            "next_actions": ["Request a csd StatPack artifact from an operator."]
        }],
        "summary": {
            "target_count": 1,
            "ready_count": 0,
            "missing_prerequisites_count": 1,
            "partially_ready_count": 0,
            "error_count": 0
        }
    });

    assert_schema_valid(&validator, &payload);
}

#[test]
fn proof_readiness_report_schema_rejects_unknown_target_fields() {
    let validator = schema_validator();
    let mut payload = json!({
        "schema_version": PROOF_READINESS_REPORT_SCHEMA_VERSION,
        "status": "ready",
        "generated_at": "2026-06-07T12:00:00Z",
        "targets": [{
            "target_id": "pq_signing_csd",
            "blocked_beads": ["flywheel_connectors-angoc.8.3"],
            "status": "ready",
            "missing": [],
            "satisfied_artifacts": [{
                "path": "artifacts/perf/pq_signing/csd.json",
                "schema_version": "fcp.pq-signing-overhead.v1",
                "digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "machine_class": "csd",
                "host_role": null,
                "redacted": true
            }],
            "command": {
                "argv_template": ["cargo", "bench"],
                "requires_remote": true,
                "proof_class": "remote-cargo"
            },
            "redaction_notes": ["safe"],
            "next_actions": ["cite the live artifact"],
            "raw_endpoint": "should-not-be-allowed"
        }],
        "summary": {
            "target_count": 1,
            "ready_count": 1,
            "missing_prerequisites_count": 0,
            "partially_ready_count": 0,
            "error_count": 0
        }
    });

    assert_schema_invalid(&validator, &payload, "unknown target fields are refused");
    payload["targets"][0]
        .as_object_mut()
        .expect("target object")
        .remove("raw_endpoint");
    assert_schema_valid(&validator, &payload);
}
