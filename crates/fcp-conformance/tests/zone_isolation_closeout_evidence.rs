use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

const MANIFEST_PATH: &str = "docs/formal/zone-isolation-closeout-evidence.json";
const README_PROOF_OBLIGATIONS_PATH: &str = "docs/formal/readme-proof-obligations.json";
const ZONE_ISOLATION: &str = "Zone Isolation";

#[derive(Clone, Copy, Debug)]
struct ArtifactRecord<'a> {
    id: &'a str,
    status: &'a str,
    git_sha: &'a str,
    age_hours: u64,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("fcp-conformance must live under crates/")
        .to_path_buf()
}

fn read_relative(root: &Path, path: &str) -> String {
    fs::read_to_string(root.join(path))
        .unwrap_or_else(|err| panic!("expected {path} to be readable: {err}"))
}

fn load_json(root: &Path, path: &str) -> Value {
    serde_json::from_str(&read_relative(root, path))
        .unwrap_or_else(|err| panic!("expected {path} to be valid JSON: {err}"))
}

fn string_field<'a>(value: &'a Value, field: &str) -> &'a str {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("expected string field {field}"))
}

fn bool_field(value: &Value, field: &str) -> bool {
    value
        .get(field)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("expected boolean field {field}"))
}

fn u64_field(value: &Value, field: &str) -> u64 {
    value
        .get(field)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("expected u64 field {field}"))
}

fn array_field<'a>(value: &'a Value, field: &str) -> &'a Vec<Value> {
    value
        .get(field)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("expected array field {field}"))
}

fn manifest(root: &Path) -> Value {
    load_json(root, MANIFEST_PATH)
}

fn readme_status(root: &Path) -> String {
    let readme = read_relative(root, "README.md");
    readme
        .lines()
        .find_map(|line| {
            let cells = line
                .trim()
                .trim_matches('|')
                .split('|')
                .map(str::trim)
                .collect::<Vec<_>>();
            let feature = cells
                .first()
                .and_then(|cell| cell.strip_prefix("**"))
                .and_then(|cell| cell.strip_suffix("**"));
            if feature == Some(ZONE_ISOLATION) && cells.len() >= 2 {
                Some(cells[1].trim_matches('`').to_owned())
            } else {
                None
            }
        })
        .unwrap_or_else(|| panic!("README.md must include {ZONE_ISOLATION}"))
}

fn records_by_id<'a>(records: &'a [ArtifactRecord<'a>]) -> BTreeMap<&'a str, ArtifactRecord<'a>> {
    records.iter().map(|record| (record.id, *record)).collect()
}

fn evaluate_artifact_gate(
    required_artifacts: &[Value],
    records: &[ArtifactRecord<'_>],
    current_sha: &str,
) -> Result<(), String> {
    let by_id = records_by_id(records);
    for artifact in required_artifacts {
        let id = string_field(artifact, "id");
        let record = by_id
            .get(id)
            .ok_or_else(|| format!("{id} artifact is missing"))?;
        if record.status != string_field(artifact, "required_status") {
            return Err(format!(
                "{id} artifact status {} is not {}",
                record.status,
                string_field(artifact, "required_status")
            ));
        }
        let max_age_hours = u64_field(artifact, "max_age_hours");
        if record.age_hours > max_age_hours {
            return Err(format!(
                "{id} artifact is stale: {}h exceeds {max_age_hours}h",
                record.age_hours
            ));
        }
        if bool_field(artifact, "require_current_sha") && record.git_sha != current_sha {
            return Err(format!(
                "{id} artifact SHA {} does not match {current_sha}",
                record.git_sha
            ));
        }
    }
    Ok(())
}

fn green_records() -> Vec<ArtifactRecord<'static>> {
    vec![
        ArtifactRecord {
            id: "lean-verify-zone-lattice",
            status: "green",
            git_sha: "abc123",
            age_hours: 1,
        },
        ArtifactRecord {
            id: "zone-isolation-full-e2e",
            status: "green",
            git_sha: "abc123",
            age_hours: 1,
        },
    ]
}

#[test]
fn evidence_pack_has_required_hvxcd_shape() {
    let root = workspace_root();
    let manifest = manifest(&root);

    assert_eq!(
        string_field(&manifest, "schema_version"),
        "fcp.zone-isolation-closeout-evidence.v1"
    );
    assert_eq!(
        string_field(&manifest["readme_gate"], "gate_manifest"),
        README_PROOF_OBLIGATIONS_PATH
    );
    let closeout_status = string_field(&manifest["closeout_status"], "status");
    assert!(
        matches!(closeout_status, "blocked" | "proven"),
        "closeout_status must be 'blocked' or 'proven', got {closeout_status}"
    );

    let beads = array_field(&manifest, "bead_ids")
        .iter()
        .map(|value| value.as_str().expect("bead id is a string"))
        .collect::<BTreeSet<_>>();
    for expected in [
        "flywheel_connectors-hvxcd",
        "flywheel_connectors-am4aq",
        "flywheel_connectors-angoc.2.1",
        "flywheel_connectors-angoc.2.2",
        "flywheel_connectors-angoc.9",
    ] {
        assert!(beads.contains(expected), "manifest must include {expected}");
    }
}

#[test]
fn evidence_pack_references_existing_paths_and_named_tests() {
    let root = workspace_root();
    let manifest = manifest(&root);

    for test in array_field(&manifest, "required_tests") {
        let path = string_field(test, "path");
        let source = read_relative(&root, path);
        for function in array_field(test, "required_functions") {
            let function = function.as_str().expect("function name is a string");
            assert!(
                source.contains(&format!("fn {function}")),
                "{path} must define {function}"
            );
        }
    }

    for artifact in array_field(&manifest, "required_ci_artifacts") {
        let producer = string_field(artifact, "producer");
        assert!(
            root.join(producer).exists(),
            "artifact producer {producer} must exist"
        );
    }
}

#[test]
fn docs_reference_only_existing_zone_isolation_proof_paths() {
    let root = workspace_root();
    let docs = [
        "README.md",
        "docs/quarterly/2026-Q2-claims-vs-reality.md",
        "docs/reality/2026-05-12-reality-check-bridge-plan.md",
    ]
    .into_iter()
    .map(|path| read_relative(&root, path))
    .collect::<Vec<_>>()
    .join("\n");

    assert!(docs.contains(ZONE_ISOLATION));
    for path in [
        "lean/Fcp/Zone/Lattice.lean",
        "crates/fcp-host/tests/allowed_zones_required.rs",
        "crates/fcp-conformance/tests/no_permissive_empty_zone_branch.rs",
        "crates/fcp-e2e/tests/zone_isolation_full_e2e.rs",
        README_PROOF_OBLIGATIONS_PATH,
        MANIFEST_PATH,
    ] {
        assert!(root.join(path).exists(), "{path} must exist");
        assert!(
            docs.contains(path),
            "docs must reference existing path {path}"
        );
    }
}

#[test]
fn readme_gate_stays_limited_until_artifacts_are_green() {
    let root = workspace_root();
    let manifest = manifest(&root);
    let source_sha = string_field(&manifest, "source_sha");

    assert_eq!(readme_status(&root), "PROVEN");
    assert_eq!(
        string_field(&manifest["readme_gate"], "current_status"),
        "PROVEN"
    );
    assert_eq!(
        string_field(&manifest["readme_gate"], "promotion_status"),
        "PROVEN"
    );

    let artifact_statuses = array_field(&manifest, "required_ci_artifacts")
        .iter()
        .map(|artifact| string_field(artifact, "current_status"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        artifact_statuses,
        BTreeSet::from(["green"]),
        "promoted Zone Isolation requires all archived artifacts to be green"
    );

    for artifact in array_field(&manifest, "required_ci_artifacts") {
        let artifact_path = string_field(artifact, "artifact_path");
        assert!(
            artifact_path.contains(source_sha),
            "{artifact_path} must be pinned to source_sha {source_sha}"
        );
        let content = read_relative(&root, artifact_path);
        for marker in array_field(artifact, "must_contain") {
            let marker = marker.as_str().expect("must_contain marker is a string");
            assert!(
                content.contains(marker),
                "{artifact_path} must contain required green marker {marker}"
            );
        }
    }
}

#[test]
fn artifact_gate_rejects_missing_queued_red_stale_and_wrong_sha() {
    let root = workspace_root();
    let manifest = manifest(&root);
    let required = array_field(&manifest, "required_ci_artifacts");

    assert!(evaluate_artifact_gate(required, &green_records(), "abc123").is_ok());
    assert!(evaluate_artifact_gate(required, &green_records()[..1], "abc123").is_err());

    for status in ["queued", "red"] {
        let mut records = green_records();
        records[0].status = status;
        let err = evaluate_artifact_gate(required, &records, "abc123")
            .expect_err("non-green artifacts must be rejected");
        assert!(err.contains(status));
    }

    let mut stale = green_records();
    stale[0].age_hours = 25;
    assert!(
        evaluate_artifact_gate(required, &stale, "abc123")
            .expect_err("stale artifacts must be rejected")
            .contains("stale")
    );

    assert!(
        evaluate_artifact_gate(required, &green_records(), "def456")
            .expect_err("wrong SHA artifacts must be rejected")
            .contains("does not match")
    );
}

#[test]
fn evidence_pack_is_redaction_safe() {
    let root = workspace_root();
    let raw = read_relative(&root, MANIFEST_PATH);
    let lower = raw.to_ascii_lowercase();

    for forbidden in [
        "/users/",
        "bearer ",
        "password",
        "api_key",
        "secret",
        "ghp_",
        "xoxb-",
        "sk-",
        "-----begin",
    ] {
        assert!(
            !lower.contains(forbidden),
            "{MANIFEST_PATH} must not contain redaction-unsafe marker {forbidden}"
        );
    }
}
