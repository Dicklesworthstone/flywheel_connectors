use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

const OBLIGATIONS_PATH: &str = "docs/formal/readme-proof-obligations.json";
const ZONE_ISOLATION: &str = "Zone Isolation";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GateVerdict {
    NonProven,
    ProvenPinned,
}

#[derive(Clone, Copy, Debug)]
struct EvidenceRecord<'a> {
    obligation_id: &'a str,
    status: &'a str,
    git_sha: &'a str,
    generated_age_hours: u64,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("fcp-conformance must live under crates/")
        .to_path_buf()
}

fn markdown_cells(line: &str) -> Vec<&str> {
    line.trim()
        .trim_matches('|')
        .split('|')
        .map(str::trim)
        .collect()
}

fn read_feature_status(readme: &str, feature: &str) -> Option<String> {
    readme.lines().find_map(|line| {
        let cells = markdown_cells(line);
        let feature_cell = cells
            .first()
            .and_then(|cell| cell.strip_prefix("**"))
            .and_then(|cell| cell.strip_suffix("**"));
        if cells.len() < 2 || feature_cell != Some(feature) {
            return None;
        }
        Some(cells[1].trim_matches('`').to_owned())
    })
}

fn load_manifest(root: &Path) -> Value {
    let raw = fs::read_to_string(root.join(OBLIGATIONS_PATH))
        .unwrap_or_else(|err| panic!("expected {OBLIGATIONS_PATH} to be readable: {err}"));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("expected {OBLIGATIONS_PATH} to be valid JSON: {err}"))
}

fn feature_obligation<'a>(manifest: &'a Value, feature: &str) -> &'a Value {
    manifest
        .get("features")
        .and_then(Value::as_array)
        .and_then(|features| {
            features
                .iter()
                .find(|candidate| candidate.get("feature").and_then(Value::as_str) == Some(feature))
        })
        .unwrap_or_else(|| panic!("{OBLIGATIONS_PATH} must register {feature}"))
}

fn required_artifacts(feature: &Value) -> &[Value] {
    feature
        .get("required_artifacts")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn string_field<'a>(object: &'a Value, field: &str) -> &'a str {
    object
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("manifest object must include string field {field}"))
}

fn bool_field(object: &Value, field: &str) -> bool {
    object
        .get(field)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("manifest object must include boolean field {field}"))
}

fn u64_field(object: &Value, field: &str) -> u64 {
    object
        .get(field)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("manifest object must include u64 field {field}"))
}

fn artifact_context(artifact: &Value) -> String {
    format!(
        "artifact_hint={}, operator_url_hint={}",
        string_field(artifact, "artifact_hint"),
        string_field(artifact, "operator_url_hint")
    )
}

fn accepted_shas(feature: &Value) -> BTreeSet<&str> {
    feature
        .get("accepted_shas")
        .and_then(Value::as_array)
        .map_or_else(BTreeSet::new, |values| {
            values.iter().filter_map(Value::as_str).collect()
        })
}

fn records_by_obligation<'a>(
    records: &'a [EvidenceRecord<'a>],
) -> BTreeMap<&'a str, EvidenceRecord<'a>> {
    records
        .iter()
        .map(|record| (record.obligation_id, *record))
        .collect()
}

fn evaluate_feature_gate(
    feature: &Value,
    readme_status: &str,
    records: &[EvidenceRecord<'_>],
    current_sha: &str,
) -> Result<GateVerdict, String> {
    let gate_status = string_field(feature, "gate_status");
    if readme_status != gate_status {
        return Ok(GateVerdict::NonProven);
    }

    let by_obligation = records_by_obligation(records);
    let accepted = accepted_shas(feature);

    for artifact in required_artifacts(feature) {
        let id = string_field(artifact, "id");
        let context = artifact_context(artifact);
        let record = by_obligation.get(id).ok_or_else(|| {
            format!("{id} artifact is missing for {gate_status} claim ({context})")
        })?;

        if record.status != "green" {
            return Err(format!(
                "{id} artifact is {} but {gate_status} requires green ({context})",
                record.status,
            ));
        }

        let max_age_hours = u64_field(artifact, "max_age_hours");
        if record.generated_age_hours > max_age_hours {
            return Err(format!(
                "{id} artifact is stale: {}h old exceeds {max_age_hours}h ({context})",
                record.generated_age_hours,
            ));
        }

        if bool_field(artifact, "require_current_sha")
            && record.git_sha != current_sha
            && !accepted.contains(record.git_sha)
        {
            return Err(format!(
                "{id} artifact SHA {} does not match current SHA {current_sha} ({context})",
                record.git_sha,
            ));
        }
    }

    Ok(GateVerdict::ProvenPinned)
}

fn zone_isolation_feature(manifest: &Value) -> &Value {
    feature_obligation(manifest, ZONE_ISOLATION)
}

fn current_readme_status(root: &Path) -> String {
    let readme = fs::read_to_string(root.join("README.md")).expect("README.md must be readable");
    read_feature_status(&readme, ZONE_ISOLATION)
        .unwrap_or_else(|| panic!("README.md must include Zone Isolation status row"))
}

fn green_zone_artifacts() -> Vec<EvidenceRecord<'static>> {
    vec![
        EvidenceRecord {
            obligation_id: "lean-verify-zone-lattice",
            status: "green",
            git_sha: "abc123",
            generated_age_hours: 1,
        },
        EvidenceRecord {
            obligation_id: "zone-isolation-full-e2e",
            status: "green",
            git_sha: "abc123",
            generated_age_hours: 1,
        },
    ]
}

#[test]
fn manifest_registers_zone_isolation_lean_and_e2e_obligations() {
    let manifest = load_manifest(&workspace_root());
    let feature = zone_isolation_feature(&manifest);

    assert_eq!(string_field(feature, "gate_status"), "PROVEN");

    let artifact_ids = required_artifacts(feature)
        .iter()
        .map(|artifact| string_field(artifact, "id"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        artifact_ids,
        BTreeSet::from(["lean-verify-zone-lattice", "zone-isolation-full-e2e"])
    );
}

#[test]
fn manifest_obligations_have_operator_artifact_hints() {
    let manifest = load_manifest(&workspace_root());
    let feature = zone_isolation_feature(&manifest);

    for artifact in required_artifacts(feature) {
        assert!(
            !string_field(artifact, "artifact_hint").is_empty(),
            "artifact obligations must tell operators where evidence is archived"
        );
        assert!(
            !string_field(artifact, "operator_url_hint").is_empty(),
            "artifact obligations must point at the proof producer"
        );
        assert!(
            !artifact
                .get("green_markers")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty),
            "artifact obligations must define green evidence markers"
        );
    }
}

#[test]
fn current_readme_row_is_gated_before_it_can_be_marked_proven() {
    let root = workspace_root();
    let manifest = load_manifest(&root);
    let feature = zone_isolation_feature(&manifest);
    let status = current_readme_status(&root);

    let accepted = accepted_shas(feature);
    let mut records = Vec::new();
    for artifact in required_artifacts(feature) {
        let id = string_field(artifact, "id");
        let hint = string_field(artifact, "artifact_hint");
        let markers = artifact
            .get("green_markers")
            .and_then(Value::as_array)
            .expect("green_markers must be an array");
        for &sha in &accepted {
            let rel_path = hint.replace("${GITHUB_SHA}", sha);
            let full_path = root.join(&rel_path);
            if let Ok(content) = fs::read_to_string(&full_path) {
                let all_present = markers
                    .iter()
                    .filter_map(Value::as_str)
                    .all(|marker| content.contains(marker));
                if all_present {
                    records.push(EvidenceRecord {
                        obligation_id: id,
                        status: "green",
                        git_sha: sha,
                        generated_age_hours: 1,
                    });
                    break;
                }
            }
        }
    }

    let verdict = evaluate_feature_gate(feature, &status, &records, "abc123")
        .expect("current README row must be consistent with proof obligations");

    if status == "PROVEN" {
        assert_eq!(verdict, GateVerdict::ProvenPinned);
    } else {
        assert_eq!(verdict, GateVerdict::NonProven);
    }
}

#[test]
fn limited_or_implemented_rows_do_not_require_artifacts() {
    let manifest = load_manifest(&workspace_root());
    let feature = zone_isolation_feature(&manifest);

    for status in ["LIMITED", "IMPLEMENTED"] {
        assert_eq!(
            evaluate_feature_gate(feature, status, &[], "abc123").expect("non-PROVEN rows pass"),
            GateVerdict::NonProven
        );
    }
}

#[test]
fn proven_zone_isolation_requires_all_green_artifacts() {
    let manifest = load_manifest(&workspace_root());
    let feature = zone_isolation_feature(&manifest);
    let records = green_zone_artifacts();

    assert_eq!(
        evaluate_feature_gate(feature, "PROVEN", &records, "abc123")
            .expect("all green artifacts should pin PROVEN"),
        GateVerdict::ProvenPinned
    );
}

#[test]
fn proven_zone_isolation_rejects_missing_artifact() {
    let manifest = load_manifest(&workspace_root());
    let feature = zone_isolation_feature(&manifest);
    let records = [EvidenceRecord {
        obligation_id: "lean-verify-zone-lattice",
        status: "green",
        git_sha: "abc123",
        generated_age_hours: 1,
    }];

    let err = evaluate_feature_gate(feature, "PROVEN", &records, "abc123")
        .expect_err("PROVEN must fail when the E2E artifact is missing");
    assert!(err.contains("zone-isolation-full-e2e artifact is missing"));
    assert!(
        err.contains("artifact_hint=artifacts/e2e/zone_isolation_full_e2e/${GITHUB_SHA}.jsonl")
    );
    assert!(err.contains("operator_url_hint=crates/fcp-e2e/tests/zone_isolation_full_e2e.rs"));
}

#[test]
fn proven_zone_isolation_rejects_red_or_queued_artifacts() {
    let manifest = load_manifest(&workspace_root());
    let feature = zone_isolation_feature(&manifest);

    for status in ["red", "queued"] {
        let mut records = green_zone_artifacts();
        records[0].status = status;
        let err = evaluate_feature_gate(feature, "PROVEN", &records, "abc123")
            .expect_err("non-green artifacts must fail PROVEN");
        assert!(err.contains(status));
    }
}

#[test]
fn proven_zone_isolation_rejects_stale_artifact() {
    let manifest = load_manifest(&workspace_root());
    let feature = zone_isolation_feature(&manifest);
    let mut records = green_zone_artifacts();
    records[0].generated_age_hours = 25;

    let err = evaluate_feature_gate(feature, "PROVEN", &records, "abc123")
        .expect_err("stale artifacts must fail PROVEN");
    assert!(err.contains("stale"));
}

#[test]
fn proven_zone_isolation_rejects_sha_mismatch() {
    let manifest = load_manifest(&workspace_root());
    let feature = zone_isolation_feature(&manifest);
    let records = green_zone_artifacts();

    let err = evaluate_feature_gate(feature, "PROVEN", &records, "def456")
        .expect_err("SHA mismatches must fail PROVEN");
    assert!(err.contains("does not match current SHA"));
    assert!(err.contains("operator_url_hint="));
}

#[test]
fn proven_zone_isolation_accepts_explicitly_accepted_sha() {
    let manifest = load_manifest(&workspace_root());
    let mut feature = zone_isolation_feature(&manifest).clone();
    feature["accepted_shas"] = serde_json::json!(["abc123"]);

    assert_eq!(
        evaluate_feature_gate(&feature, "PROVEN", &green_zone_artifacts(), "def456")
            .expect("accepted SHA must pin an explicitly reviewed artifact"),
        GateVerdict::ProvenPinned
    );
}
