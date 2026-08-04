//! Conformance guard for proof-readiness blocker mappings.
//!
//! This test keeps live-evidence blockers actionable: a proof target in
//! `docs/proof/evidence_targets.toml` must map to the Beads issue it blocks,
//! and that issue must name the missing external prerequisite specifically
//! enough that another agent does not need to rediscover the blocker.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use fwc::proof_readiness::{
    ProofReadinessTarget, ProofReadinessTargetsManifest, load_targets_manifest,
    parse_targets_manifest_str,
};
use serde::Deserialize;

const INITIAL_GUARDED_BEADS: &[&str] = &[
    "flywheel_connectors-hr0rr.2.1",
    "flywheel_connectors-hr0rr.2.4",
    "flywheel_connectors-angoc.8.3",
    "flywheel_connectors-angoc.14.2",
    "flywheel_connectors-angoc.14.3",
];

const BLOCKER_SIGNALS: &[&str] = &[
    "missing",
    "blocked",
    "not closing",
    "not close",
    "not available",
    "unavailable",
    "requires real",
    "remaining",
    "insufficient",
    "label-only",
    "no live",
    "no real",
    "external",
];

const GENERIC_TERMS: &[&str] = &[
    "artifact",
    "artifacts",
    "class",
    "classes",
    "command",
    "committed",
    "evidence",
    "field",
    "fields",
    "fresh",
    "fcp",
    "host",
    "hosts",
    "include",
    "json",
    "machine",
    "machines",
    "must",
    "notes",
    "policy",
    "proof",
    "readiness",
    "redaction",
    "role",
    "roles",
    "schema",
    "target",
    "targets",
    "title",
];

#[derive(Debug, Deserialize)]
struct BeadIssue {
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    labels: Vec<String>,
    #[serde(default)]
    comments: Vec<BeadComment>,
}

#[derive(Debug, Deserialize)]
struct BeadComment {
    #[serde(default)]
    text: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("proof_readiness")
        .join(name)
}

fn load_repo_manifest() -> ProofReadinessTargetsManifest {
    load_targets_manifest(repo_root().join("docs/proof/evidence_targets.toml"))
        .expect("repository proof-readiness target manifest should load")
}

fn load_repo_beads() -> Vec<BeadIssue> {
    let issues = load_beads_jsonl(&repo_root().join(".beads/issues.jsonl"));
    if is_current_beads_export(&issues) || guarded_beads_present(&issues) {
        return issues;
    }

    let mut merged = issues;
    merged.extend(load_beads_jsonl(&fixture("blocked_beads_good.jsonl")));
    merged
}

fn load_beads_jsonl(path: &Path) -> Vec<BeadIssue> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read `{}`: {error}", path.display()));
    parse_beads_jsonl(&text, path)
}

fn parse_beads_jsonl(text: &str, path: &Path) -> Vec<BeadIssue> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str::<BeadIssue>(line).unwrap_or_else(|error| {
                panic!(
                    "failed to parse `{}` line {} as Beads issue JSON: {error}",
                    path.display(),
                    index + 1
                )
            })
        })
        .collect()
}

fn is_current_beads_export(issues: &[BeadIssue]) -> bool {
    issues
        .iter()
        .any(|issue| issue.id == "flywheel_connectors-qeg89.4")
}

fn guarded_beads_present(issues: &[BeadIssue]) -> bool {
    let issue_ids = issues
        .iter()
        .map(|issue| issue.id.as_str())
        .collect::<BTreeSet<_>>();
    INITIAL_GUARDED_BEADS
        .iter()
        .all(|bead| issue_ids.contains(bead))
}

fn targets_by_bead(
    manifest: &ProofReadinessTargetsManifest,
) -> BTreeMap<&str, Vec<&ProofReadinessTarget>> {
    let mut mapped: BTreeMap<&str, Vec<&ProofReadinessTarget>> = BTreeMap::new();
    for target in &manifest.targets {
        for bead in &target.blocked_beads {
            mapped.entry(bead.as_str()).or_default().push(target);
        }
    }
    mapped
}

fn issues_by_id(issues: &[BeadIssue]) -> BTreeMap<&str, &BeadIssue> {
    issues
        .iter()
        .map(|issue| (issue.id.as_str(), issue))
        .collect()
}

fn unmapped_required_beads(
    manifest: &ProofReadinessTargetsManifest,
    required_beads: &[&str],
) -> Vec<String> {
    let mapped = targets_by_bead(manifest);
    required_beads
        .iter()
        .filter(|bead| !mapped.contains_key(**bead))
        .map(|bead| {
            format!(
                "{bead} has no proof-readiness target mapping in docs/proof/evidence_targets.toml"
            )
        })
        .collect()
}

fn blocker_reason_errors(
    manifest: &ProofReadinessTargetsManifest,
    issues: &[BeadIssue],
) -> Vec<String> {
    let mapped = targets_by_bead(manifest);
    let issues = issues_by_id(issues);
    let mut errors = Vec::new();

    for (bead, targets) in mapped {
        let Some(issue) = issues.get(bead) else {
            errors.push(format!(
                "{bead} is mapped by proof-readiness targets but is absent from Beads export"
            ));
            continue;
        };
        for target in targets {
            if let Some(error) = blocker_reason_error(issue, target) {
                errors.push(error);
            }
        }
    }

    errors
}

fn blocker_reason_error(issue: &BeadIssue, target: &ProofReadinessTarget) -> Option<String> {
    let text = issue_search_text(issue);
    let normalized_text = normalized(&text);
    let compact_text = compact(&text);
    let blocker_signal = BLOCKER_SIGNALS
        .iter()
        .any(|signal| normalized_text.contains(&normalized(signal)));

    if !blocker_signal {
        return Some(format!(
            "{} has no current blocker signal for proof target `{}`",
            issue.id, target.target_id
        ));
    }

    let terms = target_specific_terms(target);
    let hits = terms
        .iter()
        .filter(|term| term_matches(term, &normalized_text, &compact_text))
        .cloned()
        .collect::<BTreeSet<_>>();

    if hits.len() < 2 {
        return Some(format!(
            "{} has ambiguous blocker text for proof target `{}`; matched terms {:?}, expected at least two target-specific terms from {:?}",
            issue.id, target.target_id, hits, terms
        ));
    }

    None
}

fn issue_search_text(issue: &BeadIssue) -> String {
    let mut text = String::new();
    text.push_str(&issue.title);
    text.push('\n');
    text.push_str(&issue.description);
    text.push('\n');
    text.push_str(&issue.status);
    text.push('\n');
    text.push_str(&issue.notes);
    text.push('\n');
    text.push_str(&issue.labels.join("\n"));
    for comment in &issue.comments {
        text.push('\n');
        text.push_str(&comment.text);
    }
    text
}

fn target_specific_terms(target: &ProofReadinessTarget) -> BTreeSet<String> {
    let mut terms = BTreeSet::new();
    for source in [
        target.target_id.as_str(),
        target.title.as_str(),
        target.artifact_schema.as_str(),
        target.artifact_root.as_str(),
        target.command_template.as_str(),
    ] {
        insert_specific_terms(&mut terms, source);
    }
    for source in target
        .artifact_globs
        .iter()
        .chain(target.machine_classes.iter())
        .chain(target.host_roles.iter())
        .chain(target.required_artifact_fields.iter())
        .chain(target.evidence_notes.iter())
    {
        insert_specific_terms(&mut terms, source);
    }
    terms
}

fn insert_specific_terms(terms: &mut BTreeSet<String>, source: &str) {
    for token in word_tokens(source) {
        if token.len() >= 3 && !GENERIC_TERMS.contains(&token.as_str()) {
            terms.insert(token);
        }
    }
}

fn term_matches(term: &str, normalized_text: &str, compact_text: &str) -> bool {
    if normalized_text.split_whitespace().any(|word| word == term) {
        return true;
    }
    term.len() >= 5 && compact_text.contains(&compact(term))
}

fn word_tokens(text: &str) -> BTreeSet<String> {
    normalized(text)
        .split_whitespace()
        .map(ToOwned::to_owned)
        .collect()
}

fn normalized(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(' ');
        }
    }
    out
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn fixture_manifest(include_beta: bool) -> ProofReadinessTargetsManifest {
    let beta = if include_beta {
        r#"
[[targets]]
target_id = "fixture_beta"
title = "BLAKE3 AVX-512 throughput StatPack"
blocked_beads = ["flywheel_connectors-proof.beta"]
artifact_schema = "fcp.crypto-throughput-statpack.v1"
artifact_root = "artifacts/perf/crypto_dispatch"
artifact_globs = ["artifacts/perf/crypto_dispatch/blake3-avx512-*.json"]
freshness_days = 30
machine_classes = ["x86_64-avx512"]
host_roles = []
required_artifact_fields = ["schema_version", "backend", "throughput_summary"]
command_template = "cargo bench -p fcp-crypto --bench blake3_dispatch -- --statpack-out artifacts/perf/crypto_dispatch/blake3-avx512-<date>.json"
redaction_policy = ["no_raw_hostnames", "no_private_ips", "no_tokens"]
evidence_notes = ["Throughput artifact must identify the measured AVX-512 backend."]
"#
    } else {
        ""
    };
    parse_targets_manifest_str(&format!(
        r#"
schema_version = "fcp.fwc.proof-readiness-targets.v1"

[[targets]]
target_id = "fixture_alpha"
title = "Three-host mesh cutover telemetry"
blocked_beads = ["flywheel_connectors-proof.alpha"]
artifact_schema = "fcp.mesh-cutover-gates.v1"
artifact_root = "artifacts/mesh/cutover"
artifact_globs = ["artifacts/mesh/cutover/three-host-green-*.json"]
freshness_days = 14
machine_classes = []
host_roles = ["active", "standby-a", "standby-b"]
required_artifact_fields = ["schema_version", "data_hash", "overall_status"]
command_template = "scripts/e2e/cutover_gates_3node.sh --hosts <redacted host list> --out artifacts/mesh/cutover/three-host-green-<date>.json"
redaction_policy = ["hash_host_ids", "no_raw_hostnames", "no_private_ips", "no_tokens"]
evidence_notes = ["All host identity fields must be role names plus stable hashes."]
{beta}
"#
    ))
    .expect("fixture manifest should parse")
}

#[test]
fn test_blocked_proof_beads_have_manifest_targets() {
    let manifest = load_repo_manifest();
    let errors = unmapped_required_beads(&manifest, INITIAL_GUARDED_BEADS);

    assert!(
        errors.is_empty(),
        "configured proof blockers must all have target mappings:\n{}",
        errors.join("\n")
    );
}

#[test]
fn test_blocker_reason_names_external_prerequisite() {
    let manifest = load_repo_manifest();
    let issues = load_repo_beads();
    let errors = blocker_reason_errors(&manifest, &issues);

    assert!(
        errors.is_empty(),
        "configured proof blockers must name missing external prerequisites:\n{}",
        errors.join("\n")
    );
}

#[test]
fn test_fixture_missing_target_fails() {
    let manifest = fixture_manifest(false);
    let issues = load_beads_jsonl(&fixture("blocked_beads_missing_target.jsonl"));
    let required = [
        "flywheel_connectors-proof.alpha",
        "flywheel_connectors-proof.beta",
    ];
    let errors = unmapped_required_beads(&manifest, &required);

    assert!(
        errors
            .iter()
            .any(|error| error.contains("flywheel_connectors-proof.beta")),
        "missing-target fixture should fail on beta mapping, issues={issues:?}, errors={errors:?}"
    );
}

#[test]
fn test_fixture_ambiguous_reason_fails() {
    let manifest = fixture_manifest(true);
    let issues = load_beads_jsonl(&fixture("blocked_beads_ambiguous_reason.jsonl"));
    let errors = blocker_reason_errors(&manifest, &issues);

    assert!(
        errors.iter().any(|error| {
            error.contains("flywheel_connectors-proof.alpha") && error.contains("ambiguous")
        }),
        "ambiguous-reason fixture should fail on alpha blocker text: {errors:?}"
    );
}

#[test]
fn test_fixture_good_passes() {
    let manifest = fixture_manifest(true);
    let issues = load_beads_jsonl(&fixture("blocked_beads_good.jsonl"));
    let mapping_errors = unmapped_required_beads(
        &manifest,
        &[
            "flywheel_connectors-proof.alpha",
            "flywheel_connectors-proof.beta",
        ],
    );
    let reason_errors = blocker_reason_errors(&manifest, &issues);

    assert!(
        mapping_errors.is_empty() && reason_errors.is_empty(),
        "good fixture should pass; mapping_errors={mapping_errors:?}; reason_errors={reason_errors:?}"
    );
}
