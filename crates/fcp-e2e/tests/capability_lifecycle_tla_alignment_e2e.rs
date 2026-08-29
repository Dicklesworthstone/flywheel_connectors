//! Alignment checks between `specs/tla/capability_lifecycle.tla` and the
//! `fcp-core` capability lifecycle runtime mirror.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use fcp_core::{
    CAPABILITY_LIFECYCLE_TLA_INVARIANT_CLAUSES, CAPABILITY_LIFECYCLE_TRANSITIONS,
    CapabilityLifecycle, CapabilityLifecycleError, CapabilityLifecycleState,
    CapabilityLifecycleTransition, ObjectId, assert_capability_lifecycle_invariants,
};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("CARGO_MANIFEST_DIR is crates/fcp-e2e")
        .to_path_buf()
}

fn read_workspace_file(path: impl AsRef<Path>) -> String {
    std::fs::read_to_string(repo_root().join(path.as_ref()))
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.as_ref().display()))
}

fn parse_tla_string_set(source: &str, operator: &str) -> BTreeSet<String> {
    let prefix = format!("{operator} ==");
    let line = source
        .lines()
        .find(|line| line.trim_start().starts_with(&prefix))
        .unwrap_or_else(|| panic!("missing TLA+ operator {operator}"));
    let (_, raw_set) = line
        .split_once("==")
        .unwrap_or_else(|| panic!("malformed TLA+ set operator {operator}"));
    let raw_set = raw_set
        .trim()
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .unwrap_or_else(|| panic!("TLA+ operator {operator} is not a string set"));
    raw_set
        .split(',')
        .map(str::trim)
        .map(|value| {
            value
                .strip_prefix('"')
                .and_then(|inner| inner.strip_suffix('"'))
                .unwrap_or_else(|| panic!("TLA+ set member {value} is not a string"))
                .to_owned()
        })
        .collect()
}

fn parse_tla_transition_set(source: &str, operator: &str) -> BTreeSet<(String, String)> {
    let prefix = format!("{operator} ==");
    let line = source
        .lines()
        .find(|line| line.trim_start().starts_with(&prefix))
        .unwrap_or_else(|| panic!("missing TLA+ operator {operator}"));
    let (_, raw_set) = line
        .split_once("==")
        .unwrap_or_else(|| panic!("malformed TLA+ set operator {operator}"));
    let raw_set = raw_set
        .trim()
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .unwrap_or_else(|| panic!("TLA+ operator {operator} is not a transition set"));

    raw_set
        .split(">>,")
        .map(str::trim)
        .map(|value| {
            let tuple = if value.ends_with(">>") {
                value.to_owned()
            } else {
                format!("{value}>>")
            };
            let tuple = tuple
                .strip_prefix("<<")
                .and_then(|value| value.strip_suffix(">>"))
                .unwrap_or_else(|| panic!("TLA+ transition {tuple} is not a tuple"));
            let (from, to) = tuple
                .split_once(',')
                .unwrap_or_else(|| panic!("TLA+ transition {tuple} is not a pair"));
            (
                parse_tla_string_literal(from.trim()),
                parse_tla_string_literal(to.trim()),
            )
        })
        .collect()
}

fn parse_tla_string_literal(value: &str) -> String {
    value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or_else(|| panic!("TLA+ value {value} is not a string literal"))
        .to_owned()
}

fn parse_rust_enum_variants(source: &str, enum_name: &str) -> BTreeSet<String> {
    let enum_start = format!("pub enum {enum_name} {{");
    let body = source
        .split_once(&enum_start)
        .unwrap_or_else(|| panic!("missing Rust enum {enum_name}"))
        .1
        .split_once('}')
        .unwrap_or_else(|| panic!("unterminated Rust enum {enum_name}"))
        .0;
    body.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with("///") || line.starts_with("#[") {
                return None;
            }
            line.split_once(',')
                .map(|(variant, _)| variant.trim().to_owned())
        })
        .collect()
}

fn annotation_name(chunk: &str) -> Option<String> {
    let marker = "TLA_INVARIANT:";
    let (_, suffix) = chunk.split_once(marker)?;
    let name: String = suffix
        .chars()
        .take_while(|value| value.is_ascii_alphanumeric() || *value == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

fn annotated_assertions(source: &str) -> BTreeSet<String> {
    source
        .split("assert!(")
        .skip(1)
        .map(|chunk| {
            annotation_name(chunk).unwrap_or_else(|| {
                panic!("capability lifecycle assert! lacks TLA_INVARIANT annotation")
            })
        })
        .collect()
}

#[test]
fn test_every_tla_transition_has_rust_path() {
    let tla = read_workspace_file("specs/tla/capability_lifecycle.tla");
    let rust = read_workspace_file("crates/fcp-core/src/capability.rs");

    let tla_states = parse_tla_string_set(&tla, "CapabilityStates");
    let rust_states = parse_rust_enum_variants(&rust, "CapabilityLifecycleState");
    let runtime_states: BTreeSet<_> = CapabilityLifecycleState::ALL
        .into_iter()
        .map(|state| state.tla_name().to_owned())
        .collect();

    assert_eq!(tla_states, rust_states);
    assert_eq!(tla_states, runtime_states);
    for state in &tla_states {
        CapabilityLifecycleState::try_from(state.as_str())
            .expect("TLA+ state maps to Rust discriminant");
    }

    let tla_actions = parse_tla_string_set(&tla, "CapabilityActions");
    let rust_actions = parse_rust_enum_variants(&rust, "CapabilityLifecycleTransition");
    let runtime_actions: BTreeSet<_> = CapabilityLifecycleTransition::ALL
        .into_iter()
        .map(|transition| transition.tla_name().to_owned())
        .collect();

    assert_eq!(tla_actions, rust_actions);
    assert_eq!(tla_actions, runtime_actions);
    for action in &tla_actions {
        CapabilityLifecycleTransition::try_from(action.as_str())
            .expect("TLA+ action maps to Rust transition");
    }

    let tla_transitions = parse_tla_transition_set(&tla, "CapabilityTransitions");
    let runtime_transition_pairs: BTreeSet<_> = CapabilityLifecycleTransition::ALL
        .into_iter()
        .map(|transition| {
            (
                transition.from_state().tla_name().to_owned(),
                transition.to_state().tla_name().to_owned(),
            )
        })
        .collect();
    let exported_transition_pairs: BTreeSet<_> = CAPABILITY_LIFECYCLE_TRANSITIONS
        .iter()
        .map(|(from, to)| (from.tla_name().to_owned(), to.tla_name().to_owned()))
        .collect();

    assert_eq!(tla_transitions, runtime_transition_pairs);
    assert_eq!(tla_transitions, exported_transition_pairs);
}

#[test]
fn test_revoke_before_use_invariant_rust_assertion() {
    let tla = read_workspace_file("specs/tla/capability_lifecycle.tla");
    let rust = read_workspace_file("crates/fcp-core/src/capability.rs");
    let invariant_body = rust
        .split_once("pub fn assert_capability_lifecycle_invariants")
        .expect("capability invariant function exists")
        .1
        .split_once("/// Small runtime mirror")
        .expect("capability lifecycle mirror follows invariant function")
        .0;

    let annotated = annotated_assertions(invariant_body);
    let exported: BTreeSet<_> = CAPABILITY_LIFECYCLE_TLA_INVARIANT_CLAUSES
        .iter()
        .map(|clause| (*clause).to_owned())
        .collect();

    assert_eq!(annotated, exported);
    assert!(
        annotated.contains("RevokeBeforeUse"),
        "runtime assertions must include the revoke-before-use invariant"
    );
    for clause in &annotated {
        assert!(
            tla.contains(&format!("{clause} ==")),
            "Rust assertion maps to missing TLA+ invariant clause {clause}"
        );
    }

    let mut lifecycle = CapabilityLifecycle::approved(3);
    lifecycle.revoke().expect("approved token can be revoked");
    assert_capability_lifecycle_invariants(&lifecycle.snapshot());
    assert_eq!(
        lifecycle
            .mark_used(ObjectId::from_unscoped_bytes(
                b"capability-lifecycle-revoked-receipt"
            ))
            .expect_err("revoked token cannot emit a receipt"),
        CapabilityLifecycleError::RevokedBeforeUse
    );
    lifecycle
        .advance_revocation_clock()
        .expect("revocation can age within SLO");
    lifecycle
        .push_revocation()
        .expect("pending revocation can be pushed");
    assert_capability_lifecycle_invariants(&lifecycle.snapshot());
}

#[test]
fn test_double_spend_rejected_at_runtime() {
    let mut lifecycle = CapabilityLifecycle::approved(3);
    let first_receipt = ObjectId::from_unscoped_bytes(b"capability-lifecycle-receipt-a");
    let second_receipt = ObjectId::from_unscoped_bytes(b"capability-lifecycle-receipt-b");

    lifecycle
        .mark_used(first_receipt)
        .expect("approved token emits first receipt");
    assert_eq!(lifecycle.state(), CapabilityLifecycleState::Used);
    assert_eq!(lifecycle.used_receipt_id(), Some(first_receipt));
    assert_capability_lifecycle_invariants(&lifecycle.snapshot());

    assert_eq!(
        lifecycle
            .mark_used(second_receipt)
            .expect_err("used token cannot emit a second receipt"),
        CapabilityLifecycleError::AlreadyUsed
    );
    assert_eq!(lifecycle.used_receipt_id(), Some(first_receipt));
}

#[test]
fn test_broken_spec_caught_by_tlc() {
    let Ok(jar) = std::env::var("TLA2TOOLS_JAR") else {
        eprintln!("skipping TLC failure smoke: TLA2TOOLS_JAR is not set");
        return;
    };
    let root = repo_root();
    let jar = {
        let candidate = std::path::Path::new(&jar);
        if candidate.is_absolute() {
            jar
        } else {
            root.join(candidate).display().to_string()
        }
    };
    let now_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after UNIX_EPOCH")
        .as_nanos();
    let metadir = std::env::temp_dir().join(format!(
        "fcp-tla-capability-lifecycle-broken-{}-{now_nanos}",
        std::process::id()
    ));
    let metadir = metadir.display().to_string();
    // TLC v1.7.4 (TLC2 2.19) cannot resolve the spec through an absolute
    // path: it then fails to read the configuration file with a misleading
    // "File not found" ConfigFileException. Run with the repo root as the
    // working directory and pass the cfg/spec as relative paths; the jar
    // may stay absolute.
    let output = Command::new("java")
        .current_dir(&root)
        .args([
            "-cp",
            jar.as_str(),
            "tlc2.TLC",
            "-deadlock",
            "-metadir",
            metadir.as_str(),
            "-config",
            "specs/tla/capability_lifecycle.cfg",
            "specs/tla/_fixtures/capability_lifecycle_broken.tla",
        ])
        .output()
        .expect("TLC failure smoke launches java");
    let combined_output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.status.success(),
        "broken fixture unexpectedly passed TLC:\n{combined_output}"
    );
    assert!(
        combined_output.contains("RevokeBeforeUse"),
        "TLC failure should name the RevokeBeforeUse invariant:\n{combined_output}"
    );
}
