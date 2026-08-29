//! Alignment checks between `specs/tla/cutover.tla` and the host-side cutover
//! state-machine mirror.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use fcp_host::{
    CUTOVER_TLA_INVARIANT_CLAUSES, CutoverAction, CutoverRuntimeSnapshot, CutoverState,
    assert_cutover_invariants,
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
            annotation_name(chunk)
                .unwrap_or_else(|| panic!("cutover assert! lacks TLA_INVARIANT annotation"))
        })
        .collect()
}

#[test]
fn test_every_tla_state_maps_to_rust_enum() {
    let tla = read_workspace_file("specs/tla/cutover.tla");
    let rust = read_workspace_file("crates/fcp-host/src/cutover/state_machine.rs");

    let tla_states = parse_tla_string_set(&tla, "CutoverStates");
    let rust_states = parse_rust_enum_variants(&rust, "CutoverState");
    let runtime_states: BTreeSet<_> = CutoverState::ALL
        .into_iter()
        .map(|state| state.tla_name().to_owned())
        .collect();

    assert_eq!(tla_states, rust_states);
    assert_eq!(tla_states, runtime_states);
    for state in &tla_states {
        CutoverState::try_from(state.as_str()).expect("TLA+ state maps to Rust discriminant");
        assert_cutover_invariants(&CutoverRuntimeSnapshot::from_state(
            CutoverState::try_from(state.as_str()).expect("known state"),
        ));
    }
}

#[test]
fn test_every_tla_action_has_rust_handler() {
    let tla = read_workspace_file("specs/tla/cutover.tla");
    let rust = read_workspace_file("crates/fcp-host/src/cutover/state_machine.rs");

    let tla_actions = parse_tla_string_set(&tla, "OperatorActions");
    let rust_actions = parse_rust_enum_variants(&rust, "CutoverAction");
    let runtime_actions: BTreeSet<_> = CutoverAction::ALL
        .into_iter()
        .map(|action| action.tla_name().to_owned())
        .collect();

    assert_eq!(tla_actions, rust_actions);
    assert_eq!(tla_actions, runtime_actions);
    for action in &tla_actions {
        CutoverAction::try_from(action.as_str()).expect("TLA+ action maps to Rust handler");
    }
}

#[test]
fn test_invariant_safety_matches_rust_assertion() {
    let tla = read_workspace_file("specs/tla/cutover.tla");
    let rust = read_workspace_file("crates/fcp-host/src/cutover/state_machine.rs");

    let annotated = annotated_assertions(&rust);
    let exported: BTreeSet<_> = CUTOVER_TLA_INVARIANT_CLAUSES
        .iter()
        .map(|clause| (*clause).to_owned())
        .collect();

    assert_eq!(annotated, exported);
    assert!(
        annotated.iter().any(|name| name.starts_with("Safety_")),
        "at least one Rust assertion must map to a Safety clause"
    );
    for clause in &annotated {
        assert!(
            tla.contains(&format!("{clause} ==")),
            "Rust assertion maps to missing TLA+ invariant clause {clause}"
        );
    }
}

#[test]
fn test_broken_spec_caught_by_tlc() {
    let Ok(jar) = std::env::var("TLA2TOOLS_JAR") else {
        eprintln!("skipping TLC failure smoke: TLA2TOOLS_JAR is not set");
        return;
    };
    let root = repo_root();
    let jar = {
        let candidate = Path::new(&jar);
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
        "fcp-tla-cutover-broken-{}-{now_nanos}",
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
            "specs/tla/cutover.cfg",
            "specs/tla/_fixtures/cutover_broken.tla",
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
        combined_output.contains("Safety"),
        "TLC failure should name the Safety invariant:\n{combined_output}"
    );
}
