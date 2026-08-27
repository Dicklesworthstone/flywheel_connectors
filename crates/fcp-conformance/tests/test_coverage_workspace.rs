//! Workspace-level connector test coverage ratchet.
//!
//! `flywheel_connectors-4kw5f.11` tracks a real gap: several manifest-backed
//! connectors currently have no crate-local `tests/` directory at all. This
//! guard intentionally lands before the per-connector test suites so new
//! connector crates cannot add another silent gap, and so each repaired
//! connector must shrink the pinned gap list below.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::json;

const EXPECTED_MISSING_TEST_DIRS: &[&str] = &[];

#[derive(Debug, Clone)]
struct ConnectorTestCoverageRecord {
    connector: String,
    manifest_path: String,
    tests_path: String,
    has_tests_dir: bool,
    local_untracked_tests_dir_ignored: bool,
    rust_test_files: Vec<String>,
    known_gap: bool,
}

impl ConnectorTestCoverageRecord {
    const fn effective_has_tracked_tests_dir(&self) -> bool {
        self.has_tests_dir && !self.local_untracked_tests_dir_ignored
    }

    const fn gap_reason(&self) -> &'static str {
        if self.local_untracked_tests_dir_ignored {
            "known_gap_untracked_local_tests_dir_ignored"
        } else if !self.has_tests_dir {
            "missing_tests_dir"
        } else {
            "none"
        }
    }

    fn to_json(&self, command_line: &str, git_revision: &str) -> serde_json::Value {
        json!({
            "event": "connector_test_coverage",
            "command_line": command_line,
            "git_revision": git_revision,
            "connector": self.connector,
            "manifest_path": self.manifest_path,
            "tests_path": self.tests_path,
            "has_tests_dir": self.has_tests_dir,
            "effective_has_tracked_tests_dir": self.effective_has_tracked_tests_dir(),
            "local_untracked_tests_dir_ignored": self.local_untracked_tests_dir_ignored,
            "rust_test_file_count": self.rust_test_files.len(),
            "rust_test_files": self.rust_test_files,
            "known_gap": self.known_gap,
            "gap_reason": self.gap_reason(),
            "redaction_decision": "connector names and repository-relative test paths only; no credentials, payloads, transcripts, prompts, or PII read",
            "cleanup_result": "not_applicable_no_temp_resources",
            "skip_reason": "runtime execution skipped; workspace filesystem coverage is sufficient for this conformance ratchet",
        })
    }
}

fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot derive workspace root from CARGO_MANIFEST_DIR".to_owned())
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).map_or_else(
        |_| path.display().to_string(),
        |relative| relative.display().to_string(),
    )
}

fn current_command_line() -> String {
    env::args().collect::<Vec<_>>().join(" ")
}

fn current_git_revision(root: &Path) -> String {
    let Ok(output) = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(root)
        .output()
    else {
        return "unknown".to_owned();
    };
    if !output.status.success() {
        return "unknown".to_owned();
    }
    String::from_utf8(output.stdout)
        .map(|stdout| stdout.trim().to_owned())
        .ok()
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn is_untracked_path(root: &Path, relative_path: &str) -> bool {
    let output = Command::new("git")
        .args(["status", "--porcelain", "--", relative_path])
        .current_dir(root)
        .output();
    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    String::from_utf8(output.stdout)
        .is_ok_and(|stdout| stdout.lines().any(|line| line.starts_with("?? ")))
}

fn expected_missing_tests_dirs() -> BTreeSet<String> {
    EXPECTED_MISSING_TEST_DIRS
        .iter()
        .map(|connector| (*connector).to_owned())
        .collect()
}

fn rust_test_files(root: &Path, tests_dir: &Path) -> Result<Vec<String>, String> {
    if !tests_dir.is_dir() {
        return Ok(Vec::new());
    }
    let entries = fs::read_dir(tests_dir)
        .map_err(|err| format!("cannot read {}: {err}", tests_dir.display()))?;
    let mut files = Vec::new();
    for entry_result in entries {
        let entry =
            entry_result.map_err(|err| format!("cannot read tests directory entry: {err}"))?;
        let path = entry.path();
        if !path.is_file() || path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        files.push(display_path(root, &path));
    }
    files.sort();
    Ok(files)
}

fn discover_connector_test_coverage(
    root: &Path,
) -> Result<Vec<ConnectorTestCoverageRecord>, String> {
    let connectors_dir = root.join("connectors");
    let expected_gaps = expected_missing_tests_dirs();
    let entries = fs::read_dir(&connectors_dir)
        .map_err(|err| format!("cannot read {}: {err}", connectors_dir.display()))?;
    let mut records = Vec::new();

    for entry_result in entries {
        let entry =
            entry_result.map_err(|err| format!("cannot read connector directory entry: {err}"))?;
        let candidate_dir = entry.path();
        if !candidate_dir.is_dir() {
            continue;
        }
        let manifest_path = candidate_dir.join("manifest.toml");
        if !manifest_path.is_file() {
            continue;
        }
        let Some(connector) = candidate_dir
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
        else {
            continue;
        };
        let tests_dir = candidate_dir.join("tests");
        let tests_path = display_path(root, &tests_dir);
        let known_gap = expected_gaps.contains(&connector);
        let local_untracked_tests_dir_ignored =
            known_gap && tests_dir.is_dir() && is_untracked_path(root, &tests_path);
        let rust_test_files = if local_untracked_tests_dir_ignored {
            Vec::new()
        } else {
            rust_test_files(root, &tests_dir)?
        };
        records.push(ConnectorTestCoverageRecord {
            known_gap,
            connector,
            manifest_path: display_path(root, &manifest_path),
            has_tests_dir: tests_dir.is_dir(),
            local_untracked_tests_dir_ignored,
            tests_path,
            rust_test_files,
        });
    }

    records.sort_by(|left, right| left.connector.cmp(&right.connector));
    Ok(records)
}

fn emit_json_line(value: &serde_json::Value) {
    match serde_json::to_string(value) {
        Ok(line) => println!("{line}"),
        Err(error) => {
            println!("{{\"event\":\"connector_test_coverage_json_failed\",\"error\":\"{error}\"}}");
        }
    }
}

#[test]
fn expected_missing_tests_dirs_are_sorted_unique_and_real_connectors() -> Result<(), String> {
    for pair in EXPECTED_MISSING_TEST_DIRS.windows(2) {
        assert!(
            pair[0] < pair[1],
            "EXPECTED_MISSING_TEST_DIRS must stay sorted and unique"
        );
    }

    let root = workspace_root()?;
    let records = discover_connector_test_coverage(&root)?;
    let known_connectors = records
        .iter()
        .map(|record| record.connector.clone())
        .collect::<BTreeSet<_>>();
    let expected_gaps = expected_missing_tests_dirs();
    assert_eq!(
        expected_gaps.len(),
        EXPECTED_MISSING_TEST_DIRS.len(),
        "EXPECTED_MISSING_TEST_DIRS must not contain duplicates"
    );

    let unknown_expected_gaps = expected_gaps
        .difference(&known_connectors)
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        unknown_expected_gaps.is_empty(),
        "expected missing-test entries must name real manifest-backed connectors: {unknown_expected_gaps:?}"
    );
    Ok(())
}

#[test]
fn workspace_connector_tests_directory_gaps_are_explicitly_tracked() -> Result<(), String> {
    let root = workspace_root()?;
    let records = discover_connector_test_coverage(&root)?;
    let command_line = current_command_line();
    let git_revision = current_git_revision(&root);
    let expected_gaps = expected_missing_tests_dirs();
    let actual_gaps = records
        .iter()
        .filter(|record| !record.effective_has_tracked_tests_dir())
        .map(|record| record.connector.clone())
        .collect::<BTreeSet<_>>();

    let unexpected_gaps = actual_gaps
        .difference(&expected_gaps)
        .cloned()
        .collect::<Vec<_>>();
    let fixed_but_still_expected = expected_gaps
        .difference(&actual_gaps)
        .cloned()
        .collect::<Vec<_>>();

    emit_json_line(&json!({
        "event": "connector_test_coverage_summary",
        "command_line": command_line,
        "git_revision": git_revision,
        "manifest_backed_connector_count": records.len(),
        "missing_tests_dir_count": actual_gaps.len(),
        "expected_missing_tests_dirs": expected_gaps,
        "actual_missing_tests_dirs": actual_gaps,
        "unexpected_missing_tests_dirs": unexpected_gaps,
        "fixed_but_still_expected": fixed_but_still_expected,
        "redaction_decision": "connector names and repository-relative test paths only; no credentials, payloads, transcripts, prompts, or PII read",
        "cleanup_result": "not_applicable_no_temp_resources",
        "skip_reason": "runtime execution skipped; workspace filesystem coverage is sufficient for this conformance ratchet",
    }));

    for record in records
        .iter()
        .filter(|record| !record.effective_has_tracked_tests_dir())
    {
        emit_json_line(&record.to_json(&command_line, &git_revision));
    }

    assert!(
        unexpected_gaps.is_empty() && fixed_but_still_expected.is_empty(),
        "connector tests/ directory gap list drifted; unexpected_missing={unexpected_gaps:?}; fixed_but_still_expected={fixed_but_still_expected:?}"
    );
    Ok(())
}

#[test]
fn existing_connector_tests_dirs_contain_rust_test_files() -> Result<(), String> {
    let root = workspace_root()?;
    let records = discover_connector_test_coverage(&root)?;
    let command_line = current_command_line();
    let git_revision = current_git_revision(&root);
    let empty_test_dirs = records
        .iter()
        .filter(|record| {
            record.effective_has_tracked_tests_dir() && record.rust_test_files.is_empty()
        })
        .collect::<Vec<_>>();

    if !empty_test_dirs.is_empty() {
        for record in &empty_test_dirs {
            emit_json_line(&record.to_json(&command_line, &git_revision));
        }
    }

    assert!(
        empty_test_dirs.is_empty(),
        "manifest-backed connector tests/ directories must contain at least one Rust test file"
    );
    Ok(())
}
