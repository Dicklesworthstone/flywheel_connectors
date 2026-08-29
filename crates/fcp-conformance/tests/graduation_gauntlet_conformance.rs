use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

const EXPECTED_CHECKS: [(&str, i32); 12] = [
    ("connector_path", 1),
    ("operations_info", 2),
    ("manifest_present", 3),
    ("readme_present", 4),
    ("verification_script_declared", 5),
    ("manifest_operations", 6),
    ("local_non_mock", 7),
    ("readme_status_match", 8),
    ("operation_inventory", 9),
    ("network_policy", 10),
    ("sandbox_profile", 11),
    ("operator_guidance", 12),
];

/// Parse a `NAME=( "a" "b" )` string array out of a bash script.
///
/// The graduation scripts (`run_gauntlet.sh`, `batch4_inventory.sh`) are the
/// source of truth for batch rosters; these tests parse them instead of
/// pinning a copy so roster edits cannot silently drift from the assertions.
fn parse_bash_string_array(script: &str, array_name: &str) -> Vec<String> {
    let mut entries = Vec::new();
    let mut in_array = false;
    for line in script.lines() {
        let trimmed = line.trim();
        if !in_array {
            if trimmed.starts_with(&format!("{array_name}=(")) {
                in_array = true;
            }
            continue;
        }
        if trimmed.starts_with(')') {
            break;
        }
        let entry = trimmed.trim_matches(|c| c == '"' || c == '\'');
        if !entry.is_empty() {
            entries.push(entry.to_string());
        }
    }
    entries
}

/// A hardcoded batch roster, parsed out of `run_gauntlet.sh` itself.
fn gauntlet_script_roster(array_name: &str) -> Vec<String> {
    let script = fs::read_to_string(gauntlet_runner()).expect("run_gauntlet.sh should be readable");
    let roster = parse_bash_string_array(&script, array_name);
    assert!(
        !roster.is_empty(),
        "run_gauntlet.sh should define a non-empty {array_name} roster"
    );
    roster
}

/// The batch1-3 exclusion list (bare connector names) from `batch4_inventory.sh`.
fn batch1_to_3_exclusion() -> BTreeSet<String> {
    let script = fs::read_to_string(batch4_inventory_runner())
        .expect("batch4_inventory.sh should be readable");
    let excluded = parse_bash_string_array(&script, "BATCH1_TO_3_CONNECTORS");
    assert!(
        !excluded.is_empty(),
        "batch4_inventory.sh should define a non-empty BATCH1_TO_3_CONNECTORS exclusion list"
    );
    excluded.into_iter().collect()
}

/// The current batch4 long-tail roster, straight from the inventory script
/// that `run_gauntlet.sh --batch batch4` itself consumes.
fn batch4_inventory_list() -> Vec<String> {
    let output = Command::new("bash")
        .current_dir(workspace_root())
        .arg(batch4_inventory_runner())
        .output()
        .expect("batch4 inventory runner should list connectors");
    assert!(
        output.status.success(),
        "batch4 inventory list failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

/// Mirror of `status_line_for` in `batch4_inventory.sh`: the first
/// `> **Status**: ...` line of the connector README, if any.
fn readme_status_line(connector_dir: &Path) -> Option<String> {
    let readme = fs::read_to_string(connector_dir.join("README.md")).ok()?;
    readme
        .lines()
        .find_map(|line| line.strip_prefix("> **Status**: "))
        .map(str::to_string)
}

/// Mirror of `is_batch4_status` in `batch4_inventory.sh`.
fn is_long_tail_status(status: Option<&str>) -> bool {
    let Some(status) = status else {
        return true; // NO_STATUS
    };
    let lower = status.to_lowercase();
    lower.contains("incubat")
        || lower.contains("planning contract")
        || lower.contains("retrofit contract")
        || lower.contains("first-slice")
}

/// Mirror of `graduation_check_readme_status_match` in
/// `scripts/graduation/checks/core.sh`: the check passes iff the README status
/// line contains the word PROVEN and the manifest declares `status = "proven"`.
/// Missing files pass vacuously (the ladder's manifest_present/readme_present
/// checks fail first in that case).
fn readme_status_match_expected_verdict(connector_dir: &Path) -> &'static str {
    let readme_path = connector_dir.join("README.md");
    let manifest_path = connector_dir.join("manifest.toml");
    if !readme_path.is_file() || !manifest_path.is_file() {
        return "pass";
    }
    let readme = fs::read_to_string(&readme_path).expect("connector README should be readable");
    let manifest =
        fs::read_to_string(&manifest_path).expect("connector manifest should be readable");
    let readme_proven = readme.lines().any(|line| {
        line.starts_with("> **Status**:")
            && line
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|word| word == "PROVEN")
    });
    let manifest_proven = manifest.lines().any(|line| {
        line.trim_start()
            .replace([' ', '\t'], "")
            .starts_with("status=\"proven\"")
    });
    if readme_proven && manifest_proven {
        "pass"
    } else {
        "fail"
    }
}

/// The `(passing, total)` counts from the doc's `Summary: `N/M` ...` line.
fn parse_summary_counts(status_doc: &str) -> (usize, usize) {
    status_doc
        .lines()
        .find_map(|line| {
            let rest = line.strip_prefix("Summary: `")?;
            let (counts, _) = rest.split_once('`')?;
            let (passing, total) = counts.split_once('/')?;
            Some((passing.parse().ok()?, total.parse().ok()?))
        })
        .expect("status doc should carry a `Summary: `N/M`` line")
}

/// Per-connector gauntlet records in emission order, derived from the JSONL.
fn group_records_by_connector(
    records: &[serde_json::Value],
) -> BTreeMap<String, Vec<(String, String)>> {
    let mut grouped: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for record in records {
        let connector = record_str(record, "connector")
            .expect("JSONL record should carry a connector")
            .to_string();
        let check = record_str(record, "check")
            .expect("JSONL record should carry a check")
            .to_string();
        let verdict = record_str(record, "verdict")
            .expect("JSONL record should carry a verdict")
            .to_string();
        grouped.entry(connector).or_default().push((check, verdict));
    }
    grouped
}

/// Relationship-based assertions for a `--batch <batch> --status-md` run.
///
/// Rosters, counts, and PROVEN verdicts below are derived from the scripts
/// and the live connector tree rather than pinned as literals: graduating a
/// connector is *supposed* to change the summary numbers, and must not fail
/// these tests. What must hold is the runner's contract: roster completeness,
/// contiguous check prefixes with early exit on first failure,
/// `readme_status_match` verdicts that agree with the README + manifest on
/// disk, and summary/promotion lines whose numbers match the JSONL evidence.
fn assert_batch_status_run(batch: &str, label: &str, roster: &[String]) {
    let fixture_root = unique_fixture_root(&format!("{batch}-status"));
    fs::create_dir_all(&fixture_root).expect("fixture root should be creatable");
    let status_path = fixture_root.join(format!("{batch}_status.md"));
    let jsonl_path = fixture_root.join(format!("{batch}_status.jsonl"));
    let output = run_gauntlet(vec![
        OsString::from("--jsonl"),
        jsonl_path.as_os_str().to_os_string(),
        OsString::from("--batch"),
        OsString::from(batch),
        OsString::from("--status-md"),
        status_path.as_os_str().to_os_string(),
    ]);
    assert!(
        output.status.success(),
        "{batch} status run failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let status_doc =
        fs::read_to_string(&status_path).expect("batch status markdown should be written");
    assert!(status_doc.contains(&format!("# {label} Graduation Status")));
    assert!(status_doc.contains(&format!(
        "scripts/graduation/run_gauntlet.sh --batch {batch}"
    )));
    for connector in roster {
        assert!(
            status_doc.contains(&format!("`{connector}`")),
            "status doc should mention {connector}"
        );
    }

    let jsonl = fs::read_to_string(&jsonl_path).expect("batch JSONL should be written");
    let records = jsonl
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("valid JSONL record"))
        .collect::<Vec<_>>();
    let grouped = group_records_by_connector(&records);

    // Roster completeness: the runner covered exactly the expected roster.
    assert_eq!(
        grouped.keys().cloned().collect::<BTreeSet<_>>(),
        roster.iter().cloned().collect::<BTreeSet<_>>(),
        "{batch} JSONL connectors should equal the roster from run_gauntlet.sh / \
         batch4_inventory.sh"
    );

    let check_order = EXPECTED_CHECKS
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>();

    let mut passing = 0_usize;
    let mut all_blocked_at_readme_status = true;
    for (connector, checks) in &grouped {
        // Records form a contiguous prefix of the 12-check ladder; the runner
        // stops at the first failure, so at most the last record may fail.
        let prefix_len = checks.len();
        assert!(
            prefix_len <= check_order.len(),
            "{connector} emitted more checks than the ladder has: {checks:?}"
        );
        for (index, (check, verdict)) in checks.iter().enumerate() {
            assert_eq!(check, check_order[index], "{connector} check order drifted");
            if index + 1 == prefix_len && prefix_len < check_order.len() {
                assert_eq!(
                    verdict, "fail",
                    "{connector} stopped early without a failing check"
                );
            } else {
                assert_eq!(verdict, "pass", "{connector} failed {check} but kept going");
            }
        }
        let connector_passed = prefix_len == check_order.len();
        if connector_passed {
            passing += 1;
        } else {
            let (last_check, _) = checks
                .last()
                .expect("blocked connector should emit at least one check");
            if last_check != "readme_status_match" {
                all_blocked_at_readme_status = false;
            }
        }

        // connector_path: the rostered connector directory must exist.
        assert_eq!(
            checks
                .first()
                .map(|(check, verdict)| (check.as_str(), verdict.as_str())),
            Some(("connector_path", "pass")),
            "{connector} should exist on disk and pass connector_path"
        );

        // readme_status_match: the verdict must agree with the README +
        // manifest currently on disk. This replaces the old hardcoded PROVEN
        // roster and follows graduations automatically.
        if let Some((_, verdict)) = checks
            .iter()
            .find(|(check, _)| check == "readme_status_match")
        {
            let expected = readme_status_match_expected_verdict(&workspace_root().join(connector));
            assert_eq!(
                verdict, expected,
                "{connector} readme_status_match verdict disagrees with on-disk README/manifest"
            );
        }
    }

    // Summary counts come from the JSONL, not from a frozen snapshot.
    let (doc_passing, doc_total) = parse_summary_counts(&status_doc);
    assert_eq!(
        doc_passing, passing,
        "{batch} summary passing count disagrees with the JSONL evidence"
    );
    assert_eq!(
        doc_total,
        roster.len(),
        "{batch} summary total disagrees with the roster size"
    );

    // Promotion/pre-promotion guidance tracks the same numbers and branch
    // conditions as write_batch_status_markdown (which checks
    // `passing == total` first, then the readme_status_match-only branch,
    // then falls through to generic remediation guidance).
    let total = roster.len();
    let unpromoted = total - passing;
    if passing == total {
        assert!(
            status_doc.contains("Keep this artifact scoped to mechanical gauntlet status"),
            "fully-passing {label} should emit the scoped-artifact guidance"
        );
    } else if all_blocked_at_readme_status {
        if passing == 0 {
            assert!(status_doc.contains(&format!(
                "Pre-promotion status: `{total}/{total}` {label} connectors pass every check \
                 before `readme_status_match`"
            )));
            assert!(
                status_doc.contains("every connector is still blocked at `readme_status_match`")
            );
        } else {
            assert!(status_doc.contains(&format!(
                "Promotion status: `{passing}/{total}` {label} connectors are PROVEN; \
                 `{unpromoted}/{total}` still pass every check before `readme_status_match`"
            )));
        }
        assert!(status_doc.contains("all_proven_connectors_pass_gauntlet"));
        assert!(
            !status_doc
                .contains("Add connector-local `tests/local_non_mock.rs` acceptance coverage"),
            "promotion-progress status should not emit stale local_non_mock guidance"
        );
    } else {
        assert!(
            status_doc.contains(&format!(
                "Do not mark any {label} connector PROVEN until its manifest, README, local \
                 non-mock proof, sandbox/network policy, and operator guidance all pass the \
                 gauntlet."
            )),
            "{label} connectors blocked before readme_status_match should emit generic \
             remediation guidance"
        );
    }

    // A batch with at least one fully-passing connector exercises all 12 checks.
    if passing > 0 {
        let emitted = records
            .iter()
            .filter_map(|record| record_str(record, "check"))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            emitted,
            check_order.iter().copied().collect::<BTreeSet<_>>(),
            "{batch} should cover the full 12-check ladder"
        );
    }
}

#[derive(Clone, Copy)]
struct FixtureOptions {
    status: &'static str,
    manifest_status: &'static str,
    include_operations_info: bool,
    include_local_non_mock: bool,
}

impl Default for FixtureOptions {
    fn default() -> Self {
        Self {
            status: "PROVEN",
            manifest_status: "proven",
            include_operations_info: true,
            include_local_non_mock: true,
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("fcp-conformance manifest should live below crates/")
        .to_path_buf()
}

fn gauntlet_runner() -> PathBuf {
    workspace_root().join("scripts/graduation/run_gauntlet.sh")
}

fn batch4_inventory_runner() -> PathBuf {
    workspace_root().join("scripts/graduation/batch4_inventory.sh")
}

fn record_str<'a>(record: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    record.get(key).and_then(serde_json::Value::as_str)
}

fn run_gauntlet<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Command::new("bash")
        .current_dir(workspace_root())
        .arg(gauntlet_runner())
        .args(args)
        .output()
        .expect("graduation gauntlet runner should execute")
}

fn unique_fixture_root(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after UNIX epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "fcp-graduation-gauntlet-{test_name}-{}-{nanos}",
        std::process::id()
    ))
}

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("fixture parent directory should be creatable");
    }
    fs::write(path, contents).expect("fixture file should be writable");
}

fn write_fixture_connector(root: &Path, options: FixtureOptions) -> PathBuf {
    let connector = root.join("fixture-connector");
    fs::create_dir_all(&connector).expect("fixture connector directory should be creatable");

    write_file(
        &connector.join("manifest.toml"),
        &format!(
            r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.fixture"
name = "Fixture Connector"
version = "0.1.0"
status = "{}"

[provides.operations."fixture.health"]
description = "Fixture health proof."
capability = "fixture.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"

[provides.operations."fixture.health".input_schema]
type = "object"

[provides.operations."fixture.health".output_schema]
type = "object"

[provides.operations."fixture.health".network_constraints]
host_allow = ["fixture.invalid"]
port_allow = [443]
deny_localhost = true
deny_private_ranges = true
deny_tailnet_ranges = true
deny_ip_literals = true

[sandbox]
profile = "connector-default"
"#,
            options.manifest_status
        ),
    );

    write_file(
        &connector.join("README.md"),
        &format!(
            r"# Fixture Connector

> **Status**: {}
> **Bead**: `fixture-gauntlet`
> **Verification script**: `scripts/e2e/fixture_connector_verification.sh`

## Purpose

Fixture connector for graduation gauntlet conformance tests.

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency |
|-----------|----------------|------------|------------|-----------|-------------|
| `fixture.health` | `GET /health` | `fixture.read` | `Safe` | `Low` | `Strict` |

## Operator Guidance

Prerequisites:
- Use the local fixture only.

Rerun commands:
- `scripts/e2e/fixture_connector_verification.sh`
",
            options.status
        ),
    );

    if options.include_operations_info {
        write_file(
            &connector.join("src/connector.rs"),
            "pub fn operations_info() -> Vec<&'static str> { vec![\"fixture.health\"] }\n",
        );
    }

    if options.include_local_non_mock {
        write_file(
            &connector.join("tests/local_non_mock.rs"),
            "#[test]\nfn local_non_mock_fixture() { assert!(true); }\n",
        );
    }

    connector
}

fn assert_failed_with(output: &Output, expected_code: i32, expected_check: &str) {
    assert_eq!(
        output.status.code(),
        Some(expected_code),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("check={expected_check}")),
        "stderr should name failed check {expected_check}, got:\n{stderr}"
    );
}

#[test]
fn test_gauntlet_recognizes_all_12_checks() {
    let output = run_gauntlet(["--list-checks"]);
    assert!(
        output.status.success(),
        "list-checks failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let records = stdout.lines().collect::<Vec<_>>();
    assert_eq!(records.len(), EXPECTED_CHECKS.len());

    for ((expected_name, expected_code), record) in EXPECTED_CHECKS.iter().zip(records) {
        let parts = record.split('|').collect::<Vec<_>>();
        assert_eq!(
            parts.len(),
            3,
            "record should be id|exit|description: {record}"
        );
        assert_eq!(parts[0], *expected_name);
        assert_eq!(parts[1].parse::<i32>(), Ok(*expected_code));
        assert!(!parts[2].is_empty(), "description should be non-empty");
    }

    let fixture_root = unique_fixture_root("passing");
    let connector = write_fixture_connector(&fixture_root, FixtureOptions::default());
    let output = run_gauntlet([connector.as_os_str()]);
    assert!(
        output.status.success(),
        "passing fixture should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_gauntlet_fail_on_missing_operations_info() {
    let fixture_root = unique_fixture_root("missing-operations-info");
    let connector = write_fixture_connector(
        &fixture_root,
        FixtureOptions {
            include_operations_info: false,
            ..FixtureOptions::default()
        },
    );

    let output = run_gauntlet([connector.as_os_str()]);
    assert_failed_with(&output, 2, "operations_info");
}

#[test]
fn test_gauntlet_fail_on_missing_local_non_mock() {
    let fixture_root = unique_fixture_root("missing-local-non-mock");
    let connector = write_fixture_connector(
        &fixture_root,
        FixtureOptions {
            include_local_non_mock: false,
            ..FixtureOptions::default()
        },
    );

    let output = run_gauntlet([connector.as_os_str()]);
    assert_failed_with(&output, 7, "local_non_mock");
}

#[test]
fn test_gauntlet_fail_on_readme_status_mismatch() {
    let fixture_root = unique_fixture_root("status-mismatch");
    let connector = write_fixture_connector(
        &fixture_root,
        FixtureOptions {
            manifest_status: "ready",
            ..FixtureOptions::default()
        },
    );

    let output = run_gauntlet([connector.as_os_str()]);
    assert_failed_with(&output, 8, "readme_status_match");
}

#[test]
fn test_gauntlet_fail_on_manifest_status_mismatch() {
    let fixture_root = unique_fixture_root("manifest-status-mismatch");
    let connector = write_fixture_connector(
        &fixture_root,
        FixtureOptions {
            status: "runtime contract documented",
            manifest_status: "proven",
            ..FixtureOptions::default()
        },
    );

    let output = run_gauntlet([connector.as_os_str()]);
    assert_failed_with(&output, 8, "readme_status_match");
}

#[test]
fn test_gauntlet_requires_actual_proven_status() {
    let fixture_root = unique_fixture_root("non-proven-status");
    let connector = write_fixture_connector(
        &fixture_root,
        FixtureOptions {
            status: "runtime contract documented",
            manifest_status: "ready",
            ..FixtureOptions::default()
        },
    );

    let output = run_gauntlet([connector.as_os_str()]);
    assert_failed_with(&output, 8, "readme_status_match");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("README and manifest must both declare PROVEN/proven"),
        "stderr should explain that matching non-PROVEN statuses are not enough: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn batch1_status_runner_writes_status_markdown() {
    assert_batch_status_run(
        "batch1",
        "Batch 1",
        &gauntlet_script_roster("BATCH1_CONNECTORS"),
    );
}

#[test]
fn batch2_status_runner_writes_status_markdown() {
    assert_batch_status_run(
        "batch2",
        "Batch 2",
        &gauntlet_script_roster("BATCH2_CONNECTORS"),
    );
}

#[test]
fn batch3_status_runner_writes_status_markdown() {
    assert_batch_status_run(
        "batch3",
        "Batch 3",
        &gauntlet_script_roster("BATCH3_CONNECTORS"),
    );
}

#[test]
fn batch4_inventory_scans_current_long_tail() {
    // The exclusion list in batch4_inventory.sh must stay in sync with the
    // batch1-3 rosters in run_gauntlet.sh, or connectors leak across batches.
    let excluded = batch1_to_3_exclusion();
    let gauntlet_prior = [
        "BATCH1_CONNECTORS",
        "BATCH2_CONNECTORS",
        "BATCH3_CONNECTORS",
    ]
    .iter()
    .flat_map(|array| gauntlet_script_roster(array))
    .map(|path| path.trim_start_matches("connectors/").to_string())
    .collect::<BTreeSet<_>>();
    assert_eq!(
        excluded, gauntlet_prior,
        "batch4_inventory.sh BATCH1_TO_3_CONNECTORS must equal the run_gauntlet.sh batch1-3 \
         rosters"
    );

    // --count must agree with the plain list.
    let count_output = Command::new("bash")
        .current_dir(workspace_root())
        .arg(batch4_inventory_runner())
        .arg("--count")
        .output()
        .expect("batch4 inventory runner should execute");
    assert!(
        count_output.status.success(),
        "batch4 inventory --count failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&count_output.stdout),
        String::from_utf8_lossy(&count_output.stderr)
    );
    let count = String::from_utf8_lossy(&count_output.stdout)
        .trim()
        .parse::<usize>()
        .expect("batch4 inventory --count should print an integer");
    let connectors = batch4_inventory_list().into_iter().collect::<BTreeSet<_>>();
    assert_eq!(
        count,
        connectors.len(),
        "--count must equal the number of listed connectors"
    );

    // Membership must equal exactly the on-disk long tail: every listed
    // connector is genuinely long-tail per its README status, and every
    // non-excluded connector on disk that is NOT listed has a non-long-tail
    // status. The second direction keeps a scanner regression (silently
    // finding fewer files) distinguishable from real graduations.
    let connectors_dir = workspace_root().join("connectors");
    for entry in fs::read_dir(&connectors_dir).expect("connectors directory should be readable") {
        let entry = entry.expect("connector directory entry should be readable");
        if !entry.path().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if excluded.contains(&name) {
            continue;
        }
        let path = format!("connectors/{name}");
        let long_tail = is_long_tail_status(readme_status_line(&entry.path()).as_deref());
        assert_eq!(
            connectors.contains(&path),
            long_tail,
            "inventory membership mismatch for {path}: listed={} long_tail={long_tail}",
            connectors.contains(&path),
        );
    }

    // --markdown must emit exactly one row per listed connector, carrying its
    // path and current README status text.
    let markdown_output = Command::new("bash")
        .current_dir(workspace_root())
        .arg(batch4_inventory_runner())
        .arg("--markdown")
        .output()
        .expect("batch4 inventory markdown should execute");
    assert!(
        markdown_output.status.success(),
        "batch4 inventory --markdown failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&markdown_output.stdout),
        String::from_utf8_lossy(&markdown_output.stderr)
    );
    let markdown = String::from_utf8_lossy(&markdown_output.stdout);
    let rows = markdown
        .lines()
        .filter(|line| line.starts_with("| `"))
        .collect::<Vec<_>>();
    assert_eq!(
        rows.len(),
        connectors.len(),
        "markdown should carry one row per long-tail connector:\n{markdown}"
    );
    for connector in &connectors {
        let status = readme_status_line(&workspace_root().join(connector))
            .unwrap_or_else(|| "NO_STATUS".to_string());
        assert!(
            rows.iter()
                .any(|row| row.contains(&format!("`{connector}`")) && row.contains(&status)),
            "markdown row for {connector} should carry status {status:?}:\n{markdown}"
        );
    }
}

#[test]
fn batch4_status_runner_writes_status_markdown() {
    let roster = batch4_inventory_list();
    assert_batch_status_run("batch4", "Batch 4", &roster);
}

#[test]
fn all_proven_connectors_pass_gauntlet() {
    let connectors_dir = workspace_root().join("connectors");
    let mut proven_connectors = Vec::new();

    for entry in fs::read_dir(&connectors_dir).expect("connectors directory should be readable") {
        let entry = entry.expect("connector directory entry should be readable");
        let readme = entry.path().join("README.md");
        if !readme.is_file() {
            continue;
        }
        let readme_contents =
            fs::read_to_string(&readme).expect("connector README should be readable");
        if readme_contents
            .lines()
            .any(|line| line.starts_with("> **Status**:") && line.contains("PROVEN"))
        {
            proven_connectors.push(entry.path());
        }
    }

    if proven_connectors.is_empty() {
        eprintln!("no literal PROVEN connector README statuses found");
    }

    for connector in proven_connectors {
        let output = run_gauntlet([connector.as_os_str()]);
        assert!(
            output.status.success(),
            "{} failed graduation gauntlet\nstdout:\n{}\nstderr:\n{}",
            connector.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
