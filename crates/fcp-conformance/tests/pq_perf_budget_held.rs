use std::{
    fs,
    path::{Path, PathBuf},
};

use serde_json::Value;

const ARTIFACT_ROOT: &str = "artifacts/perf/pq_signing";
const HYBRID_VERIFY_BUDGET_MS: f64 = 2.0;

#[derive(Debug)]
struct PerfBudgetReport {
    machine_class: String,
    p99_ms: f64,
    source: PathBuf,
}

#[test]
fn test_hybrid_verify_p99_under_2ms_csd() -> Result<(), String> {
    assert_machine_budget_or_skip("csd")
}

#[test]
fn test_hybrid_verify_p99_under_2ms_contabo() -> Result<(), String> {
    assert_machine_budget_or_skip("contabo")
}

#[test]
fn test_hybrid_verify_p99_under_2ms_laptop() -> Result<(), String> {
    assert_machine_budget_or_skip("laptop")
}

#[test]
fn test_p99_breach_triggers_gate() {
    let report = PerfBudgetReport {
        machine_class: "synthetic".to_string(),
        p99_ms: 3.0,
        source: PathBuf::from("synthetic-statpack.json"),
    };
    let err = assert_budget(&report).expect_err("synthetic 3ms p99 must breach the 2ms gate");
    assert!(
        err.contains("exceeded"),
        "gate error must name the exceeded budget: {err}"
    );
}

fn resolve_artifact_root() -> PathBuf {
    let direct = PathBuf::from(ARTIFACT_ROOT);
    if direct.exists() {
        return direct;
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(ARTIFACT_ROOT)
}

fn assert_machine_budget_or_skip(machine_class: &str) -> Result<(), String> {
    let root = resolve_artifact_root();
    if !root.exists() {
        eprintln!(
            "SKIP: {ARTIFACT_ROOT} is absent; angoc.1.1/angoc.1.2 StatPack artifacts have not landed yet"
        );
        return Ok(());
    }

    let report = load_latest_report(&root, machine_class)?.ok_or_else(|| {
        format!(
            "no pq signing StatPack artifact found for machine class {machine_class} under {}",
            root.display()
        )
    })?;
    assert_budget(&report)
}

fn load_latest_report(
    root: &Path,
    machine_class: &str,
) -> Result<Option<PerfBudgetReport>, String> {
    let mut paths = fs::read_dir(root)
        .map_err(|err| format!("failed to read {}: {err}", root.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext == "json")
        })
        .collect::<Vec<_>>();
    paths.sort_by(|left, right| left.file_name().cmp(&right.file_name()));

    let mut latest = None;
    for path in paths {
        let raw = fs::read_to_string(&path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        let json = serde_json::from_str::<Value>(&raw)
            .map_err(|err| format!("failed to parse {}: {err}", path.display()))?;
        if !matches_machine_class(&json, &path, machine_class) {
            continue;
        }
        let p99_ms = extract_hybrid_verify_p99_ms(&json)
            .ok_or_else(|| format!("{} does not expose hybrid verify p99", path.display()))?;
        latest = Some(PerfBudgetReport {
            machine_class: machine_class.to_string(),
            p99_ms,
            source: path,
        });
    }

    Ok(latest)
}

fn matches_machine_class(json: &Value, path: &Path, machine_class: &str) -> bool {
    let file_name_matches = path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.to_ascii_lowercase().contains(machine_class));
    file_name_matches
        || [
            &["machine_class"][..],
            &["machine", "class"][..],
            &["machine", "machine_class"][..],
            &["host", "machine_class"][..],
        ]
        .into_iter()
        .filter_map(|path| string_at_path(json, path))
        .any(|class| class.eq_ignore_ascii_case(machine_class))
}

fn extract_hybrid_verify_p99_ms(json: &Value) -> Option<f64> {
    for path in [
        &["benchmarks", "verify_hybrid", "p99_ms"][..],
        &["benchmarks", "verify_hybrid", "p99"][..],
        &["benchmarks", "hybrid_verify", "p99_ms"][..],
        &["benchmarks", "hybrid_verify", "p99"][..],
        &["statpack", "verify_hybrid", "p99_ms"][..],
        &["statpack", "verify_hybrid", "p99"][..],
        &["verify_hybrid", "p99_ms"][..],
        &["verify_hybrid", "p99"][..],
        &["hybrid_verify", "p99_ms"][..],
        &["hybrid_verify", "p99"][..],
        &["hybrid_verify_p99_ms"][..],
        &["p99_ms"][..],
        &["p99"][..],
    ] {
        if let Some(value) = number_at_path(json, path) {
            return Some(value);
        }
    }

    for (path, divisor) in [
        (&["hybrid_verify_p99_us"][..], 1_000.0),
        (&["p99_us"][..], 1_000.0),
        (&["hybrid_verify_p99_ns"][..], 1_000_000.0),
        (&["p99_ns"][..], 1_000_000.0),
    ] {
        if let Some(value) = number_at_path(json, path) {
            return Some(value / divisor);
        }
    }

    None
}

fn string_at_path<'a>(json: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter()
        .try_fold(json, |value, key| value.get(*key))
        .and_then(Value::as_str)
}

fn number_at_path(json: &Value, path: &[&str]) -> Option<f64> {
    path.iter()
        .try_fold(json, |value, key| value.get(*key))
        .and_then(Value::as_f64)
}

fn assert_budget(report: &PerfBudgetReport) -> Result<(), String> {
    if report.p99_ms <= HYBRID_VERIFY_BUDGET_MS {
        return Ok(());
    }

    Err(format!(
        "hybrid verify p99 for {} exceeded budget: observed {:.3}ms > {:.3}ms in {}",
        report.machine_class,
        report.p99_ms,
        HYBRID_VERIFY_BUDGET_MS,
        report.source.display()
    ))
}
