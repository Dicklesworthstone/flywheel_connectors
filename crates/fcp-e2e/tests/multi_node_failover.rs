#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fcp_testkit::local_mesh::{LocalChaosMode, LocalMeshHarness, LocalMeshHarnessError};
use fcp_testkit::redacted_replay_bundle::{
    verify_in_memory_replay_bundle, verify_written_replay_bundle,
};
use serde_json::{json, Value};

#[test]
fn deterministic_local_mesh_failover_smoke_covers_all_a4_chaos_modes()
-> Result<(), Box<dyn std::error::Error>> {
    let scenarios = seed_mode_scenarios();
    let artifact_root = replay_artifact_root("matrix_forward");
    let forward_matrix = failover_hash_matrix(scenarios.iter().copied(), Some(&artifact_root))?;
    let reverse_matrix = failover_hash_matrix(scenarios.iter().rev().copied(), None)?;

    assert_eq!(
        forward_matrix.len(),
        300,
        "A.4 smoke must cover 100 seeds x 3 chaos modes"
    );
    assert_eq!(
        replay_artifact_dir_count(&artifact_root)?,
        300,
        "forward seed/mode matrix should write one replay bundle per scenario"
    );
    assert_eq!(
        forward_matrix, reverse_matrix,
        "seed/mode final-state hashes must be independent of traversal order"
    );
    let golden_matrix = load_golden_matrix()?;
    assert_eq!(
        golden_matrix.len(),
        forward_matrix.len(),
        "golden matrix must cover every seed/mode scenario; regenerate with `{REGEN_COMMAND}`"
    );
    for ((seed_index, chaos_mode), actual_hash) in &forward_matrix {
        let key = scenario_key(*seed_index, *chaos_mode);
        let expected_hash = golden_matrix.get(&key).ok_or_else(|| {
            invalid_replay_artifact(format!(
                "golden matrix is missing scenario {key}; regenerate with `{REGEN_COMMAND}`"
            ))
        })?;
        assert_eq!(
            expected_hash, actual_hash,
            "scenario {key} final-state hash drifted from the checked-in golden matrix; \
             if this behavior change is intentional, regenerate with `{REGEN_COMMAND}` and review the diff"
        );
    }
    Ok(())
}

#[test]
fn local_mesh_replay_events_are_jsonl_serializable_and_redacted()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = LocalMeshHarness::new_three_node(42)?;
    let outcome = harness.run_failover_scenario(LocalChaosMode::KillLeaderMidWrite)?;
    let jsonl = outcome.replay_bundle.events_jsonl()?;

    assert!(!jsonl.trim().is_empty());
    let mut previous_logical_time_ms = 0;
    let mut observed_handoff_target = false;
    for line in jsonl.lines() {
        let value: Value = serde_json::from_str(line)?;
        assert_transition_event_contract(
            &value,
            &outcome.scenario_id,
            42,
            "kill_leader_mid_write",
            &mut previous_logical_time_ms,
            &mut observed_handoff_target,
        )?;
        assert!(
            !line.contains("mesh-harness-node-"),
            "JSONL events must be redacted: {line}"
        );
    }
    assert!(
        observed_handoff_target,
        "kill-leader replay should include at least one redacted handoff target"
    );
    Ok(())
}

#[test]
fn local_mesh_replay_bundle_writes_documented_artifacts() -> Result<(), Box<dyn std::error::Error>>
{
    let mut harness = LocalMeshHarness::new_three_node(7)?;
    let outcome = harness.run_failover_scenario(LocalChaosMode::NetworkPartitionThenHeal)?;
    let paths = outcome
        .replay_bundle
        .write_to_dir(replay_artifact_root(&outcome.scenario_id))?;

    let summary = verify_written_replay_bundle(&paths, 3)?;
    assert_eq!(summary.scenario_id, outcome.scenario_id);
    assert_eq!(summary.node_count, 3);
    assert_eq!(summary.snapshot_file_count, 12);
    assert_eq!(summary.final_state_hash, outcome.final_state_hash);
    assert_eq!(summary.per_node_state_hash_count, 3);
    assert_eq!(summary.active_holder_hash, outcome.active_holder_hash);
    assert_eq!(summary.online_node_count, 3);
    assert!(summary.all_nodes_online_at_end);
    assert_eq!(summary.orphaned_active_lease_count, 0);
    assert_eq!(summary.orphaned_connector_state_count, 0);
    assert_eq!(summary.invalid_receipt_signature_count, 0);

    Ok(())
}

#[test]
fn local_mesh_replay_bundle_refuses_unredacted_artifact_writes()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = LocalMeshHarness::new_three_node(7)?;
    let outcome = harness.run_failover_scenario(LocalChaosMode::KillLeaderMidWrite)?;
    let mut bundle = outcome.replay_bundle.clone();
    bundle.manifest.scenario_id = "mesh-harness-node-raw".to_owned();
    let unsafe_dir = replay_artifact_root("unsafe");

    assert!(matches!(
        bundle.write_to_dir(&unsafe_dir),
        Err(LocalMeshHarnessError::ReplayArtifactRedaction)
    ));
    assert!(
        !unsafe_dir.exists(),
        "redaction failure must happen before artifact directories are created"
    );
    Ok(())
}

/// Regenerates `golden/multi_node_failover/matrix.json` from a doubly-run
/// deterministic matrix. Ignored by default: run explicitly with
/// `cargo test -p fcp-e2e --no-default-features --test multi_node_failover -- --ignored generate_multi_node_failover_golden_matrix`
/// and review the resulting diff before committing.
#[test]
#[ignore = "writes the checked-in golden matrix"]
fn generate_multi_node_failover_golden_matrix() -> Result<(), Box<dyn std::error::Error>> {
    let scenarios = seed_mode_scenarios();
    let forward_matrix = failover_hash_matrix(scenarios.iter().copied(), None)?;
    let reverse_matrix = failover_hash_matrix(scenarios.iter().rev().copied(), None)?;
    assert_eq!(
        forward_matrix, reverse_matrix,
        "refusing to write goldens from a non-deterministic matrix run"
    );

    let mut scenario_hashes = serde_json::Map::new();
    for ((seed_index, chaos_mode), hash) in &forward_matrix {
        scenario_hashes.insert(
            scenario_key(*seed_index, *chaos_mode),
            Value::String(hash.clone()),
        );
    }
    let document = json!({
        "schema": GOLDEN_MATRIX_SCHEMA,
        "scenario_hashes": Value::Object(scenario_hashes),
    });
    let path = golden_matrix_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, format!("{}\n", serde_json::to_string_pretty(&document)?))?;
    Ok(())
}

fn seed_mode_scenarios() -> Vec<(u64, LocalChaosMode)> {
    (0..100)
        .flat_map(|seed_index| {
            LocalChaosMode::all().map(move |chaos_mode| (seed_index, chaos_mode))
        })
        .collect()
}

fn failover_hash_matrix(
    scenarios: impl IntoIterator<Item = (u64, LocalChaosMode)>,
    artifact_root: Option<&Path>,
) -> Result<BTreeMap<(u64, LocalChaosMode), String>, Box<dyn std::error::Error>> {
    let mut matrix = BTreeMap::new();
    for (seed_index, chaos_mode) in scenarios {
        let mut harness = LocalMeshHarness::new_three_node(seed_index)?;
        let outcome = harness.run_failover_scenario(chaos_mode)?;
        if let Some(root) = artifact_root {
            outcome
                .replay_bundle
                .write_to_dir(root.join(&outcome.scenario_id))?;
        }

        assert_eq!(
            harness.mesh_node_count(),
            3,
            "A.4 local harness must instantiate three real MeshNode values"
        );
        assert_eq!(
            outcome.receipt_count, 1,
            "idempotency retry should produce exactly one receipt"
        );
        assert_eq!(
            outcome.duplicate_receipt_count, 0,
            "duplicate receipt count must stay zero under chaos"
        );
        assert_eq!(
            outcome.invariants.active_holder_hash, outcome.active_holder_hash,
            "active holder invariant should identify the selected holder"
        );
        assert_eq!(
            outcome.invariants.online_node_count, 3,
            "all local mesh nodes should be online after recovery"
        );
        assert!(
            outcome.invariants.all_nodes_online_at_end,
            "failover recovery should leave every local node online"
        );
        assert_eq!(
            outcome.invariants.orphaned_active_lease_count, 0,
            "active singleton holder must be online and in holder role"
        );
        assert_eq!(
            outcome.invariants.orphaned_connector_state_count, 0,
            "operation receipts must stay connected to request refs, outcomes, and known nodes"
        );
        assert_eq!(
            outcome.invariants.invalid_receipt_signature_count, 0,
            "operation receipts must verify against the executing node key"
        );
        assert_eq!(
            outcome.replay_bundle.invariants.orphaned_active_lease_count, 0,
            "replay bundle should carry the same lease invariant evidence"
        );
        assert!(
            outcome.replay_bundle.is_redaction_safe()?,
            "replay bundle must not expose raw node ids or secret-bearing labels"
        );
        assert_eq!(outcome.replay_bundle.manifest.result, "pass");
        let replay_summary = verify_in_memory_replay_bundle(&outcome.replay_bundle, 3)?;
        assert_ne!(
            replay_summary.event_count, 0,
            "replay bundle should include node transition events"
        );
        assert_eq!(
            replay_summary.node_count, 3,
            "replay bundle should include one redacted snapshot per node"
        );
        assert_eq!(
            replay_summary.timeline_count, 3,
            "replay bundle should include one per-node timeline per node"
        );

        let previous = matrix.insert((seed_index, chaos_mode), outcome.final_state_hash);
        assert!(
            previous.is_none(),
            "seed/mode matrix should contain each scenario exactly once"
        );
    }
    Ok(matrix)
}

fn required_string_field<'a>(
    value: &'a Value,
    field: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_replay_artifact(format!("missing string field {field}")))
}

fn required_u64_field(value: &Value, field: &str) -> Result<u64, Box<dyn std::error::Error>> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_replay_artifact(format!("missing u64 field {field}")))
}

fn assert_transition_event_contract(
    value: &Value,
    scenario_id: &str,
    seed_index: u64,
    chaos_mode: &str,
    previous_logical_time_ms: &mut u64,
    observed_handoff_target: &mut bool,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(required_string_field(value, "scenario_id")?, scenario_id);
    assert_eq!(required_u64_field(value, "seed_index")?, seed_index);
    assert_eq!(required_string_field(value, "chaos_mode")?, chaos_mode);

    let node_id_hash = required_string_field(value, "node_id_hash")?;
    assert_hash_value("node_id_hash", node_id_hash);

    let prior_role = required_string_field(value, "prior_role")?;
    let new_role = required_string_field(value, "new_role")?;
    assert_known_local_role("prior_role", prior_role);
    assert_known_local_role("new_role", new_role);
    assert_ne!(
        prior_role, new_role,
        "transition event should only be emitted when the role changes"
    );

    let transition_duration_ms = required_u64_field(value, "transition_duration_ms")?;
    assert!(
        transition_duration_ms > 0,
        "transition duration should be positive"
    );
    let logical_time_ms = required_u64_field(value, "logical_time_ms")?;
    assert!(
        logical_time_ms > *previous_logical_time_ms,
        "logical transition time should increase monotonically"
    );
    *previous_logical_time_ms = logical_time_ms;

    match value.get("lease_handoff_target_hash") {
        Some(Value::Null) => {}
        Some(Value::String(target_hash)) => {
            *observed_handoff_target = true;
            assert_hash_value("lease_handoff_target_hash", target_hash);
        }
        Some(_) => {
            return Err(invalid_replay_artifact(
                "lease_handoff_target_hash must be a hash string or null",
            ));
        }
        None => {
            return Err(invalid_replay_artifact(
                "transition event missing lease_handoff_target_hash",
            ));
        }
    }

    Ok(())
}

fn assert_known_local_role(field: &str, role: &str) {
    assert!(
        matches!(
            role,
            "candidate" | "holder" | "follower" | "partitioned" | "offline" | "recovered"
        ),
        "{field} should use the LocalNodeRole snake_case contract: {role}"
    );
}

fn assert_hash_value(field: &str, value: &str) {
    assert_eq!(value.len(), 64, "{field} should be a 64-character hash");
    assert!(
        value.chars().all(|character| character.is_ascii_hexdigit()),
        "{field} should be hex-encoded"
    );
}

fn invalid_replay_artifact(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message.into(),
    ))
}

fn replay_artifact_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!(
        "fcp-multi-node-failover-replay-{}-{nanos}-{label}",
        std::process::id()
    ))
}

fn replay_artifact_dir_count(root: &Path) -> Result<usize, Box<dyn std::error::Error>> {
    let mut count = 0;
    for entry in fs::read_dir(root)? {
        if entry?.file_type()?.is_dir() {
            count += 1;
        }
    }
    Ok(count)
}

const GOLDEN_MATRIX_SCHEMA: &str = "fcp.multi-node-failover-matrix/v1";
const REGEN_COMMAND: &str = "cargo test -p fcp-e2e --no-default-features --test multi_node_failover -- --ignored generate_multi_node_failover_golden_matrix";

fn golden_matrix_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("golden/multi_node_failover/matrix.json")
}

fn scenario_key(seed_index: u64, chaos_mode: LocalChaosMode) -> String {
    format!("seed_{seed_index}_{}", chaos_mode.as_str())
}

fn load_golden_matrix() -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
    let path = golden_matrix_path();
    let raw = fs::read_to_string(&path).map_err(|source| {
        invalid_replay_artifact(format!(
            "golden matrix {} is unreadable: {source}; regenerate with `{REGEN_COMMAND}`",
            path.display()
        ))
    })?;
    let document: Value = serde_json::from_str(&raw)?;
    let schema = required_string_field(&document, "schema")?;
    if schema != GOLDEN_MATRIX_SCHEMA {
        return Err(invalid_replay_artifact(format!(
            "golden matrix schema `{schema}` does not match `{GOLDEN_MATRIX_SCHEMA}`; regenerate with `{REGEN_COMMAND}`"
        )));
    }
    let hashes = document
        .get("scenario_hashes")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_replay_artifact("golden matrix missing scenario_hashes object"))?;
    let mut matrix = BTreeMap::new();
    for (scenario, hash) in hashes {
        let hash = hash.as_str().ok_or_else(|| {
            invalid_replay_artifact(format!(
                "golden matrix scenario {scenario} hash must be a string"
            ))
        })?;
        assert_hash_value("golden scenario hash", hash);
        matrix.insert(scenario.clone(), hash.to_owned());
    }
    Ok(matrix)
}
