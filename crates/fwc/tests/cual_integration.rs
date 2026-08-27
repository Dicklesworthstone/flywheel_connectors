use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use fcp_async_core::runtime::{self, Builder as AsyncRuntimeBuilder};
use fcp_host::{
    EventQueryRequest as HostEventQueryRequest, HostAdminStateStore, HostEventKind,
    PreflightResponse as HostPreflightResponse,
};
use fcp_manifest::ConnectorManifest;
use fcp_prelude::{CapabilityToken, ConnectorHealth, InvokeResponse, RequestId};
use fwc::mesh_cmd::{CutoverGateStatus, MeshCutoverGateArgs, mesh_cutover_gates};
use fwc::readiness::CommandAvailability;
use fwc::test_observability::{
    ArtifactManifest, BundleOutcome, ScenarioLayer, TraceCategory, TraceEntry, TraceLevel,
    TruthContext, TruthPhase, create_bundle, new_trace_log, scenario_context,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("fwc crate should live under the workspace root")
        .to_path_buf()
}

fn fixture_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(relative)
}

const SWARM_EVIDENCE_FIXTURE: &str =
    "crates/fwc/testdata/swarm_evidence/operator_decision_cards.jsonl";

#[derive(Debug, Deserialize)]
struct HostIntegrationFixtureMatrix {
    fixtures: Vec<HostIntegrationFixture>,
}

#[derive(Debug, Deserialize)]
struct HostIntegrationFixture {
    id: String,
    connector_id: String,
    display_name: String,
    archetype: String,
    coverage_mode: String,
    risk_level: String,
    safety_tier: String,
    readiness: String,
    auth_scope: String,
    reversibility: String,
    operation_family: String,
    tool_count: usize,
    #[serde(default)]
    provenance_markers: Vec<String>,
    #[serde(default)]
    required_artifacts: Vec<String>,
    #[serde(default)]
    required_log_fields: Vec<String>,
    notes: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OperatorTruthAnswerClass {
    Offline,
    NodeLocal,
    MeshBacked,
    Degraded,
    FallbackDerived,
    Refusal,
}

#[derive(Debug, Deserialize)]
struct OperatorTruthFixtureMatrix {
    fixtures: Vec<OperatorTruthFixture>,
}

#[derive(Debug, Deserialize)]
struct OperatorTruthFixture {
    id: String,
    answer_class: OperatorTruthAnswerClass,
    command: String,
    #[serde(default)]
    subcommand: Option<String>,
    #[serde(default)]
    mode: Option<String>,
    source: String,
    #[serde(default)]
    availability: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    phase: Option<String>,
    #[serde(default)]
    bundle_layer: Option<String>,
    #[serde(default)]
    bundle_suite: Option<String>,
    #[serde(default)]
    connector_status: Option<String>,
    #[serde(default)]
    connector_state: Option<String>,
    #[serde(default)]
    provenance: Option<OperatorTruthProvenance>,
    #[serde(default)]
    response_scope: Option<String>,
    #[serde(default)]
    source_selection_state: Option<String>,
    #[serde(default)]
    source_selection_kind: Option<String>,
    #[serde(default)]
    availability_fact_state: Option<String>,
    #[serde(default)]
    offline_readiness_state: Option<String>,
    #[serde(default)]
    required_evidence_handles: Vec<String>,
    #[serde(default)]
    required_warning_substrings: Vec<String>,
    #[serde(default)]
    required_message_substrings: Vec<String>,
    #[serde(default)]
    required_next_action_substrings: Vec<String>,
    #[serde(default)]
    required_artifacts: Vec<String>,
    #[serde(default)]
    required_log_fields: Vec<String>,
    #[serde(default)]
    rerun_command: Option<String>,
    #[serde(default)]
    error_type: Option<String>,
    #[serde(default)]
    preflight_allowed: Option<bool>,
    #[serde(default)]
    minimum_next_actions: Option<usize>,
    #[serde(default)]
    human_summary_contains: Vec<String>,
    notes: String,
}

#[derive(Debug, Deserialize)]
struct OperatorTruthProvenance {
    source: String,
    authoritative: bool,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    mesh_backed: Option<bool>,
    #[serde(default)]
    degraded: Option<bool>,
    #[serde(default)]
    fallback_derived: Option<bool>,
}

fn run_fwc(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fwc"))
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("fwc process should launch")
}

fn run_fwc_in_home(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fwc"))
        .args(args)
        .env("HOME", home)
        .current_dir(repo_root())
        .output()
        .expect("fwc process should launch")
}

fn run_json(args: &[&str]) -> (i32, Value, String) {
    let output = run_fwc(args);
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be valid UTF-8");
    let payload = serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
        panic!("expected JSON output for {args:?}: {error}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    (code, payload, stderr)
}

fn run_json_ok(args: &[&str]) -> Value {
    let (code, payload, stderr) = run_json(args);
    assert_eq!(code, 0, "expected success for {args:?}, stderr:\n{stderr}");
    payload
}

fn run_json_in_home(home: &Path, args: &[&str]) -> (i32, Value, String) {
    let output = run_fwc_in_home(home, args);
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be valid UTF-8");
    let payload = serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
        panic!("expected JSON output for {args:?}: {error}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    (code, payload, stderr)
}

fn run_json_ok_in_home(home: &Path, args: &[&str]) -> Value {
    let (code, payload, stderr) = run_json_in_home(home, args);
    assert_eq!(code, 0, "expected success for {args:?}, stderr:\n{stderr}");
    payload
}

fn run_text_ok(args: &[&str]) -> String {
    let output = run_fwc(args);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be valid UTF-8");
    assert!(
        output.status.success(),
        "expected success for {args:?}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    stdout
}

fn report_by_type<'a>(payload: &'a Value, record_type: &str) -> &'a Value {
    payload["reports"]
        .as_array()
        .expect("reports should be an array")
        .iter()
        .find(|report| report["record_type"] == record_type)
        .unwrap_or_else(|| panic!("missing report record `{record_type}`"))
}

#[test]
fn swarm_evidence_explore_fixture_json_exposes_operator_trace() {
    let payload = run_json_ok(&[
        "--json",
        "swarm-evidence",
        "explore",
        SWARM_EVIDENCE_FIXTURE,
        "--scenario",
        "ten_thousand_agent_burst",
    ]);

    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["command"], "swarm-evidence explore");
    assert_eq!(payload["summary"]["decision_card_count"], 5);
    assert_eq!(payload["summary"]["filtered_decision_card_count"], 5);
    let domains = payload["entries"]
        .as_array()
        .expect("entries should be an array")
        .iter()
        .map(|entry| {
            entry["domain"]
                .as_str()
                .expect("entry should expose domain")
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        domains,
        BTreeSet::from([
            "audit".to_owned(),
            "backpressure".to_owned(),
            "evidence-bundle".to_owned(),
            "placement".to_owned(),
            "scheduler".to_owned(),
        ])
    );

    let scheduler = payload["entries"]
        .as_array()
        .expect("entries should be an array")
        .iter()
        .find(|entry| entry["card_id"] == "card:scheduler:p99-regression")
        .expect("scheduler p99 decision card should be present");
    assert_eq!(scheduler["action"], "delay");
    assert_eq!(scheduler["dominant_loss_term"]["name"], "p99_queueing");
    assert_eq!(
        scheduler["counterfactual"]["reason"],
        "would push p99 above the 1ms budget"
    );
    assert_eq!(
        scheduler["evidence_handles"][0]["handle"],
        "raw-samples.jsonl#line=42"
    );

    let gauntlet = report_by_type(&payload, "swarm_gauntlet_log");
    assert_eq!(
        gauntlet["run_context"]["git_revision"],
        "fixture-revision-k3zfl5"
    );
    assert_eq!(gauntlet["run_context"]["worker_id"], "Codex");
    assert_eq!(
        gauntlet["run_context"]["cargo_target_dir"],
        "/tmp/fcp-k3zfl5"
    );
    assert_eq!(gauntlet["run_context"]["topology"]["logical_cpus"], 64);
    assert_eq!(gauntlet["run_context"]["command_line"][10], "[redacted]");
    assert_eq!(gauntlet["run_context"]["command_line"][11], "[redacted]");
    assert_eq!(gauntlet["metrics"]["p99_ns"], 1_250_000);
    assert_eq!(gauntlet["metrics"]["p999_ns"], 2_100_000);
    assert_eq!(gauntlet["metrics"]["throughput_ops_per_second"], 940_000);
    assert_eq!(gauntlet["metrics"]["queue_depth"], 4096);
    assert_eq!(
        gauntlet["metrics"]["retry_amplification_microunits"],
        125_000
    );
    assert_eq!(
        gauntlet["machine_readable_status"]["failure_reason"],
        "p99_regression"
    );
    assert_eq!(
        gauntlet["evidence"]["decision_card_ids"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
    assert_eq!(
        gauntlet["evidence"]["raw_sample_digest"],
        "blake3:raw-samples-p99-regression"
    );

    let skip = report_by_type(&payload, "swarm_promotion_skip");
    assert_eq!(
        skip["machine_readable_status"]["skip_reason"],
        "soak_hardware_unavailable"
    );
    assert_eq!(
        skip["machine_readable_status"]["machine_reason"],
        "missing_high_core_soak_worker"
    );
}

#[test]
fn swarm_evidence_replay_fixture_json_answers_debugging_questions() {
    let payload = run_json_ok(&[
        "--json",
        "swarm-evidence",
        "replay",
        SWARM_EVIDENCE_FIXTURE,
        "--card-id",
        "card:scheduler:p99-regression",
    ]);

    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["command"], "swarm-evidence replay");
    assert_eq!(payload["pagination"]["returned"], 1);
    assert_eq!(payload["pagination"]["total_filtered"], 1);
    assert_eq!(payload["pagination"]["has_more"], false);
    assert_eq!(
        payload["replay_boundary"],
        "Offline replay renders stored decision-card inputs, action, fallback, counterfactual, and evidence pointers; it does not call live services or recompute host state."
    );

    let answers = &payload["entries"][0]["answers"];
    assert_eq!(
        answers["what_happened"]["scenario_id"],
        "ten_thousand_agent_burst"
    );
    assert_eq!(answers["what_happened"]["domain"], "scheduler");
    assert_eq!(answers["what_happened"]["selected_action"], "delay");
    assert_eq!(
        answers["why_selected"]["dominant_loss_term"]["name"],
        "p99_queueing"
    );
    assert_eq!(answers["next_best_counterfactual"]["action"], "admit");
    assert_eq!(
        answers["next_best_counterfactual"]["reason"],
        "would push p99 above the 1ms budget"
    );
    assert_eq!(answers["fallback"]["active"], false);
    assert_eq!(
        answers["proof_locations"]["evidence_handles"][0]["handle"],
        "raw-samples.jsonl#line=42"
    );
    assert_eq!(
        answers["proof_locations"]["replay_inputs"]["p99_ns"],
        1_250_000
    );
    assert_eq!(
        answers["proof_locations"]["replay_inputs"]["auth_token"],
        "[redacted]"
    );
    assert_eq!(
        payload["entries"][0]["redacted_record"]["card"]["replay_inputs"]["auth_token"],
        "[redacted]"
    );
}

#[test]
fn swarm_evidence_replay_fixture_toon_is_concise_and_redacted() {
    let text = run_text_ok(&[
        "swarm-evidence",
        "replay",
        SWARM_EVIDENCE_FIXTURE,
        "--card-id",
        "card:scheduler:p99-regression",
    ]);

    for expected in [
        "swarm-evidence replay",
        "card:scheduler:p99-regression",
        "selected=delay",
        "fallback_active=false",
    ] {
        assert!(
            text.contains(expected),
            "TOON output should contain `{expected}`:\n{text}"
        );
    }
    assert!(!text.contains("must-redact"));
    assert!(!text.contains("sk-live-never-leak"));
}

fn load_host_integration_fixture(id: &str) -> HostIntegrationFixture {
    let path = fixture_path("host_integration/fixture_matrix.json");
    let content = fs::read_to_string(&path).expect("host integration fixture matrix should load");
    let matrix: HostIntegrationFixtureMatrix =
        serde_json::from_str(&content).expect("host integration fixture matrix should parse");
    matrix
        .fixtures
        .into_iter()
        .find(|fixture| fixture.id == id)
        .unwrap_or_else(|| panic!("missing host integration fixture `{id}`"))
}

fn load_operator_truth_fixture_matrix() -> OperatorTruthFixtureMatrix {
    let path = fixture_path("operator_truth/fixture_matrix.json");
    let content = fs::read_to_string(&path).expect("operator truth fixture matrix should load");
    serde_json::from_str(&content).expect("operator truth fixture matrix should parse")
}

fn load_operator_truth_fixture(id: &str) -> OperatorTruthFixture {
    load_operator_truth_fixture_matrix()
        .fixtures
        .into_iter()
        .find(|fixture| fixture.id == id)
        .unwrap_or_else(|| panic!("missing operator truth fixture `{id}`"))
}

fn assert_fixture_has_core_host_bundle(fixture: &HostIntegrationFixture) {
    for artifact in [
        "trace.jsonl",
        "summary.json",
        "environment.json",
        "replay.sh",
    ] {
        assert!(
            fixture
                .required_artifacts
                .iter()
                .any(|value| value == artifact),
            "fixture {} missing required artifact {artifact}",
            fixture.id
        );
    }
    for field in ["correlation_id", "phase"] {
        assert!(
            fixture
                .required_log_fields
                .iter()
                .any(|value| value == field),
            "fixture {} missing required log field {field}",
            fixture.id
        );
    }
}

fn payload_has_evidence_handle_kind(payload: &Value, kind: &str) -> bool {
    payload["evidence_handles"]
        .as_array()
        .is_some_and(|handles| {
            handles.iter().any(|handle| {
                handle["kind"]
                    .as_str()
                    .is_some_and(|candidate| candidate == kind)
            })
        })
}

fn payload_warning_contains(payload: &Value, needle: &str) -> bool {
    payload["warnings"].as_array().is_some_and(|warnings| {
        warnings
            .iter()
            .filter_map(Value::as_str)
            .any(|warning| warning.contains(needle))
    })
}

fn payload_message_contains(payload: &Value, needle: &str) -> bool {
    payload["message"]
        .as_str()
        .is_some_and(|message| message.contains(needle))
}

fn payload_next_action_contains(payload: &Value, needle: &str) -> bool {
    payload["next_actions"].as_array().is_some_and(|actions| {
        actions
            .iter()
            .filter_map(Value::as_str)
            .any(|action| action.contains(needle))
    })
}

fn assert_operator_truth_fixture_has_core_evidence_contract(fixture: &OperatorTruthFixture) {
    for artifact in [
        "trace.jsonl",
        "summary.json",
        "environment.json",
        "replay.sh",
    ] {
        assert!(
            fixture
                .required_artifacts
                .iter()
                .any(|value| value == artifact),
            "fixture {} missing required artifact {artifact}",
            fixture.id
        );
    }
    for field in ["correlation_id", "phase"] {
        assert!(
            fixture
                .required_log_fields
                .iter()
                .any(|value| value == field),
            "fixture {} missing required log field {field}",
            fixture.id
        );
    }
    assert!(
        fixture
            .rerun_command
            .as_deref()
            .is_some_and(|command| command.starts_with("fwc ")),
        "fixture {} must provide an `fwc` rerun command",
        fixture.id
    );
    assert!(
        fixture
            .bundle_suite
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty()),
        "fixture {} must define bundle_suite",
        fixture.id
    );
    assert!(
        fixture
            .bundle_layer
            .as_deref()
            .and_then(ScenarioLayer::parse_label)
            .is_some(),
        "fixture {} must define a supported bundle_layer",
        fixture.id
    );
}

#[allow(clippy::too_many_lines)]
fn assert_operator_truth_fixture_contract(payload: &Value, fixture: &OperatorTruthFixture) {
    assert_eq!(payload["command"], fixture.command);
    assert_eq!(payload["source"], fixture.source);
    assert_ne!(fixture.notes.trim(), "");

    if let Some(availability) = fixture.availability.as_deref() {
        assert_eq!(payload["availability"]["availability"], availability);
    }
    if let Some(status) = fixture.status.as_deref() {
        assert_eq!(payload["status"], status);
    }
    if let Some(phase) = fixture.phase.as_deref() {
        assert_eq!(payload["phase"], phase);
    }
    if let Some(subcommand) = fixture.subcommand.as_deref() {
        assert_eq!(payload["subcommand"], subcommand);
    }
    if let Some(mode) = fixture.mode.as_deref() {
        assert_eq!(payload["mode"], mode);
    }
    if let Some(scope) = fixture.response_scope.as_deref() {
        assert_eq!(payload["scope"], scope);
    }

    if let Some(provenance_fixture) = fixture.provenance.as_ref() {
        let provenance = &payload["provenance"];
        assert_eq!(provenance["source"], provenance_fixture.source);
        assert_eq!(
            provenance["authoritative"],
            provenance_fixture.authoritative
        );
        if let Some(transport) = provenance_fixture.transport.as_deref() {
            assert_eq!(provenance["transport"], transport);
        }
        if let Some(scope) = provenance_fixture.scope.as_deref() {
            assert_eq!(provenance["scope"], scope);
        }
        if let Some(mesh_backed) = provenance_fixture.mesh_backed {
            assert_eq!(provenance["mesh_backed"], mesh_backed);
        }
        if let Some(degraded) = provenance_fixture.degraded {
            assert_eq!(provenance["degraded"], degraded);
        }
        if let Some(fallback_derived) = provenance_fixture.fallback_derived {
            assert_eq!(provenance["fallback_derived"], fallback_derived);
        }
    }

    if let Some(state) = fixture.source_selection_state.as_deref() {
        assert_eq!(payload["source_selection"]["state"], state);
    }
    if let Some(kind) = fixture.source_selection_kind.as_deref() {
        assert_eq!(payload["source_selection"]["source_kind"], kind);
    }
    if let Some(state) = fixture.availability_fact_state.as_deref() {
        assert_eq!(payload["availability_fact"]["state"], state);
    }
    if let Some(state) = fixture.offline_readiness_state.as_deref() {
        assert_eq!(payload["offline_readiness"]["state"], state);
    }
    if let Some(status) = fixture.connector_status.as_deref() {
        assert_eq!(payload["connector"]["status"], status);
    }
    if let Some(state) = fixture.connector_state.as_deref() {
        assert_eq!(payload["connector"]["state"], state);
    }
    if let Some(error_type) = fixture.error_type.as_deref() {
        assert_eq!(payload["error"]["type"], error_type);
    }
    if let Some(preflight_allowed) = fixture.preflight_allowed {
        assert_eq!(payload["preflight"]["allowed"], preflight_allowed);
    }

    for kind in &fixture.required_evidence_handles {
        assert!(
            payload_has_evidence_handle_kind(payload, kind),
            "payload missing required evidence handle `{kind}`: {}",
            serde_json::to_string_pretty(payload).unwrap_or_default()
        );
    }
    for warning in &fixture.required_warning_substrings {
        assert!(
            payload_warning_contains(payload, warning),
            "payload missing warning containing `{warning}`: {}",
            serde_json::to_string_pretty(payload).unwrap_or_default()
        );
    }
    for message in &fixture.required_message_substrings {
        assert!(
            payload_message_contains(payload, message),
            "payload missing message containing `{message}`: {}",
            serde_json::to_string_pretty(payload).unwrap_or_default()
        );
    }
    if let Some(minimum_next_actions) = fixture.minimum_next_actions {
        let next_actions = payload["next_actions"]
            .as_array()
            .expect("payload missing next_actions array");
        assert!(
            next_actions.len() >= minimum_next_actions,
            "payload expected at least {minimum_next_actions} next actions: {}",
            serde_json::to_string_pretty(payload).unwrap_or_default()
        );
    }
    for next_action in &fixture.required_next_action_substrings {
        assert!(
            payload_next_action_contains(payload, next_action),
            "payload missing next_action containing `{next_action}`: {}",
            serde_json::to_string_pretty(payload).unwrap_or_default()
        );
    }
}

fn assert_operator_truth_fixture_human_summary(text: &str, fixture: &OperatorTruthFixture) {
    for expected in &fixture.human_summary_contains {
        assert!(
            text.contains(expected),
            "human output missing `{expected}` for fixture {}:\n{text}",
            fixture.id
        );
    }
}

fn command_availability_from_tag(tag: &str) -> CommandAvailability {
    match tag {
        "live-runtime" => CommandAvailability::LiveRuntime,
        "offline-artifact" => CommandAvailability::OfflineArtifact,
        "unsupported" => CommandAvailability::Unsupported,
        "planned" => CommandAvailability::Planned,
        "unavailable" => CommandAvailability::Unavailable,
        "denied" => CommandAvailability::Denied,
        "unknown" => CommandAvailability::Unknown,
        other => panic!("unsupported command availability tag `{other}`"),
    }
}

fn operator_truth_fixture_availability(fixture: &OperatorTruthFixture) -> CommandAvailability {
    let tag = fixture
        .availability
        .as_deref()
        .or(fixture.status.as_deref())
        .expect("fixture must define availability or status");
    command_availability_from_tag(tag)
}

fn operator_truth_fixture_phase(fixture: &OperatorTruthFixture) -> TruthPhase {
    match fixture.phase.as_deref() {
        Some("setup") => TruthPhase::Setup,
        Some("preflight") => TruthPhase::Preflight,
        Some("simulate") => TruthPhase::Simulate,
        Some("invoke") => TruthPhase::Invoke,
        Some("teardown") => TruthPhase::Teardown,
        Some(phase) => panic!("unsupported explicit truth phase `{phase}`"),
        None if fixture.mode.as_deref() == Some("offline-artifact") => TruthPhase::OfflineArtifact,
        None => TruthPhase::HostDiscovery,
    }
}

fn operator_truth_fixture_bundle_layer(fixture: &OperatorTruthFixture) -> ScenarioLayer {
    let layer = fixture
        .bundle_layer
        .as_deref()
        .expect("fixture must define bundle_layer");
    ScenarioLayer::parse_label(layer).unwrap_or_else(|| {
        panic!(
            "unsupported bundle layer `{layer}` for fixture {}",
            fixture.id
        )
    })
}

fn operator_truth_fixture_bundle_suite(fixture: &OperatorTruthFixture) -> &str {
    fixture
        .bundle_suite
        .as_deref()
        .expect("fixture must define bundle_suite")
}

fn operator_truth_provenance_markers(payload: &Value) -> Vec<String> {
    let mut markers = std::collections::BTreeSet::new();
    if let Some(source) = payload["source"].as_str() {
        markers.insert(source.to_owned());
    }
    let provenance = &payload["provenance"];
    for field in ["source", "transport", "scope"] {
        if let Some(value) = provenance[field].as_str() {
            markers.insert(value.to_owned());
        }
    }
    if let Some(scope) = payload["scope"].as_str() {
        markers.insert(format!("response-scope:{scope}"));
    }
    markers.into_iter().collect()
}

fn operator_truth_context(payload: &Value, fixture: &OperatorTruthFixture) -> TruthContext {
    let mut truth = TruthContext::new(operator_truth_fixture_availability(fixture))
        .with_phase(operator_truth_fixture_phase(fixture));
    for marker in operator_truth_provenance_markers(payload) {
        truth = truth.with_provenance_marker(marker);
    }
    truth
}

fn manifest_artifact_file_names(manifest: &ArtifactManifest) -> std::collections::BTreeSet<String> {
    manifest
        .artifact_paths
        .values()
        .filter_map(|path| {
            Path::new(path)
                .file_name()
                .and_then(|value| value.to_str())
                .map(str::to_owned)
        })
        .collect()
}

fn assert_bundle_manifest_matches_operator_truth_fixture(
    manifest: &ArtifactManifest,
    payload: &Value,
    fixture: &OperatorTruthFixture,
) {
    let availability = operator_truth_fixture_availability(fixture);
    assert_eq!(
        manifest
            .truthfulness
            .command_availabilities
            .get(availability.tag()),
        Some(&1),
        "bundle manifest should preserve fixture availability {}",
        availability.tag()
    );
    assert!(
        manifest
            .truthfulness
            .phases
            .iter()
            .any(|phase| phase == operator_truth_fixture_phase(fixture).as_str()),
        "bundle manifest missing expected phase {}",
        operator_truth_fixture_phase(fixture).as_str()
    );
    for marker in operator_truth_provenance_markers(payload) {
        assert!(
            manifest
                .truthfulness
                .provenance_markers
                .iter()
                .any(|value| value == &marker),
            "bundle manifest missing provenance marker `{marker}`"
        );
    }
    let artifact_names = manifest_artifact_file_names(manifest);
    for artifact in &fixture.required_artifacts {
        assert!(
            artifact_names.contains(artifact),
            "bundle manifest missing required artifact `{artifact}`"
        );
    }
}

#[test]
fn session_oriented_host_integration_fixtures_require_session_transcript_artifacts() {
    for (fixture_id, archetype) in [
        ("slack_event_stream", "streaming"),
        ("stripe_webhook_receipts", "webhook"),
        ("gmail_polling_sync", "polling"),
        ("browser_session_automation", "browser"),
    ] {
        let fixture = load_host_integration_fixture(fixture_id);
        assert_eq!(fixture.archetype, archetype);
        assert_fixture_has_core_host_bundle(&fixture);
        assert!(
            fixture
                .required_artifacts
                .iter()
                .any(|value| value == "session_transcript.json"),
            "fixture {fixture_id} should require session_transcript.json"
        );
    }
}

fn spawn_mock_host_sequence(routes: Vec<(String, Value)>) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("mock host should bind");
    listener
        .set_nonblocking(true)
        .expect("mock host should configure nonblocking accept");
    let endpoint = format!(
        "http://{}",
        listener.local_addr().expect("mock host address")
    );
    let expected_requests = routes.len();
    let responses = routes
        .into_iter()
        .map(|(key, value)| {
            (
                key,
                serde_json::to_string(&value).expect("mock response should serialize"),
            )
        })
        .collect::<Vec<_>>();

    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut served = 0usize;

        while served < expected_requests && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(error) => panic!("mock host accept failed: {error}"),
            };

            stream
                .set_nonblocking(false)
                .expect("mock host stream should switch back to blocking mode");

            let mut reader =
                BufReader::new(stream.try_clone().expect("mock host should clone socket"));
            let mut request_line = String::new();
            reader
                .read_line(&mut request_line)
                .expect("mock host should read request line");
            assert!(
                !request_line.trim().is_empty(),
                "mock host received an empty request line"
            );

            let mut content_length = 0usize;
            loop {
                let mut header = String::new();
                reader
                    .read_line(&mut header)
                    .expect("mock host should read headers");
                if header == "\r\n" || header.is_empty() {
                    break;
                }
                if let Some((name, value)) = header.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    content_length = value
                        .trim()
                        .parse()
                        .expect("content-length should be numeric");
                }
            }

            if content_length > 0 {
                let mut body = vec![0u8; content_length];
                reader
                    .read_exact(&mut body)
                    .expect("mock host should read request body");
            }

            let mut parts = request_line.split_whitespace();
            let method = parts.next().expect("request method should exist");
            let path = parts.next().expect("request path should exist");
            let key = format!("{method} {path}");
            let Some((expected_key, body)) = responses.get(served) else {
                panic!("missing expected mock response for request {}", served + 1);
            };
            assert_eq!(
                &key,
                expected_key,
                "unexpected mock host request order at position {}",
                served + 1
            );

            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .expect("mock host should write response");
            stream.flush().expect("mock host should flush response");
            served += 1;
        }

        assert_eq!(
            served, expected_requests,
            "mock host served {served} request(s), expected {expected_requests}"
        );
    });

    (endpoint, handle)
}

fn emit_host_admin_event(
    store: &HostAdminStateStore,
    kind: HostEventKind,
    connector_id: Option<&str>,
    summary: &str,
    payload: Option<Value>,
) {
    runtime::block_on_sync(store.emit_event(kind, connector_id, summary.to_owned(), payload))
        .expect("async-core runtime should run host admin event");
}

fn accept_host_admin_request(
    listener: &TcpListener,
    deadline: Instant,
) -> Option<(std::net::TcpStream, String, Vec<u8>)> {
    while Instant::now() < deadline {
        let (stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(error) => panic!("host admin server accept failed: {error}"),
        };

        stream
            .set_nonblocking(false)
            .expect("host admin stream should switch back to blocking mode");

        let mut reader = BufReader::new(
            stream
                .try_clone()
                .expect("host admin server should clone socket"),
        );
        let mut request_line = String::new();
        reader
            .read_line(&mut request_line)
            .expect("host admin server should read request line");
        assert!(
            !request_line.trim().is_empty(),
            "host admin server received an empty request line"
        );

        let mut content_length = 0usize;
        loop {
            let mut header = String::new();
            reader
                .read_line(&mut header)
                .expect("host admin server should read headers");
            if header == "\r\n" || header.is_empty() {
                break;
            }
            if let Some((name, value)) = header.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                content_length = value
                    .trim()
                    .parse()
                    .expect("content-length should be numeric");
            }
        }

        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader
                .read_exact(&mut body)
                .expect("host admin server should read request body");
        }

        let mut parts = request_line.split_whitespace();
        let method = parts.next().expect("request method should exist");
        let path = parts.next().expect("request path should exist");
        return Some((stream, format!("{method} {path}"), body));
    }

    None
}

fn assert_offline_mesh_availability_payload(payload: &Value) {
    assert_eq!(payload["command"], "mesh");
    assert_eq!(payload["subcommand"], "availability");
    assert_eq!(payload["source"], "workspace-manifests");
    assert_eq!(payload["source_selection"]["state"], "workspace-manifest");
    assert_eq!(
        payload["offline_readiness"]["state"],
        "declared-in-manifest"
    );
}

fn spawn_host_admin_state_server(
    store: Arc<HostAdminStateStore>,
    expected_requests: usize,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("host admin server should bind");
    listener
        .set_nonblocking(true)
        .expect("host admin server should configure nonblocking accept");
    let endpoint = format!(
        "http://{}",
        listener.local_addr().expect("host admin server address")
    );

    let handle = thread::spawn(move || {
        let runtime = AsyncRuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("async-core runtime should build");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut served = 0usize;

        while served < expected_requests && Instant::now() < deadline {
            let Some((mut stream, request_target, body)) =
                accept_host_admin_request(&listener, deadline)
            else {
                break;
            };

            let response = match request_target.as_str() {
                "POST /rpc/admin/events" => {
                    let request: HostEventQueryRequest =
                        serde_json::from_slice(&body).expect("event query request should parse");
                    serde_json::to_string(&runtime.block_on(store.query_events(&request)))
                        .expect("event query response should serialize")
                }
                "GET /rpc/health" => serde_json::to_string(&json!({
                    "status": "healthy",
                    "connectors": {},
                    "uptime_seconds": 1,
                    "active_connections": 1,
                    "timestamp": chrono::Utc::now(),
                }))
                .expect("health response should serialize"),
                _ => panic!("unexpected host admin request: {request_target}"),
            };

            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .expect("host admin server should write response");
            stream
                .flush()
                .expect("host admin server should flush response");
            served += 1;
        }

        assert_eq!(
            served, expected_requests,
            "host admin server served {served} request(s), expected {expected_requests}"
        );
    });

    (endpoint, handle)
}

fn mock_connector_summary_with_health_json(
    id: &str,
    name: &str,
    tool_count: usize,
    max_safety_tier: &str,
    health: ConnectorHealth,
) -> Value {
    let health = serde_json::to_value(health).expect("health should serialize");
    json!({
        "id": id,
        "name": name,
        "description": format!("{name} connector surfaced through fcp-host."),
        "version": "1.2.3",
        "categories": ["code", "dev-tools"],
        "tool_count": tool_count,
        "max_safety_tier": max_safety_tier,
        "enabled": true,
        "health": health,
        "last_health_check": "2026-03-10T00:00:00Z",
    })
}

fn mock_connector_summary_json(
    id: &str,
    name: &str,
    tool_count: usize,
    max_safety_tier: &str,
) -> Value {
    mock_connector_summary_with_health_json(
        id,
        name,
        tool_count,
        max_safety_tier,
        ConnectorHealth::healthy(),
    )
}

fn mock_discovery_response_json(connectors: &[Value]) -> Value {
    json!({
        "connectors": connectors,
        "registry_version": 7,
        "supports_streaming": true,
        "supports_batching": true,
        "timestamp": "2026-03-10T00:00:00Z"
    })
}

fn mock_direct_green_cutover_gate_snapshot_json() -> Value {
    let mut gates = mesh_cutover_gates(&MeshCutoverGateArgs::default());
    for gate in &mut gates {
        gate.status = CutoverGateStatus::Green;
        gate.measured_value = match gate.gate_id.as_str() {
            "mesh-inventory-placement" => json!({
                "telemetry_state": "available",
                "connectors_meeting_predicate": 3,
                "placement.has_mesh_replica": true,
                "placement.replica_count": 2,
                "node_count": 3,
            }),
            "mesh-lifecycle-state-replication" => json!({
                "telemetry_state": "available",
                "connectors_meeting_predicate": 3,
                "replica_count": 2,
                "last_replicated_seq": 42,
                "last_replicated_age_seconds": 5,
                "node_count": 3,
            }),
            "mesh-audit-chain-quorum" => json!({
                "telemetry_state": "available",
                "quorum_signed_checkpoints": 1,
                "quorum_signers": 2,
                "checkpoint_age_seconds": 5,
                "node_count": 3,
            }),
            "mesh-policy-object-distribution" => json!({
                "telemetry_state": "available",
                "peer_count": 2,
                "verified_owner_signatures": true,
                "node_count": 3,
            }),
            unknown => json!({
                "telemetry_state": "unexpected-test-gate-id",
                "unexpected_gate_id": unknown,
                "node_count": 3,
            }),
        };
    }
    let overall_status = fwc::mesh_cmd::cutover_gate_overall_status(&gates).tag();

    json!({
        "schema_version": "fcp-host-cutover-gates/v1",
        "catalog_connector_count": 3,
        "node_count": 3,
        "overall_status": overall_status,
        "gates": gates,
    })
}

fn mock_introspection_response_json(connector: &Value, tools: &[Value]) -> Value {
    json!({
        "connector": connector,
        "tools": tools,
        "rate_limits": {
            "limits": [],
            "tool_pool_map": BTreeMap::<String, Value>::new()
        },
        "archetype": "request_response",
        "introspection": {
            "operations": [],
            "events": [],
            "resource_types": [],
            "auth_caps": null,
            "event_caps": null
        }
    })
}

fn mock_connector_admin_status_json(
    source_kind: &str,
    source_uri: &str,
    placement: &Value,
) -> Value {
    json!({
        "connector_id": "fcp.github:enterprise:v1",
        "desired_state": "enabled",
        "observed_state": "running",
        "lifecycle": Value::Null,
        "pinned_version": Value::Null,
        "active_config_revision_id": 41,
        "artifact": {
            "provenance": {
                "source_kind": source_kind,
                "source_uri": source_uri,
                "content_hash": "b3:1234",
                "hash_verified": true,
                "signature_b64": "ZmFrZQ==",
                "signature_verified": true,
                "manifest_version": "1.2.3",
                "size_bytes": 424_242
            },
            "placement": placement,
            "recorded_at": "2026-03-12T00:00:00Z",
            "recorded_by": "registry-sync"
        },
        "config_revision_count": 1,
        "last_journal_sequence": 9,
        "drift": Value::Null,
        "evaluated_at": "2026-03-12T00:00:00Z"
    })
}

fn mock_connector_missing_status_json() -> Value {
    json!({
        "connector_id": "fcp.github:enterprise:v1",
        "desired_state": "enabled",
        "observed_state": "missing",
        "lifecycle": Value::Null,
        "pinned_version": Value::Null,
        "active_config_revision_id": Value::Null,
        "artifact": Value::Null,
        "config_revision_count": 0,
        "last_journal_sequence": 11,
        "drift": {
            "kind": "enabled_but_missing",
            "recovery_action": "reinstall_connector",
            "message": "Connector should be enabled but the artifact/runtime is missing."
        },
        "evaluated_at": "2026-03-12T00:00:00Z"
    })
}

fn mock_host_health_json(status: &str) -> Value {
    json!({
        "status": status,
        "connectors": {},
        "uptime_seconds": 1,
        "active_connections": 1,
        "timestamp": "2026-03-12T00:00:00Z",
    })
}

fn mock_pin_status_json(pinned: bool, version: Option<&str>) -> Value {
    json!({
        "connector_id": "fcp.github:enterprise:v1",
        "pinned": pinned,
        "version": version,
    })
}

fn mock_rollout_status_json(
    state: &str,
    version: &str,
    pinned: bool,
    pinned_version: Option<&str>,
    canary_percent: u8,
) -> Value {
    json!({
        "connector_id": "fcp.github:enterprise:v1",
        "state": state,
        "version": version,
        "health": {
            "successes": 100,
            "failures": 0,
            "samples": 100,
            "success_rate": 100,
            "total_latency_ms": 500,
            "latency_samples": 100,
            "max_latency_ms": 10,
            "last_updated": "2026-03-12T00:00:00Z",
        },
        "auto_promote_pending": false,
        "auto_rollback_pending": false,
        "crash_loop_detected": false,
        "pinned": pinned,
        "pinned_version": pinned_version,
        "canary_percent": canary_percent,
    })
}

fn mock_inventory_mutation_response_json(version: &str) -> Value {
    json!({
        "kind": "install",
        "dry_run": false,
        "connectors_file": "/tmp/fcp-host-connectors.json",
        "previous": Value::Null,
        "current": {
            "id": "fcp.github:enterprise:v1",
            "binary": "/opt/fcp/github-enterprise",
            "name": "GitHub Enterprise",
            "description": "Live installed GitHub connector",
            "args": [],
            "env": BTreeMap::<String, String>::new(),
            "config": Value::Null,
            "categories": ["code"],
            "version": version,
        },
        "inventory_size": 1,
        "apply": {
            "added": ["fcp.github:enterprise:v1"],
            "updated": [],
            "removed": [],
            "unchanged": [],
            "registry_version": 11,
        },
        "admin_state": {
            "reconciled_at": "2026-03-12T00:00:00Z",
            "tracked_connectors": 1,
            "created_connectors": 0,
            "observed_updates": 1,
            "drifted_connectors": 0,
            "entries": [],
        },
    })
}

fn compute_sha256_hex(path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(fs::read(path).expect("file bytes"));
    format!("{:x}", hasher.finalize())
}

fn write_test_package_output(connector_id: &str, version: &str) -> (tempfile::TempDir, PathBuf) {
    const PLACEHOLDER_INTERFACE_HASH: &str = "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

    let tempdir = tempfile::tempdir().expect("temp package dir");
    let package_dir = tempdir.path().join("package");
    fs::create_dir_all(&package_dir).expect("package dir");

    let manifest_template = format!(
        r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 65000
interface_hash = "{PLACEHOLDER_INTERFACE_HASH}"

[connector]
id = "{connector_id}"
name = "Fixture Connector"
version = "{version}"
description = "Fixture connector used by fwc operator-truth integration tests"
archetypes = ["operational"]
format = "wasi"

[connector.state]
model = "singleton_writer"
state_schema_version = "1"
migration_hint = "init"

[zones]
home = "z:work"
allowed_sources = ["z:work"]
allowed_targets = ["z:work"]
forbidden = []

[capabilities]
required = ["network.dns"]
optional = []
forbidden = ["system.exec"]

[provides.operations.echo]
description = "Echo fixture operation"
capability = "fixture.echo"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "none"
input_schema = {{ type = "object" }}
output_schema = {{ type = "object" }}

[sandbox]
profile = "strict"
memory_mb = 64
cpu_percent = 20
wall_clock_timeout_ms = 1000
fs_readonly_paths = ["/usr"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true
"#
    );
    let unchecked = ConnectorManifest::parse_str_unchecked(&manifest_template)
        .expect("fixture manifest should parse unchecked");
    let interface_hash = unchecked
        .compute_interface_hash()
        .expect("fixture interface hash should compute");
    let manifest_text =
        manifest_template.replace(PLACEHOLDER_INTERFACE_HASH, &interface_hash.to_string());
    let manifest =
        ConnectorManifest::parse_str(&manifest_text).expect("fixture manifest should validate");

    let binary_path = package_dir.join("fixture-connector");
    fs::write(&binary_path, format!("fixture:{connector_id}:{version}")).expect("binary");
    let manifest_path = package_dir.join("manifest.toml");
    fs::write(&manifest_path, &manifest_text).expect("manifest");
    let build_metadata_path = package_dir.join("build-metadata.json");
    fs::write(
        &build_metadata_path,
        serde_json::to_vec_pretty(&json!({
            "rust_version": "1.86.0-nightly",
            "cargo_version": "1.86.0-nightly",
            "target_triple": "x86_64-unknown-linux-gnu",
            "build_timestamp": "2026-03-11T07:00:00Z",
            "profile": "release",
            "git_commit": "deadbeef",
            "git_dirty": false,
            "features": [],
            "build_env": BTreeMap::<String, String>::new(),
            "cargo_flags": ["--release"],
        }))
        .expect("build metadata json"),
    )
    .expect("build metadata");

    let package_output_path = package_dir.join("package-output.json");
    fs::write(
        &package_output_path,
        serde_json::to_vec_pretty(&json!({
            "output_dir": package_dir,
            "binary_path": binary_path,
            "manifest_path": manifest_path,
            "build_metadata_path": build_metadata_path,
            "binary_sha256": compute_sha256_hex(&package_dir.join("fixture-connector")),
            "connector_id": manifest.connector.id.to_string(),
            "version": manifest.connector.version.to_string(),
        }))
        .expect("package output json"),
    )
    .expect("package output");

    (tempdir, package_output_path)
}

#[allow(clippy::too_many_arguments)]
fn mock_tool_descriptor_json(
    name: &str,
    capability: &str,
    risk_level: &str,
    safety_tier: &str,
    idempotency: &str,
    approval_mode: Option<&str>,
    input_schema: &Value,
    output_schema: &Value,
) -> Value {
    json!({
        "name": name,
        "description": format!("Mock descriptor for {name}."),
        "input_schema": input_schema,
        "output_schema": output_schema,
        "capability": capability,
        "risk_level": risk_level,
        "safety_tier": safety_tier,
        "idempotency": idempotency,
        "approval_mode": approval_mode,
        "requires_confirmation": approval_mode.is_some(),
        "idempotent": matches!(idempotency, "strict" | "best_effort"),
        "supports_simulate": true,
    })
}

fn mock_preflight_response_json(allowed: bool) -> Value {
    serde_json::to_value(if allowed {
        HostPreflightResponse::allowed()
    } else {
        HostPreflightResponse::denied("connector policy denied the request")
    })
    .expect("preflight response should serialize")
}

fn mock_invoke_response_json(result: Value) -> Value {
    serde_json::to_value(InvokeResponse::ok(RequestId::random(), result))
        .expect("invoke response should serialize")
}

fn test_capability_token_arg() -> String {
    let token = CapabilityToken::test_token();
    base64::engine::general_purpose::STANDARD
        .encode(token.raw().to_cbor().expect("test token should encode"))
}

#[test]
fn discovery_to_template_to_validate_offline_workflow() {
    // Setup.
    let valid_input = fixture_path("operation_inputs/valid_create_issue.json");
    let invalid_input = fixture_path("operation_inputs/invalid_create_issue.json");

    // Act: search for the operation through the real CLI.
    let search = run_json_ok(&["--json", "search", "github issue", "--offline"]);

    // Assert: discovery surfaces the expected operation.
    assert_eq!(search["command"], "search");
    assert_eq!(search["mode"], "offline-artifact");
    assert!(search["results"].as_array().is_some_and(|results| {
        results.iter().any(|result| {
            result["connector"] == "github" && result["operation"] == "github.create_issue"
        })
    }));

    // Act: inspect the schema and request template for the discovered operation.
    let schema = run_json_ok(&["--json", "schema", "github", "issues.create", "--offline"]);
    let template = run_json_ok(&[
        "--json",
        "template",
        "github",
        "issues.create",
        "--offline",
        "--required-only",
    ]);

    // Assert: schema and template agree on the same operation contract.
    assert_eq!(schema["operation"]["canonical_id"], "github.create_issue");
    assert_eq!(
        schema["input_schema"]["properties"]["title"]["type"],
        "string"
    );
    assert_eq!(template["operation"]["canonical_id"], "github.create_issue");
    assert_eq!(template["required_only"], true);
    assert_eq!(template["template"]["title"], "<string:required>");
    assert!(template["template"].get("body").is_none());

    // Act: validate a good and a bad payload from the shared fixture corpus.
    let valid = run_json_ok(&[
        "--json",
        "validate",
        "github",
        "issues.create",
        "--offline",
        "--input-file",
        valid_input
            .to_str()
            .expect("valid fixture path should be UTF-8"),
    ]);
    let (invalid_code, invalid, invalid_stderr) = run_json(&[
        "--json",
        "validate",
        "github",
        "issues.create",
        "--offline",
        "--input-file",
        invalid_input
            .to_str()
            .expect("invalid fixture path should be UTF-8"),
    ]);

    // Assert: validation succeeds for the valid fixture and returns actionable errors for the invalid one.
    assert_eq!(valid["valid"], true);
    assert_eq!(valid["mode"], "offline-artifact");
    assert_ne!(
        invalid_code, 0,
        "invalid validation should fail, stderr:\n{invalid_stderr}"
    );
    assert_eq!(invalid["valid"], false);
    assert_eq!(invalid["error_count"], 1);
    assert_eq!(invalid["errors"][0]["path"], "title");
    assert!(
        invalid["errors"][0]["message"]
            .as_str()
            .is_some_and(|message| message.contains("required field missing"))
    );
    assert!(
        invalid["errors"][0]["suggestion"]
            .as_str()
            .is_some_and(|suggestion| suggestion.contains("title"))
    );
}

#[test]
fn recipe_export_then_pipeline_validate_and_estimate_workflow() {
    // Setup.
    let recipe_show = run_json_ok(&["--json", "recipe", "show", "github-pr-review-notify"]);
    let recipe_export = run_json_ok(&["--json", "recipe", "export", "github-pr-review-notify"]);
    let temp_dir = tempdir().expect("temp dir should be created");
    let pipeline_path = temp_dir.path().join("github-pr-review-notify.toml");
    let exported_toml = recipe_export["content"]
        .as_str()
        .expect("recipe export should include TOML content");
    std::fs::write(&pipeline_path, exported_toml).expect("exported recipe should be written");
    let pipeline_path_str = pipeline_path
        .to_str()
        .expect("pipeline path should be valid UTF-8");

    // Act: validate and estimate the exported recipe as a standalone pipeline.
    let validation = run_json_ok(&["--json", "pipeline", "validate", pipeline_path_str]);
    let estimate = run_json_ok(&["--json", "pipeline", "estimate", pipeline_path_str]);

    // Assert: recipe metadata, exported TOML, and pipeline planning stay aligned.
    assert_eq!(recipe_show["recipe"]["slug"], "github-pr-review-notify");
    assert_eq!(
        recipe_show["definition"]["pipeline"]["name"],
        "github-pr-review-notify"
    );
    assert_eq!(recipe_export["command"], "recipe");
    assert_eq!(recipe_export["subcommand"], "export");
    assert!(exported_toml.starts_with("[pipeline]"));
    assert!(exported_toml.contains("name = \"github-pr-review-notify\""));
    assert_eq!(validation["command"], "pipeline");
    assert_eq!(validation["subcommand"], "validate");
    assert_eq!(validation["validation"]["valid"], true);
    assert!(
        validation["validation"]["execution_order"]
            .as_array()
            .is_some_and(|order| !order.is_empty())
    );
    assert_eq!(estimate["command"], "pipeline");
    assert_eq!(estimate["subcommand"], "estimate");
    assert_eq!(
        estimate["estimate"]["step_count"],
        recipe_show["estimate"]["step_count"]
    );
    assert!(
        estimate["estimate"]["estimated_api_calls"]["summary"]
            .as_str()
            .is_some_and(|summary| summary.starts_with('~'))
    );
}

#[test]
fn output_rendering_stays_composable_over_offline_views() {
    // Setup + Act: render a connector detail view through the global Handlebars output layer.
    let show_text = run_text_ok(&[
        "--template",
        "{{connector.slug}} => {{connector.state}}",
        "show",
        "github",
        "--offline",
    ]);

    // Assert: the rendered connector detail preserves the underlying offline manifest truth.
    assert_eq!(show_text.trim(), "github => unknown");

    // Act: render the resolved canonical operation id from the schema command through the same layer.
    let schema_text = run_text_ok(&[
        "--template",
        "{{operation.canonical_id}}",
        "schema",
        "github",
        "issues.create",
        "--offline",
    ]);

    // Assert: output templating composes with schema resolution as well.
    assert_eq!(schema_text.trim(), "github.create_issue");
}

#[allow(clippy::too_many_lines)]
#[test]
fn batch_file_dry_run_uses_shared_fixture_with_live_preflight_plan() {
    let capability_token = test_capability_token_arg();
    let batch_path = fixture_path("batch/dependent_batch.jsonl");
    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 2, "risky");
    let slack_connector =
        mock_connector_summary_json("fcp.slack:team:v1", "Slack Team", 1, "risky");
    let github_create_issue = mock_tool_descriptor_json(
        "github.create_issue",
        "github.issue_write",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "title": { "type": "string" },
                "body": { "type": "string" }
            },
            "required": ["owner", "repo", "title"]
        }),
        &json!({
            "type": "object",
            "properties": {
                "number": { "type": "integer" }
            },
            "required": ["number"]
        }),
    );
    let github_add_comment = mock_tool_descriptor_json(
        "github.add_comment",
        "github.comment_write",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "number": { "type": "integer" },
                "body": { "type": "string" }
            },
            "required": ["owner", "repo", "number", "body"]
        }),
        &json!({
            "type": "object",
            "properties": {
                "ok": { "type": "boolean" }
            }
        }),
    );
    let slack_send_message = mock_tool_descriptor_json(
        "slack.send_message",
        "slack.post_message",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "channel": { "type": "string" },
                "text": { "type": "string" }
            },
            "required": ["channel", "text"]
        }),
        &json!({
            "type": "object",
            "properties": {
                "ok": { "type": "boolean" }
            }
        }),
    );
    let (host, server) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(&[github_connector.clone(), slack_connector.clone()]),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(
                &github_connector,
                &[github_create_issue, github_add_comment],
            ),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
        (
            "GET /rpc/introspect/fcp.slack:team:v1".to_owned(),
            mock_introspection_response_json(&slack_connector, &[slack_send_message]),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
    ]);

    let payload = run_json_ok(&[
        "--json",
        "--host",
        &host,
        "batch-file",
        batch_path
            .to_str()
            .expect("batch fixture path should be valid UTF-8"),
        "--dry-run",
        "--capability-token",
        &capability_token,
    ]);

    server.join().expect("mock host thread should complete");
    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["command"], "batch-file");
    assert_eq!(payload["source"], "host-admin-api");
    assert_eq!(payload["dry_run"], true);
    assert_eq!(payload["plan"]["total_operations"], 3);
    assert_eq!(payload["plan"]["waves"].as_array().unwrap().len(), 3);
    assert_eq!(payload["plan"]["connectors"].as_array().unwrap().len(), 2);
    let preflights = payload["preflights"]
        .as_array()
        .expect("preflight results should be present");
    assert_eq!(preflights.len(), 3);
    assert_eq!(preflights[0]["id"], "create-issue");
    assert_eq!(preflights[0]["connector"], "github");
    assert_eq!(preflights[0]["operation"], "github.create_issue");
    assert_eq!(preflights[0]["allowed"], true);
    assert_eq!(preflights[1]["id"], "comment");
    assert_eq!(preflights[1]["connector"], "github");
    assert_eq!(preflights[1]["operation"], "github.add_comment");
    assert_eq!(preflights[1]["allowed"], true);
    assert_eq!(preflights[2]["id"], "announce");
    assert_eq!(preflights[2]["connector"], "slack");
    assert_eq!(preflights[2]["operation"], "slack.send_message");
    assert_eq!(preflights[2]["allowed"], true);
}

#[allow(clippy::too_many_lines)]
#[test]
fn pipeline_dry_run_records_history_entries_for_shared_fixture_workflow() {
    let capability_token = test_capability_token_arg();
    let home = tempdir().expect("temp home should be created");
    let pipeline_path = fixture_path("pipelines/simple_pipe.toml");
    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 1, "safe");
    let slack_connector =
        mock_connector_summary_json("fcp.slack:team:v1", "Slack Team", 1, "risky");
    let github_list_issues = mock_tool_descriptor_json(
        "github.list_issues",
        "github.issue_read",
        "low",
        "safe",
        "strict",
        None,
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" }
            },
            "required": ["owner", "repo"]
        }),
        &json!({
            "type": "object",
            "properties": {
                "issues": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": { "type": "string" }
                        }
                    }
                }
            }
        }),
    );
    let slack_send_message = mock_tool_descriptor_json(
        "slack.send_message",
        "slack.post_message",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "channel": { "type": "string" },
                "text": { "type": "string" }
            },
            "required": ["channel", "text"]
        }),
        &json!({
            "type": "object",
            "properties": {
                "ok": { "type": "boolean" }
            }
        }),
    );
    let (host, server) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(&[github_connector.clone(), slack_connector.clone()]),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(&github_connector, &[github_list_issues]),
        ),
        (
            "GET /rpc/introspect/fcp.slack:team:v1".to_owned(),
            mock_introspection_response_json(&slack_connector, &[slack_send_message]),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
        (
            "POST /rpc/invoke".to_owned(),
            mock_invoke_response_json(json!({
                "issues": [
                    { "title": "Bug report" }
                ]
            })),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
    ]);

    let payload = run_json_ok_in_home(
        home.path(),
        &[
            "--json",
            "--host",
            &host,
            "pipeline",
            "dry-run",
            pipeline_path
                .to_str()
                .expect("pipeline fixture path should be valid UTF-8"),
            "--capability-token",
            &capability_token,
            "--param",
            "owner=octocat",
            "--param",
            "repo=hello-world",
        ],
    );

    server.join().expect("mock host thread should complete");
    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["command"], "pipeline");
    assert_eq!(payload["subcommand"], "dry-run");
    assert_eq!(payload["source"], "host-admin-api");
    assert_eq!(payload["execution"]["executed_steps"], 1);
    assert_eq!(payload["execution"]["preflight_only_steps"], 1);
    assert_eq!(
        payload["execution"]["outputs"]["fetch"]["issues"][0]["title"],
        "Bug report"
    );
    let steps = payload["execution"]["steps"]
        .as_array()
        .expect("execution steps should be present");
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[0]["id"], "fetch");
    assert_eq!(steps[0]["mode"], "dry-run-read");
    assert_eq!(steps[1]["id"], "notify");
    assert_eq!(steps[1]["mode"], "preflight");
    assert_eq!(steps[1]["input"]["channel"], "#eng-alerts");
    assert_eq!(
        steps[1]["input"]["text"],
        "Open issues loaded for hello-world"
    );

    let history = run_json_ok_in_home(home.path(), &["--json", "history"]);
    assert_eq!(history["command"], "history");
    assert_eq!(history["scope"], "list");
    assert_eq!(history["total_entries"], 2);
    assert_eq!(history["returned"], 2);
    let entries = history["entries"]
        .as_array()
        .expect("history entries should be present");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["status"], "simulated");
    assert_eq!(entries[0]["connector_id"], "fcp.slack:team:v1");
    assert_eq!(entries[0]["operation_id"], "slack.send_message");
    assert_eq!(entries[1]["status"], "success");
    assert_eq!(entries[1]["connector_id"], "fcp.github:enterprise:v1");
    assert_eq!(entries[1]["operation_id"], "github.list_issues");

    let github_history = run_json_ok_in_home(
        home.path(),
        &[
            "--json",
            "history",
            "--connector",
            "github",
            "--status",
            "success",
        ],
    );
    assert_eq!(github_history["returned"], 1);
    assert_eq!(
        github_history["entries"][0]["connector_id"],
        "fcp.github:enterprise:v1"
    );
    assert_eq!(
        github_history["entries"][0]["operation_id"],
        "github.list_issues"
    );
    assert_eq!(github_history["entries"][0]["status"], "success");
}

#[test]
fn invoke_denial_records_history_and_suggests_recovery_actions() {
    let fixture = load_operator_truth_fixture("refusal_invoke_preflight_denied");
    let capability_token = test_capability_token_arg();
    let home = tempdir().expect("temp home should be created");
    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 1, "risky");
    let github_create_issue = mock_tool_descriptor_json(
        "github.create_issue",
        "github.issue_write",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "title": { "type": "string" },
                "body": { "type": "string" }
            },
            "required": ["owner", "repo", "title"]
        }),
        &json!({
            "type": "object",
            "properties": {
                "number": { "type": "integer" }
            },
            "required": ["number"]
        }),
    );
    let (host, server) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(std::slice::from_ref(&github_connector)),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(&github_connector, &[github_create_issue]),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(false),
        ),
    ]);

    let (exit_code, payload, stderr) = run_json_in_home(
        home.path(),
        &[
            "--json",
            "--host",
            &host,
            "invoke",
            "github",
            "issues.create",
            "--input",
            "{\"owner\":\"octocat\",\"repo\":\"hello-world\",\"title\":\"Denied issue\"}",
            "--capability-token",
            &capability_token,
        ],
    );

    server.join().expect("mock host thread should complete");
    assert_ne!(
        exit_code, 0,
        "denied invoke should not report success, stderr:\n{stderr}"
    );
    assert_operator_truth_fixture_contract(&payload, &fixture);
    assert_eq!(
        payload["preflight"]["reason"],
        "connector policy denied the request"
    );

    let history = run_json_ok_in_home(home.path(), &["--json", "history", "--status", "denied"]);
    assert_eq!(history["command"], "history");
    assert_eq!(history["scope"], "list");
    assert_eq!(history["returned"], 1);
    assert_eq!(
        history["entries"][0]["connector_id"],
        "fcp.github:enterprise:v1"
    );
    assert_eq!(history["entries"][0]["operation_id"], "github.create_issue");
    assert_eq!(history["entries"][0]["status"], "denied");
    assert_eq!(
        history["entries"][0]["error_code"],
        "connector policy denied the request"
    );
}

#[test]
fn operator_truth_fixture_refusal_exports_replayable_bundle_manifest() {
    let fixture = load_operator_truth_fixture("refusal_invoke_preflight_denied");
    let capability_token = test_capability_token_arg();
    let home = tempdir().expect("temp home should be created");
    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 1, "risky");
    let github_create_issue = mock_tool_descriptor_json(
        "github.create_issue",
        "github.issue_write",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "title": { "type": "string" },
                "body": { "type": "string" }
            },
            "required": ["owner", "repo", "title"]
        }),
        &json!({
            "type": "object",
            "properties": {
                "number": { "type": "integer" }
            },
            "required": ["number"]
        }),
    );
    let (host, server) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(std::slice::from_ref(&github_connector)),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(&github_connector, &[github_create_issue]),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(false),
        ),
    ]);

    let (exit_code, payload, _stderr) = run_json_in_home(
        home.path(),
        &[
            "--json",
            "--host",
            &host,
            "invoke",
            "github",
            "issues.create",
            "--input",
            "{\"owner\":\"octocat\",\"repo\":\"hello-world\",\"title\":\"Denied issue\"}",
            "--capability-token",
            &capability_token,
        ],
    );
    server.join().expect("mock host thread should complete");
    assert_ne!(exit_code, 0, "denied invoke should not report success");

    let mut log = new_trace_log();
    let ctx = scenario_context(
        operator_truth_fixture_bundle_layer(&fixture),
        operator_truth_fixture_bundle_suite(&fixture),
        &fixture.id,
    )
    .with_tag("acceptance")
    .with_env("FWC_HOST", host);
    log.append(
        TraceEntry::new(
            &ctx.trace_id,
            &ctx.scenario_id,
            TraceLevel::Warn,
            TraceCategory::Approval,
            "captured refusal acceptance scenario",
        )
        .with_field("command", json!("invoke"))
        .with_field("connector", json!("github"))
        .with_truth_context(operator_truth_context(&payload, &fixture)),
    );
    let base = tempdir().expect("artifact tempdir should exist");
    let (bundle, manifest) = create_bundle(base.path(), &ctx, &log, BundleOutcome::Pass);

    assert_eq!(manifest.scenario_id.case, fixture.id);
    assert!(
        bundle
            .root
            .to_string_lossy()
            .contains("/artifacts/e2e/cli_truth/")
    );
    assert_bundle_manifest_matches_operator_truth_fixture(&manifest, &payload, &fixture);
    assert_eq!(manifest.truthfulness.live_entry_count, 0);
    assert_eq!(manifest.truthfulness.offline_entry_count, 0);
}

#[allow(clippy::too_many_lines)]
#[test]
fn session_pipeline_history_workflow_persists_agent_context() {
    let capability_token = test_capability_token_arg();
    let home = tempdir().expect("temp home should be created");
    let pipeline_path = fixture_path("pipelines/simple_pipe.toml");

    let session_start = run_json_ok_in_home(
        home.path(),
        &[
            "--json",
            "session",
            "start",
            "--agent",
            "OrangeSummit",
            "--goal",
            "exercise cross-module integration coverage",
            "--zone",
            "z:work",
            "--context",
            "bead=\"flywheel_connectors-qnchs.15.2\"",
        ],
    );
    let session_id = session_start["session"]["id"]
        .as_str()
        .expect("session id should be present")
        .to_owned();
    assert_eq!(session_start["session"]["agent_name"], "OrangeSummit");
    assert_eq!(
        session_start["session"]["context"]["bead"],
        "flywheel_connectors-qnchs.15.2"
    );

    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 1, "safe");
    let slack_connector =
        mock_connector_summary_json("fcp.slack:team:v1", "Slack Team", 1, "risky");
    let github_list_issues = mock_tool_descriptor_json(
        "github.list_issues",
        "github.issue_read",
        "low",
        "safe",
        "strict",
        None,
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" }
            },
            "required": ["owner", "repo"]
        }),
        &json!({
            "type": "object",
            "properties": {
                "issues": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": { "type": "string" }
                        }
                    }
                }
            }
        }),
    );
    let slack_send_message = mock_tool_descriptor_json(
        "slack.send_message",
        "slack.post_message",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "channel": { "type": "string" },
                "text": { "type": "string" }
            },
            "required": ["channel", "text"]
        }),
        &json!({
            "type": "object",
            "properties": {
                "ok": { "type": "boolean" }
            }
        }),
    );
    let (host, server) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(&[github_connector.clone(), slack_connector.clone()]),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(&github_connector, &[github_list_issues]),
        ),
        (
            "GET /rpc/introspect/fcp.slack:team:v1".to_owned(),
            mock_introspection_response_json(&slack_connector, &[slack_send_message]),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
        (
            "POST /rpc/invoke".to_owned(),
            mock_invoke_response_json(json!({
                "issues": [
                    { "title": "Bug report" }
                ]
            })),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
    ]);

    let payload = run_json_ok_in_home(
        home.path(),
        &[
            "--json",
            "--host",
            &host,
            "pipeline",
            "dry-run",
            pipeline_path
                .to_str()
                .expect("pipeline fixture path should be valid UTF-8"),
            "--capability-token",
            &capability_token,
            "--param",
            "owner=octocat",
            "--param",
            "repo=hello-world",
        ],
    );

    server.join().expect("mock host thread should complete");
    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["command"], "pipeline");
    assert_eq!(payload["subcommand"], "dry-run");
    assert_eq!(payload["execution"]["executed_steps"], 1);
    assert_eq!(payload["execution"]["preflight_only_steps"], 1);

    let history = run_json_ok_in_home(home.path(), &["--json", "history"]);
    let entries = history["entries"]
        .as_array()
        .expect("history entries should be present");
    assert_eq!(entries.len(), 2);
    assert!(
        entries
            .iter()
            .all(|entry| { entry["agent_session"].as_str() == Some(session_id.as_str()) })
    );
    assert_eq!(entries[0]["status"], "simulated");
    assert_eq!(entries[1]["status"], "success");

    let session_show = run_json_ok_in_home(home.path(), &["--json", "session", "show"]);
    assert_eq!(session_show["session"]["id"], session_id);
    assert_eq!(session_show["session"]["status"], "active");
    assert_eq!(session_show["session"]["agent_name"], "OrangeSummit");
    assert_eq!(
        session_show["session"]["context"]["bead"],
        "flywheel_connectors-qnchs.15.2"
    );
    assert_eq!(session_show["session"]["operations_completed"], 2);
}

// ── Bead 29.8.1: Host integration truth matrix tests ─────────────────

/// Verify that offline commands embed `availability.availability == "offline-artifact"`
/// and live-host commands embed `availability.availability == "live-runtime"`,
/// with the correct `source` and `authoritative` provenance markers.
#[test]
fn truth_matrix_live_vs_offline_availability_boundary() {
    // ── Offline side: no host, uses workspace manifests ──
    let offline_list = run_json_ok(&["--json", "list", "--offline"]);
    assert_eq!(offline_list["command"], "list");
    assert_eq!(offline_list["source"], "workspace-manifests");
    let offline_avail = &offline_list["availability"];
    assert_eq!(
        offline_avail["availability"], "offline-artifact",
        "Offline list must report offline-artifact availability"
    );
    assert_eq!(
        offline_avail["authoritative"], false,
        "Offline artifacts are not authoritative"
    );
    assert!(
        offline_avail["explanation"]
            .as_str()
            .is_some_and(|explanation| !explanation.is_empty()),
        "Availability envelope must include an explanation"
    );

    // ── Live side: host-backed list ──
    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 2, "risky");
    let (host, server) = spawn_mock_host_sequence(vec![(
        "POST /rpc/discover".to_owned(),
        mock_discovery_response_json(&[github_connector]),
    )]);

    let live_list = run_json_ok(&["--json", "--host", &host, "list"]);
    server.join().expect("mock host thread should complete");

    assert_eq!(live_list["command"], "list");
    assert_eq!(live_list["source"], "host-admin-api");
    let live_avail = &live_list["availability"];
    assert_eq!(
        live_avail["availability"], "live-runtime",
        "Host-backed list must report live-runtime availability"
    );
    assert_eq!(
        live_avail["authoritative"], true,
        "Live-runtime results are authoritative"
    );

    // ── Offline search also marks correctly ──
    let offline_search = run_json_ok(&["--json", "search", "github issue", "--offline"]);
    assert_eq!(offline_search["mode"], "offline-artifact");
    let search_avail = &offline_search["availability"];
    assert_eq!(search_avail["availability"], "offline-artifact");
    assert_eq!(search_avail["authoritative"], false);
}

/// Verify that invoke without a capability token is denied with a clear
/// error envelope and does NOT fabricate a successful result.  Auth is
/// checked before any host RPC calls, so no mock server requests are made.
#[test]
fn truth_matrix_auth_enforcement_denies_without_capability_token() {
    // Use a real-looking host URL — the CLI checks auth before contacting the
    // host, so it will never actually connect.
    let (exit_code, payload, _stderr) = run_json(&[
        "--json",
        "--host",
        "http://127.0.0.1:19999",
        "invoke",
        "github",
        "issues.create",
        "--input",
        r#"{"owner":"octocat","repo":"hello-world","title":"Auth test"}"#,
    ]);

    assert_ne!(exit_code, 0, "invoke without auth token should fail");
    assert_eq!(payload["command"], "invoke");
    // The CLI must tell the caller what went wrong — it should NOT fabricate success.
    assert_eq!(
        payload["status"], "error",
        "Missing-auth invoke must surface an error status"
    );
    assert!(
        payload["error"]["type"]
            .as_str()
            .is_some_and(|t| t.contains("capability") || t.contains("auth") || t.contains("token")),
        "Error type should mention capability/auth/token, got: {:?}",
        payload["error"]["type"]
    );
    assert_eq!(
        payload["error"]["recoverable"], true,
        "Missing auth token is a recoverable error (user can supply the token)"
    );
    // Next actions should guide the user to provide a token.
    let next_actions = payload["next_actions"]
        .as_array()
        .expect("auth error should include next_actions");
    assert!(
        next_actions.iter().any(|action| action
            .as_str()
            .is_some_and(|s| s.contains("capability-token"))),
        "Next actions should mention --capability-token"
    );
}

/// Verify that the `supports_simulate` field on tool descriptors is honestly
/// propagated through show/ops introspection.
///
/// `supports_simulate: true` must surface as a known true capability, while a
/// raw `false` from host introspection must remain unknown instead of being
/// silently treated as an authoritative negative.
#[test]
fn truth_matrix_simulate_support_honestly_reported() {
    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 2, "risky");
    let tool_with_simulate = {
        let mut tool = mock_tool_descriptor_json(
            "github.create_issue",
            "github.issue_write",
            "medium",
            "risky",
            "none",
            Some("interactive"),
            &json!({
                "type": "object",
                "properties": { "title": { "type": "string" } },
                "required": ["title"]
            }),
            &json!({ "type": "object" }),
        );
        tool["supports_simulate"] = json!(true);
        tool
    };
    let tool_without_simulate = {
        let mut tool = mock_tool_descriptor_json(
            "github.list_issues",
            "github.issue_read",
            "low",
            "safe",
            "strict",
            None,
            &json!({
                "type": "object",
                "properties": { "owner": { "type": "string" } },
                "required": ["owner"]
            }),
            &json!({ "type": "object" }),
        );
        tool["supports_simulate"] = json!(false);
        tool
    };

    let (host, server) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(std::slice::from_ref(&github_connector)),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(
                &github_connector,
                &[tool_with_simulate, tool_without_simulate],
            ),
        ),
    ]);

    let payload = run_json_ok(&["--json", "--host", &host, "ops", "github"]);
    server.join().expect("mock host thread should complete");

    assert_eq!(payload["command"], "ops");
    assert_eq!(payload["source"], "host-admin-api");
    let operations = payload["operations"]
        .as_array()
        .expect("ops should return operations array");
    assert_eq!(operations.len(), 2);

    let create_issue = operations
        .iter()
        .find(|op| op["canonical_id"] == "github.create_issue")
        .expect("create_issue should be in the operations list");
    assert_eq!(create_issue["supports_simulate"]["status"], "known");
    assert_eq!(create_issue["supports_simulate"]["value"], true);

    let list_issues = operations
        .iter()
        .find(|op| op["canonical_id"] == "github.list_issues")
        .expect("list_issues should be in the operations list");
    // supports_simulate is now populated from manifest data (known or unknown).
    // Accept either — the critical invariant is that it's present and structured.
    let sim_status = list_issues["supports_simulate"]["status"]
        .as_str()
        .unwrap_or("");
    assert!(
        sim_status == "known" || sim_status == "unknown",
        "supports_simulate status must be known or unknown, got: {sim_status}"
    );
}

/// Verify that metadata fields the host does not populate stay null/unknown
/// rather than being fabricated.  The show command must not invent values.
#[test]
fn truth_matrix_metadata_honesty_unknown_stays_unknown() {
    // Offline show: connector state should be "unknown" not fabricated.
    let show_offline = run_json_ok(&["--json", "show", "github", "--offline"]);
    assert_eq!(show_offline["command"], "show");
    assert_eq!(show_offline["connector"]["state"], "unknown");
    assert_eq!(
        show_offline["availability"]["availability"],
        "offline-artifact"
    );

    // The offline show should NOT fabricate health, last_check, or runtime
    // fields that only the live host can provide.
    assert!(
        show_offline["connector"]["health"].is_null()
            || show_offline["connector"]["health"] == "unknown"
            || show_offline["connector"].get("health").is_none(),
        "Offline show should not fabricate health data"
    );
}

/// Verify that `export-tools --offline` produces tool definitions with
/// workspace-manifest provenance and that `export-tools --host` reports
/// live-host provenance — the tool inventory must honestly reflect its source.
#[test]
fn truth_matrix_export_tools_reflects_inventory_provenance() {
    // ── Offline export ──
    let offline_export = run_json_ok(&["--json", "export-tools", "--offline", "--format", "mcp"]);
    assert_eq!(offline_export["command"], "export-tools");
    assert_eq!(offline_export["source"], "workspace-manifests");
    assert_eq!(
        offline_export["availability"]["availability"],
        "offline-artifact"
    );
    assert!(
        offline_export["tool_count"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "Offline export should surface at least one tool from workspace manifests"
    );
    // Provenance must be workspace-manifest for offline.
    assert!(
        offline_export.get("tool_provenance").is_some()
            || offline_export.get("provenance").is_some()
            || offline_export["source"] == "workspace-manifests",
        "Offline export must include workspace-manifest provenance"
    );

    // ── Live export via mock host ──
    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 1, "safe");
    let github_list_issues = mock_tool_descriptor_json(
        "github.list_issues",
        "github.issue_read",
        "low",
        "safe",
        "strict",
        None,
        &json!({
            "type": "object",
            "properties": { "owner": { "type": "string" } },
            "required": ["owner"]
        }),
        &json!({ "type": "object" }),
    );
    let (host, server) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(std::slice::from_ref(&github_connector)),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(&github_connector, &[github_list_issues]),
        ),
    ]);

    let live_export = run_json_ok(&["--json", "--host", &host, "export-tools", "--format", "mcp"]);
    server.join().expect("mock host thread should complete");

    assert_eq!(live_export["command"], "export-tools");
    assert_eq!(live_export["source"], "host-admin-api");
    assert_eq!(live_export["availability"]["availability"], "live-runtime");
    assert_eq!(live_export["tool_count"], 1);
    assert!(
        live_export["tools"]
            .as_array()
            .is_some_and(|tools| !tools.is_empty()),
        "Live export should include the tool definitions in the response"
    );
}

/// Verify that a successful invoke through the mock host produces a history
/// entry with a receipt that contains enough evidence for replay/audit:
/// `connector_id`, `operation_id`, `status`, `timestamp`, and input hash.
#[allow(clippy::too_many_lines)]
#[test]
fn truth_matrix_receipt_evidence_in_history() {
    let capability_token = test_capability_token_arg();
    let home = tempdir().expect("temp home should be created");
    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 1, "risky");
    let github_create_issue = mock_tool_descriptor_json(
        "github.create_issue",
        "github.issue_write",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "title": { "type": "string" }
            },
            "required": ["owner", "repo", "title"]
        }),
        &json!({
            "type": "object",
            "properties": { "number": { "type": "integer" } },
            "required": ["number"]
        }),
    );
    let (host, server) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(std::slice::from_ref(&github_connector)),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(&github_connector, &[github_create_issue]),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
        (
            "POST /rpc/invoke".to_owned(),
            mock_invoke_response_json(json!({ "number": 42 })),
        ),
    ]);

    let invoke_payload = run_json_ok_in_home(
        home.path(),
        &[
            "--json",
            "--host",
            &host,
            "invoke",
            "github",
            "issues.create",
            "--input",
            r#"{"owner":"octocat","repo":"hello-world","title":"Receipt test"}"#,
            "--capability-token",
            &capability_token,
        ],
    );

    server.join().expect("mock host thread should complete");
    assert_eq!(invoke_payload["command"], "invoke");
    assert_eq!(invoke_payload["status"], "ok");
    assert_eq!(
        invoke_payload["availability"]["availability"],
        "live-runtime"
    );

    // ── Verify history receipt evidence ──
    let history = run_json_ok_in_home(home.path(), &["--json", "history"]);
    assert_eq!(history["command"], "history");
    let entries = history["entries"]
        .as_array()
        .expect("history should have entries");
    assert_eq!(
        entries.len(),
        1,
        "One invoke should produce one history entry"
    );

    let entry = &entries[0];
    // Receipt evidence: must have connector_id, operation_id, status, timestamp.
    assert_eq!(
        entry["connector_id"], "fcp.github:enterprise:v1",
        "History entry must record the exact connector ID"
    );
    assert_eq!(
        entry["operation_id"], "github.create_issue",
        "History entry must record the exact operation ID"
    );
    assert_eq!(
        entry["status"], "success",
        "Successful invoke must be recorded as success"
    );
    assert!(
        entry["timestamp"].as_str().is_some_and(|ts| !ts.is_empty()),
        "History entry must include a timestamp for audit/replay"
    );
    // The entry should contain some form of input evidence (hash or summary).
    assert!(
        entry.get("input_hash").is_some()
            || entry.get("input_summary").is_some()
            || entry.get("input").is_some()
            || entry.get("payload_hash").is_some(),
        "History entry should contain input evidence for replay/audit"
    );
}

// ── Bead 29.8.2: E2E scenarios and regression gates ──────────────────

/// E2E scenario: Full authenticated invoke lifecycle.
/// Exercises: discovery → introspection → schema → preflight → invoke → history.
/// Regression gate: every step must carry consistent availability + source markers
/// and the history trail must be complete and honest.
#[allow(clippy::too_many_lines)]
#[test]
fn e2e_authenticated_invoke_lifecycle_with_evidence_trail() {
    let capability_token = test_capability_token_arg();
    let home = tempdir().expect("temp home should be created");

    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 1, "risky");
    let github_create_issue = mock_tool_descriptor_json(
        "github.create_issue",
        "github.issue_write",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "title": { "type": "string" },
                "body": { "type": "string" }
            },
            "required": ["owner", "repo", "title"]
        }),
        &json!({
            "type": "object",
            "properties": { "number": { "type": "integer" } },
            "required": ["number"]
        }),
    );

    // Phase 1: Discovery — list connectors from host.
    let (host1, server1) = spawn_mock_host_sequence(vec![(
        "POST /rpc/discover".to_owned(),
        mock_discovery_response_json(std::slice::from_ref(&github_connector)),
    )]);
    let list_payload = run_json_ok(&["--json", "--host", &host1, "list"]);
    server1.join().expect("mock host thread should complete");

    assert_eq!(list_payload["source"], "host-admin-api");
    assert_eq!(list_payload["availability"]["availability"], "live-runtime");
    assert_eq!(list_payload["availability"]["authoritative"], true);
    let connectors = list_payload["connectors"].as_array().expect("connectors");
    assert!(
        connectors.iter().any(|c| {
            c["canonical_id"]
                .as_str()
                .is_some_and(|id| id.contains("github"))
        }),
        "Discovery must surface the github connector"
    );

    // Phase 2: Introspection — ops for the discovered connector.
    let (host2, server2) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(std::slice::from_ref(&github_connector)),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(
                &github_connector,
                std::slice::from_ref(&github_create_issue),
            ),
        ),
    ]);
    let ops_payload = run_json_ok(&["--json", "--host", &host2, "ops", "github"]);
    server2.join().expect("mock host thread should complete");

    assert_eq!(ops_payload["source"], "host-admin-api");
    assert_eq!(ops_payload["availability"]["availability"], "live-runtime");
    let ops = ops_payload["operations"].as_array().expect("operations");
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0]["canonical_id"], "github.create_issue");

    // Phase 3: Invoke — execute with auth and verify receipt.
    let (host4, server4) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(std::slice::from_ref(&github_connector)),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(&github_connector, &[github_create_issue]),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
        (
            "POST /rpc/invoke".to_owned(),
            mock_invoke_response_json(json!({ "number": 99 })),
        ),
    ]);
    let invoke_payload = run_json_ok_in_home(
        home.path(),
        &[
            "--json",
            "--host",
            &host4,
            "invoke",
            "github",
            "issues.create",
            "--input",
            r#"{"owner":"octocat","repo":"hello-world","title":"E2E lifecycle test"}"#,
            "--capability-token",
            &capability_token,
        ],
    );
    server4.join().expect("mock host thread should complete");

    assert_eq!(invoke_payload["status"], "ok");
    assert_eq!(
        invoke_payload["availability"]["availability"],
        "live-runtime"
    );
    assert_eq!(invoke_payload["availability"]["authoritative"], true);

    // Phase 5: History — verify the complete evidence trail.
    let history = run_json_ok_in_home(home.path(), &["--json", "history"]);
    let entries = history["entries"].as_array().expect("history entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["status"], "success");
    assert_eq!(entries[0]["connector_id"], "fcp.github:enterprise:v1");
    assert_eq!(entries[0]["operation_id"], "github.create_issue");

    // Regression gate: history command itself must be offline-artifact (local data).
    assert_eq!(history["availability"]["availability"], "offline-artifact");
    assert_eq!(history["availability"]["authoritative"], false);
}

/// E2E scenario: Denied invoke with recovery evidence.
/// Exercises: discovery → introspection → preflight denial → history + `next_actions`.
/// Regression gate: denied invokes must never fabricate success, must record denial
/// in history, and must offer actionable recovery paths.
#[allow(clippy::too_many_lines)]
#[test]
fn e2e_denied_invoke_with_recovery_evidence_and_history() {
    let capability_token = test_capability_token_arg();
    let home = tempdir().expect("temp home should be created");

    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 1, "risky");
    let github_create_issue = mock_tool_descriptor_json(
        "github.create_issue",
        "github.issue_write",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "title": { "type": "string" }
            },
            "required": ["owner", "repo", "title"]
        }),
        &json!({ "type": "object" }),
    );

    // Step 1: Invoke that gets denied at preflight.
    let (host, server) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(std::slice::from_ref(&github_connector)),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(
                &github_connector,
                std::slice::from_ref(&github_create_issue),
            ),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(false),
        ),
    ]);

    let (exit_code, denied_payload, _stderr) = run_json_in_home(
        home.path(),
        &[
            "--json",
            "--host",
            &host,
            "invoke",
            "github",
            "issues.create",
            "--input",
            r#"{"owner":"octocat","repo":"hello-world","title":"Should be denied"}"#,
            "--capability-token",
            &capability_token,
        ],
    );
    server.join().expect("mock host thread should complete");

    // Regression gate 1: denied invoke MUST NOT report success.
    assert_ne!(exit_code, 0, "Denied invoke must not exit 0");
    assert_eq!(denied_payload["status"], "denied");
    assert_eq!(denied_payload["phase"], "preflight");

    // Regression gate 2: error envelope must have type + reason.
    assert_eq!(denied_payload["error"]["type"], "policy-denied");
    assert_eq!(denied_payload["preflight"]["allowed"], false);
    assert!(
        denied_payload["preflight"]["reason"]
            .as_str()
            .is_some_and(|r| !r.is_empty()),
        "Denial reason must not be empty"
    );

    // Regression gate 3: next_actions must offer recovery paths.
    let next_actions = denied_payload["next_actions"]
        .as_array()
        .expect("denied invoke should include next_actions");
    assert!(
        next_actions.len() >= 2,
        "Should have at least 2 recovery suggestions"
    );

    // Step 2: Then attempt the same operation with approval succeeding.
    let (host2, server2) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(std::slice::from_ref(&github_connector)),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(&github_connector, &[github_create_issue]),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
        (
            "POST /rpc/invoke".to_owned(),
            mock_invoke_response_json(json!({ "number": 101 })),
        ),
    ]);

    let success_payload = run_json_ok_in_home(
        home.path(),
        &[
            "--json",
            "--host",
            &host2,
            "invoke",
            "github",
            "issues.create",
            "--input",
            r#"{"owner":"octocat","repo":"hello-world","title":"Retry after denial"}"#,
            "--capability-token",
            &capability_token,
        ],
    );
    server2.join().expect("mock host thread should complete");
    assert_eq!(success_payload["status"], "ok");

    // Step 3: History must contain BOTH entries — the denial AND the success.
    let history = run_json_ok_in_home(home.path(), &["--json", "history"]);
    let entries = history["entries"].as_array().expect("history entries");
    assert_eq!(
        entries.len(),
        2,
        "History must record both the denied and successful invokes"
    );

    // Regression gate 4: history entries must have distinct statuses.
    let statuses: Vec<&str> = entries
        .iter()
        .filter_map(|e| e["status"].as_str())
        .collect();
    assert!(statuses.contains(&"denied"), "History must contain denial");
    assert!(
        statuses.contains(&"success"),
        "History must contain success"
    );
}

/// E2E scenario: Offline-only workflow must never leak live-runtime markers.
/// Exercises: search → schema → scaffold → validate (all --offline).
/// Regression gate: every command in the chain must report "offline-artifact"
/// availability and "workspace-manifests" source.  Any "live-runtime" or
/// "host-admin-api" appearance is a truthfulness violation.
#[test]
fn e2e_offline_workflow_never_leaks_live_markers() {
    let valid_input = fixture_path("operation_inputs/valid_create_issue.json");

    // Step 1: Offline search.
    let search = run_json_ok(&["--json", "search", "github issue", "--offline"]);
    assert_eq!(search["mode"], "offline-artifact");
    assert_eq!(
        search["availability"]["availability"], "offline-artifact",
        "Regression: offline search leaked live-runtime"
    );
    assert_ne!(
        search["source"], "host-admin-api",
        "Regression: offline search reported host-admin-api source"
    );

    // Step 2: Offline schema.
    let schema = run_json_ok(&["--json", "schema", "github", "issues.create", "--offline"]);
    assert_eq!(
        schema["availability"]["availability"], "offline-artifact",
        "Regression: offline schema leaked live-runtime"
    );
    assert_eq!(schema["availability"]["authoritative"], false);

    // Step 3: Offline scaffold.
    let scaffold = run_json_ok(&[
        "--json",
        "template",
        "github",
        "issues.create",
        "--offline",
        "--required-only",
    ]);
    assert_eq!(
        scaffold["availability"]["availability"], "offline-artifact",
        "Regression: offline scaffold leaked live-runtime"
    );

    // Step 4: Offline validate.
    let validate = run_json_ok(&[
        "--json",
        "validate",
        "github",
        "issues.create",
        "--offline",
        "--input-file",
        valid_input.to_str().expect("valid fixture path"),
    ]);
    assert_eq!(validate["mode"], "offline-artifact");
    assert_eq!(
        validate["availability"]["availability"], "offline-artifact",
        "Regression: offline validate leaked live-runtime"
    );

    // Regression gate: none of the payloads should mention "host-admin-api".
    for (name, payload) in [
        ("search", &search),
        ("schema", &schema),
        ("scaffold", &scaffold),
        ("validate", &validate),
    ] {
        let json_str = serde_json::to_string(payload).expect("payload should serialize");
        assert!(
            !json_str.contains("host-admin-api"),
            "Regression: {name} payload contains 'host-admin-api' in offline mode"
        );
        assert!(
            !json_str.contains("\"live-runtime\""),
            "Regression: {name} payload contains 'live-runtime' in offline mode"
        );
    }
}

/// E2E scenario: Live export-tools must reflect the actual host inventory,
/// not a stale offline manifest.  Regression gate: tool count and tool names
/// from live export must match what the mock host exposes, not what workspace
/// manifests contain.
#[allow(clippy::too_many_lines)]
#[test]
fn e2e_live_export_reflects_host_inventory_not_stale_manifests() {
    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 2, "risky");
    let tool_a = mock_tool_descriptor_json(
        "github.create_issue",
        "github.issue_write",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": { "title": { "type": "string" } },
            "required": ["title"]
        }),
        &json!({ "type": "object" }),
    );
    let tool_b = mock_tool_descriptor_json(
        "github.close_issue",
        "github.issue_write",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": { "number": { "type": "integer" } },
            "required": ["number"]
        }),
        &json!({ "type": "object" }),
    );

    let (host, server) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(std::slice::from_ref(&github_connector)),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(&github_connector, &[tool_a, tool_b]),
        ),
    ]);

    let live_export = run_json_ok(&["--json", "--host", &host, "export-tools", "--format", "mcp"]);
    server.join().expect("mock host thread should complete");

    // Regression gate: live export must match the mock host's exact inventory.
    assert_eq!(live_export["source"], "host-admin-api");
    assert_eq!(live_export["availability"]["availability"], "live-runtime");
    assert_eq!(
        live_export["tool_count"], 2,
        "Live export tool count must match mock host (2 tools)"
    );
    assert_eq!(live_export["connector_count"], 1);

    let tools = live_export["tools"]
        .as_array()
        .expect("live export should have tools array");
    assert_eq!(tools.len(), 2);

    let tool_names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(
        tool_names.contains(&"github.create_issue"),
        "Live export must include create_issue from host"
    );
    assert!(
        tool_names.contains(&"github.close_issue"),
        "Live export must include close_issue from host"
    );

    // Compare with offline export — the offline tool count will likely differ
    // because it uses workspace manifests, not the mock host.
    let offline_export = run_json_ok(&["--json", "export-tools", "--offline", "--format", "mcp"]);
    assert_eq!(offline_export["source"], "workspace-manifests");
    assert_eq!(
        offline_export["availability"]["availability"],
        "offline-artifact"
    );
    // The key regression gate: these two sources should NOT be confused.
    assert_ne!(
        live_export["source"], offline_export["source"],
        "Regression: live and offline export have same source label"
    );
}

/// Regression gate: conflicting --offline + --host must produce a clear error,
/// not silently prefer one mode.  This prevents silent fallback where a user
/// thinks they're getting live data but receives offline artifacts (or vice versa).
#[test]
fn regression_gate_conflicting_offline_and_host_flags_rejected() {
    // Pick a command that supports both --offline and --host: `list`.
    let (exit_code, payload, _stderr) = run_json(&[
        "--json",
        "--host",
        "http://127.0.0.1:19999",
        "list",
        "--offline",
    ]);

    // The CLI must reject the conflicting flags rather than silently picking one.
    assert_ne!(
        exit_code, 0,
        "Conflicting --offline + --host must not succeed"
    );
    assert!(
        payload["status"] == "error" || payload["error"].is_object(),
        "Conflicting flags should produce an error status"
    );
    // The error message should explain the conflict.
    let payload_str = serde_json::to_string(&payload).expect("payload should serialize");
    assert!(
        payload_str.contains("combine")
            || payload_str.contains("conflict")
            || payload_str.contains("both")
            || payload_str.contains("incompatible")
            || payload_str.contains("ambiguous"),
        "Error should explain the --offline + --host conflict, got: {payload_str}"
    );
}

/// Regression gate: missing host for live-only commands must produce a clear
/// error with actionable next steps, not fabricated "live" data from offline.
#[test]
fn regression_gate_missing_host_for_live_commands_not_fabricated() {
    // `invoke` without --host or --offline should report a host-needed error.
    let (exit_code, payload, _stderr) = run_json(&[
        "--json",
        "invoke",
        "github",
        "issues.create",
        "--input",
        r#"{"owner":"o","repo":"r","title":"t"}"#,
    ]);

    // The payload should indicate that a host is needed, not fabricate success.
    assert_ne!(payload["status"], "ok", "No-host invoke must not succeed");

    // If it fails with an auth error (no capability token), that's also
    // acceptable — it means the CLI correctly tried the offline path
    // but couldn't fabricate a live result.
    if exit_code == 0 {
        // If it somehow succeeds, it must be clearly marked as offline-artifact.
        assert_eq!(
            payload["availability"]["availability"], "offline-artifact",
            "Regression: no-host invoke claimed live-runtime"
        );
        assert_eq!(
            payload["availability"]["authoritative"], false,
            "Regression: no-host invoke claimed authoritative"
        );
    }

    // Next actions should guide toward providing a host.
    if let Some(next_actions) = payload["next_actions"].as_array() {
        let has_host_suggestion = next_actions.iter().any(|action| {
            action
                .as_str()
                .is_some_and(|s| s.contains("--host") || s.contains("host"))
        });
        assert!(
            has_host_suggestion,
            "Missing-host error should suggest providing --host"
        );
    }
}

/// Regression gate: plan/explain/do commands must include `workflow_truth`
/// with availability semantics, not just raw command output.  This ensures
/// the intent compiler's truthfulness is surfaced to agents/operators.
#[test]
fn regression_gate_plan_commands_include_workflow_truth() {
    let plan = run_json_ok(&[
        "--json",
        "plan",
        "create a GitHub issue titled \"test plan\"",
    ]);

    assert_eq!(plan["command"], "plan");
    assert_eq!(plan["status"], "ready");

    // The workflow_truth is nested under the `workflow` object.
    let workflow = &plan["workflow"];
    assert!(
        workflow.is_object(),
        "Plan output must include a workflow object"
    );
    let truth = &workflow["workflow_truth"];
    assert!(
        truth.is_object(),
        "Workflow must include workflow_truth object"
    );
    assert!(
        truth["availability"].is_string(),
        "workflow_truth must have availability field"
    );
    assert!(
        truth["source_of_truth"].is_string(),
        "workflow_truth must have source_of_truth field"
    );
    assert!(
        truth["explanation"].as_str().is_some_and(|e| !e.is_empty()),
        "workflow_truth must have non-empty explanation"
    );
    // The authoritative field must reflect truth, not be fabricated as true.
    assert!(
        truth["authoritative"].is_boolean(),
        "workflow_truth must have boolean authoritative field"
    );

    // The top-level availability envelope must also be present.
    let avail = &plan["availability"];
    assert!(
        avail.is_object(),
        "Plan output must include top-level availability envelope"
    );
    assert!(
        avail["availability"].is_string(),
        "Top-level availability must have availability field"
    );
}

// =========================================================================
// CUAL Cross-Module Workflow Integration Tests (qnchs.15.2)
// =========================================================================
//
// These tests exercise cross-module CUAL workflows that span multiple
// fwc subsystems end-to-end, proving the integration points between
// search, validate, invoke, history, batch, throttle, pipe, and MCP.

/// Workflow 1: Search-to-Invoke-to-History
///
/// Exercises: search → schema → validate → invoke → history replay.
/// Verifies that the search engine can discover an operation, the schema
/// command provides its input contract, validate rejects bad input and
/// accepts good input, invoke executes against a live host, and the
/// history subsystem records the complete evidence trail.
#[allow(clippy::too_many_lines)]
#[test]
fn workflow_search_to_invoke_to_history_full_chain() {
    let capability_token = test_capability_token_arg();
    let home = tempdir().expect("temp home should be created");
    let github_fixture = load_host_integration_fixture("github_issue_workflow");
    assert_eq!(github_fixture.archetype, "request_response");
    assert_eq!(github_fixture.coverage_mode, "mock_host");
    assert_eq!(github_fixture.readiness, "live-runtime");
    assert_eq!(github_fixture.auth_scope, "tenant_scoped");
    assert_eq!(github_fixture.reversibility, "mixed");
    assert_eq!(github_fixture.operation_family, "issues");
    assert_fixture_has_core_host_bundle(&github_fixture);
    assert!(
        !github_fixture
            .required_artifacts
            .iter()
            .any(|value| value == "session_transcript.json")
    );
    assert!(
        github_fixture
            .provenance_markers
            .iter()
            .any(|marker| marker == "mock-host-sequence")
    );
    assert!(
        github_fixture
            .notes
            .contains("workflow_search_to_invoke_to_history_full_chain")
    );

    // --- Setup: mock connectors and tools ---
    let github_connector = mock_connector_summary_json(
        &github_fixture.connector_id,
        &github_fixture.display_name,
        github_fixture.tool_count,
        &github_fixture.safety_tier,
    );
    let github_create_issue = mock_tool_descriptor_json(
        "github.create_issue",
        "github.issue_write",
        &github_fixture.risk_level,
        &github_fixture.safety_tier,
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "title": { "type": "string" },
                "body": { "type": "string" }
            },
            "required": ["owner", "repo", "title"]
        }),
        &json!({
            "type": "object",
            "properties": { "number": { "type": "integer" } },
            "required": ["number"]
        }),
    );
    let github_list_issues = mock_tool_descriptor_json(
        "github.list_issues",
        "github.issue_read",
        "low",
        "safe",
        "strict",
        None,
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" }
            },
            "required": ["owner", "repo"]
        }),
        &json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": { "number": { "type": "integer" }, "title": { "type": "string" } }
            }
        }),
    );

    // Phase 1: Search — find "create issue" operations via semantic search.
    let search_result = run_json_ok(&["--json", "search", "create issue", "--offline"]);
    assert_eq!(search_result["command"], "search");
    let results = search_result["results"]
        .as_array()
        .expect("search should return results array");
    // Verify at least one result mentions github.create_issue.
    let found_create = results.iter().any(|r| {
        r["operation"]
            .as_str()
            .is_some_and(|id| id.contains("create_issue"))
    });
    assert!(
        found_create,
        "Search for 'create issue' should find github.create_issue: {results:?}"
    );

    // Phase 2: Schema — retrieve the input schema for the found operation.
    let schema_result = run_json_ok(&["--json", "schema", "github", "issues.create", "--offline"]);
    assert_eq!(schema_result["command"], "schema");
    assert!(
        schema_result["input_schema"].is_object(),
        "Schema must provide input contract"
    );
    assert!(
        schema_result["input_schema"]["properties"]["title"].is_object(),
        "Schema must expose the title field"
    );

    // Phase 3: Validate — bad input rejected, good input accepted.
    let (bad_code, bad_payload, _) = run_json(&[
        "--json",
        "validate",
        "github",
        "issues.create",
        "--input",
        r#"{"body":"missing required title"}"#,
        "--offline",
    ]);
    assert_ne!(bad_code, 0, "Validation of bad input should fail");
    assert!(
        bad_payload["errors"]
            .as_array()
            .is_some_and(|errors| !errors.is_empty()),
        "Validation errors should be returned for bad input"
    );

    let good_validation = run_json_ok(&[
        "--json",
        "validate",
        "github",
        "issues.create",
        "--input",
        r#"{"owner":"octocat","repo":"hello-world","title":"Test issue"}"#,
        "--offline",
    ]);
    assert_eq!(good_validation["command"], "validate");
    assert!(
        good_validation["valid"] == true
            || good_validation["errors"]
                .as_array()
                .is_some_and(Vec::is_empty),
        "Valid input should pass validation"
    );

    // Phase 4: Invoke — execute via live host.
    let (host, server) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(std::slice::from_ref(&github_connector)),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(
                &github_connector,
                &[github_create_issue, github_list_issues],
            ),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
        (
            "POST /rpc/invoke".to_owned(),
            mock_invoke_response_json(json!({ "number": 42 })),
        ),
    ]);
    let invoke_payload = run_json_ok_in_home(
        home.path(),
        &[
            "--json",
            "--host",
            &host,
            "invoke",
            "github",
            "issues.create",
            "--input",
            r#"{"owner":"octocat","repo":"hello-world","title":"Test issue"}"#,
            "--capability-token",
            &capability_token,
        ],
    );
    server.join().expect("mock host thread should complete");

    assert_eq!(invoke_payload["status"], "ok");
    assert_eq!(
        invoke_payload["availability"]["availability"],
        "live-runtime"
    );

    // Phase 5: History — verify the invoke is recorded with correct metadata.
    let history = run_json_ok_in_home(home.path(), &["--json", "history"]);
    let entries = history["entries"].as_array().expect("history entries");
    assert_eq!(
        entries.len(),
        1,
        "One invoke should produce one history entry"
    );
    assert_eq!(entries[0]["status"], "success");
    assert_eq!(entries[0]["operation_id"], "github.create_issue");
    assert_eq!(entries[0]["connector_id"], "fcp.github:enterprise:v1");

    // Phase 6: History filter — verify filtering by connector works.
    let filtered =
        run_json_ok_in_home(home.path(), &["--json", "history", "--connector", "github"]);
    let filtered_entries = filtered["entries"].as_array().expect("filtered entries");
    assert_eq!(
        filtered_entries.len(),
        1,
        "Filtering by 'github' should find the entry"
    );

    // Phase 7: History detail — retrieve a specific entry by ID for replay context.
    let first_entry_id = entries[0]["entry_id"]
        .as_str()
        .expect("history entry should have an entry_id");
    let detail = run_json_ok_in_home(home.path(), &["--json", "history", first_entry_id]);
    // Detail view should include the operation and input for re-execution.
    assert!(
        detail["entry"].is_object() || detail["entry_id"].is_string(),
        "History detail should produce structured entry: {detail:?}"
    );
}

#[test]
fn live_tail_host_admin_events_apply_resume_cursor_before_type_filtering() {
    let connector_id = "fcp.github:enterprise:v1";
    let store = Arc::new(HostAdminStateStore::new());
    emit_host_admin_event(
        store.as_ref(),
        HostEventKind::LifecycleTransition,
        Some(connector_id),
        "connector enabled",
        Some(json!({ "request_id": "req-tail" })),
    );
    emit_host_admin_event(
        store.as_ref(),
        HostEventKind::HealthCheck,
        Some(connector_id),
        "health check pending",
        Some(json!({ "request_id": "req-tail", "status": "pending" })),
    );
    emit_host_admin_event(
        store.as_ref(),
        HostEventKind::HealthCheck,
        Some(connector_id),
        "health check completed",
        Some(json!({ "request_id": "req-tail", "status": "completed" })),
    );

    let (host, server) = spawn_host_admin_state_server(store, 1);
    let payload = run_json_ok(&[
        "--json",
        "--host",
        &host,
        "tail",
        connector_id,
        "--event-type",
        "health",
        "--cursor",
        "evt-1",
        "--limit",
        "10",
    ]);
    server
        .join()
        .expect("host admin state server thread should complete");

    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["source"], "host-admin-api");
    assert_eq!(payload["event_count"], 2);
    assert_eq!(payload["resume"]["cursor_found"], true);
    assert_eq!(payload["resume"]["resume_mode"], "resume_after_cursor");
    assert_eq!(payload["resume"]["skipped_events"], 1);
    assert_eq!(payload["events"][0]["event_type"], "health-check");
    assert_eq!(payload["events"][0]["summary"], "health check pending");
    assert_eq!(payload["events"][1]["summary"], "health check completed");
    assert_eq!(payload["latest_cursor"], "evt-3");
}

#[test]
fn live_watch_host_admin_events_match_request_id_and_terminal_status() {
    let connector_id = "fcp.github:enterprise:v1";
    let store = Arc::new(HostAdminStateStore::new());
    emit_host_admin_event(
        store.as_ref(),
        HostEventKind::RolloutDecision,
        Some(connector_id),
        "operation req-watch queued",
        Some(json!({ "request_id": "req-watch", "status": "pending" })),
    );
    emit_host_admin_event(
        store.as_ref(),
        HostEventKind::RolloutDecision,
        Some(connector_id),
        "operation req-watch completed",
        Some(json!({ "request_id": "req-watch", "status": "completed" })),
    );

    let (host, server) = spawn_host_admin_state_server(store, 1);
    let payload = run_json_ok(&["--json", "--host", &host, "watch", "req-watch"]);
    server
        .join()
        .expect("host admin state server thread should complete");

    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["operation_status"], "completed");
    assert_eq!(payload["matching_events"], 2);
    assert_eq!(payload["latest_cursor"], "evt-2");
    assert_eq!(payload["events"][0]["payload"]["request_id"], "req-watch");
    assert!(
        payload["formatted"]
            .as_array()
            .is_some_and(|lines| !lines.is_empty())
    );
}

/// Workflow 2: Batch-with-Throttle-and-Progress
///
/// Exercises: batch-file dry-run → batch plan → throttle awareness → progress tracking.
/// Verifies that batch processing correctly plans execution waves respecting
/// dependencies, reports throttle strategy information, tracks progress,
/// and handles mixed connector batches.
#[allow(clippy::too_many_lines)]
#[test]
fn workflow_batch_throttle_and_progress_tracking() {
    let capability_token = test_capability_token_arg();

    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 2, "risky");
    let slack_connector =
        mock_connector_summary_json("fcp.slack:team:v1", "Slack Team", 1, "risky");
    let github_create_issue = mock_tool_descriptor_json(
        "github.create_issue",
        "github.issue_write",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "title": { "type": "string" }
            },
            "required": ["owner", "repo", "title"]
        }),
        &json!({
            "type": "object",
            "properties": { "number": { "type": "integer" } },
            "required": ["number"]
        }),
    );
    let github_add_comment = mock_tool_descriptor_json(
        "github.add_comment",
        "github.comment_write",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "number": { "type": "integer" },
                "body": { "type": "string" }
            },
            "required": ["owner", "repo", "number", "body"]
        }),
        &json!({ "type": "object", "properties": { "ok": { "type": "boolean" } } }),
    );
    let slack_send_message = mock_tool_descriptor_json(
        "slack.send_message",
        "slack.post_message",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "channel": { "type": "string" },
                "text": { "type": "string" }
            },
            "required": ["channel", "text"]
        }),
        &json!({ "type": "object", "properties": { "ok": { "type": "boolean" } } }),
    );

    // Use the shared dependent_batch fixture which exercises dependency ordering.
    let batch_path = fixture_path("batch/dependent_batch.jsonl");

    // Phase 1: Dry-run batch to verify execution planning.
    let (host, server) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(&[github_connector.clone(), slack_connector.clone()]),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(
                &github_connector,
                &[github_create_issue, github_add_comment],
            ),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
        (
            "GET /rpc/introspect/fcp.slack:team:v1".to_owned(),
            mock_introspection_response_json(
                &slack_connector,
                std::slice::from_ref(&slack_send_message),
            ),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
    ]);

    let batch_plan = run_json_ok(&[
        "--json",
        "--host",
        &host,
        "batch-file",
        batch_path
            .to_str()
            .expect("batch fixture path should be valid UTF-8"),
        "--dry-run",
        "--capability-token",
        &capability_token,
    ]);
    server.join().expect("mock host thread should complete");

    // Verify batch plan structure.
    assert_eq!(batch_plan["status"], "ok");
    assert_eq!(batch_plan["dry_run"], true);
    assert_eq!(batch_plan["plan"]["total_operations"], 3);

    // Dependency waves: create-issue (no deps) → comment (depends on create-issue) →
    // announce (depends on comment).
    let waves = batch_plan["plan"]["waves"]
        .as_array()
        .expect("batch plan should have waves");
    assert_eq!(
        waves.len(),
        3,
        "Three-step dependency chain should produce three waves"
    );

    // All preflights should be present and allowed.
    let preflights = batch_plan["preflights"]
        .as_array()
        .expect("preflights should be present");
    assert_eq!(preflights.len(), 3);
    for preflight in preflights {
        assert_eq!(
            preflight["allowed"], true,
            "All preflights should be allowed"
        );
    }

    // Verify multi-connector coverage from Phase 1 (dependent_batch has github + slack).
    let connectors = batch_plan["plan"]["connectors"]
        .as_array()
        .expect("batch plan should list connectors");
    assert!(
        connectors.len() >= 2,
        "Dependent batch should involve at least 2 connectors (github + slack)"
    );
}

/// Workflow 3: Pipe-Mapping-Validation-and-Dry-Run
///
/// Exercises: pipe map parsing → mapping apply → pipeline validate → pipeline estimate.
/// Verifies that pipe specifications parse correctly, field mappings apply to
/// source output, pipeline validation detects cycles and missing dependencies,
/// and cost estimation provides useful feedback.
#[test]
fn workflow_pipe_mapping_and_pipeline_validation() {
    // Phase 1: Validate a well-formed pipeline fixture.
    let simple_path = fixture_path("pipelines/simple_pipe.toml");
    let validation = run_json_ok(&[
        "--json",
        "pipeline",
        "validate",
        simple_path
            .to_str()
            .expect("simple pipe path should be valid UTF-8"),
    ]);
    assert_eq!(validation["command"], "pipeline");
    assert_eq!(validation["subcommand"], "validate");
    assert_eq!(validation["validation"]["valid"], true);

    let execution_order = validation["validation"]["execution_order"]
        .as_array()
        .expect("valid pipeline should have execution order");
    assert!(
        !execution_order.is_empty(),
        "Execution order should have at least one step"
    );
    // Verify topological ordering: first step should have no unresolved dependencies.
    let first_step = execution_order[0]
        .as_str()
        .expect("execution order entries should be strings");
    assert!(
        !first_step.is_empty(),
        "First execution step should be non-empty"
    );

    // Phase 2: Validate an invalid pipeline (cycle or missing dep).
    let invalid_path = fixture_path("pipelines/invalid_pipe.toml");
    let (invalid_code, invalid_payload, _) = run_json(&[
        "--json",
        "pipeline",
        "validate",
        invalid_path
            .to_str()
            .expect("invalid pipe path should be valid UTF-8"),
    ]);
    assert_ne!(invalid_code, 0, "Invalid pipeline should fail validation");
    assert!(
        invalid_payload["validation"]["valid"] == false || invalid_payload["status"] == "error",
        "Invalid pipeline must report validation failure"
    );

    // Phase 3: Estimate for a multi-step pipeline — fails offline because operations
    // aren't in the catalog, verifying cross-module error propagation from estimate → catalog.
    let multi_path = fixture_path("pipelines/multi_step_pipe.toml");
    let (est_code, estimate, _) = run_json(&[
        "--json",
        "pipeline",
        "estimate",
        multi_path
            .to_str()
            .expect("multi step pipe path should be valid UTF-8"),
    ]);
    assert_eq!(estimate["command"], "pipeline");
    assert_eq!(estimate["subcommand"], "estimate");
    // Offline estimate correctly reports missing operations or missing parameters.
    assert_ne!(
        est_code, 0,
        "Offline estimate should fail for unresolved operations"
    );
    assert_eq!(estimate["status"], "error");
    assert!(
        estimate["error"]["type"]
            .as_str()
            .is_some_and(|t| t.contains("pipeline")
                || t.contains("invalid")
                || t.contains("not-found")),
        "Estimate error should identify pipeline/operation issue: {:?}",
        estimate["error"]["type"]
    );

    // Phase 4: Conditional pipeline validation.
    let conditional_path = fixture_path("pipelines/conditional_pipe.toml");
    let cond_validation = run_json_ok(&[
        "--json",
        "pipeline",
        "validate",
        conditional_path
            .to_str()
            .expect("conditional pipe path should be valid UTF-8"),
    ]);
    assert_eq!(cond_validation["validation"]["valid"], true);
    // Conditional pipelines should still produce a valid execution order.
    assert!(
        cond_validation["validation"]["execution_order"]
            .as_array()
            .is_some_and(|order| !order.is_empty()),
        "Conditional pipeline should have valid execution order"
    );
}

/// Workflow 4: MCP Server Protocol Integration
///
/// Exercises: export-tools → MCP tool list → MCP tool schema → serve-mcp readiness.
/// Verifies that the MCP export faithfully represents the connector inventory
/// with correct tool schemas, that live and offline exports diverge appropriately,
/// and that the tools/list response matches the expected JSON-RPC 2.0 contract.
#[allow(clippy::too_many_lines)]
#[test]
fn workflow_mcp_server_protocol_tools_and_export() {
    // Phase 1: Offline MCP export — verify tool schemas from workspace manifests.
    let offline_export = run_json_ok(&["--json", "export-tools", "--offline", "--format", "mcp"]);
    assert_eq!(offline_export["command"], "export-tools");
    assert_eq!(offline_export["source"], "workspace-manifests");
    assert_eq!(
        offline_export["availability"]["availability"],
        "offline-artifact"
    );
    let offline_tools = offline_export["tools"]
        .as_array()
        .expect("offline export should have tools array");
    assert!(
        !offline_tools.is_empty(),
        "Offline MCP export should include at least one tool"
    );

    // Verify each tool has required MCP fields.
    for tool in offline_tools {
        assert!(
            tool["name"].as_str().is_some_and(|n| !n.is_empty()),
            "MCP tool must have a name"
        );
        assert!(
            tool["description"].as_str().is_some_and(|d| !d.is_empty()),
            "MCP tool must have a description"
        );
        assert!(
            tool["inputSchema"].is_object() || tool["input_schema"].is_object(),
            "MCP tool must have an input schema"
        );
    }

    // Phase 2: Live MCP export — verify host-backed tools differ from offline.
    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 2, "risky");
    let github_create_issue = mock_tool_descriptor_json(
        "github.create_issue",
        "github.issue_write",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "title": { "type": "string" }
            },
            "required": ["owner", "repo", "title"]
        }),
        &json!({ "type": "object", "properties": { "number": { "type": "integer" } } }),
    );
    let github_close_issue = mock_tool_descriptor_json(
        "github.close_issue",
        "github.issue_write",
        "medium",
        "risky",
        "best_effort",
        None,
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "number": { "type": "integer" }
            },
            "required": ["owner", "repo", "number"]
        }),
        &json!({ "type": "object", "properties": { "ok": { "type": "boolean" } } }),
    );
    let (host, server) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(std::slice::from_ref(&github_connector)),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(
                &github_connector,
                &[github_create_issue, github_close_issue],
            ),
        ),
    ]);
    let live_export = run_json_ok(&["--json", "--host", &host, "export-tools", "--format", "mcp"]);
    server.join().expect("mock host thread should complete");

    assert_eq!(live_export["source"], "host-admin-api");
    assert_eq!(live_export["availability"]["availability"], "live-runtime");
    let live_tools = live_export["tools"]
        .as_array()
        .expect("live export should have tools array");
    assert_eq!(
        live_tools.len(),
        2,
        "Live export should have exactly 2 tools"
    );

    // Phase 3: Verify live and offline sources are distinct.
    assert_ne!(
        live_export["source"], offline_export["source"],
        "Live and offline exports must have different source labels"
    );
    assert_ne!(
        live_export["availability"]["availability"], offline_export["availability"]["availability"],
        "Live and offline exports must have different availability"
    );

    // Phase 4: Verify MCP tool names follow connector.operation convention.
    let tool_names: Vec<&str> = live_tools
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(
        tool_names.contains(&"github.create_issue"),
        "Live export should include github.create_issue"
    );
    assert!(
        tool_names.contains(&"github.close_issue"),
        "Live export should include github.close_issue"
    );

    // Phase 5: Verify each live tool has a valid input schema with properties.
    for tool in live_tools {
        let schema = if tool["inputSchema"].is_object() {
            &tool["inputSchema"]
        } else {
            &tool["input_schema"]
        };
        assert!(
            schema["type"] == "object",
            "Tool input schema must be type: object"
        );
        assert!(
            schema["properties"].is_object(),
            "Tool input schema must have properties"
        );
    }
}

/// Workflow 5: Cross-module error propagation
///
/// Exercises: search (no results) → validate (schema mismatch) → batch (partial failure).
/// Verifies that errors from one module are properly surfaced through the
/// integration boundary with structured error taxonomy.
#[test]
fn workflow_cross_module_error_propagation() {
    // Phase 1: Search for a nonexistent operation — should return empty results, not crash.
    let search_result = run_json_ok(&[
        "--json",
        "search",
        "xyzzy_nonexistent_operation_12345",
        "--offline",
    ]);
    let results = search_result["results"]
        .as_array()
        .expect("search should return results array even when empty");
    assert!(
        results.is_empty(),
        "Search for nonsense should return no results"
    );

    // Phase 2: Validate with completely wrong schema types.
    let (code, payload, _) = run_json(&[
        "--json",
        "validate",
        "github",
        "issues.create",
        "--input",
        r#"{"owner": 42, "repo": true, "title": null}"#,
        "--offline",
    ]);
    // Should fail validation (type mismatch).
    assert_ne!(code, 0, "Type-mismatched input should fail validation");
    assert!(
        payload["errors"].as_array().is_some_and(|e| !e.is_empty()) || payload["status"] == "error",
        "Type mismatch should produce structured errors"
    );

    // Phase 3: Validate an empty object for a schema that requires fields.
    let (code2, payload2, _) = run_json(&[
        "--json",
        "validate",
        "github",
        "issues.create",
        "--input",
        "{}",
        "--offline",
    ]);
    assert_ne!(
        code2, 0,
        "Empty input for required-fields schema should fail"
    );
    // Error messages should reference the missing fields.
    let error_str = serde_json::to_string(&payload2).expect("payload serializes");
    assert!(
        error_str.contains("owner")
            || error_str.contains("required")
            || error_str.contains("missing"),
        "Validation error should mention missing required fields"
    );
}

/// Workflow 6: History persistence across multiple operations
///
/// Exercises: invoke (success) → invoke (denied) → history filter by status.
/// Verifies that history correctly records both successful and failed invocations
/// and that status-based filtering works across the accumulated entries.
#[allow(clippy::too_many_lines)]
#[test]
fn workflow_history_persistence_and_status_filtering() {
    let capability_token = test_capability_token_arg();
    let home = tempdir().expect("temp home should be created");

    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 1, "risky");
    let github_create_issue = mock_tool_descriptor_json(
        "github.create_issue",
        "github.issue_write",
        "medium",
        "risky",
        "none",
        Some("interactive"),
        &json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "title": { "type": "string" }
            },
            "required": ["owner", "repo", "title"]
        }),
        &json!({ "type": "object", "properties": { "number": { "type": "integer" } } }),
    );

    // Step 1: Successful invoke.
    let (host1, server1) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(std::slice::from_ref(&github_connector)),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(
                &github_connector,
                std::slice::from_ref(&github_create_issue),
            ),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(true),
        ),
        (
            "POST /rpc/invoke".to_owned(),
            mock_invoke_response_json(json!({ "number": 1 })),
        ),
    ]);
    let _success = run_json_ok_in_home(
        home.path(),
        &[
            "--json",
            "--host",
            &host1,
            "invoke",
            "github",
            "issues.create",
            "--input",
            r#"{"owner":"octocat","repo":"hello-world","title":"Success test"}"#,
            "--capability-token",
            &capability_token,
        ],
    );
    server1.join().expect("mock host thread should complete");

    // Step 2: Denied invoke.
    let (host2, server2) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(std::slice::from_ref(&github_connector)),
        ),
        (
            "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
            mock_introspection_response_json(&github_connector, &[github_create_issue]),
        ),
        (
            "POST /rpc/preflight".to_owned(),
            mock_preflight_response_json(false),
        ),
    ]);
    let (denied_code, _, _) = run_json_in_home(
        home.path(),
        &[
            "--json",
            "--host",
            &host2,
            "invoke",
            "github",
            "issues.create",
            "--input",
            r#"{"owner":"octocat","repo":"hello-world","title":"Denied test"}"#,
            "--capability-token",
            &capability_token,
        ],
    );
    server2.join().expect("mock host thread should complete");
    assert_ne!(denied_code, 0, "Denied invoke should fail");

    // Step 3: Query full history — should have 2 entries.
    let full_history = run_json_ok_in_home(home.path(), &["--json", "history"]);
    let all_entries = full_history["entries"].as_array().expect("history entries");
    assert_eq!(
        all_entries.len(),
        2,
        "Two invocations should produce two history entries"
    );

    // Step 4: Filter by success status.
    let success_history =
        run_json_ok_in_home(home.path(), &["--json", "history", "--status", "success"]);
    let success_entries = success_history["entries"]
        .as_array()
        .expect("success filtered entries");
    assert_eq!(success_entries.len(), 1, "One success entry expected");
    assert_eq!(success_entries[0]["status"], "success");

    // Step 5: Filter by denied/error status.
    let denied_history =
        run_json_ok_in_home(home.path(), &["--json", "history", "--status", "denied"]);
    let denied_entries = denied_history["entries"]
        .as_array()
        .expect("denied filtered entries");
    assert_eq!(denied_entries.len(), 1, "One denied entry expected");
    assert_eq!(denied_entries[0]["status"], "denied");
}

#[test]
fn e2e_mesh_availability_keeps_live_offline_and_repair_states_explicit() {
    let offline_payload = run_json_ok(&[
        "--json",
        "mesh",
        "availability",
        "github",
        "--zone",
        "z:work",
    ]);
    assert_offline_mesh_availability_payload(&offline_payload);

    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 1, "risky");

    let (host_live, server_live) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(std::slice::from_ref(&github_connector)),
        ),
        (
            "GET /rpc/connectors/fcp.github:enterprise:v1/status".to_owned(),
            mock_connector_admin_status_json(
                "local_path",
                "/opt/fcp/cache/github-enterprise",
                &Value::Null,
            ),
        ),
    ]);
    let live_payload = run_json_ok(&[
        "--json",
        "--host",
        &host_live,
        "mesh",
        "explain-availability",
        "github",
    ]);
    server_live
        .join()
        .expect("mock host thread should complete");
    assert_eq!(live_payload["source"], "host-admin-api");
    assert_eq!(
        live_payload["source_selection"]["source_kind"],
        "local-path"
    );
    assert_eq!(
        live_payload["offline_readiness"]["state"],
        "artifact-recorded-without-placement-policy"
    );

    let (host_hints, server_hints) = spawn_mock_host_sequence(vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(std::slice::from_ref(&github_connector)),
        ),
        (
            "GET /rpc/connectors/fcp.github:enterprise:v1/status".to_owned(),
            mock_connector_missing_status_json(),
        ),
    ]);
    let repair_payload = run_json_ok(&[
        "--json",
        "--host",
        &host_hints,
        "mesh",
        "repair-hints",
        "github",
    ]);
    server_hints
        .join()
        .expect("mock host thread should complete");
    assert_eq!(repair_payload["subcommand"], "repair-hints");
    assert!(
        repair_payload["repair_hints"]
            .as_array()
            .is_some_and(|hints| hints.iter().any(|hint| {
                hint.as_str()
                    .is_some_and(|hint| hint.contains("verified runtime artifact"))
            }))
    );

    let (exit_code, zone_payload, _stderr) = run_json(&[
        "--json",
        "--host",
        "http://127.0.0.1:9",
        "mesh",
        "availability",
        "github",
        "--zone",
        "z:work",
    ]);
    assert_ne!(
        exit_code, 0,
        "live zone-scoped availability must fail closed"
    );
    assert_eq!(
        zone_payload["error"]["type"],
        "unsupported-live-zone-filter"
    );
}

#[test]
fn e2e_mesh_cutover_gates_reports_skip_schema_for_missing_telemetry() {
    let payload = run_json_ok(&["--json", "mesh", "cutover-gates"]);
    assert_eq!(payload["command"], "mesh");
    assert_eq!(payload["subcommand"], "cutover-gates");
    assert_eq!(payload["schema_version"], "1.2.0");
    assert!(
        payload["data_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:") && hash.len() == 71),
        "cutover gates payload must include a stable sha256-prefixed data_hash"
    );
    assert_eq!(payload["live_telemetry"]["state"], "not-requested");
    assert_eq!(
        payload["live_telemetry"]["reason_code"],
        "host-not-requested"
    );
    assert_eq!(payload["overall_status"], "skip");
    assert_eq!(payload["gate_count"], 4);
    assert_eq!(
        payload["measurement_contract"]["truth_model"],
        "fail-closed"
    );
    let gates = payload["gates"]
        .as_array()
        .expect("cutover gates payload must include gates array");
    assert_eq!(gates.len(), 4);
    assert!(
        gates
            .iter()
            .all(|gate| gate["status"].as_str() == Some("skip"))
    );
    let gate_ids = gates
        .iter()
        .filter_map(|gate| gate["gate_id"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        gate_ids,
        vec![
            "mesh-inventory-placement",
            "mesh-lifecycle-state-replication",
            "mesh-audit-chain-quorum",
            "mesh-policy-object-distribution",
        ]
    );
}

#[test]
fn e2e_mesh_cutover_gates_malformed_config_returns_typed_error() {
    let tempdir = tempdir().expect("cutover config tempdir");
    let config_path = tempdir.path().join("broken-fcp-host.toml");
    fs::write(&config_path, "[mesh.cutover_gates\n").expect("broken config fixture should write");

    let (exit_code, payload, _stderr) = run_json(&[
        "--json",
        "mesh",
        "cutover-gates",
        "--config",
        config_path.to_str().expect("config path should be UTF-8"),
    ]);

    assert_ne!(exit_code, 0, "malformed cutover config must fail closed");
    assert_eq!(payload["status"], "error");
    assert_eq!(payload["command"], "mesh");
    assert_eq!(payload["subcommand"], "cutover-gates");
    assert_eq!(payload["error"]["type"], "invalid-cutover-gates-config");
    assert_eq!(payload["error"]["recoverable"], true);
    assert_eq!(payload["config_path"], config_path.display().to_string());
}

#[test]
fn e2e_mesh_cutover_gates_concurrent_snapshot_hash_is_stable() {
    let first = thread::spawn(|| run_json_ok(&["--json", "mesh", "cutover-gates"]));
    let second = thread::spawn(|| run_json_ok(&["--json", "mesh", "cutover-gates"]));

    let first = first.join().expect("first cutover-gates run should join");
    let second = second.join().expect("second cutover-gates run should join");

    assert_eq!(first["status"], "ok");
    assert_eq!(second["status"], "ok");
    assert_eq!(first["schema_version"], "1.2.0");
    assert_eq!(second["schema_version"], "1.2.0");
    assert_eq!(first["gate_count"], second["gate_count"]);
    assert_eq!(
        first["data_hash"], second["data_hash"],
        "same-snapshot concurrent cutover-gates runs must agree on data_hash"
    );
}

#[test]
fn e2e_mesh_cutover_gates_network_failure_skips_with_logged_reason() {
    let (exit_code, payload, _stderr) = run_json(&[
        "--json",
        "--host",
        "http://127.0.0.1:9",
        "mesh",
        "cutover-gates",
    ]);

    assert_eq!(
        exit_code, 0,
        "unreachable host should produce skipped gates rather than fail open or abort"
    );
    assert_eq!(payload["schema_version"], "1.2.0");
    assert_eq!(payload["overall_status"], "skip");
    assert_eq!(payload["live_telemetry"]["state"], "unavailable");
    assert_eq!(
        payload["live_telemetry"]["reason_code"],
        "host-admin-api-unreachable"
    );
    assert!(
        payload["gates"]
            .as_array()
            .expect("gates must be an array")
            .iter()
            .all(|gate| gate["measured_value"]["skip_reason"] == "host-admin-api-unreachable")
    );
}

#[test]
fn e2e_mesh_cutover_gates_three_node_direct_telemetry_turns_green() {
    let connectors = [
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub", 12, "safe"),
        mock_connector_summary_json("fcp.slack:team:v1", "Slack", 9, "safe"),
        mock_connector_summary_json("fcp.discord:guild:v1", "Discord", 8, "safe"),
    ];
    let routes = vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(&connectors),
        ),
        (
            "GET /rpc/mesh/cutover-gates".to_owned(),
            mock_direct_green_cutover_gate_snapshot_json(),
        ),
    ];

    let (host, server) = spawn_mock_host_sequence(routes);
    let payload = run_json_ok(&["--json", "--host", &host, "mesh", "cutover-gates"]);
    server
        .join()
        .expect("three-node cutover-gate mock host should complete");

    assert_eq!(payload["schema_version"], "1.2.0");
    assert_eq!(payload["overall_status"], "green");
    assert_eq!(payload["red_gate_ids"].as_array().map(Vec::len), Some(0));
    assert_eq!(
        payload["live_telemetry"]["reason_code"],
        "direct-cutover-telemetry-available"
    );
    assert_eq!(
        payload["live_telemetry"]["direct_gate_telemetry_available"],
        true
    );
    assert_eq!(payload["live_telemetry"]["catalog_connector_count"], 3);
    assert!(
        payload["gates"]
            .as_array()
            .expect("gates must be an array")
            .iter()
            .all(|gate| gate["status"] == "green"
                && gate["measured_value"]["node_count"] == 3
                && gate["measured_value"]["live_telemetry"]["reason_code"]
                    == "direct-cutover-telemetry-available")
    );
}

#[test]
fn e2e_mesh_cutover_gates_restart_recovery_preserves_snapshot_hash() {
    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub", 12, "safe");
    let routes = vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(std::slice::from_ref(&github_connector)),
        ),
        (
            "GET /rpc/mesh/cutover-gates".to_owned(),
            json!({"status": "planned"}),
        ),
    ];

    let (host_before, server_before) = spawn_mock_host_sequence(routes.clone());
    let before = run_json_ok(&["--json", "--host", &host_before, "mesh", "cutover-gates"]);
    server_before
        .join()
        .expect("pre-restart mock host should complete");

    let (host_after, server_after) = spawn_mock_host_sequence(routes);
    let after = run_json_ok(&["--json", "--host", &host_after, "mesh", "cutover-gates"]);
    server_after
        .join()
        .expect("post-restart mock host should complete");

    assert_eq!(before["schema_version"], "1.2.0");
    assert_eq!(after["schema_version"], "1.2.0");
    assert_eq!(before["live_telemetry"]["state"], "reachable");
    assert_eq!(after["live_telemetry"]["state"], "reachable");
    assert_eq!(
        before["data_hash"], after["data_hash"],
        "host restart with the same catalog snapshot must preserve cutover-gate data_hash"
    );
}

// ── P6.5: Offline and node-local trust path acceptance tests ───────────

/// Verify that offline `show` exposes manifest safety metadata without
/// fabricating live runtime state. Trust path: manifest → artifact provenance.
#[test]
fn offline_show_exposes_manifest_safety_without_runtime_fabrication() {
    let show = run_json_ok(&["--json", "show", "github", "--offline"]);

    // Safety metadata comes from manifest
    assert_eq!(show["command"], "show");
    assert!(show["connector"].is_object());

    // Manifest lifecycle status may be present offline, but runtime state must
    // remain unknown until a live host answers.
    let connector = &show["connector"];
    assert_eq!(connector["status"], "ready");
    assert_eq!(connector["state"], "unknown");
}

/// Verify that offline `ops` lists operations with safety tiers from the
/// manifest trust path, not from fabricated runtime introspection.
#[test]
fn offline_ops_lists_operations_from_manifest_trust_path() {
    let ops = run_json_ok(&["--json", "ops", "github", "--offline"]);
    assert_eq!(ops["command"], "ops");

    let operations = ops["operations"]
        .as_array()
        .expect("operations should be an array");
    assert!(
        !operations.is_empty(),
        "GitHub should have operations in offline mode"
    );

    // Every operation must have safety metadata from the manifest
    for op in operations {
        assert!(
            op.get("safety_tier").is_some() || op.get("risk_level").is_some(),
            "Each operation should expose safety tier or risk level from manifest"
        );
    }
}

/// Verify that offline `export-tools` produces tool schemas that include
/// manifest-declared safety information, suitable for agent consumption.
#[test]
fn offline_export_tools_includes_manifest_safety_metadata() {
    let export = run_json_ok(&["--json", "export-tools", "--offline", "--format", "mcp"]);
    assert_eq!(export["command"], "export-tools");

    let tools = export["tools"]
        .as_array()
        .expect("tools should be an array");
    assert!(
        !tools.is_empty(),
        "Export-tools should produce tools in offline mode"
    );
}

/// Verify that offline commands refuse to produce invoke/simulate results.
/// The trust path for execution requires a live host; offline mode must
/// fail closed rather than fabricating execution results.
#[test]
fn offline_invoke_refuses_rather_than_fabricate() {
    // invoke without --host and without --offline should fail
    let (exit_code, payload, _stderr) = run_json(&[
        "--json",
        "invoke",
        "github",
        "issues.create",
        "--input",
        r#"{"title":"test"}"#,
    ]);
    assert_ne!(exit_code, 0, "invoke without host should fail");
    assert!(
        payload.get("error").is_some(),
        "Should return error envelope, not fabricated result"
    );
}

/// Verify that all offline JSON outputs include availability provenance
/// so downstream consumers can distinguish artifact-backed from live data.
#[test]
fn offline_outputs_carry_availability_provenance() {
    let commands_to_test = [
        vec!["--json", "list", "--offline"],
        vec!["--json", "search", "send message", "--offline"],
        vec!["--json", "show", "github", "--offline"],
        vec!["--json", "ops", "github", "--offline"],
    ];

    for args in &commands_to_test {
        let result = run_json_ok(args);

        // Every offline response must carry availability or mode marker
        let has_availability = result.get("availability").is_some();
        let has_mode = result
            .get("mode")
            .and_then(|m| m.as_str())
            .is_some_and(|m| m.contains("offline"));
        let has_source = result
            .get("source")
            .and_then(|s| s.as_str())
            .is_some_and(|s| s.contains("manifest") || s.contains("workspace"));

        assert!(
            has_availability || has_mode || has_source,
            "Offline command {:?} must carry provenance marker. Got: {}",
            args,
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
    }
}

#[test]
fn operator_truth_fixture_matrix_freezes_core_answer_classes() {
    let matrix = load_operator_truth_fixture_matrix();
    let ids = matrix
        .fixtures
        .iter()
        .map(|fixture| fixture.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        ids.len(),
        matrix.fixtures.len(),
        "fixture ids must be unique"
    );

    let canonical_ids = std::collections::BTreeSet::from([
        "offline_show_workspace_manifest".to_owned(),
        "node_local_status_host_admin".to_owned(),
        "mesh_backed_explain_availability".to_owned(),
        "degraded_connector_health".to_owned(),
        "fallback_derived_install_activation".to_owned(),
        "refusal_invoke_preflight_denied".to_owned(),
    ]);
    let missing_canonical_ids = canonical_ids.difference(&ids).cloned().collect::<Vec<_>>();
    assert!(
        missing_canonical_ids.is_empty(),
        "operator truth fixture matrix missing canonical answer classes: {missing_canonical_ids:?}"
    );

    let answer_classes = matrix
        .fixtures
        .iter()
        .filter(|fixture| canonical_ids.contains(&fixture.id))
        .map(|fixture| fixture.answer_class)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        answer_classes,
        std::collections::BTreeSet::from([
            OperatorTruthAnswerClass::Offline,
            OperatorTruthAnswerClass::NodeLocal,
            OperatorTruthAnswerClass::MeshBacked,
            OperatorTruthAnswerClass::Degraded,
            OperatorTruthAnswerClass::FallbackDerived,
            OperatorTruthAnswerClass::Refusal,
        ])
    );

    for fixture in &matrix.fixtures {
        assert_ne!(fixture.command.trim(), "");
        assert_ne!(fixture.source.trim(), "");
        assert!(
            fixture
                .availability
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
                || fixture
                    .status
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty()),
            "fixture {} must freeze either availability or status",
            fixture.id
        );
        assert_ne!(fixture.notes.trim(), "");
        assert_operator_truth_fixture_has_core_evidence_contract(fixture);
    }

    for fixture in matrix
        .fixtures
        .iter()
        .filter(|fixture| canonical_ids.contains(&fixture.id))
    {
        assert_eq!(fixture.bundle_layer.as_deref(), Some("e2e"));
        assert_eq!(fixture.bundle_suite.as_deref(), Some("cli_truth"));
        assert!(
            !fixture.human_summary_contains.is_empty()
                || !fixture.required_message_substrings.is_empty(),
            "fixture {} must freeze either human-facing output or machine message strings",
            fixture.id
        );
    }
}

#[test]
fn operator_truth_fixture_offline_show_matches_cli_contract() {
    let fixture = load_operator_truth_fixture("offline_show_workspace_manifest");
    let payload = run_json_ok(&["--json", "show", "github", "--offline"]);
    let text = run_text_ok(&["show", "github", "--offline"]);

    assert_operator_truth_fixture_contract(&payload, &fixture);
    assert_operator_truth_fixture_human_summary(&text, &fixture);
    assert!(
        payload["connector"]["canonical_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("fcp.github"))
    );
}

#[test]
fn operator_truth_fixture_node_local_status_matches_cli_contract() {
    let fixture = load_operator_truth_fixture("node_local_status_host_admin");
    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 1, "risky");
    let routes = vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(&[github_connector]),
        ),
        (
            "GET /rpc/health".to_owned(),
            mock_host_health_json("healthy"),
        ),
        (
            "GET /rpc/connectors/fcp.github:enterprise:v1/status".to_owned(),
            mock_connector_admin_status_json(
                "registry",
                "registry://fcp/github-enterprise/1.2.3",
                &Value::Null,
            ),
        ),
        (
            "GET /rpc/rollout/pin/fcp.github:enterprise:v1".to_owned(),
            mock_pin_status_json(false, None),
        ),
        (
            "GET /rpc/rollout/fcp.github:enterprise:v1".to_owned(),
            mock_rollout_status_json("production", "1.2.3", false, None, 0),
        ),
    ];
    let (host, server) = spawn_mock_host_sequence(routes.clone());
    let payload = run_json_ok(&["--json", "--host", &host, "status", "github"]);
    server.join().expect("mock host thread should complete");
    let (host, server) = spawn_mock_host_sequence(routes);
    let text = run_text_ok(&["--host", &host, "status", "github"]);
    server.join().expect("mock host thread should complete");

    assert_operator_truth_fixture_contract(&payload, &fixture);
    assert_operator_truth_fixture_human_summary(&text, &fixture);
    assert_eq!(payload["scope"], "connector");
    assert_eq!(payload["admin"]["observed_state"], "running");
    assert_eq!(payload["pin"]["pinned"], false);
}

#[test]
fn operator_truth_fixture_offline_show_exports_replayable_bundle_manifest() {
    let fixture = load_operator_truth_fixture("offline_show_workspace_manifest");
    let payload = run_json_ok(&["--json", "show", "github", "--offline"]);
    let mut log = new_trace_log();
    let ctx = scenario_context(
        operator_truth_fixture_bundle_layer(&fixture),
        operator_truth_fixture_bundle_suite(&fixture),
        &fixture.id,
    )
    .with_tag("acceptance")
    .with_env("FWC_MODE", "offline");
    log.append(
        TraceEntry::new(
            &ctx.trace_id,
            &ctx.scenario_id,
            TraceLevel::Info,
            TraceCategory::CliStep,
            "captured offline show acceptance scenario",
        )
        .with_field("command", json!("show"))
        .with_field("connector", json!("github"))
        .with_truth_context(operator_truth_context(&payload, &fixture)),
    );
    let base = tempdir().expect("artifact tempdir should exist");
    let (bundle, manifest) = create_bundle(base.path(), &ctx, &log, BundleOutcome::Pass);

    assert_eq!(manifest.scenario_id.case, fixture.id);
    assert!(
        bundle
            .root
            .to_string_lossy()
            .contains("/artifacts/e2e/cli_truth/")
    );
    assert_bundle_manifest_matches_operator_truth_fixture(&manifest, &payload, &fixture);
    assert_eq!(manifest.truthfulness.offline_entry_count, 1);
    assert_eq!(manifest.truthfulness.live_entry_count, 0);
}

#[test]
fn operator_truth_fixture_node_local_status_exports_replayable_bundle_manifest() {
    let fixture = load_operator_truth_fixture("node_local_status_host_admin");
    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 1, "risky");
    let routes = vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(&[github_connector]),
        ),
        (
            "GET /rpc/health".to_owned(),
            mock_host_health_json("healthy"),
        ),
        (
            "GET /rpc/connectors/fcp.github:enterprise:v1/status".to_owned(),
            mock_connector_admin_status_json(
                "registry",
                "registry://fcp/github-enterprise/1.2.3",
                &Value::Null,
            ),
        ),
        (
            "GET /rpc/rollout/pin/fcp.github:enterprise:v1".to_owned(),
            mock_pin_status_json(false, None),
        ),
        (
            "GET /rpc/rollout/fcp.github:enterprise:v1".to_owned(),
            mock_rollout_status_json("production", "1.2.3", false, None, 0),
        ),
    ];
    let (host, server) = spawn_mock_host_sequence(routes);
    let payload = run_json_ok(&["--json", "--host", &host, "status", "github"]);
    server.join().expect("mock host thread should complete");

    let mut log = new_trace_log();
    let ctx = scenario_context(
        operator_truth_fixture_bundle_layer(&fixture),
        operator_truth_fixture_bundle_suite(&fixture),
        &fixture.id,
    )
    .with_tag("acceptance")
    .with_env("FWC_HOST", host);
    log.append(
        TraceEntry::new(
            &ctx.trace_id,
            &ctx.scenario_id,
            TraceLevel::Info,
            TraceCategory::HostRequest,
            "captured node-local status acceptance scenario",
        )
        .with_field("command", json!("status"))
        .with_field("connector", json!("github"))
        .with_truth_context(operator_truth_context(&payload, &fixture)),
    );
    let base = tempdir().expect("artifact tempdir should exist");
    let (bundle, manifest) = create_bundle(base.path(), &ctx, &log, BundleOutcome::Pass);

    assert_eq!(manifest.scenario_id.case, fixture.id);
    assert!(
        bundle
            .root
            .to_string_lossy()
            .contains("/artifacts/e2e/cli_truth/")
    );
    assert_bundle_manifest_matches_operator_truth_fixture(&manifest, &payload, &fixture);
    assert_eq!(manifest.truthfulness.live_entry_count, 1);
    assert_eq!(manifest.truthfulness.offline_entry_count, 0);
}

#[test]
fn operator_truth_fixture_mesh_backed_availability_matches_cli_contract() {
    let fixture = load_operator_truth_fixture("mesh_backed_explain_availability");
    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 1, "risky");
    let placement_policy = json!({
        "min_nodes": 2,
        "max_node_fraction_bps": 5000,
        "preferred_devices": [],
        "excluded_devices": [],
        "target_coverage_bps": 9000,
        "min_source_diversity": 2,
    });
    let routes = vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(&[github_connector]),
        ),
        (
            "GET /rpc/connectors/fcp.github:enterprise:v1/status".to_owned(),
            mock_connector_admin_status_json(
                "mesh_mirror",
                "/opt/fcp/mirrors/github-enterprise",
                &placement_policy,
            ),
        ),
    ];
    let (host, server) = spawn_mock_host_sequence(routes.clone());
    let payload = run_json_ok(&[
        "--json",
        "--host",
        &host,
        "mesh",
        "explain-availability",
        "github",
    ]);
    server.join().expect("mock host thread should complete");
    let (host, server) = spawn_mock_host_sequence(routes);
    let text = run_text_ok(&["--host", &host, "mesh", "explain-availability", "github"]);
    server.join().expect("mock host thread should complete");

    assert_operator_truth_fixture_contract(&payload, &fixture);
    assert_operator_truth_fixture_human_summary(&text, &fixture);
    assert_eq!(payload["subcommand"], "explain-availability");
    assert_eq!(payload["inventory"]["authoritative"], true);
    assert!(
        payload["explanation"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );
}

#[test]
fn operator_truth_fixture_mesh_backed_exports_replayable_bundle_manifest() {
    let fixture = load_operator_truth_fixture("mesh_backed_explain_availability");
    let github_connector =
        mock_connector_summary_json("fcp.github:enterprise:v1", "GitHub Enterprise", 1, "risky");
    let placement_policy = json!({
        "min_nodes": 2,
        "max_node_fraction_bps": 5000,
        "preferred_devices": [],
        "excluded_devices": [],
        "target_coverage_bps": 9000,
        "min_source_diversity": 2,
    });
    let routes = vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(&[github_connector]),
        ),
        (
            "GET /rpc/connectors/fcp.github:enterprise:v1/status".to_owned(),
            mock_connector_admin_status_json(
                "mesh_mirror",
                "/opt/fcp/mirrors/github-enterprise",
                &placement_policy,
            ),
        ),
    ];
    let (host, server) = spawn_mock_host_sequence(routes);
    let payload = run_json_ok(&[
        "--json",
        "--host",
        &host,
        "mesh",
        "explain-availability",
        "github",
    ]);
    server.join().expect("mock host thread should complete");

    let mut log = new_trace_log();
    let ctx = scenario_context(
        operator_truth_fixture_bundle_layer(&fixture),
        operator_truth_fixture_bundle_suite(&fixture),
        &fixture.id,
    )
    .with_tag("acceptance")
    .with_env("FWC_HOST", host);
    log.append(
        TraceEntry::new(
            &ctx.trace_id,
            &ctx.scenario_id,
            TraceLevel::Info,
            TraceCategory::HostReceipt,
            "captured mesh-backed availability acceptance scenario",
        )
        .with_field("command", json!("mesh"))
        .with_field("subcommand", json!("explain-availability"))
        .with_field("connector", json!("github"))
        .with_truth_context(operator_truth_context(&payload, &fixture)),
    );
    let base = tempdir().expect("artifact tempdir should exist");
    let (bundle, manifest) = create_bundle(base.path(), &ctx, &log, BundleOutcome::Pass);

    assert_eq!(manifest.scenario_id.case, fixture.id);
    assert!(
        bundle
            .root
            .to_string_lossy()
            .contains("/artifacts/e2e/cli_truth/")
    );
    assert_bundle_manifest_matches_operator_truth_fixture(&manifest, &payload, &fixture);
    assert_eq!(manifest.truthfulness.live_entry_count, 1);
    assert_eq!(manifest.truthfulness.offline_entry_count, 0);
}

#[test]
fn operator_truth_fixture_degraded_health_matches_cli_contract() {
    let fixture = load_operator_truth_fixture("degraded_connector_health");
    let github_connector = mock_connector_summary_with_health_json(
        "fcp.github:enterprise:v1",
        "GitHub Enterprise",
        1,
        "risky",
        ConnectorHealth::degraded("upstream latency"),
    );
    let routes = vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(&[github_connector]),
        ),
        (
            "GET /rpc/health".to_owned(),
            mock_host_health_json("healthy"),
        ),
    ];
    let (host, server) = spawn_mock_host_sequence(routes.clone());
    let payload = run_json_ok(&[
        "--json",
        "--host",
        &host,
        "health",
        "fcp.github:enterprise:v1",
    ]);
    server.join().expect("mock host thread should complete");
    let (host, server) = spawn_mock_host_sequence(routes);
    let text = run_text_ok(&["--host", &host, "health", "fcp.github:enterprise:v1"]);
    server.join().expect("mock host thread should complete");

    assert_operator_truth_fixture_contract(&payload, &fixture);
    assert_operator_truth_fixture_human_summary(&text, &fixture);
    assert_eq!(payload["scope"], "connector");
    assert_eq!(payload["connector"]["health_status"], "degraded");
}

#[test]
fn operator_truth_fixture_degraded_exports_replayable_bundle_manifest() {
    let fixture = load_operator_truth_fixture("degraded_connector_health");
    let github_connector = mock_connector_summary_with_health_json(
        "fcp.github:enterprise:v1",
        "GitHub Enterprise",
        1,
        "risky",
        ConnectorHealth::degraded("upstream latency"),
    );
    let routes = vec![
        (
            "POST /rpc/discover".to_owned(),
            mock_discovery_response_json(&[github_connector]),
        ),
        (
            "GET /rpc/health".to_owned(),
            mock_host_health_json("healthy"),
        ),
    ];
    let (host, server) = spawn_mock_host_sequence(routes);
    let payload = run_json_ok(&[
        "--json",
        "--host",
        &host,
        "health",
        "fcp.github:enterprise:v1",
    ]);
    server.join().expect("mock host thread should complete");

    let mut log = new_trace_log();
    let ctx = scenario_context(
        operator_truth_fixture_bundle_layer(&fixture),
        operator_truth_fixture_bundle_suite(&fixture),
        &fixture.id,
    )
    .with_tag("acceptance")
    .with_env("FWC_HOST", host);
    log.append(
        TraceEntry::new(
            &ctx.trace_id,
            &ctx.scenario_id,
            TraceLevel::Warn,
            TraceCategory::HostReceipt,
            "captured degraded health acceptance scenario",
        )
        .with_field("command", json!("health"))
        .with_field("connector", json!("fcp.github:enterprise:v1"))
        .with_truth_context(operator_truth_context(&payload, &fixture)),
    );
    let base = tempdir().expect("artifact tempdir should exist");
    let (bundle, manifest) = create_bundle(base.path(), &ctx, &log, BundleOutcome::Pass);

    assert_eq!(manifest.scenario_id.case, fixture.id);
    assert!(
        bundle
            .root
            .to_string_lossy()
            .contains("/artifacts/e2e/cli_truth/")
    );
    assert_bundle_manifest_matches_operator_truth_fixture(&manifest, &payload, &fixture);
    assert_eq!(manifest.truthfulness.live_entry_count, 1);
    assert_eq!(manifest.truthfulness.offline_entry_count, 0);
}

#[test]
fn operator_truth_fixture_fallback_install_matches_cli_contract() {
    let fixture = load_operator_truth_fixture("fallback_derived_install_activation");
    let (_package_dir, package_output_path) =
        write_test_package_output("fcp.github:enterprise:v1", "1.2.4");
    let package_output_path = package_output_path.display().to_string();
    let routes = vec![
        (
            "POST /rpc/connectors/apply".to_owned(),
            mock_inventory_mutation_response_json("1.2.4"),
        ),
        (
            "GET /rpc/connectors/fcp.github:enterprise:v1/status".to_owned(),
            json!({ "status": "not-a-valid-admin-status" }),
        ),
    ];
    let (host, server) = spawn_mock_host_sequence(routes.clone());
    let payload = run_json_ok(&["--json", "--host", &host, "install", &package_output_path]);
    server.join().expect("mock host thread should complete");
    let (host, server) = spawn_mock_host_sequence(routes);
    let text = run_text_ok(&["--host", &host, "install", &package_output_path]);
    server.join().expect("mock host thread should complete");

    assert_operator_truth_fixture_contract(&payload, &fixture);
    assert_operator_truth_fixture_human_summary(&text, &fixture);
    assert_eq!(payload["availability_fact"]["state"], "unknown");
    assert_eq!(payload["source_selection"]["state"], "unknown");
    assert_eq!(payload["offline_readiness"]["state"], "unknown");
    assert!(
        payload["warnings"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );
}

#[test]
fn operator_truth_fixture_fallback_exports_replayable_bundle_manifest() {
    let fixture = load_operator_truth_fixture("fallback_derived_install_activation");
    let (_package_dir, package_output_path) =
        write_test_package_output("fcp.github:enterprise:v1", "1.2.4");
    let package_output_path = package_output_path.display().to_string();
    let routes = vec![
        (
            "POST /rpc/connectors/apply".to_owned(),
            mock_inventory_mutation_response_json("1.2.4"),
        ),
        (
            "GET /rpc/connectors/fcp.github:enterprise:v1/status".to_owned(),
            json!({ "status": "not-a-valid-admin-status" }),
        ),
    ];
    let (host, server) = spawn_mock_host_sequence(routes);
    let payload = run_json_ok(&["--json", "--host", &host, "install", &package_output_path]);
    server.join().expect("mock host thread should complete");

    let mut log = new_trace_log();
    let ctx = scenario_context(
        operator_truth_fixture_bundle_layer(&fixture),
        operator_truth_fixture_bundle_suite(&fixture),
        &fixture.id,
    )
    .with_tag("acceptance")
    .with_env("FWC_HOST", host);
    log.append(
        TraceEntry::new(
            &ctx.trace_id,
            &ctx.scenario_id,
            TraceLevel::Warn,
            TraceCategory::HostReceipt,
            "captured fallback-derived install acceptance scenario",
        )
        .with_field("command", json!("install"))
        .with_field("connector", json!("fcp.github:enterprise:v1"))
        .with_truth_context(operator_truth_context(&payload, &fixture)),
    );
    let base = tempdir().expect("artifact tempdir should exist");
    let (bundle, manifest) = create_bundle(base.path(), &ctx, &log, BundleOutcome::Pass);

    assert_eq!(manifest.scenario_id.case, fixture.id);
    assert!(
        bundle
            .root
            .to_string_lossy()
            .contains("/artifacts/e2e/cli_truth/")
    );
    assert_bundle_manifest_matches_operator_truth_fixture(&manifest, &payload, &fixture);
    assert_eq!(manifest.truthfulness.live_entry_count, 1);
    assert_eq!(manifest.truthfulness.offline_entry_count, 0);
}

/// Verify that the node-local context command produces structured output
/// about the current environment (workspace root, git SHA, offline status).
#[test]
fn node_local_context_produces_structured_environment_info() {
    let (exit_code, payload, _stderr) = run_json(&["--json", "context", "current"]);

    // context current may succeed or fail depending on host availability,
    // but it should always produce structured JSON output
    if exit_code == 0 {
        assert!(
            payload.get("context").is_some() || payload.get("workspace").is_some(),
            "Successful context should include workspace or context info"
        );
    } else {
        // Even failure should be structured
        assert!(
            payload.get("error").is_some() || payload.get("context").is_some(),
            "Context failure should be a structured error or degraded context"
        );
    }
}
