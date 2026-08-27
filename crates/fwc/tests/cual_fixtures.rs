use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use fcp_host::{
    ConnectorAdminStatus, IntrospectionResponse, ManagedConnectorConfig, RolloutAuditEvent,
    StartupReconciliationReport,
};
use fcp_prelude::{
    PolicyBundle, ProvisioningRecipe, ProvisioningState, ProvisioningValidation, SetupDescriptor,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct FixtureCatalog {
    fixtures: Vec<FixtureCatalogEntry>,
}

#[derive(Debug, Deserialize)]
struct FixtureCatalogEntry {
    path: String,
    kind: String,
    purpose: String,
    validation: String,
}

#[derive(Debug, Deserialize)]
struct PipelineFixture {
    pipeline: PipelineMetadataFixture,
    #[serde(default)]
    steps: Vec<PipelineStepFixture>,
}

#[derive(Debug, Deserialize)]
struct PipelineMetadataFixture {
    name: String,
}

#[derive(Debug, Deserialize)]
struct PipelineStepFixture {
    id: String,
    operation: String,
    #[serde(default)]
    depends_on: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct BatchOpFixture {
    id: Option<String>,
    connector: Option<String>,
    operation: Option<String>,
    input: Option<Value>,
    #[serde(default)]
    depends_on: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DispatchInvocationFixture {
    name: String,
    argv: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct InstallOutputFixture {
    connector_id: String,
    version: String,
    target: String,
    zone_id: String,
    manifest_hash: String,
    binary_hash: String,
    manifest_object_id: Option<String>,
    binary_object_id: Option<String>,
    verification: InstallVerificationFixture,
    installed_at: u64,
    installed_at_iso: String,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Deserialize)]
struct InstallVerificationFixture {
    publisher_signature_verified: bool,
    registry_signature_verified: bool,
    publisher_signatures_valid: u8,
    publisher_threshold: u8,
    supply_chain_policy_satisfied: bool,
    capability_ceiling_respected: bool,
    #[serde(default)]
    verified_attestations: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HostIntegrationArchetype {
    RequestResponse,
    Streaming,
    Webhook,
    Polling,
    Browser,
    Database,
    LifecycleHeavy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HostIntegrationCoverageMode {
    MockHost,
    RealHost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HostIntegrationAuthScope {
    None,
    SingleProfile,
    MultiProfile,
    TenantScoped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OperationReversibility {
    Reversible,
    Mixed,
    Irreversible,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum FixtureReadiness {
    LiveRuntime,
    OfflineArtifact,
    DegradedOffline,
    Planned,
}

#[derive(Debug, Deserialize)]
struct HostIntegrationFixtureCatalog {
    fixtures: Vec<HostIntegrationFixture>,
}

#[derive(Debug, Deserialize)]
struct HostIntegrationFixture {
    id: String,
    connector_id: String,
    display_name: String,
    archetype: HostIntegrationArchetype,
    coverage_mode: HostIntegrationCoverageMode,
    risk_level: String,
    safety_tier: String,
    readiness: FixtureReadiness,
    auth_scope: HostIntegrationAuthScope,
    reversibility: OperationReversibility,
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

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata")
}

fn fixture_path(relative: &str) -> PathBuf {
    fixture_root().join(relative)
}

fn read(relative: &str) -> String {
    fs::read_to_string(fixture_path(relative)).expect("fixture file should be readable")
}

fn load_json<T: serde::de::DeserializeOwned>(relative: &str) -> T {
    serde_json::from_str(&read(relative)).expect("fixture JSON should deserialize")
}

fn collect_fixture_files(root: &Path) -> Vec<String> {
    fn walk(root: &Path, current: &Path, out: &mut Vec<String>) {
        let mut entries = fs::read_dir(current)
            .expect("fixture directory should be readable")
            .map(|entry| entry.expect("dir entry should load").path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .expect("fixture path should stay under root")
                    .to_string_lossy()
                    .into_owned();
                out.push(relative);
            }
        }
    }

    let mut out = Vec::new();
    walk(root, root, &mut out);
    out
}

fn load_catalog() -> FixtureCatalog {
    load_json("catalog.json")
}

fn validate_schema(value: &Value, schema: &Value) -> Result<(), String> {
    let Some(kind) = schema.get("type").and_then(Value::as_str) else {
        return Ok(());
    };

    match kind {
        "object" => {
            let object = value
                .as_object()
                .ok_or_else(|| format!("expected object, got {}", value_type_name(value)))?;
            if let Some(required) = schema.get("required").and_then(Value::as_array) {
                for field in required.iter().filter_map(Value::as_str) {
                    if !object.contains_key(field) {
                        return Err(format!("missing required field `{field}`"));
                    }
                }
            }
            if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
                for (name, property_schema) in properties {
                    if let Some(child) = object.get(name) {
                        validate_schema(child, property_schema)
                            .map_err(|error| format!("field `{name}`: {error}"))?;
                    }
                }
            }
            Ok(())
        }
        "array" => {
            let items = value
                .as_array()
                .ok_or_else(|| format!("expected array, got {}", value_type_name(value)))?;
            if let Some(item_schema) = schema.get("items") {
                for (index, item) in items.iter().enumerate() {
                    validate_schema(item, item_schema)
                        .map_err(|error| format!("index {index}: {error}"))?;
                }
            }
            Ok(())
        }
        "string" => value
            .as_str()
            .map(|_| ())
            .ok_or_else(|| format!("expected string, got {}", value_type_name(value))),
        "integer" => {
            let is_integer = value
                .as_i64()
                .or_else(|| value.as_u64().and_then(|n| i64::try_from(n).ok()))
                .is_some();
            if is_integer {
                Ok(())
            } else {
                Err(format!("expected integer, got {}", value_type_name(value)))
            }
        }
        "number" => {
            if value.is_number() {
                Ok(())
            } else {
                Err(format!("expected number, got {}", value_type_name(value)))
            }
        }
        "boolean" => value
            .as_bool()
            .map(|_| ())
            .ok_or_else(|| format!("expected boolean, got {}", value_type_name(value))),
        "null" => {
            if value.is_null() {
                Ok(())
            } else {
                Err(format!("expected null, got {}", value_type_name(value)))
            }
        }
        _ => Ok(()),
    }
}

const fn value_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn validate_pipeline_fixture(relative: &str) -> Result<(), String> {
    let parsed: PipelineFixture =
        toml::from_str(&read(relative)).map_err(|error| format!("invalid TOML: {error}"))?;

    if parsed.pipeline.name.trim().is_empty() {
        return Err("pipeline.name must not be empty".to_string());
    }
    if parsed.steps.is_empty() {
        return Err("pipeline must declare at least one step".to_string());
    }

    let mut ids = HashSet::new();
    for step in &parsed.steps {
        if step.id.trim().is_empty() {
            return Err("pipeline step id must not be empty".to_string());
        }
        if step.operation.trim().is_empty() {
            return Err(format!("step `{}` must declare an operation", step.id));
        }
        if !ids.insert(step.id.clone()) {
            return Err(format!("duplicate pipeline step id `{}`", step.id));
        }
    }

    let mut in_degree = BTreeMap::<String, usize>::new();
    let mut dependents = BTreeMap::<String, Vec<String>>::new();
    for step in &parsed.steps {
        in_degree.entry(step.id.clone()).or_insert(0);
        for dep in &step.depends_on {
            if !ids.contains(dep) {
                return Err(format!(
                    "step `{}` depends on unknown step `{dep}`",
                    step.id
                ));
            }
            *in_degree.entry(step.id.clone()).or_insert(0) += 1;
            dependents
                .entry(dep.clone())
                .or_default()
                .push(step.id.clone());
        }
    }

    let mut queue = in_degree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(id, _)| id.clone())
        .collect::<VecDeque<_>>();
    let mut visited = 0usize;

    while let Some(id) = queue.pop_front() {
        visited += 1;
        if let Some(children) = dependents.get(&id) {
            for child in children {
                if let Some(degree) = in_degree.get_mut(child) {
                    *degree -= 1;
                    if *degree == 0 {
                        queue.push_back(child.clone());
                    }
                }
            }
        }
    }

    if visited != parsed.steps.len() {
        return Err("dependency cycle detected".to_string());
    }

    Ok(())
}

fn validate_batch_fixture(relative: &str) -> Result<(), String> {
    let content = read(relative);
    let mut ids = HashSet::new();
    let mut ops = Vec::new();
    for (line_no, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let op: BatchOpFixture =
            serde_json::from_str(line).map_err(|error| format!("line {}: {error}", line_no + 1))?;
        let id = op
            .id
            .clone()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("line {}: missing `id`", line_no + 1))?;
        let connector = op
            .connector
            .clone()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("line {}: missing `connector`", line_no + 1))?;
        let operation = op
            .operation
            .clone()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("line {}: missing `operation`", line_no + 1))?;
        let input = op
            .input
            .ok_or_else(|| format!("line {}: missing `input`", line_no + 1))?;
        if !input.is_object() {
            return Err(format!("line {}: `input` must be an object", line_no + 1));
        }
        if !ids.insert(id.clone()) {
            return Err(format!("duplicate batch id `{id}`"));
        }
        ops.push((id, connector, operation, op.depends_on));
    }

    if ops.is_empty() {
        return Err("batch fixture must contain at least one operation".to_string());
    }

    let known_ids = ops
        .iter()
        .map(|(id, _, _, _)| id.clone())
        .collect::<HashSet<_>>();
    for (id, _, _, deps) in &ops {
        for dep in deps {
            if !known_ids.contains(dep) {
                return Err(format!("operation `{id}` depends on unknown `{dep}`"));
            }
        }
    }

    Ok(())
}

fn load_host_integration_fixture_catalog() -> HostIntegrationFixtureCatalog {
    load_json("host_integration/fixture_matrix.json")
}

fn assert_contains_all_strings(actual: &[String], expected: &[&str], label: &str) {
    for expected_value in expected {
        assert!(
            actual.iter().any(|value| value == expected_value),
            "{label} missing `{expected_value}`; got {actual:?}"
        );
    }
}

#[test]
fn catalog_covers_every_fixture_file() {
    let catalog = load_catalog();
    let catalog_paths = catalog
        .fixtures
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<BTreeSet<_>>();
    let fixture_files = collect_fixture_files(&fixture_root())
        .into_iter()
        .filter(|path| path != "README.md" && path != "catalog.json")
        .collect::<BTreeSet<_>>();

    assert_eq!(catalog_paths, fixture_files);
    assert_eq!(catalog_paths.len(), catalog.fixtures.len());
    for entry in &catalog.fixtures {
        assert_ne!(entry.kind.trim(), "");
        assert_ne!(entry.purpose.trim(), "");
        assert_ne!(entry.validation.trim(), "");
    }
}

#[test]
fn every_fixture_is_syntax_valid() {
    for relative in collect_fixture_files(&fixture_root()) {
        if relative == "README.md" {
            continue;
        }

        let content = read(&relative);
        match Path::new(&relative)
            .extension()
            .and_then(|ext| ext.to_str())
        {
            Some("json") => {
                let _: Value = serde_json::from_str(&content)
                    .unwrap_or_else(|error| panic!("{relative} should parse as JSON: {error}"));
            }
            Some("toml") => {
                let _: toml::Value = toml::from_str(&content)
                    .unwrap_or_else(|error| panic!("{relative} should parse as TOML: {error}"));
            }
            Some("jsonl") => {
                for (line_no, line) in content.lines().enumerate() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    serde_json::from_str::<Value>(line).unwrap_or_else(|error| {
                        panic!(
                            "{relative} line {} should parse as JSON: {error}",
                            line_no + 1
                        )
                    });
                }
            }
            Some("toon") => {
                assert!(!content.trim().is_empty(), "{relative} should not be empty");
            }
            other => panic!("unexpected fixture extension for {relative}: {other:?}"),
        }
    }
}

#[test]
fn introspection_fixtures_deserialize_with_expected_cardinality() {
    let github: IntrospectionResponse = load_json("introspection/github_introspection.json");
    let slack: IntrospectionResponse = load_json("introspection/slack_introspection.json");
    let minimal: IntrospectionResponse = load_json("introspection/minimal_introspection.json");
    let large: IntrospectionResponse = load_json("introspection/large_introspection.json");

    assert_eq!(github.tools.len(), 10);
    assert_eq!(slack.tools.len(), 5);
    assert_eq!(minimal.tools.len(), 1);
    assert_eq!(large.tools.len(), 50);

    for response in [&github, &slack, &minimal, &large] {
        assert_eq!(response.connector.tool_count as usize, response.tools.len());
        for tool in &response.tools {
            assert_ne!(tool.description.trim(), "");
            assert!(tool.input_schema.is_object());
            assert!(tool.output_schema.is_object() || tool.output_schema.is_array());
        }
    }
}

#[test]
fn operation_inputs_and_api_responses_match_tool_schemas() {
    let github: IntrospectionResponse = load_json("introspection/github_introspection.json");
    let slack: IntrospectionResponse = load_json("introspection/slack_introspection.json");

    let github_tools = github
        .tools
        .iter()
        .map(|tool| (tool.name.as_str(), tool))
        .collect::<BTreeMap<_, _>>();
    let slack_tools = slack
        .tools
        .iter()
        .map(|tool| (tool.name.as_str(), tool))
        .collect::<BTreeMap<_, _>>();

    let valid_issue_input: Value = load_json("operation_inputs/valid_create_issue.json");
    let invalid_issue_input: Value = load_json("operation_inputs/invalid_create_issue.json");
    let valid_send_message: Value = load_json("operation_inputs/valid_send_message.json");
    let create_issue_output: Value = load_json("api_responses/github_create_issue_response.json");
    let list_issues_output: Value = load_json("api_responses/github_list_issues_response.json");
    let slack_send_output: Value = load_json("api_responses/slack_send_message_response.json");

    validate_schema(
        &valid_issue_input,
        &github_tools["github.create_issue"].input_schema,
    )
    .expect("valid github.create_issue input should match schema");
    assert!(
        validate_schema(
            &invalid_issue_input,
            &github_tools["github.create_issue"].input_schema,
        )
        .is_err()
    );
    validate_schema(
        &valid_send_message,
        &slack_tools["slack.send_message"].input_schema,
    )
    .expect("valid slack.send_message input should match schema");

    validate_schema(
        &create_issue_output,
        &github_tools["github.create_issue"].output_schema,
    )
    .expect("github create_issue response should match schema");
    validate_schema(
        &list_issues_output,
        &github_tools["github.list_issues"].output_schema,
    )
    .expect("github list_issues response should match schema");
    validate_schema(
        &slack_send_output,
        &slack_tools["slack.send_message"].output_schema,
    )
    .expect("slack send_message response should match schema");

    for relative in [
        "api_responses/error_401_response.json",
        "api_responses/error_429_response.json",
        "api_responses/error_500_response.json",
    ] {
        let payload: Value = load_json(relative);
        let error = payload
            .get("error")
            .and_then(Value::as_object)
            .expect("error payload should have an `error` object");
        assert!(error.get("status").and_then(Value::as_i64).is_some());
        assert!(error.get("code").and_then(Value::as_str).is_some());
        assert!(error.get("message").and_then(Value::as_str).is_some());
    }
}

#[test]
fn pipeline_and_batch_fixtures_validate_semantically() {
    for relative in [
        "pipelines/simple_pipe.toml",
        "pipelines/conditional_pipe.toml",
        "pipelines/multi_step_pipe.toml",
    ] {
        validate_pipeline_fixture(relative)
            .unwrap_or_else(|error| panic!("{relative} should be valid: {error}"));
    }
    assert!(validate_pipeline_fixture("pipelines/invalid_pipe.toml").is_err());

    for relative in [
        "batch/simple_batch.jsonl",
        "batch/mixed_batch.jsonl",
        "batch/dependent_batch.jsonl",
    ] {
        validate_batch_fixture(relative)
            .unwrap_or_else(|error| panic!("{relative} should be valid: {error}"));
    }
    assert!(validate_batch_fixture("batch/invalid_batch.jsonl").is_err());
}

#[test]
fn typed_access_setup_and_mesh_fixtures_deserialize() {
    let previous: PolicyBundle = load_json("access/policy_bundle_previous.json");
    let current: PolicyBundle = load_json("access/policy_bundle_current.json");
    previous
        .validate()
        .expect("previous policy bundle should validate");
    current
        .validate()
        .expect("current policy bundle should validate");
    assert!(current.policy_seq > previous.policy_seq);

    let provisioning_recipe: ProvisioningRecipe =
        load_json("setup/provisioning_recipe_github.json");
    let setup_descriptor: SetupDescriptor = load_json("setup/setup_descriptor_github.json");
    let provisioning_state: ProvisioningState =
        load_json("setup/provisioning_state_awaiting_human.json");
    let provisioning_validation: ProvisioningValidation =
        load_json("setup/provisioning_validation_drifted.json");
    assert_eq!(provisioning_recipe.steps.len(), 3);
    assert!(!setup_descriptor.tool_descriptor.is_null());
    assert!(!provisioning_state.awaiting_human.is_empty());
    assert!(!provisioning_validation.valid);

    let managed_inventory: Vec<ManagedConnectorConfig> =
        load_json("mesh/managed_connector_inventory.json");
    let connector_status: ConnectorAdminStatus =
        load_json("mesh/connector_admin_status_degraded.json");
    let reconciliation: StartupReconciliationReport =
        load_json("mesh/startup_reconciliation_report.json");
    let rollout: RolloutAuditEvent = load_json("mesh/rollout_audit_event_promote.json");
    let install_output: InstallOutputFixture = load_json("mesh/install_output_mirrored.json");

    assert_eq!(managed_inventory.len(), 2);
    assert_eq!(connector_status.config_revision_count, 9);
    assert_eq!(reconciliation.tracked_connectors, 2);
    assert_eq!(rollout.reason_code, "promotion_threshold_met");
    assert_eq!(install_output.connector_id, "fcp.github:enterprise:v1");
    assert_eq!(install_output.version, "1.2.3");
    assert_eq!(install_output.target, "x86_64-unknown-linux-gnu");
    assert_eq!(install_output.zone_id, "z:work");
    assert!(install_output.manifest_hash.starts_with("sha256:"));
    assert!(install_output.binary_hash.starts_with("sha256:"));
    assert_eq!(
        install_output.manifest_object_id.as_deref(),
        Some("obj-manifest-0007")
    );
    assert_eq!(
        install_output.binary_object_id.as_deref(),
        Some("obj-binary-0007")
    );
    assert_eq!(install_output.installed_at, 1_710_115_200);
    assert_eq!(install_output.installed_at_iso, "2026-03-11T00:00:00Z");
    assert!(install_output.verification.publisher_signature_verified);
    assert!(install_output.verification.registry_signature_verified);
    assert_eq!(install_output.verification.publisher_signatures_valid, 2);
    assert_eq!(install_output.verification.publisher_threshold, 2);
    assert!(install_output.verification.capability_ceiling_respected);
    assert!(install_output.verification.supply_chain_policy_satisfied);
    assert_eq!(install_output.verification.verified_attestations.len(), 2);
}

#[test]
fn golden_output_snapshots_are_non_empty_and_dispatchable() {
    for relative in [
        "golden/access_plan.toon",
        "golden/setup_repair.toon",
        "golden/mesh_rollout.toon",
    ] {
        let content = read(relative);
        assert!(
            content.lines().count() >= 4,
            "{relative} should have multiple lines"
        );
        assert_ne!(content.trim(), "");
    }

    let invocations: Vec<DispatchInvocationFixture> = load_json("golden/dispatch_invocations.json");
    assert_eq!(invocations.len(), 3);
    for invocation in invocations {
        assert_ne!(invocation.name.trim(), "");
        assert_ne!(invocation.argv, [] as [std::string::String; 0]);
        assert_eq!(invocation.argv[0], "fwc");
    }
}

#[test]
fn host_integration_fixture_matrix_covers_required_archetypes_and_modes() {
    let catalog = load_host_integration_fixture_catalog();
    assert!(
        catalog.fixtures.len() >= 7,
        "fixture matrix should cover the core host-backed archetypes"
    );

    let ids = catalog
        .fixtures
        .iter()
        .map(|fixture| fixture.id.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        ids.len(),
        catalog.fixtures.len(),
        "fixture ids must be unique"
    );

    let connectors = catalog
        .fixtures
        .iter()
        .map(|fixture| fixture.connector_id.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        connectors.len(),
        catalog.fixtures.len(),
        "fixture matrix should not duplicate connector ids"
    );

    let archetypes = catalog
        .fixtures
        .iter()
        .map(|fixture| fixture.archetype)
        .collect::<BTreeSet<_>>();
    assert!(archetypes.contains(&HostIntegrationArchetype::RequestResponse));
    assert!(archetypes.contains(&HostIntegrationArchetype::Streaming));
    assert!(archetypes.contains(&HostIntegrationArchetype::Webhook));
    assert!(archetypes.contains(&HostIntegrationArchetype::Polling));
    assert!(archetypes.contains(&HostIntegrationArchetype::Browser));
    assert!(archetypes.contains(&HostIntegrationArchetype::Database));
    assert!(archetypes.contains(&HostIntegrationArchetype::LifecycleHeavy));

    let coverage_modes = catalog
        .fixtures
        .iter()
        .map(|fixture| fixture.coverage_mode)
        .collect::<BTreeSet<_>>();
    assert!(coverage_modes.contains(&HostIntegrationCoverageMode::MockHost));
    assert!(coverage_modes.contains(&HostIntegrationCoverageMode::RealHost));

    assert!(catalog.fixtures.iter().any(|fixture| {
        matches!(
            fixture.auth_scope,
            HostIntegrationAuthScope::MultiProfile | HostIntegrationAuthScope::TenantScoped
        )
    }));
    assert!(
        catalog
            .fixtures
            .iter()
            .any(|fixture| fixture.reversibility == OperationReversibility::Irreversible)
    );
    assert!(
        catalog
            .fixtures
            .iter()
            .any(|fixture| fixture.reversibility == OperationReversibility::Reversible)
    );
    assert!(
        catalog
            .fixtures
            .iter()
            .all(|fixture| fixture.readiness == FixtureReadiness::LiveRuntime)
    );
}

#[test]
fn host_integration_fixture_matrix_entries_are_semantically_complete() {
    let catalog = load_host_integration_fixture_catalog();
    for fixture in &catalog.fixtures {
        assert_ne!(fixture.id.trim(), "");
        assert!(fixture.connector_id.starts_with("fcp."));
        assert_ne!(fixture.display_name.trim(), "");
        assert_ne!(fixture.risk_level.trim(), "");
        assert_ne!(fixture.safety_tier.trim(), "");
        assert_ne!(fixture.operation_family.trim(), "");
        assert!(fixture.tool_count > 0);
        assert!(
            !fixture.provenance_markers.is_empty(),
            "fixture {} should carry provenance markers",
            fixture.id
        );
        assert!(
            fixture
                .provenance_markers
                .iter()
                .all(|marker| !marker.trim().is_empty())
        );
        assert!(
            !fixture.notes.trim().is_empty(),
            "fixture {} should explain why it exists",
            fixture.id
        );
        assert_contains_all_strings(
            &fixture.required_artifacts,
            &[
                "trace.jsonl",
                "summary.json",
                "environment.json",
                "replay.sh",
            ],
            &format!("fixture {} required_artifacts", fixture.id),
        );
        assert_contains_all_strings(
            &fixture.required_log_fields,
            &["correlation_id", "phase"],
            &format!("fixture {} required_log_fields", fixture.id),
        );
    }

    let github = catalog
        .fixtures
        .iter()
        .find(|fixture| fixture.id == "github_issue_workflow")
        .expect("github workflow fixture should exist");
    assert_eq!(github.archetype, HostIntegrationArchetype::RequestResponse);
    assert_eq!(github.coverage_mode, HostIntegrationCoverageMode::MockHost);
    assert_eq!(github.auth_scope, HostIntegrationAuthScope::TenantScoped);
    assert_eq!(github.reversibility, OperationReversibility::Mixed);
    assert_eq!(github.tool_count, 2);
    assert!(
        !github
            .required_artifacts
            .iter()
            .any(|artifact| artifact == "session_transcript.json")
    );
    assert!(
        github
            .notes
            .contains("workflow_search_to_invoke_to_history_full_chain")
    );

    for fixture_id in [
        "slack_event_stream",
        "stripe_webhook_receipts",
        "gmail_polling_sync",
        "browser_session_automation",
    ] {
        let fixture = catalog
            .fixtures
            .iter()
            .find(|fixture| fixture.id == fixture_id)
            .unwrap_or_else(|| panic!("fixture {fixture_id} should exist"));
        assert!(
            fixture
                .required_artifacts
                .iter()
                .any(|artifact| artifact == "session_transcript.json"),
            "fixture {fixture_id} should require session_transcript.json"
        );
    }
}
