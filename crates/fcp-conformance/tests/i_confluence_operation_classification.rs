//! Conformance tests for I-CONFLUENCE operation classification (`flywheel_connectors-angoc.11.1.1`).
//!
//! Validates:
//! 1. Golden classification cases and invalid combinations in
//!    `tests/fixtures/i_confluence/operation_classification.json`.
//! 2. `test_every_connector_op_has_classification`: every operation in `connectors/*/manifest.toml`
//!    resolves to a valid `CoordinationClass` and passes `validate_classification`.
//! 3. `test_read_ops_classified_iconfluent`: side-effect-free / read-named operations classify as
//!    `CoordinationClass::IConfluent`.
//! 4. `test_write_ops_classified_quorum_or_fencing`: side-effecting operations classify as
//!    `CoordinationClass::RequiresQuorum` or `CoordinationClass::RequiresFencing`.
//! 5. `test_introspect_includes_coordination_class`: `Introspection` JSON output includes
//!    `coordination_class` on every entry in `operations[]`.

use std::fs;
use std::path::PathBuf;

use fcp_core::{
    AgentHint, CapabilityId, CoordinationClass, IdempotencyClass, Introspection, OperationId,
    OperationInfo, RiskLevel, SafetyTier,
};
use fcp_manifest::ConnectorManifest;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
struct GoldenFixture {
    rubric_version: String,
    cases: Vec<GoldenCase>,
    invalid_combinations: Vec<InvalidCase>,
    introspect_response_contract: IntrospectContract,
}

#[derive(Debug, Deserialize)]
struct GoldenCase {
    name: String,
    side_effects: bool,
    idempotency_class: IdempotencyClass,
    expected_class: CoordinationClass,
    rationale: String,
}

#[derive(Debug, Deserialize)]
struct InvalidCase {
    name: String,
    side_effects: bool,
    expected_class: CoordinationClass,
    expected_error: String,
    rationale: String,
}

#[derive(Debug, Deserialize)]
struct IntrospectContract {
    field_name: String,
    enum_values: Vec<String>,
    required: bool,
}

fn connectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .join("connectors")
}

fn load_all_connector_manifests() -> Vec<(String, ConnectorManifest)> {
    let dir = connectors_dir();
    let mut manifests = Vec::new();
    let entries = fs::read_dir(&dir).expect("connectors dir should be readable");
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest_path = path.join("manifest.toml");
        if !manifest_path.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<unknown>")
            .to_owned();
        let body = fs::read_to_string(&manifest_path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", manifest_path.display()));
        if let Ok(manifest) = ConnectorManifest::parse_str_unchecked(&body) {
            manifests.push((name, manifest));
        }
    }
    manifests.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(
        manifests.len() >= 150,
        "expected at least 150 parsed connector manifests, got {}",
        manifests.len()
    );
    manifests
}

#[test]
fn test_golden_fixture_classification_cases_and_invalid_combinations() {
    let raw = include_str!("fixtures/i_confluence/operation_classification.json");
    let fixture: GoldenFixture =
        serde_json::from_str(raw).expect("golden fixture should deserialize");
    assert_eq!(fixture.rubric_version, "2026.Q3.v1");
    assert_eq!(fixture.cases.len(), 11);
    assert_eq!(fixture.invalid_combinations.len(), 2);

    for case in &fixture.cases {
        let actual =
            CoordinationClass::classify(&case.name, case.side_effects, case.idempotency_class);
        assert_eq!(
            actual, case.expected_class,
            "mismatch for golden case `{}` ({})",
            case.name, case.rationale
        );
        actual
            .validate_classification(&case.name, case.side_effects)
            .unwrap_or_else(|err| {
                panic!(
                    "golden case `{}` should pass validation: {err}",
                    case.name
                )
            });
    }

    for invalid in &fixture.invalid_combinations {
        let err = invalid
            .expected_class
            .validate_classification(&invalid.name, invalid.side_effects)
            .unwrap_err();
        assert_eq!(
            err.code(),
            invalid.expected_error,
            "unexpected error code for invalid case `{}` ({})",
            invalid.name,
            invalid.rationale
        );
    }
}

#[test]
fn test_every_connector_op_has_classification() {
    let manifests = load_all_connector_manifests();
    let mut total_ops = 0usize;

    for (connector, manifest) in &manifests {
        assert!(
            !manifest.provides.operations.is_empty(),
            "connector `{connector}` must declare at least one operation"
        );
        for (op_id, op_section) in &manifest.provides.operations {
            total_ops += 1;
            let side_effects = op_section.effective_side_effects(op_id);
            let class = op_section.effective_coordination_class(op_id);
            class
                .validate_classification(op_id, side_effects)
                .unwrap_or_else(|err| {
                    panic!(
                        "connector `{connector}` op `{op_id}` failed I-CONFLUENCE validation: {err}"
                    )
                });
        }
    }

    assert!(
        total_ops >= 500,
        "expected at least 500 total operations across manifests, got {total_ops}"
    );
}

#[test]
fn test_read_ops_classified_iconfluent() {
    let manifests = load_all_connector_manifests();
    let mut read_ops_checked = 0usize;

    for (connector, manifest) in &manifests {
        for (op_id, op_section) in &manifest.provides.operations {
            let side_effects = op_section.effective_side_effects(op_id);
            if !side_effects {
                read_ops_checked += 1;
                let class = op_section.effective_coordination_class(op_id);
                assert_eq!(
                    class,
                    CoordinationClass::IConfluent,
                    "read/side-effect-free op `{op_id}` in `{connector}` must be IConfluent"
                );
            }
        }
    }

    assert!(
        read_ops_checked > 0,
        "expected to check at least one read operation"
    );
}

#[test]
fn test_write_ops_classified_quorum_or_fencing() {
    let manifests = load_all_connector_manifests();
    let mut write_ops_checked = 0usize;

    for (connector, manifest) in &manifests {
        for (op_id, op_section) in &manifest.provides.operations {
            let side_effects = op_section.effective_side_effects(op_id);
            if side_effects {
                write_ops_checked += 1;
                let class = op_section.effective_coordination_class(op_id);
                assert!(
                    matches!(
                        class,
                        CoordinationClass::RequiresQuorum | CoordinationClass::RequiresFencing
                    ),
                    "mutating op `{op_id}` in `{connector}` must be RequiresQuorum or RequiresFencing, got {class}"
                );
            }
        }
    }

    assert!(
        write_ops_checked > 0,
        "expected to check at least one mutating operation"
    );
}

#[test]
fn test_introspect_includes_coordination_class() {
    let raw = include_str!("fixtures/i_confluence/operation_classification.json");
    let fixture: GoldenFixture =
        serde_json::from_str(raw).expect("golden fixture should deserialize");
    assert!(fixture.introspect_response_contract.required);
    assert_eq!(
        fixture.introspect_response_contract.field_name,
        "coordination_class"
    );

    let introspect = Introspection {
        operations: vec![
            OperationInfo {
                id: OperationId::new("stripe.list_charges").expect("valid id"),
                summary: "List charges".to_owned(),
                description: None,
                input_schema: json!({"type": "object"}),
                output_schema: json!({"type": "object"}),
                capability: CapabilityId::new("stripe.read").expect("valid cap"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint::default(),
                rate_limit: None,
                requires_approval: None,
            },
            OperationInfo {
                id: OperationId::new("stripe.create_charge").expect("valid id"),
                summary: "Create charge".to_owned(),
                description: None,
                input_schema: json!({"type": "object"}),
                output_schema: json!({"type": "object"}),
                capability: CapabilityId::new("stripe.write").expect("valid cap"),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint::default(),
                rate_limit: None,
                requires_approval: None,
            },
            OperationInfo {
                id: OperationId::new("stripe.refund_charge").expect("valid id"),
                summary: "Refund charge".to_owned(),
                description: None,
                input_schema: json!({"type": "object"}),
                output_schema: json!({"type": "object"}),
                capability: CapabilityId::new("stripe.write").expect("valid cap"),
                risk_level: RiskLevel::High,
                safety_tier: SafetyTier::Dangerous,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint::default(),
                rate_limit: None,
                requires_approval: None,
            },
        ],
        events: vec![],
        resource_types: vec![],
        auth_caps: None,
        event_caps: None,
    };

    let serialized: Value =
        serde_json::to_value(&introspect).expect("introspect should serialize");
    let operations = serialized["operations"]
        .as_array()
        .expect("operations array");
    assert_eq!(operations.len(), 3);

    for op_val in operations {
        let class_str = op_val["coordination_class"]
            .as_str()
            .expect("every introspect operation must include coordination_class string");
        assert!(
            fixture
                .introspect_response_contract
                .enum_values
                .iter()
                .any(|allowed| allowed == class_str),
            "unexpected coordination_class `{class_str}`"
        );
    }

    assert_eq!(operations[0]["coordination_class"], "i_confluent");
    assert_eq!(operations[1]["coordination_class"], "requires_quorum");
    assert_eq!(operations[2]["coordination_class"], "requires_fencing");
}
