#![allow(clippy::expect_used, clippy::too_many_lines)]

use std::collections::BTreeSet;

use fcp_apple_reminders::AppleRemindersConnector;
use fcp_apple_reminders::error::AppleRemindersError;
use fcp_manifest::ManifestApprovalMode;
use fcp_prelude::{ApprovalMode, FcpConnector, FcpError, IdempotencyClass, RiskLevel, SafetyTier};
use fcp_testkit::{OperationContract, assert_operation_contracts};
use serde_json::Value;

const CONNECTOR_ID: &str = "fcp.apple-reminders";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_HEALTH: &str = "apple_reminders.health";
const OP_LIST_LISTS: &str = "apple_reminders.list_lists";
const OP_LIST_REMINDERS: &str = "apple_reminders.list_reminders";
const OP_CREATE_REMINDER: &str = "apple_reminders.create_reminder";
const OP_COMPLETE_REMINDER: &str = "apple_reminders.complete_reminder";

const CAP_READ: &str = "apple_reminders.read";
const CAP_WRITE: &str = "apple_reminders.write";

#[test]
fn apple_reminders_schema_operation_and_error_contracts_are_advertised() {
    let connector = AppleRemindersConnector::new();
    let introspection =
        serde_json::to_value(connector.introspect()).expect("introspection should serialize");

    assert_eq!(connector.id().as_str(), CONNECTOR_ID);
    assert_operation_contracts(
        &introspection,
        &[
            OperationContract {
                id: OP_HEALTH,
                capability: CAP_READ,
                required_input_fields: &[],
                output_fields: &["status", "platform", "manifest_hash"],
            },
            OperationContract {
                id: OP_LIST_LISTS,
                capability: CAP_READ,
                required_input_fields: &[],
                output_fields: &["lists"],
            },
            OperationContract {
                id: OP_LIST_REMINDERS,
                capability: CAP_READ,
                required_input_fields: &[],
                output_fields: &["reminders"],
            },
            OperationContract {
                id: OP_CREATE_REMINDER,
                capability: CAP_WRITE,
                required_input_fields: &["title"],
                output_fields: &["id", "title", "list"],
            },
            OperationContract {
                id: OP_COMPLETE_REMINDER,
                capability: CAP_WRITE,
                required_input_fields: &["reminder_id"],
                output_fields: &["id", "title", "completed"],
            },
        ],
    );

    let event_caps = introspection
        .get("event_caps")
        .expect("Apple Reminders should advertise event capabilities");
    assert_eq!(event_caps["streaming"], false);
    assert_eq!(event_caps["replay"], false);
    assert_eq!(event_caps["min_buffer_events"], 0);
    assert!(
        introspection
            .get("events")
            .and_then(Value::as_array)
            .expect("events should serialize as an array")
            .is_empty(),
        "Apple Reminders is a local request-response connector with no event stream"
    );

    assert!(matches!(
        AppleRemindersError::Config("blank title".into()).to_fcp_error(),
        FcpError::InvalidRequest { code: 1003, .. }
    ));
    assert!(matches!(
        AppleRemindersError::UnsupportedPlatform("linux".into()).to_fcp_error(),
        FcpError::ConnectorUnavailable { code: 5001, .. }
    ));
    assert!(matches!(
        AppleRemindersError::Process("automation denied".into()).to_fcp_error(),
        FcpError::Internal { .. }
    ));
    assert!(matches!(
        AppleRemindersError::Parse("missing id".into()).to_fcp_error(),
        FcpError::Internal { .. }
    ));
    assert!(matches!(
        AppleRemindersError::Timeout { timeout_secs: 1 }.to_fcp_error(),
        FcpError::Internal { .. }
    ));
    assert!(!AppleRemindersError::Timeout { timeout_secs: 1 }.is_retryable());
}

#[test]
fn apple_reminders_advertises_complete_operation_matrix_with_user_facing_metadata() {
    let connector = AppleRemindersConnector::new();
    let introspection = connector.introspect();
    let expected = [
        (
            OP_HEALTH,
            CAP_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            None,
        ),
        (
            OP_LIST_LISTS,
            CAP_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            None,
        ),
        (
            OP_LIST_REMINDERS,
            CAP_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            None,
        ),
        (
            OP_CREATE_REMINDER,
            CAP_WRITE,
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            Some(ApprovalMode::Policy),
        ),
        (
            OP_COMPLETE_REMINDER,
            CAP_WRITE,
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
            Some(ApprovalMode::Policy),
        ),
    ];

    assert_eq!(
        introspection.operations.len(),
        expected.len(),
        "Apple Reminders should expose its complete local operation matrix"
    );
    for (operation_id, capability, risk_level, safety_tier, idempotency, approval) in expected {
        let operation = introspection
            .operations
            .iter()
            .find(|candidate| candidate.id.as_str() == operation_id)
            .expect("expected operation contract to be advertised");
        assert_eq!(operation.capability.as_str(), capability);
        assert_eq!(
            operation.risk_level, risk_level,
            "{operation_id} risk level drifted"
        );
        assert_eq!(
            operation.safety_tier, safety_tier,
            "{operation_id} safety tier drifted"
        );
        assert_eq!(
            operation.idempotency, idempotency,
            "{operation_id} idempotency drifted"
        );
        assert_eq!(
            operation.requires_approval, approval,
            "{operation_id} approval policy drifted"
        );
        assert!(
            !operation.summary.trim().is_empty(),
            "{operation_id} has empty summary"
        );
        assert!(
            operation
                .description
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
            "{operation_id} has no useful description"
        );
        assert_eq!(operation.input_schema["type"], "object");
        assert_eq!(operation.output_schema["type"], "object");
        assert!(
            !operation.ai_hints.when_to_use.trim().is_empty(),
            "{operation_id} has no operator guidance"
        );
        assert!(
            !operation.ai_hints.common_mistakes.is_empty(),
            "{operation_id} should teach agents what not to do"
        );
        assert!(
            !operation.ai_hints.examples.is_empty(),
            "{operation_id} should include a synthetic example"
        );
        for example in &operation.ai_hints.examples {
            let parsed: Value =
                serde_json::from_str(example).expect("ai_hints examples should be JSON objects");
            assert!(
                parsed.is_object(),
                "{operation_id} example should be a JSON object"
            );
            assert_redacted(example);
        }
    }
}

#[test]
fn apple_reminders_manifest_matches_introspection_and_local_bridge_security_contract() {
    let manifest: toml::Value =
        toml::from_str(MANIFEST_TOML).expect("Apple Reminders manifest should parse as TOML");
    let connector = AppleRemindersConnector::new();
    let introspection =
        serde_json::to_value(connector.introspect()).expect("introspection should serialize");

    assert_eq!(string_at(&manifest, &["connector", "id"]), CONNECTOR_ID);
    assert_eq!(string_at(&manifest, &["connector", "format"]), "native");
    assert_eq!(string_at(&manifest, &["zones", "home"]), "z:owner");
    assert_array_contains(&manifest, &["zones", "allowed_sources"], "z:owner");
    assert_array_contains(&manifest, &["zones", "allowed_sources"], "z:private");
    assert_array_contains(&manifest, &["zones", "forbidden"], "z:public");
    assert_array_contains(&manifest, &["zones", "forbidden"], "z:community");
    assert_array_contains(&manifest, &["zones", "forbidden"], "z:work");
    assert_array_contains(&manifest, &["capabilities", "required"], CAP_READ);
    assert_array_contains(&manifest, &["capabilities", "required"], CAP_WRITE);
    assert_array_contains(&manifest, &["capabilities", "forbidden"], "network.listen");
    assert_array_contains(
        &manifest,
        &["capabilities", "forbidden"],
        "network.outbound",
    );
    assert_array_contains(&manifest, &["capabilities", "forbidden"], "system.exec");
    assert_array_contains(
        &manifest,
        &["capabilities", "forbidden"],
        "system.privileged",
    );
    assert_eq!(string_at(&manifest, &["sandbox", "profile"]), "strict");
    assert_eq!(integer_at(&manifest, &["sandbox", "memory_mb"]), 64);
    assert_eq!(
        integer_at(&manifest, &["sandbox", "wall_clock_timeout_ms"]),
        30_000
    );
    assert!(
        !bool_at(&manifest, &["sandbox", "deny_exec"]),
        "Apple Reminders has a bounded osascript carveout, not ambient shell execution"
    );

    let introspection_ids = introspection_operation_ids(&introspection);
    let manifest_ids = manifest_operation_ids(&manifest);
    assert_eq!(
        introspection_ids, manifest_ids,
        "manifest and connector operation catalog drifted"
    );

    for operation_id in introspection_ids {
        let manifest_op = value_at(&manifest, &["provides", "operations", operation_id]);
        let introspection_op = introspection_operation(&introspection, operation_id);
        assert_eq!(
            manifest_op["capability"].as_str(),
            introspection_op["capability"].as_str(),
            "{operation_id} capability drifted"
        );
        assert_eq!(
            manifest_op["risk_level"].as_str(),
            introspection_op["risk_level"].as_str(),
            "{operation_id} risk level drifted"
        );
        assert_eq!(
            manifest_op["safety_tier"].as_str(),
            introspection_op["safety_tier"].as_str(),
            "{operation_id} safety tier drifted"
        );
        assert_eq!(
            manifest_op["idempotency"].as_str(),
            introspection_op["idempotency"].as_str(),
            "{operation_id} idempotency drifted"
        );
        let manifest_approval: ManifestApprovalMode = manifest_op["requires_approval"]
            .clone()
            .try_into()
            .expect("manifest approval mode should deserialize");
        let expected_approval = match manifest_approval {
            ManifestApprovalMode::None => None,
            ManifestApprovalMode::Policy => Some("policy"),
            ManifestApprovalMode::Interactive => Some("interactive"),
            ManifestApprovalMode::ElevationToken => Some("elevation_token"),
        };
        assert_eq!(
            expected_approval,
            introspection_op["requires_approval"].as_str(),
            "{operation_id} approval mode drifted"
        );
        assert!(
            manifest_op["ai_hints"]["when_to_use"]
                .as_str()
                .is_some_and(|value| !value.trim().is_empty()),
            "{operation_id} manifest ai_hints are empty"
        );
        assert_no_egress_network_constraints(manifest_op, operation_id);
    }

    assert_manifest_output_fields(
        &manifest,
        OP_HEALTH,
        &["status", "platform", "manifest_hash"],
    );
    assert_manifest_output_fields(&manifest, OP_LIST_LISTS, &["lists"]);
    assert_manifest_output_fields(&manifest, OP_LIST_REMINDERS, &["reminders"]);
    assert_manifest_output_fields(&manifest, OP_CREATE_REMINDER, &["id", "title", "list"]);
    assert_manifest_output_fields(
        &manifest,
        OP_COMPLETE_REMINDER,
        &["id", "title", "completed"],
    );
}

fn introspection_operation_ids(introspection: &Value) -> BTreeSet<&str> {
    introspection
        .get("operations")
        .and_then(Value::as_array)
        .expect("introspection should expose operations array")
        .iter()
        .map(|operation| {
            operation
                .get("id")
                .and_then(Value::as_str)
                .expect("operation id should be a string")
        })
        .collect()
}

fn introspection_operation<'a>(introspection: &'a Value, operation_id: &str) -> &'a Value {
    introspection
        .get("operations")
        .and_then(Value::as_array)
        .expect("introspection should expose operations array")
        .iter()
        .find(|operation| operation.get("id").and_then(Value::as_str) == Some(operation_id))
        .expect("expected operation should be advertised")
}

fn manifest_operation_ids(manifest: &toml::Value) -> BTreeSet<&str> {
    value_at(manifest, &["provides", "operations"])
        .as_table()
        .expect("manifest provides.operations should be a table")
        .keys()
        .map(String::as_str)
        .collect()
}

fn assert_manifest_output_fields(manifest: &toml::Value, operation_id: &str, fields: &[&str]) {
    let properties = value_at(
        manifest,
        &[
            "provides",
            "operations",
            operation_id,
            "output_schema",
            "properties",
        ],
    )
    .as_table()
    .expect("operation output_schema.properties should be a table");
    for field in fields {
        assert!(
            properties.contains_key(*field),
            "{operation_id} manifest output schema should advertise {field}"
        );
    }
}

fn value_at<'a>(value: &'a toml::Value, path: &[&str]) -> &'a toml::Value {
    let mut current = value;
    for segment in path {
        current = current
            .get(*segment)
            .expect("manifest path segment should exist");
    }
    current
}

fn string_at<'a>(value: &'a toml::Value, path: &[&str]) -> &'a str {
    value_at(value, path)
        .as_str()
        .expect("manifest path should contain a string")
}

fn integer_at(value: &toml::Value, path: &[&str]) -> i64 {
    value_at(value, path)
        .as_integer()
        .expect("manifest path should contain an integer")
}

fn bool_at(value: &toml::Value, path: &[&str]) -> bool {
    value_at(value, path)
        .as_bool()
        .expect("manifest path should contain a bool")
}

fn assert_array_contains(value: &toml::Value, path: &[&str], expected: &str) {
    let array = value_at(value, path)
        .as_array()
        .expect("manifest path should contain an array");
    assert!(
        array.iter().any(|item| item.as_str() == Some(expected)),
        "{} should contain {expected}",
        path.join(".")
    );
}

fn assert_no_egress_network_constraints(operation: &toml::Value, operation_id: &str) {
    let constraints = operation
        .get("network_constraints")
        .expect("Apple Reminders operation should declare network_constraints");
    assert_eq!(
        string_array_field(constraints, "host_allow"),
        vec!["none.invalid"],
        "{operation_id} should use the no-egress sentinel host"
    );
    assert_eq!(
        integer_array_field(constraints, "port_allow"),
        vec![0],
        "{operation_id} should use the no-egress sentinel port"
    );
    assert!(
        string_array_field(constraints, "ip_allow").is_empty(),
        "{operation_id} should not allow IP egress"
    );
    assert!(
        string_array_field(constraints, "cidr_deny").is_empty(),
        "{operation_id} should not need CIDR deny exceptions"
    );
    assert!(
        string_array_field(constraints, "spki_pins").is_empty(),
        "{operation_id} should not pin TLS keys for a no-egress operation"
    );
    assert!(
        bool_field(constraints, "deny_localhost"),
        "{operation_id} should deny localhost egress"
    );
    assert!(
        bool_field(constraints, "deny_private_ranges"),
        "{operation_id} should deny private-range egress"
    );
    assert!(
        bool_field(constraints, "deny_tailnet_ranges"),
        "{operation_id} should deny tailnet egress"
    );
    assert!(
        !bool_field(constraints, "require_sni"),
        "{operation_id} should not require SNI for a no-egress operation"
    );
    assert!(
        bool_field(constraints, "deny_ip_literals"),
        "{operation_id} should deny IP-literal egress"
    );
    assert!(
        bool_field(constraints, "require_host_canonicalization"),
        "{operation_id} should require host canonicalization"
    );
    assert_eq!(
        integer_field(constraints, "dns_max_ips"),
        0,
        "{operation_id} should not resolve DNS for no-egress operations"
    );
    assert_eq!(
        integer_field(constraints, "max_redirects"),
        0,
        "{operation_id} should deny redirects"
    );
    assert_eq!(
        integer_field(constraints, "connect_timeout_ms"),
        10_000,
        "{operation_id} should keep a bounded connect timeout"
    );
    assert_eq!(
        integer_field(constraints, "total_timeout_ms"),
        30_000,
        "{operation_id} should stay within the connector wall-clock timeout"
    );
    assert_eq!(
        integer_field(constraints, "max_response_bytes"),
        65_536,
        "{operation_id} should bound hypothetical response bytes"
    );
}

fn string_array_field<'a>(value: &'a toml::Value, field: &str) -> Vec<&'a str> {
    value
        .get(field)
        .unwrap_or_else(|| panic!("network_constraints should contain {field}"))
        .as_array()
        .unwrap_or_else(|| panic!("network_constraints.{field} should be an array"))
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("network_constraints.{field} entries should be strings"))
        })
        .collect()
}

fn integer_array_field(value: &toml::Value, field: &str) -> Vec<i64> {
    value
        .get(field)
        .unwrap_or_else(|| panic!("network_constraints should contain {field}"))
        .as_array()
        .unwrap_or_else(|| panic!("network_constraints.{field} should be an array"))
        .iter()
        .map(|item| {
            item.as_integer()
                .unwrap_or_else(|| panic!("network_constraints.{field} entries should be integers"))
        })
        .collect()
}

fn bool_field(value: &toml::Value, field: &str) -> bool {
    value
        .get(field)
        .unwrap_or_else(|| panic!("network_constraints should contain {field}"))
        .as_bool()
        .unwrap_or_else(|| panic!("network_constraints.{field} should be a bool"))
}

fn integer_field(value: &toml::Value, field: &str) -> i64 {
    value
        .get(field)
        .unwrap_or_else(|| panic!("network_constraints should contain {field}"))
        .as_integer()
        .unwrap_or_else(|| panic!("network_constraints.{field} should be an integer"))
}

fn assert_redacted(value: &str) {
    for forbidden in [
        "password",
        "secret",
        "token",
        "@example.com",
        "/Users/",
        "/tmp/",
    ] {
        assert!(
            !value.to_ascii_lowercase().contains(forbidden),
            "operator-facing guidance leaked forbidden marker: {forbidden}"
        );
    }
}
