#![allow(clippy::expect_used, clippy::too_many_lines)]

use fcp_prelude::{ApprovalMode, FcpConnector, FcpError, IdempotencyClass, SafetyTier};
use fcp_signal::SignalConnector;
use fcp_signal::error::SignalError;
use fcp_testkit::{OperationContract, assert_operation_contracts};
use serde_json::Value;
use std::collections::BTreeSet;

const CONNECTOR_ID: &str = "fcp.signal";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_SEND_MESSAGE: &str = "signal.send_message";
const OP_RECEIVE_MESSAGES: &str = "signal.receive_messages";
const OP_LIST_GROUPS: &str = "signal.list_groups";
const OP_GET_GROUP: &str = "signal.get_group";
const OP_GET_IDENTITY: &str = "signal.get_identity";
const OP_TRUST_IDENTITY: &str = "signal.trust_identity";

const CAP_SEND: &str = "signal.send";
const CAP_READ: &str = "signal.read";
const CAP_ADMIN: &str = "signal.admin";

const EVENT_MESSAGE_RECEIVED: &str = "signal.message.received";
const EVENT_REACTION_RECEIVED: &str = "signal.reaction.received";
const EVENT_RECEIPT_READ: &str = "signal.receipt.read";
const EVENT_TYPING_RECEIVED: &str = "signal.typing.received";
const EVENT_POLICY_DENIED: &str = "signal.policy.denied";
const EVENT_ALL: &str = "signal.events";

#[test]
fn signal_schema_operation_event_and_error_contracts_are_advertised() {
    let connector = SignalConnector::new();
    let introspection =
        serde_json::to_value(connector.introspect()).expect("introspection should serialize");

    assert_eq!(connector.id().as_str(), CONNECTOR_ID);
    assert_operation_contracts(
        &introspection,
        &[
            OperationContract {
                id: OP_SEND_MESSAGE,
                capability: CAP_SEND,
                required_input_fields: &["recipients", "message"],
                output_fields: &["timestamp", "coordination"],
            },
            OperationContract {
                id: OP_RECEIVE_MESSAGES,
                capability: CAP_READ,
                required_input_fields: &[],
                output_fields: &["messages", "count", "receive_cursor", "cached_group_count"],
            },
            OperationContract {
                id: OP_GET_GROUP,
                capability: CAP_READ,
                required_input_fields: &["group_id"],
                output_fields: &["id", "name", "members", "admins"],
            },
            OperationContract {
                id: OP_GET_IDENTITY,
                capability: CAP_READ,
                required_input_fields: &["number"],
                output_fields: &["number", "uuid", "trust_level"],
            },
            OperationContract {
                id: OP_TRUST_IDENTITY,
                capability: CAP_ADMIN,
                required_input_fields: &["number"],
                output_fields: &["status"],
            },
        ],
    );

    let list_groups = introspection
        .get("operations")
        .and_then(Value::as_array)
        .expect("introspection should expose operations array")
        .iter()
        .find(|operation| operation["id"] == OP_LIST_GROUPS)
        .expect("list_groups operation should be advertised");
    assert_eq!(list_groups["capability"], CAP_READ);
    assert_eq!(
        list_groups["input_schema"],
        serde_json::json!({ "type": "object" }),
        "list_groups should remain a zero-input operation"
    );
    assert!(list_groups["output_schema"]["properties"]["groups"].is_object());

    let event_caps = introspection
        .get("event_caps")
        .expect("Signal should advertise event capabilities");
    assert_eq!(event_caps["streaming"], true);
    assert_eq!(event_caps["replay"], false);
    assert_eq!(event_caps["min_buffer_events"], 100);
    assert_eq!(event_caps["requires_ack"], true);

    let topics = introspection_events(&introspection)
        .iter()
        .map(|event| {
            let topic = event["topic"]
                .as_str()
                .expect("event topic should serialize as a string");
            assert_object_schema(&event["schema"], topic, "event schema");
            assert_eq!(event["requires_ack"], true, "{topic} requires_ack drifted");
            topic
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        topics,
        BTreeSet::from([
            EVENT_MESSAGE_RECEIVED,
            EVENT_REACTION_RECEIVED,
            EVENT_RECEIPT_READ,
            EVENT_TYPING_RECEIVED,
            EVENT_POLICY_DENIED,
            EVENT_ALL,
        ])
    );

    assert!(matches!(
        SignalError::Unauthorized("denied".into()).to_fcp_error(),
        FcpError::Unauthorized { .. }
    ));
    assert!(matches!(
        SignalError::RateLimited {
            retry_after_ms: 2_000,
        }
        .to_fcp_error(),
        FcpError::RateLimited {
            retry_after_ms: 2_000,
            ..
        }
    ));
    assert!(matches!(
        SignalError::BridgeTimeout { timeout_ms: 250 }.to_fcp_error(),
        FcpError::External {
            service,
            retryable: true,
            ..
        } if service == "signal"
    ));
    assert!(matches!(
        SignalError::AttachmentError("too large".into()).to_fcp_error(),
        FcpError::InvalidRequest { code: 1006, .. }
    ));
}

#[test]
fn signal_advertises_full_operation_matrix_with_user_facing_metadata() {
    let connector = SignalConnector::new();
    let introspection = connector.introspect();
    let expected: [(
        &str,
        &str,
        SafetyTier,
        IdempotencyClass,
        Option<ApprovalMode>,
    ); 6] = [
        (
            OP_SEND_MESSAGE,
            CAP_SEND,
            SafetyTier::Risky,
            IdempotencyClass::None,
            None,
        ),
        (
            OP_RECEIVE_MESSAGES,
            CAP_READ,
            SafetyTier::Safe,
            IdempotencyClass::None,
            None,
        ),
        (
            OP_LIST_GROUPS,
            CAP_READ,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            None,
        ),
        (
            OP_GET_GROUP,
            CAP_READ,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            None,
        ),
        (
            OP_GET_IDENTITY,
            CAP_READ,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            None,
        ),
        (
            OP_TRUST_IDENTITY,
            CAP_ADMIN,
            SafetyTier::Dangerous,
            IdempotencyClass::BestEffort,
            Some(ApprovalMode::Interactive),
        ),
    ];

    assert_eq!(
        introspection.operations.len(),
        expected.len(),
        "Signal should expose its complete connector operation matrix"
    );
    for (operation_id, capability, safety_tier, idempotency, approval) in expected {
        let operation = introspection
            .operations
            .iter()
            .find(|candidate| candidate.id.as_str() == operation_id)
            .expect("expected operation contract to be advertised");
        assert_eq!(operation.capability.as_str(), capability);
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
        assert_object_schema(&operation.input_schema, operation_id, "input_schema");
        assert_object_schema(&operation.output_schema, operation_id, "output_schema");
        assert!(
            !operation.ai_hints.when_to_use.trim().is_empty(),
            "{operation_id} has no operator guidance"
        );
        assert!(
            operation
                .ai_hints
                .related
                .iter()
                .all(|capability| !capability.as_str().trim().is_empty()),
            "{operation_id} has blank related capabilities"
        );
    }
}

#[test]
fn signal_manifest_keeps_loopback_security_and_event_contracts_in_sync() {
    let manifest: toml::Value =
        toml::from_str(MANIFEST_TOML).expect("Signal manifest should parse as TOML");
    assert_eq!(string_at(&manifest, &["connector", "id"]), CONNECTOR_ID);
    assert_eq!(string_at(&manifest, &["zones", "home"]), "z:private");
    assert_array_contains(&manifest, &["manifest", "protocol_features"], "signal.sse");
    assert_array_contains(&manifest, &["zones", "forbidden"], "z:public");
    assert_array_contains(&manifest, &["zones", "forbidden"], "z:community");
    assert_array_contains(&manifest, &["capabilities", "forbidden"], "system.exec");
    assert_array_contains(&manifest, &["capabilities", "forbidden"], "network.listen");
    assert_array_contains(
        &manifest,
        &["capabilities", "forbidden"],
        "system.privileged",
    );
    assert!(bool_at(&manifest, &["event_caps", "streaming"]));
    assert!(!bool_at(&manifest, &["event_caps", "replay"]));
    assert_eq!(
        integer_at(&manifest, &["event_caps", "min_buffer_events"]),
        100
    );
    assert!(bool_at(&manifest, &["sandbox", "deny_exec"]));
    assert_eq!(integer_at(&manifest, &["sandbox", "memory_mb"]), 64);

    let connector = SignalConnector::new();
    let introspection_op_ids = connector
        .introspect()
        .operations
        .into_iter()
        .map(|operation| operation.id.as_str().to_string())
        .collect::<BTreeSet<_>>();
    let manifest_operations = manifest
        .get("provides")
        .and_then(|value| value.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("manifest should declare operations");
    let manifest_op_ids = manifest_operations.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        manifest_op_ids, introspection_op_ids,
        "manifest operations must stay in sync with introspection"
    );

    for (operation_id, operation) in manifest_operations {
        assert!(
            operation
                .get("description")
                .and_then(toml::Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "{operation_id} missing manifest description"
        );
        assert!(
            operation
                .get("ai_hints")
                .and_then(|value| value.get("when_to_use"))
                .and_then(toml::Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "{operation_id} missing manifest ai_hints.when_to_use"
        );
        let network_constraints = operation
            .get("network_constraints")
            .expect("operation should declare loopback network constraints");
        assert_string_array_contains(
            network_constraints,
            &["host_allow"],
            "localhost",
            operation_id,
        );
        assert_string_array_contains(
            network_constraints,
            &["host_allow"],
            "127.0.0.1",
            operation_id,
        );
        assert_string_array_contains(network_constraints, &["host_allow"], "::1", operation_id);
        assert!(
            bool_from(network_constraints, &["deny_tailnet_ranges"]),
            "{operation_id} must deny tailnet daemon endpoints by default"
        );
        assert_eq!(
            integer_from(network_constraints, &["max_redirects"]),
            0,
            "{operation_id} must not follow redirects across trust boundaries"
        );
    }

    let manifest_events = manifest
        .get("provides")
        .and_then(|value| value.get("events"))
        .and_then(toml::Value::as_table)
        .expect("manifest should declare events");
    let manifest_event_topics = manifest_events.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        manifest_event_topics,
        BTreeSet::from([
            EVENT_MESSAGE_RECEIVED.to_string(),
            EVENT_REACTION_RECEIVED.to_string(),
            EVENT_RECEIPT_READ.to_string(),
            EVENT_TYPING_RECEIVED.to_string(),
            EVENT_POLICY_DENIED.to_string(),
            EVENT_ALL.to_string(),
        ])
    );
    for (topic, event) in manifest_events {
        assert!(
            bool_from(event, &["streaming"]),
            "{topic} must remain streamable"
        );
        assert!(
            !bool_from(event, &["replay"]),
            "{topic} must remain explicit no-replay"
        );
        assert!(
            bool_from(event, &["requires_ack"]),
            "{topic} must require host acknowledgement"
        );
        assert_eq!(event["capability"].as_str(), Some(CAP_READ));
        assert_eq!(
            event["subscribe_operation"].as_str(),
            Some("signal.subscribe")
        );
        assert_eq!(
            event["resource_uri"].as_str(),
            Some(format!("signal:events:{topic}").as_str())
        );
        assert!(
            event.get("schema").is_some(),
            "{topic} missing manifest event schema"
        );
    }
}

fn introspection_events(introspection: &Value) -> &[Value] {
    introspection
        .get("events")
        .and_then(Value::as_array)
        .expect("introspection should expose events array")
}

fn assert_object_schema(schema: &Value, operation_id: &str, field: &str) {
    assert_eq!(
        schema.get("type").and_then(Value::as_str),
        Some("object"),
        "{operation_id} {field} should be an object schema"
    );
    assert!(
        schema.get("properties").is_some_and(|properties| properties
            .as_object()
            .is_some_and(|object| !object.is_empty()))
            || schema.get("oneOf").is_some_and(|alternatives| alternatives
                .as_array()
                .is_some_and(|items| !items.is_empty()))
            || schema == &serde_json::json!({ "type": "object" }),
        "{operation_id} {field} should declare properties or composition"
    );
}

fn value_at<'a>(root: &'a toml::Value, path: &[&str]) -> &'a toml::Value {
    path.iter().fold(root, |current, segment| {
        let next = current.get(segment);
        assert!(
            next.is_some(),
            "missing TOML path segment {segment} in path {path:?}"
        );
        next.expect("missing TOML path segment after assertion")
    })
}

fn string_at(root: &toml::Value, path: &[&str]) -> String {
    let value = value_at(root, path).as_str();
    assert!(value.is_some(), "TOML path {path:?} should be a string");
    value
        .expect("TOML path should be a string after assertion")
        .to_string()
}

fn bool_at(root: &toml::Value, path: &[&str]) -> bool {
    let value = value_at(root, path).as_bool();
    assert!(value.is_some(), "TOML path {path:?} should be a bool");
    value.expect("TOML path should be a bool after assertion")
}

fn integer_at(root: &toml::Value, path: &[&str]) -> i64 {
    let value = value_at(root, path).as_integer();
    assert!(value.is_some(), "TOML path {path:?} should be an integer");
    value.expect("TOML path should be an integer after assertion")
}

fn value_from<'a>(root: &'a toml::Value, path: &[&str]) -> &'a toml::Value {
    value_at(root, path)
}

fn bool_from(root: &toml::Value, path: &[&str]) -> bool {
    let value = value_from(root, path).as_bool();
    assert!(value.is_some(), "TOML path {path:?} should be a bool");
    value.expect("TOML path should be a bool after assertion")
}

fn integer_from(root: &toml::Value, path: &[&str]) -> i64 {
    let value = value_from(root, path).as_integer();
    assert!(value.is_some(), "TOML path {path:?} should be an integer");
    value.expect("TOML path should be an integer after assertion")
}

fn assert_array_contains(root: &toml::Value, path: &[&str], expected: &str) {
    assert_string_array_contains(value_at(root, path), &[], expected, &path.join("."));
}

fn assert_string_array_contains(root: &toml::Value, path: &[&str], expected: &str, context: &str) {
    let array = value_from(root, path).as_array();
    assert!(
        array.is_some(),
        "{context} TOML path {path:?} should be an array"
    );
    let array = array.expect("TOML path should be an array after assertion");
    assert!(
        array.iter().any(|value| value.as_str() == Some(expected)),
        "{context} should contain {expected}"
    );
}
