#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::collections::{BTreeMap, BTreeSet};

use fcp_google_chat::{connector::ChatConnector, error::ChatError};
use fcp_manifest::{ConnectorManifest, OperationSection};
use fcp_prelude::FcpError;
use serde::Serialize;
use serde_json::Value;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const EXPECTED_OPERATION_COUNT: usize = 10;
const HOST_FORWARDED_WEBHOOK_OP: &str = "chat.ingest_webhook";

fn manifest() -> ConnectorManifest {
    ConnectorManifest::parse_str_unchecked(MANIFEST_TOML)
        .expect("Google Chat manifest TOML should deserialize")
}

async fn runtime_operations() -> Vec<Value> {
    let connector = ChatConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("Google Chat introspection should serialize");
    introspection["operations"]
        .as_array()
        .expect("operations should be an array")
        .clone()
}

fn serialized_str(value: &impl Serialize) -> String {
    serde_json::to_value(value)
        .expect("serialize manifest enum")
        .as_str()
        .expect("manifest enum should serialize as a string")
        .to_string()
}

fn assert_object_schema(schema: &Value, operation_id: &str, label: &str) {
    assert_eq!(
        schema["type"], "object",
        "{operation_id} {label}_schema should be an object"
    );
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        if required.is_empty() {
            return;
        }
        let properties = schema.get("properties").and_then(Value::as_object);
        assert!(
            properties.is_some(),
            "{operation_id} {label}_schema has required fields but no properties"
        );
        let properties = properties.expect("schema properties existence was asserted");
        for field in required {
            let field = field
                .as_str()
                .expect("required schema entries should be strings");
            assert!(
                properties.contains_key(field),
                "{operation_id} {label}_schema requires `{field}` but does not declare it"
            );
        }
    }
}

fn assert_manifest_operation_contract(id: &str, op: &OperationSection) {
    assert!(
        !op.description.trim().is_empty(),
        "{id} should have a manifest description"
    );
    assert_object_schema(&op.input_schema, id, "input");
    assert_object_schema(&op.output_schema, id, "output");
    assert!(
        !op.ai_hints.when_to_use.trim().is_empty(),
        "{id} should advertise ai_hints.when_to_use"
    );
    assert!(
        !op.ai_hints.examples.is_empty(),
        "{id} should advertise at least one ai_hints example"
    );
    assert!(
        !op.capability.as_str().trim().is_empty(),
        "{id} should declare a capability"
    );
    assert!(
        !serialized_str(&op.risk_level).trim().is_empty(),
        "{id} should declare risk_level"
    );
    assert!(
        !serialized_str(&op.safety_tier).trim().is_empty(),
        "{id} should declare safety_tier"
    );
    assert!(
        !serialized_str(&op.idempotency).trim().is_empty(),
        "{id} should declare idempotency"
    );
}

#[fcp_async_core::runtime::test]
async fn runtime_catalog_matches_manifest_operation_contracts() {
    let manifest = manifest();
    let runtime_ops = runtime_operations().await;

    assert_eq!(
        manifest.provides.operations.len(),
        EXPECTED_OPERATION_COUNT,
        "manifest operation count changed; update connector-local conformance expectations"
    );
    assert_eq!(
        runtime_ops.len(),
        EXPECTED_OPERATION_COUNT,
        "runtime operation count changed; update connector-local conformance expectations"
    );

    let runtime_by_id: BTreeMap<&str, &Value> = runtime_ops
        .iter()
        .map(|op| (op["id"].as_str().expect("runtime operation id"), op))
        .collect();
    let manifest_ids: BTreeSet<&str> = manifest
        .provides
        .operations
        .keys()
        .map(String::as_str)
        .collect();
    let runtime_ids: BTreeSet<&str> = runtime_by_id.keys().copied().collect();
    assert_eq!(manifest_ids, runtime_ids);

    for (id, manifest_op) in &manifest.provides.operations {
        assert_manifest_operation_contract(id, manifest_op);
        let runtime_op = runtime_by_id
            .get(id.as_str())
            .expect("manifest operation should be present in runtime introspection");

        assert_eq!(
            runtime_op["capability"],
            manifest_op.capability.as_str(),
            "{id}"
        );
        assert_eq!(
            runtime_op["risk_level"],
            serialized_str(&manifest_op.risk_level),
            "{id}"
        );
        assert_eq!(
            runtime_op["safety_tier"],
            serialized_str(&manifest_op.safety_tier),
            "{id}"
        );
        assert_eq!(
            runtime_op["idempotency"],
            serialized_str(&manifest_op.idempotency),
            "{id}"
        );
        if matches!(id.as_str(), "chat.list_spaces" | "chat.list_messages" | "chat.list_members") {
            assert_eq!(runtime_op["input_schema"], manifest_op.input_schema, "{id}");
            assert_eq!(runtime_op["output_schema"], manifest_op.output_schema, "{id}");
        }
        assert_object_schema(&runtime_op["input_schema"], id, "runtime input");
        assert_object_schema(&runtime_op["output_schema"], id, "runtime output");
        assert!(
            runtime_op["ai_hints"]["when_to_use"]
                .as_str()
                .is_some_and(|value| !value.trim().is_empty()),
            "{id} should advertise runtime ai_hints.when_to_use"
        );
        assert!(
            runtime_op["ai_hints"]["examples"]
                .as_array()
                .is_some_and(|items| !items.is_empty()),
            "{id} should advertise runtime ai_hints.examples"
        );
    }
}

#[test]
fn manifest_network_constraints_are_complete_for_all_declared_operations() {
    let manifest = manifest();

    for (id, op) in &manifest.provides.operations {
        let constraints = op
            .network_constraints
            .as_ref()
            .expect("operation should declare operation-level network constraints");
        if id == HOST_FORWARDED_WEBHOOK_OP {
            assert_eq!(
                constraints.host_allow,
                vec!["none.invalid".to_string()],
                "host-forwarded webhook must use the no-egress sentinel host"
            );
            assert_eq!(
                constraints.port_allow,
                vec![0],
                "host-forwarded webhook must use the no-egress sentinel port"
            );
            assert_eq!(constraints.dns_max_ips, 0, "{id} should not resolve DNS");
            assert!(
                !constraints.require_sni,
                "{id} should not require SNI without provider egress"
            );
            assert_eq!(
                constraints.max_response_bytes, 65_536,
                "{id} should keep a finite no-egress response cap"
            );
        } else {
            assert_eq!(
                constraints.host_allow,
                vec!["chat.googleapis.com".to_string()],
                "{id} should only allow Google Chat API host egress"
            );
            assert_eq!(
                constraints.port_allow,
                vec![443],
                "{id} should stay TLS-only"
            );
            assert_eq!(constraints.dns_max_ips, 16, "{id} should bound DNS fanout");
            assert!(
                constraints.max_response_bytes <= 10 * 1_048_576,
                "{id} should keep response caps bounded"
            );
        }
        assert!(constraints.deny_localhost, "{id} should deny localhost");
        assert!(
            constraints.deny_private_ranges,
            "{id} should deny private ranges"
        );
        assert!(
            constraints.deny_tailnet_ranges,
            "{id} should deny tailnet ranges"
        );
        if id != HOST_FORWARDED_WEBHOOK_OP {
            assert!(constraints.require_sni, "{id} should require SNI");
        }
        assert!(constraints.deny_ip_literals, "{id} should deny IP literals");
        assert!(
            constraints.require_host_canonicalization,
            "{id} should require host canonicalization"
        );
        assert_eq!(constraints.max_redirects, 0, "{id} should forbid redirects");
        assert!(
            constraints.connect_timeout_ms <= constraints.total_timeout_ms,
            "{id} connect timeout should fit inside total timeout"
        );
    }
}

#[test]
fn error_taxonomy_maps_to_fcp_error_classes() {
    let unauthorized = ChatError::Unauthorized.to_fcp_error();
    assert!(matches!(
        unauthorized,
        FcpError::Unauthorized { code: 2001, .. }
    ));

    let forbidden = ChatError::Forbidden {
        message: "scope denied".to_string(),
    }
    .to_fcp_error();
    assert!(matches!(
        forbidden,
        FcpError::Unauthorized { code: 2001, .. }
    ));

    let missing = ChatError::SpaceNotFound {
        space_name: "spaces/secret".to_string(),
    }
    .to_fcp_error();
    assert!(matches!(
        missing,
        FcpError::ResourceNotFound { resource } if resource == "space:spaces/secret"
    ));

    let limited = ChatError::RateLimited {
        retry_after_ms: 30_000,
    }
    .to_fcp_error();
    assert!(matches!(
        limited,
        FcpError::RateLimited {
            retry_after_ms: 30_000,
            ..
        }
    ));

    let provider_retryable = ChatError::Api {
        status_code: 503,
        message: "backend unavailable".to_string(),
    }
    .to_fcp_error();
    assert!(matches!(
        provider_retryable,
        FcpError::External {
            service,
            status_code: Some(503),
            retryable: true,
            ..
        } if service == "google_chat"
    ));

    let provider_bad_request = ChatError::Api {
        status_code: 400,
        message: "bad request".to_string(),
    }
    .to_fcp_error();
    assert!(matches!(
        provider_bad_request,
        FcpError::External {
            service,
            status_code: Some(400),
            retryable: false,
            ..
        } if service == "google_chat"
    ));
}
