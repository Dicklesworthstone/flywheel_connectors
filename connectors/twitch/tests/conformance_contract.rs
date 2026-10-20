#![allow(clippy::panic_in_result_fn)]

use std::collections::BTreeSet;

use fcp_prelude::{ApprovalMode, FcpConnector, FcpError, IdempotencyClass, RiskLevel, SafetyTier};
use fcp_testkit::{OperationContract, assert_operation_contracts};
use fcp_twitch::{
    connector::{TwitchConnector, operations_info},
    error::TwitchError,
};
use serde_json::json;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const EXPECTED_OPERATIONS: [&str; 7] = [
    "twitch.streams.list",
    "twitch.streams.get",
    "twitch.users.get",
    "twitch.channels.get",
    "twitch.clips.list",
    "twitch.games.list",
    "twitch.health",
];

const MANIFEST_OPERATION_KEYS: [&str; 7] = [
    "streams_list",
    "streams_get",
    "users_get",
    "channels_get",
    "clips_list",
    "games_list",
    "health",
];

#[test]
fn operation_contracts_are_advertised_for_ai_and_schema_consumers() {
    let connector = TwitchConnector::new();
    let introspection =
        serde_json::to_value(connector.introspect()).expect("introspection should serialize");

    assert_operation_contracts(
        &introspection,
        &[
            OperationContract {
                id: "twitch.streams.list",
                capability: "twitch.read",
                required_input_fields: &[],
                output_fields: &["streams", "count"],
            },
            OperationContract {
                id: "twitch.streams.get",
                capability: "twitch.read",
                required_input_fields: &["user_login"],
                output_fields: &["stream", "is_live"],
            },
            OperationContract {
                id: "twitch.users.get",
                capability: "twitch.read",
                required_input_fields: &["login"],
                output_fields: &["id", "login", "display_name"],
            },
            OperationContract {
                id: "twitch.channels.get",
                capability: "twitch.read",
                required_input_fields: &["broadcaster_id"],
                output_fields: &["broadcaster_id", "title", "game_name"],
            },
            OperationContract {
                id: "twitch.clips.list",
                capability: "twitch.read",
                required_input_fields: &["broadcaster_id"],
                output_fields: &["clips", "count"],
            },
            OperationContract {
                id: "twitch.games.list",
                capability: "twitch.read",
                required_input_fields: &[],
                output_fields: &["games", "count"],
            },
            OperationContract {
                id: "twitch.health",
                capability: "twitch.read",
                required_input_fields: &[],
                output_fields: &["status", "api_reachable"],
            },
        ],
    );
}

#[test]
fn operation_metadata_is_read_only_safe_and_approval_free() {
    let ops = operations_info();
    let ids = ops.iter().map(|op| op.id.as_str()).collect::<BTreeSet<_>>();

    assert_eq!(ids.len(), EXPECTED_OPERATIONS.len());
    for expected in EXPECTED_OPERATIONS {
        assert!(ids.contains(expected), "missing operation {expected}");
    }

    for operation in &ops {
        assert_eq!(operation.capability.as_str(), "twitch.read");
        assert_eq!(operation.risk_level, RiskLevel::Low);
        assert_eq!(operation.safety_tier, SafetyTier::Safe);
        assert_eq!(operation.requires_approval, Some(ApprovalMode::None));
        assert!(
            !operation.ai_hints.when_to_use.trim().is_empty(),
            "{} should advertise an ai_hints.when_to_use hint",
            operation.id
        );

        if operation.id.as_str() == "twitch.health" {
            assert_eq!(operation.idempotency, IdempotencyClass::Strict);
        } else {
            assert_eq!(operation.idempotency, IdempotencyClass::None);
        }
    }

    for write_operation in [
        "twitch.channels.modify",
        "twitch.clips.create",
        "twitch.chat.send",
    ] {
        assert!(
            !ids.contains(write_operation),
            "write operation {write_operation} must not be exposed"
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn manifest_operation_schemas_compile_and_validate_declared_payloads() -> Result<(), String> {
    let manifest = manifest()?;

    for operation in MANIFEST_OPERATION_KEYS {
        assert_manifest_operation(&manifest, operation)?;
    }

    assert_schema_accepts(
        &schema(&manifest, "streams_list", "input_schema")?,
        &json!({"game_id": "509658", "user_login": "fixture_login", "first": 2}),
    )?;
    assert_schema_rejects(
        &schema(&manifest, "streams_list", "input_schema")?,
        &json!({"first": 0}),
    )?;
    assert_schema_rejects(
        &schema(&manifest, "streams_get", "input_schema")?,
        &json!({}),
    )?;
    assert_schema_accepts(
        &schema(&manifest, "streams_get", "input_schema")?,
        &json!({"user_login": "fixture_login"}),
    )?;
    assert_schema_rejects(
        &schema(&manifest, "users_get", "input_schema")?,
        &json!({"login": "fixture_login", "extra": true}),
    )?;
    assert_schema_accepts(
        &schema(&manifest, "channels_get", "input_schema")?,
        &json!({"broadcaster_id": "12345"}),
    )?;
    assert_schema_rejects(
        &schema(&manifest, "clips_list", "input_schema")?,
        &json!({"first": 2}),
    )?;
    assert_schema_accepts(
        &schema(&manifest, "games_list", "input_schema")?,
        &json!({"name": "Just Chatting"}),
    )?;
    assert_schema_rejects(
        &schema(&manifest, "games_list", "input_schema")?,
        &json!({"id": "509658", "extra": true}),
    )?;

    assert_schema_accepts(
        &schema(&manifest, "streams_list", "output_schema")?,
        &json!({
            "streams": [{
                "id": "stream-1",
                "user_id": "12345",
                "user_login": "fixture_login",
                "user_name": "FixtureBroadcaster",
                "game_id": "509658",
                "game_name": "Just Chatting",
                "type": "live",
                "title": "Fixture stream",
                "viewer_count": 42,
                "started_at": "2026-05-08T02:00:00Z",
                "language": "en",
                "tags": ["English"],
                "is_mature": false
            }],
            "count": 1
        }),
    )?;
    assert_schema_rejects(
        &schema(&manifest, "streams_list", "output_schema")?,
        &json!({"streams": []}),
    )?;

    assert_schema_accepts(
        &schema(&manifest, "clips_list", "output_schema")?,
        &json!({
            "clips": [{
                "id": "clip-1",
                "url": "https://clips.twitch.tv/clip-1",
                "embed_url": "https://clips.twitch.tv/embed?clip=clip-1",
                "broadcaster_id": "12345",
                "broadcaster_name": "FixtureBroadcaster",
                "creator_id": "98765",
                "creator_name": "FixtureCreator",
                "game_id": "509658",
                "language": "en",
                "title": "Fixture clip",
                "view_count": 7,
                "created_at": "2026-05-08T02:10:00Z",
                "duration": 12.5
            }],
            "count": 1
        }),
    )?;
    assert_schema_accepts(
        &schema(&manifest, "users_get", "output_schema")?,
        &json!({"error": "User not found"}),
    )?;
    assert_schema_accepts(
        &schema(&manifest, "health", "output_schema")?,
        &json!({
            "status": "ok",
            "api_reachable": true,
            "token_valid": true,
            "expires_in": 3600,
            "scopes": ["user:read:email"]
        }),
    )?;
    assert_schema_rejects(
        &schema(&manifest, "health", "output_schema")?,
        &json!({"status": "failed", "api_reachable": false}),
    )?;

    Ok(())
}

#[test]
fn twitch_error_taxonomy_maps_to_fcp_errors() {
    assert!(matches!(
        TwitchError::RateLimited {
            retry_after_ms: 1_500
        }
        .to_fcp_error(),
        FcpError::RateLimited {
            retry_after_ms: 1_500,
            ..
        }
    ));
    assert!(matches!(
        TwitchError::Unauthorized("bad token".into()).to_fcp_error(),
        FcpError::Unauthorized { code: 2001, .. }
    ));
    assert!(matches!(
        TwitchError::TokenError("invalid client".into()).to_fcp_error(),
        FcpError::Unauthorized { code: 2002, .. }
    ));
    assert!(matches!(
        TwitchError::InvalidInput("missing".into()).to_fcp_error(),
        FcpError::InvalidRequest { code: 1008, .. }
    ));

    let retryable = TwitchError::Api {
        status: 503,
        message: "unavailable".into(),
    };
    assert!(retryable.is_retryable());
    assert!(matches!(
        retryable.to_fcp_error(),
        FcpError::External {
            status_code: Some(503),
            retryable: true,
            ..
        }
    ));

    let terminal = TwitchError::Api {
        status: 400,
        message: "bad request".into(),
    };
    assert!(!terminal.is_retryable());
    assert!(matches!(
        terminal.to_fcp_error(),
        FcpError::External {
            status_code: Some(400),
            retryable: false,
            ..
        }
    ));
}

fn manifest() -> Result<toml::Value, String> {
    toml::from_str(MANIFEST_TOML).map_err(|error| format!("manifest should parse: {error}"))
}

fn manifest_operations(
    manifest: &toml::Value,
) -> Result<&toml::map::Map<String, toml::Value>, String> {
    manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .ok_or_else(|| "manifest should declare [provides.operations]".to_owned())
}

fn assert_manifest_operation(manifest: &toml::Value, operation: &str) -> Result<(), String> {
    let table = manifest_operations(manifest)?
        .get(operation)
        .and_then(toml::Value::as_table)
        .ok_or_else(|| format!("manifest should declare operation {operation}"))?;

    let capability = table
        .get("capability")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| format!("{operation} should declare capability"))?;
    if capability != "twitch.read" {
        return Err(format!("{operation} should require twitch.read"));
    }

    for field in ["input_schema", "output_schema", "network_constraints"] {
        let field_value = table
            .get(field)
            .and_then(toml::Value::as_table)
            .ok_or_else(|| format!("{operation} should declare {field}"))?;
        if field_value.is_empty() {
            return Err(format!("{operation}.{field} should not be empty"));
        }
    }

    let input = schema(manifest, operation, "input_schema")?;
    jsonschema::Validator::new(&input)
        .map_err(|error| format!("{operation}.input_schema should compile: {error}"))?;
    let output = schema(manifest, operation, "output_schema")?;
    jsonschema::Validator::new(&output)
        .map_err(|error| format!("{operation}.output_schema should compile: {error}"))?;

    Ok(())
}

fn schema(
    manifest: &toml::Value,
    operation: &str,
    field: &str,
) -> Result<serde_json::Value, String> {
    let schema = manifest_operations(manifest)?
        .get(operation)
        .and_then(toml::Value::as_table)
        .and_then(|op| op.get(field))
        .ok_or_else(|| format!("{operation} should declare {field}"))?;
    serde_json::to_value(schema)
        .map_err(|error| format!("{operation}.{field} should convert to JSON: {error}"))
}

fn assert_schema_accepts(
    schema: &serde_json::Value,
    payload: &serde_json::Value,
) -> Result<(), String> {
    let validator = jsonschema::Validator::new(schema)
        .map_err(|error| format!("schema should compile: {error}"))?;
    let errors = validator
        .iter_errors(payload)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "schema should accept {payload}; errors: {errors:?}"
        ))
    }
}

fn assert_schema_rejects(
    schema: &serde_json::Value,
    payload: &serde_json::Value,
) -> Result<(), String> {
    let validator = jsonschema::Validator::new(schema)
        .map_err(|error| format!("schema should compile: {error}"))?;
    if validator.iter_errors(payload).next().is_some() {
        Ok(())
    } else {
        Err(format!("schema should reject {payload}"))
    }
}
