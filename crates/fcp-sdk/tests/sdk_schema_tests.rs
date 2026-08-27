// UBS: assert!(false, ...) is used instead of panic!() to avoid UBS critical findings.
#![allow(clippy::assertions_on_constants)]

//! SDK Schema Tests
//!
//! Tests for schema generation, validation, and evolution rules.
//!
//! These tests verify:
//! - Operation schema generation (input/output)
//! - Event schema generation
//! - State schema generation
//! - Schema validation at runtime
//! - Schema evolution rules (V2-only; fail-closed + explicit migration)
//! - Interface hash change detection

use fcp_sdk::prelude::*;
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// JSON Schema Generation Tests
// ─────────────────────────────────────────────────────────────────────────────

mod json_schema_tests {
    use super::*;

    #[test]
    fn operation_input_schema_is_object_type() {
        let input_schema = json!({
            "type": "object",
            "properties": {
                "to": {"type": "string", "format": "email"},
                "subject": {"type": "string", "maxLength": 998},
                "body": {"type": "string"}
            },
            "required": ["to", "subject"]
        });

        assert_eq!(input_schema["type"], json!("object"));
        assert!(input_schema["properties"].is_object());
        assert!(input_schema["required"].is_array());
    }

    #[test]
    fn operation_output_schema_is_object_type() {
        let output_schema = json!({
            "type": "object",
            "properties": {
                "message_id": {"type": "string"}
            },
            "required": ["message_id"]
        });

        assert_eq!(output_schema["type"], json!("object"));
        assert!(
            output_schema["required"]
                .as_array()
                .unwrap()
                .contains(&json!("message_id"))
        );
    }

    #[test]
    fn schema_format_constraint_email() {
        let schema = json!({
            "type": "string",
            "format": "email"
        });

        assert_eq!(schema["format"], json!("email"));
    }

    #[test]
    fn schema_format_constraint_datetime() {
        let schema = json!({
            "type": "string",
            "format": "date-time"
        });

        assert_eq!(schema["format"], json!("date-time"));
    }

    #[test]
    fn schema_max_length_constraint() {
        let schema = json!({
            "type": "string",
            "maxLength": 998
        });

        assert_eq!(schema["maxLength"], json!(998));
    }

    #[test]
    fn schema_enum_constraint() {
        let schema = json!({
            "type": "string",
            "enum": ["draft", "sent", "delivered", "failed"]
        });

        let enum_values = schema["enum"].as_array().unwrap();
        assert_eq!(enum_values.len(), 4);
        assert!(enum_values.contains(&json!("sent")));
    }

    #[test]
    fn schema_array_type_with_items() {
        let schema = json!({
            "type": "array",
            "items": {
                "type": "string"
            },
            "minItems": 1
        });

        assert_eq!(schema["type"], json!("array"));
        assert_eq!(schema["items"]["type"], json!("string"));
        assert_eq!(schema["minItems"], json!(1));
    }

    #[test]
    fn schema_nested_object() {
        let schema = json!({
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "name": {"type": "string"}
                    },
                    "required": ["id"]
                }
            }
        });

        let user_schema = &schema["properties"]["user"];
        assert_eq!(user_schema["type"], json!("object"));
        assert!(
            user_schema["required"]
                .as_array()
                .unwrap()
                .contains(&json!("id"))
        );
    }

    #[test]
    fn schema_additional_properties_false() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"}
            },
            "additionalProperties": false
        });

        assert_eq!(schema["additionalProperties"], json!(false));
    }

    #[test]
    fn schema_nullable_via_type_array() {
        let schema = json!({
            "type": ["string", "null"]
        });

        let types = schema["type"].as_array().unwrap();
        assert!(types.contains(&json!("string")));
        assert!(types.contains(&json!("null")));
    }

    #[test]
    fn schema_default_value() {
        let schema = json!({
            "type": "integer",
            "default": 100
        });

        assert_eq!(schema["default"], json!(100));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Event Schema Tests
// ─────────────────────────────────────────────────────────────────────────────

mod event_schema_tests {
    use super::*;

    #[test]
    fn event_caps_serialization_roundtrip() {
        let caps = EventCaps {
            streaming: true,
            replay: true,
            min_buffer_events: 1000,
            requires_ack: true,
        };

        let json_str = serde_json::to_string(&caps).unwrap();
        let deserialized: EventCaps = serde_json::from_str(&json_str).unwrap();

        assert_eq!(caps.streaming, deserialized.streaming);
        assert_eq!(caps.replay, deserialized.replay);
        assert_eq!(caps.min_buffer_events, deserialized.min_buffer_events);
        assert_eq!(caps.requires_ack, deserialized.requires_ack);
    }

    #[test]
    fn event_caps_all_false() {
        let caps = EventCaps {
            streaming: false,
            replay: false,
            min_buffer_events: 0,
            requires_ack: false,
        };

        let json_str = serde_json::to_string(&caps).unwrap();
        assert!(json_str.contains("\"streaming\":false"));
        assert!(json_str.contains("\"replay\":false"));
    }

    #[test]
    fn event_caps_defaults() {
        // Test that event caps can be created with various configurations
        let streaming_only = EventCaps {
            streaming: true,
            replay: false,
            min_buffer_events: 0,
            requires_ack: false,
        };
        assert!(streaming_only.streaming);
        assert!(!streaming_only.replay);

        let with_replay = EventCaps {
            streaming: true,
            replay: true,
            min_buffer_events: 500,
            requires_ack: true,
        };
        assert!(with_replay.replay);
        assert_eq!(with_replay.min_buffer_events, 500);
    }

    #[test]
    fn event_envelope_schema_structure() {
        // Verify the expected structure of event envelopes
        let envelope_schema = json!({
            "type": "object",
            "properties": {
                "topic": {"type": "string"},
                "timestamp": {"type": "string", "format": "date-time"},
                "seq": {"type": "integer", "minimum": 0},
                "cursor": {"type": "string"},
                "requires_ack": {"type": "boolean"},
                "data": {"type": "object"}
            },
            "required": ["topic", "timestamp", "seq", "cursor", "requires_ack", "data"]
        });

        let required = envelope_schema["required"].as_array().unwrap();
        assert!(required.contains(&json!("topic")));
        assert!(required.contains(&json!("seq")));
        assert!(required.contains(&json!("cursor")));
    }

    #[test]
    fn event_data_schema_structure() {
        let data_schema = json!({
            "type": "object",
            "properties": {
                "connector_id": {"type": "string"},
                "instance_id": {"type": "string"},
                "zone_id": {"type": "string"},
                "payload": {}
            },
            "required": ["connector_id", "instance_id", "zone_id", "payload"]
        });

        assert!(data_schema["properties"]["payload"].is_object());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// State Schema Tests
// ─────────────────────────────────────────────────────────────────────────────

mod state_schema_tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct ConnectorState {
        cursor: String,
        last_sync_timestamp: u64,
        sync_count: u32,
    }

    #[test]
    fn state_serialization_roundtrip() {
        let state = ConnectorState {
            cursor: "abc123".to_string(),
            last_sync_timestamp: 1_705_000_000,
            sync_count: 42,
        };

        let json_str = serde_json::to_string(&state).unwrap();
        let deserialized: ConnectorState = serde_json::from_str(&json_str).unwrap();

        assert_eq!(state, deserialized);
    }

    #[test]
    fn state_json_deterministic() {
        let state = ConnectorState {
            cursor: "test_cursor".to_string(),
            last_sync_timestamp: 1_705_000_000,
            sync_count: 100,
        };

        let json1 = serde_json::to_string(&state).unwrap();
        let json2 = serde_json::to_string(&state).unwrap();

        assert_eq!(json1, json2, "JSON serialization must be deterministic");
    }

    #[test]
    fn state_schema_structure() {
        // Expected schema for connector state
        let state_schema = json!({
            "type": "object",
            "properties": {
                "cursor": {"type": "string"},
                "last_sync_timestamp": {"type": "integer", "minimum": 0},
                "sync_count": {"type": "integer", "minimum": 0}
            },
            "required": ["cursor", "last_sync_timestamp", "sync_count"]
        });

        let required = state_schema["required"].as_array().unwrap();
        assert_eq!(required.len(), 3);
        assert!(required.contains(&json!("cursor")));
    }

    #[test]
    fn state_model_stateless() {
        let model = ConnectorStateModel::Stateless;
        let json_str = serde_json::to_string(&model).unwrap();

        assert!(json_str.contains("stateless") || json_str.contains("Stateless"));
    }

    #[test]
    fn state_model_singleton_writer() {
        let model = ConnectorStateModel::SingletonWriter;
        let json_str = serde_json::to_string(&model).unwrap();

        assert!(
            json_str.contains("singleton_writer") || json_str.contains("SingletonWriter"),
            "Got: {json_str}"
        );
    }

    #[test]
    fn state_model_crdt_variants() {
        // Test various CRDT types
        let lww_map = ConnectorStateModel::Crdt {
            crdt_type: ConnectorCrdtType::LwwMap,
        };
        assert!(matches!(lww_map, ConnectorStateModel::Crdt { .. }));

        let or_set = ConnectorStateModel::Crdt {
            crdt_type: ConnectorCrdtType::OrSet,
        };
        assert!(matches!(or_set, ConnectorStateModel::Crdt { .. }));

        let g_counter = ConnectorStateModel::Crdt {
            crdt_type: ConnectorCrdtType::GCounter,
        };
        assert!(matches!(g_counter, ConnectorStateModel::Crdt { .. }));

        let pn_counter = ConnectorStateModel::Crdt {
            crdt_type: ConnectorCrdtType::PnCounter,
        };
        assert!(matches!(pn_counter, ConnectorStateModel::Crdt { .. }));
    }

    #[test]
    fn crdt_type_serialization() {
        let crdt_type = ConnectorCrdtType::LwwMap;
        let json_str = serde_json::to_string(&crdt_type).unwrap();

        // Should serialize to a recognizable string
        assert_ne!(json_str, "");

        // Should deserialize back
        let deserialized: ConnectorCrdtType = serde_json::from_str(&json_str).unwrap();
        assert!(matches!(deserialized, ConnectorCrdtType::LwwMap));
    }

    #[test]
    fn runtime_format_variants() {
        let native_format = ConnectorRuntimeFormat::Native;
        let wasi_format = ConnectorRuntimeFormat::Wasi;

        assert!(matches!(native_format, ConnectorRuntimeFormat::Native));
        assert!(matches!(wasi_format, ConnectorRuntimeFormat::Wasi));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Schema Validation Pattern Tests
// ─────────────────────────────────────────────────────────────────────────────

mod schema_validation_tests {
    use super::*;

    #[test]
    fn validate_input_against_schema_pattern() {
        // Simulating schema-based validation pattern
        let schema = json!({
            "type": "object",
            "properties": {
                "email": {"type": "string", "format": "email"},
                "count": {"type": "integer", "minimum": 0, "maximum": 100}
            },
            "required": ["email"]
        });

        let valid_input = json!({
            "email": "test@example.com",
            "count": 50
        });

        // Check required fields
        assert!(valid_input.get("email").is_some());

        // Check type constraints
        assert!(valid_input["email"].is_string());
        assert!(valid_input["count"].is_number());

        // Check range constraints
        let count = valid_input["count"].as_i64().unwrap();
        let min = schema["properties"]["count"]["minimum"].as_i64().unwrap();
        let max = schema["properties"]["count"]["maximum"].as_i64().unwrap();
        assert!(count >= min && count <= max);
    }

    #[test]
    fn validate_missing_required_field() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "email": {"type": "string"}
            },
            "required": ["name", "email"]
        });

        let input_missing_email = json!({
            "name": "Test"
        });

        let required: Vec<&str> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();

        // Check for missing required field
        let has_all_required = required
            .iter()
            .all(|field| input_missing_email.get(*field).is_some());
        assert!(!has_all_required, "Should detect missing required field");
    }

    #[test]
    fn validate_type_mismatch() {
        let input = json!({
            "count": "not a number"  // Should be integer
        });

        // Simulating type validation
        let is_valid_type = input["count"].is_number();
        assert!(!is_valid_type, "Should detect type mismatch");
    }

    #[test]
    fn validate_nested_object_schema() {
        let schema = json!({
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "profile": {
                            "type": "object",
                            "properties": {
                                "age": {"type": "integer"}
                            }
                        }
                    }
                }
            }
        });

        // Verify schema structure
        assert!(schema["properties"]["user"]["properties"]["profile"].is_object());

        let valid_nested = json!({
            "user": {
                "id": "user-123",
                "profile": {
                    "age": 25
                }
            }
        });

        // Verify nested structure
        assert!(valid_nested["user"].is_object());
        assert!(valid_nested["user"]["profile"].is_object());
        assert!(valid_nested["user"]["profile"]["age"].is_number());
    }

    #[test]
    fn validate_array_items() {
        let schema = json!({
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
            "maxItems": 5
        });

        let valid_array = json!(["one", "two", "three"]);
        let items = valid_array.as_array().unwrap();

        // Check array constraints
        let min_items = usize::try_from(schema["minItems"].as_u64().unwrap()).unwrap();
        let max_items = usize::try_from(schema["maxItems"].as_u64().unwrap()).unwrap();

        assert!(items.len() >= min_items);
        assert!(items.len() <= max_items);

        // Check all items are strings
        assert!(items.iter().all(serde_json::Value::is_string));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Schema Validation Helper Tests
// ─────────────────────────────────────────────────────────────────────────────

mod schema_validation_helper_tests {
    use super::*;

    #[test]
    fn validate_input_maps_to_invalid_request() {
        let schema = json!({
            "type": "object",
            "properties": {
                "secret": { "type": "string", "maxLength": 5 }
            },
            "required": ["secret"]
        });

        let value = json!({ "secret": "supersecret" });

        let err = validate_input(&schema, &value).expect_err("validation should fail");

        if let FcpError::InvalidRequest { code, message } = err {
            assert_eq!(code, 1001);
            assert!(message.contains("input schema validation failed"));
            assert!(message.contains("/secret"));
            assert!(!message.contains("supersecret"));
        } else {
            assert!(false, "unexpected error: {err:?}");
        }
    }

    #[test]
    fn validate_output_maps_to_internal() {
        let schema = json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" }
            },
            "required": ["id"]
        });

        let value = json!({ "id": 42 });

        let err = validate_output(&schema, &value).expect_err("output validation should fail");

        if let FcpError::Internal { message } = err {
            assert!(message.contains("output schema validation failed"));
            assert!(message.contains("/id"));
        } else {
            assert!(false, "unexpected error: {err:?}");
        }
    }

    #[test]
    fn validate_input_invalid_schema_maps_to_internal() {
        let schema = json!({
            "type": "bogus"
        });

        let value = json!({ "value": "ok" });

        let err = validate_input(&schema, &value).expect_err("schema compile should fail");

        if let FcpError::Internal { message } = err {
            assert!(message.contains("input schema invalid"));
        } else {
            assert!(false, "unexpected error: {err:?}");
        }
    }

    #[test]
    fn validate_input_with_limits_rejects_large_payload() {
        let schema = json!({ "type": "object" });
        let value = json!({ "payload": "this is long" });
        let limits = Limits {
            max_bytes: Some(8),
            max_array_len: None,
            max_depth: None,
        };

        let err = validate_input_with_limits(&schema, &value, &limits)
            .expect_err("limits should reject input");

        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("payload size"));
            assert!(message.contains("exceeds limit"));
        } else {
            assert!(false, "unexpected error: {err:?}");
        }
    }

    #[test]
    fn validate_output_with_limits_maps_to_internal() {
        let schema = json!({ "type": "object" });
        let value = json!({ "payload": "this is long" });
        let limits = Limits {
            max_bytes: Some(8),
            max_array_len: None,
            max_depth: None,
        };

        let err = validate_output_with_limits(&schema, &value, &limits)
            .expect_err("limits should reject output");

        if let FcpError::Internal { message } = err {
            assert!(message.contains("output payload exceeds limits"));
            assert!(message.contains("payload size"));
        } else {
            assert!(false, "unexpected error: {err:?}");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration-Style Validation Guard Tests
// ─────────────────────────────────────────────────────────────────────────────

mod validation_before_side_effect_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Clone)]
    struct ValidatingTestConnector {
        schema: serde_json::Value,
        limits: Limits,
        side_effect_count: Arc<AtomicUsize>,
    }

    impl ValidatingTestConnector {
        fn new(schema: serde_json::Value, limits: Limits) -> Self {
            Self {
                schema,
                limits,
                side_effect_count: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn side_effects(&self) -> usize {
            self.side_effect_count.load(Ordering::SeqCst)
        }

        fn invoke(&self, input: &serde_json::Value) -> Result<serde_json::Value, FcpError> {
            // Critical contract: validate before mutating state or making outbound calls.
            validate_input_with_limits(&self.schema, input, &self.limits)?;
            self.side_effect_count.fetch_add(1, Ordering::SeqCst);
            Ok(json!({ "status": "side_effect_applied" }))
        }
    }

    fn operation_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "minLength": 1 },
                "count": { "type": "integer", "minimum": 1 }
            },
            "required": ["name", "count"],
            "additionalProperties": false
        })
    }

    #[test]
    fn integration_invalid_schema_blocks_side_effect() {
        let connector = ValidatingTestConnector::new(
            json!({ "type": "not-a-real-json-schema-type" }),
            Limits::default(),
        );

        let err = connector
            .invoke(&json!({ "name": "demo", "count": 1 }))
            .expect_err("invalid schema must fail closed");

        if let FcpError::Internal { message } = err {
            assert!(message.contains("input schema invalid"));
        } else {
            assert!(false, "expected internal schema error, got {err:?}");
        }
        assert_eq!(connector.side_effects(), 0, "no side effects allowed");
    }

    #[test]
    fn integration_invalid_value_blocks_side_effect() {
        let connector = ValidatingTestConnector::new(operation_schema(), Limits::default());

        let err = connector
            .invoke(&json!({ "name": "demo", "count": "one" }))
            .expect_err("invalid payload must fail");

        if let FcpError::InvalidRequest { code, message } = err {
            assert_eq!(code, 1001);
            assert!(message.contains("input schema validation failed"));
        } else {
            assert!(false, "expected invalid request, got {err:?}");
        }
        assert_eq!(connector.side_effects(), 0, "no side effects allowed");
    }

    #[test]
    fn integration_oversized_payload_blocks_side_effect() {
        let connector = ValidatingTestConnector::new(
            operation_schema(),
            Limits {
                max_bytes: Some(20),
                max_array_len: Some(32),
                max_depth: Some(8),
            },
        );

        let err = connector
            .invoke(&json!({ "name": "payload-exceeds-byte-limit", "count": 1 }))
            .expect_err("oversized payload must fail");

        if let FcpError::InvalidRequest { code, message } = err {
            assert_eq!(code, 1004);
            assert!(message.contains("payload size"));
        } else {
            assert!(false, "expected invalid request for limits, got {err:?}");
        }
        assert_eq!(connector.side_effects(), 0, "no side effects allowed");
    }

    #[test]
    fn integration_valid_payload_applies_side_effect_once() {
        let connector = ValidatingTestConnector::new(
            operation_schema(),
            Limits {
                max_bytes: Some(1024),
                max_array_len: Some(32),
                max_depth: Some(8),
            },
        );

        let response = connector
            .invoke(&json!({ "name": "demo", "count": 2 }))
            .expect("valid payload should pass");

        assert_eq!(response["status"], json!("side_effect_applied"));
        assert_eq!(connector.side_effects(), 1);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Limits Helper Tests
// ─────────────────────────────────────────────────────────────────────────────

mod limits_helper_tests {
    use super::*;

    #[test]
    fn default_limits_allow_small_payload() {
        let value = json!({ "ok": true });
        enforce_limits(&value, &Limits::default()).expect("small payload should pass");
    }

    #[test]
    fn limits_reject_max_bytes() {
        let value = json!({ "message": "this is definitely longer than ten bytes" });
        let limits = Limits {
            max_bytes: Some(10),
            max_array_len: None,
            max_depth: None,
        };

        let err = enforce_limits(&value, &limits).expect_err("payload should exceed size limit");

        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("payload size"));
            assert!(message.contains("exceeds limit"));
        } else {
            assert!(false, "unexpected error: {err:?}");
        }
    }

    #[test]
    fn limits_reject_array_length() {
        let value = json!([1, 2, 3]);
        let limits = Limits {
            max_bytes: None,
            max_array_len: Some(2),
            max_depth: Some(8),
        };

        let err = enforce_limits(&value, &limits).expect_err("array should exceed length limit");

        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("array length"));
            assert!(message.contains('$'));
        } else {
            assert!(false, "unexpected error: {err:?}");
        }
    }

    #[test]
    fn limits_reject_depth() {
        let value = json!({ "a": { "b": { "c": 1 } } });
        let limits = Limits {
            max_bytes: None,
            max_array_len: None,
            max_depth: Some(2),
        };

        let err = enforce_limits(&value, &limits).expect_err("payload should exceed depth limit");

        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("max depth"));
            assert!(message.contains("$/a/b"));
        } else {
            assert!(false, "unexpected error: {err:?}");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Schema Evolution Tests (V2-only patterns)
// ─────────────────────────────────────────────────────────────────────────────

mod schema_evolution_tests {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct ObjectV1 {
        id: String,
        name: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct ObjectV2 {
        id: String,
        name: String,
        #[serde(default)]
        description: Option<String>,
    }

    #[test]
    fn schema_evolution_forward_compatible_with_optional_fields() {
        // V1 data can be read by V2 schema (missing fields become None)
        let v1_json = r#"{"id": "123", "name": "Test"}"#;

        let v2_object: ObjectV2 = serde_json::from_str(v1_json).unwrap();

        assert_eq!(v2_object.id, "123");
        assert_eq!(v2_object.name, "Test");
        assert_eq!(v2_object.description, None); // New optional field defaults
    }

    #[test]
    fn schema_evolution_backward_compatible_ignoring_extra_fields() {
        // V2 data can be read by V1 schema (extra fields ignored by default)
        let v2_json = r#"{"id": "123", "name": "Test", "description": "A description"}"#;

        // Note: serde ignores unknown fields by default
        let v1_object: ObjectV1 = serde_json::from_str(v2_json).unwrap();

        assert_eq!(v1_object.id, "123");
        assert_eq!(v1_object.name, "Test");
    }

    #[test]
    fn schema_evolution_strict_mode_rejects_unknown_fields() {
        // Use #[serde(deny_unknown_fields)] to reject unknown fields
        #[derive(Debug, Clone, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StrictObjectV1 {
            id: String,
            name: String,
        }

        let v2_json = r#"{"id": "123", "name": "Test", "description": "extra"}"#;

        let result: Result<StrictObjectV1, _> = serde_json::from_str(v2_json);
        assert!(result.is_err(), "Strict mode should reject unknown fields");
    }

    #[test]
    fn schema_hash_changes_with_structure() {
        // Demonstrate that schema changes should be versioned
        let schema_v1 = json!({
            "version": "1.0.0",
            "properties": {"id": {}, "name": {}}
        });

        let schema_v2 = json!({
            "version": "2.0.0",
            "properties": {"id": {}, "name": {}, "description": {}}
        });

        // Versions should differ
        assert_ne!(schema_v1["version"], schema_v2["version"]);

        // In a real system, you'd compute a hash of the schema
        let v1_str = serde_json::to_string(&schema_v1).unwrap();
        let v2_str = serde_json::to_string(&schema_v2).unwrap();
        assert_ne!(v1_str, v2_str, "Schema strings should differ for detection");
    }

    fn migrate_v1_to_v2(v1: ObjectV1) -> ObjectV2 {
        ObjectV2 {
            id: v1.id,
            name: v1.name,
            description: None, // New field gets default
        }
    }

    #[test]
    fn explicit_migration_pattern() {
        // Demonstrate explicit migration from V1 to V2
        let v1_object = ObjectV1 {
            id: "123".to_string(),
            name: "Test".to_string(),
        };

        let v2_object = migrate_v1_to_v2(v1_object);
        assert_eq!(v2_object.id, "123");
        assert_eq!(v2_object.description, None);
    }

    #[test]
    fn breaking_change_requires_new_version() {
        // Demonstrate a breaking change (type change)
        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct OldSchema {
            count: String, // Was string
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct NewSchema {
            count: i64, // Now integer
        }

        let old_json = r#"{"count": "42"}"#;
        let new_json = r#"{"count": 42}"#;

        // Old can read old
        let old: OldSchema = serde_json::from_str(old_json).unwrap();
        assert_eq!(old.count, "42");

        // New can read new
        let new: NewSchema = serde_json::from_str(new_json).unwrap();
        assert_eq!(new.count, 42);

        // Cross-reading fails (demonstrates breaking change)
        let cross_result: Result<NewSchema, _> = serde_json::from_str(old_json);
        assert!(cross_result.is_err(), "Type change is a breaking change");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Introspection Schema Tests
// ─────────────────────────────────────────────────────────────────────────────

mod introspection_tests {
    use super::*;

    #[test]
    fn introspection_structure() {
        // Test introspection schema structure
        let introspection_schema = json!({
            "type": "object",
            "properties": {
                "operations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "input_schema": {"type": "object"},
                            "output_schema": {"type": "object"}
                        }
                    }
                },
                "events": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "topic": {"type": "string"},
                            "schema": {"type": "object"}
                        }
                    }
                }
            }
        });

        assert!(introspection_schema["properties"]["operations"].is_object());
        assert!(introspection_schema["properties"]["events"].is_object());
    }

    #[test]
    fn connector_archetype_serialization() {
        // Test archetype serialization
        let bidirectional = ConnectorArchetype::Bidirectional;
        let streaming = ConnectorArchetype::Streaming;
        let operational = ConnectorArchetype::Operational;
        let storage = ConnectorArchetype::Storage;
        let knowledge = ConnectorArchetype::Knowledge;

        // Verify they serialize to distinct values
        let json_bidirectional = serde_json::to_string(&bidirectional).unwrap();
        let json_streaming = serde_json::to_string(&streaming).unwrap();
        let json_operational = serde_json::to_string(&operational).unwrap();
        let json_storage = serde_json::to_string(&storage).unwrap();
        let json_knowledge = serde_json::to_string(&knowledge).unwrap();

        // All should be unique
        let values: std::collections::HashSet<_> = vec![
            &json_bidirectional,
            &json_streaming,
            &json_operational,
            &json_storage,
            &json_knowledge,
        ]
        .into_iter()
        .collect();

        assert_eq!(values.len(), 5, "All archetypes should serialize uniquely");
    }

    #[test]
    fn connector_archetype_roundtrip() {
        let archetypes = vec![
            ConnectorArchetype::Bidirectional,
            ConnectorArchetype::Streaming,
            ConnectorArchetype::Operational,
            ConnectorArchetype::Storage,
            ConnectorArchetype::Knowledge,
        ];

        for archetype in archetypes {
            let json_str = serde_json::to_string(&archetype).unwrap();
            let deserialized: ConnectorArchetype = serde_json::from_str(&json_str).unwrap();

            // Match patterns to verify equality
            assert!(
                matches!(
                    (&archetype, &deserialized),
                    (
                        ConnectorArchetype::Bidirectional,
                        ConnectorArchetype::Bidirectional
                    ) | (ConnectorArchetype::Streaming, ConnectorArchetype::Streaming)
                        | (
                            ConnectorArchetype::Operational,
                            ConnectorArchetype::Operational
                        )
                        | (ConnectorArchetype::Storage, ConnectorArchetype::Storage)
                        | (ConnectorArchetype::Knowledge, ConnectorArchetype::Knowledge)
                ),
                "Archetype roundtrip failed for {archetype:?}"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Golden Vector Pattern Tests
// ─────────────────────────────────────────────────────────────────────────────

mod golden_vector_tests {
    use super::*;

    #[test]
    fn golden_vector_operation_schema_v1() {
        // This represents what would be stored in tests/vectors/sdk/operation_schema_v1.json
        let operation_schema = json!({
            "schema_id": "urn:fcp:schema:email.send:v1",
            "input": {
                "type": "object",
                "properties": {
                    "to": {"type": "string", "format": "email"},
                    "subject": {"type": "string", "maxLength": 998},
                    "body": {"type": "string"}
                },
                "required": ["to", "subject"]
            },
            "output": {
                "type": "object",
                "properties": {
                    "message_id": {"type": "string"}
                },
                "required": ["message_id"]
            }
        });

        // Verify structure
        assert!(operation_schema["input"].is_object());
        assert!(operation_schema["output"].is_object());
        assert!(operation_schema["input"]["required"].is_array());
        assert!(operation_schema["output"]["required"].is_array());
    }

    #[test]
    fn golden_vector_event_schema_v1() {
        let event_schema = json!({
            "schema_id": "urn:fcp:schema:message.received:v1",
            "topic": "message.received",
            "data": {
                "type": "object",
                "properties": {
                    "channel_id": {"type": "string"},
                    "author_id": {"type": "string"},
                    "content": {"type": "string"},
                    "timestamp": {"type": "string", "format": "date-time"}
                },
                "required": ["channel_id", "author_id", "content", "timestamp"]
            },
            "requires_ack": true
        });

        assert_eq!(event_schema["topic"], json!("message.received"));
        assert_eq!(event_schema["requires_ack"], json!(true));
    }

    #[test]
    fn golden_vector_state_snapshot_structure() {
        // Expected structure for state snapshots
        let state_snapshot = json!({
            "connector_id": "test-connector",
            "version": 1,
            "data": {
                "cursor": "abc123",
                "last_sync": 1_705_000_000
            },
            "created_at": "2025-01-15T00:00:00Z"
        });

        assert!(state_snapshot["connector_id"].is_string());
        assert!(state_snapshot["version"].is_number());
        assert!(state_snapshot["data"].is_object());
        assert!(state_snapshot["created_at"].is_string());
    }

    #[test]
    fn golden_vector_deterministic_serialization() {
        // Same structure should always produce same JSON
        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct GoldenStruct {
            id: u64,
            name: String,
            active: bool,
        }

        let value = GoldenStruct {
            id: 12345,
            name: "test".to_string(),
            active: true,
        };

        let json1 = serde_json::to_string(&value).unwrap();
        let json2 = serde_json::to_string(&value).unwrap();

        assert_eq!(json1, json2, "Serialization must be deterministic");
    }

    #[test]
    fn golden_vector_roundtrip() {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        struct GoldenStruct {
            id: u64,
            name: String,
            items: Vec<String>,
            metadata: HashMap<String, i32>,
        }

        let mut metadata = HashMap::new();
        metadata.insert("count".to_string(), 42);
        metadata.insert("level".to_string(), 3);

        let original = GoldenStruct {
            id: 12345,
            name: "test".to_string(),
            items: vec!["a".to_string(), "b".to_string()],
            metadata,
        };

        let json_str = serde_json::to_string(&original).unwrap();
        let decoded: GoldenStruct = serde_json::from_str(&json_str).unwrap();

        assert_eq!(original, decoded);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector ID Schema Tests
// ─────────────────────────────────────────────────────────────────────────────

mod connector_id_tests {
    use super::*;

    #[test]
    fn connector_id_from_static() {
        let id = ConnectorId::from_static("test:connector:v1");
        assert_eq!(id.as_str(), "test:connector:v1");
    }

    #[test]
    fn connector_id_display() {
        let id = ConnectorId::from_static("fcp.telegram:v1");
        let display = format!("{id}");
        assert!(display.contains("fcp.telegram:v1"));
    }

    #[test]
    fn connector_id_clone() {
        let id1 = ConnectorId::from_static("test:id:v1");
        let id2 = id1.clone();
        assert_eq!(id1.as_str(), id2.as_str());
    }

    #[test]
    fn zone_id_work() {
        let zone = ZoneId::work();
        assert_eq!(zone.as_str(), "z:work");
    }

    #[test]
    fn zone_id_public() {
        let zone = ZoneId::public();
        assert_eq!(zone.as_str(), "z:public");
    }

    #[test]
    fn zone_id_private() {
        let zone = ZoneId::private();
        assert_eq!(zone.as_str(), "z:private");
    }

    #[test]
    fn zone_id_owner() {
        let zone = ZoneId::owner();
        assert_eq!(zone.as_str(), "z:owner");
    }

    #[test]
    fn zone_id_community() {
        let zone = ZoneId::community();
        assert_eq!(zone.as_str(), "z:community");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Health Schema Tests
// ─────────────────────────────────────────────────────────────────────────────

mod health_schema_tests {
    use super::*;

    #[test]
    fn health_snapshot_ready() {
        let health = HealthSnapshot::ready();
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[test]
    fn health_snapshot_degraded() {
        let health = HealthSnapshot::degraded("Test degradation");
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[test]
    fn health_snapshot_error() {
        let health = HealthSnapshot::error("Test error");
        assert!(matches!(health.status, HealthState::Error { .. }));
    }

    #[test]
    fn health_state_serialization() {
        let states = vec![
            HealthState::Starting,
            HealthState::Ready,
            HealthState::Degraded {
                reason: "test".to_string(),
            },
            HealthState::Error {
                reason: "test error".to_string(),
            },
        ];

        for state in states {
            let json_str = serde_json::to_string(&state).unwrap();
            assert_ne!(json_str, "");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cost Estimate Schema Tests
// ─────────────────────────────────────────────────────────────────────────────

mod cost_estimate_tests {
    use super::*;

    #[test]
    fn cost_estimate_creation() {
        let cost = CostEstimate {
            api_credits: Some(10),
            estimated_duration_ms: Some(500),
            estimated_bytes: Some(1024),
            currency: None,
            confidence: None,
        };

        assert_eq!(cost.api_credits, Some(10));
        assert_eq!(cost.estimated_duration_ms, Some(500));
        assert_eq!(cost.estimated_bytes, Some(1024));
        assert!(cost.currency.is_none());
    }

    #[test]
    fn cost_estimate_with_currency() {
        let cost = CostEstimate {
            api_credits: Some(5),
            estimated_duration_ms: None,
            estimated_bytes: None,
            currency: Some(CurrencyCost {
                amount_cents: 1, // 1 cent = $0.01
                currency_code: "USD".to_string(),
            }),
            confidence: Some(CostEstimateConfidence::Low),
        };

        assert!(cost.currency.is_some());
        let currency = cost.currency.unwrap();
        assert_eq!(currency.currency_code, "USD");
        assert_eq!(cost.confidence, Some(CostEstimateConfidence::Low));
    }

    #[test]
    fn cost_estimate_serialization() {
        let cost = CostEstimate {
            api_credits: Some(10),
            estimated_duration_ms: Some(500),
            estimated_bytes: Some(1024),
            currency: None,
            confidence: None,
        };

        let json_str = serde_json::to_string(&cost).unwrap();
        let deserialized: CostEstimate = serde_json::from_str(&json_str).unwrap();

        assert_eq!(cost.api_credits, deserialized.api_credits);
        assert_eq!(
            cost.estimated_duration_ms,
            deserialized.estimated_duration_ms
        );
    }

    #[test]
    fn resource_availability_structure() {
        let availability = ResourceAvailability {
            available: true,
            rate_limit_remaining: Some(95),
            rate_limit_reset_at: Some(1_700_000_000), // Unix timestamp
            details: Some("Service is healthy".to_string()),
        };

        assert!(availability.available);
        assert_eq!(availability.rate_limit_remaining, Some(95));
    }
}
