//! Pre-invoke input validation with human-readable error messages.
//!
//! Validates operation inputs against JSON Schema BEFORE sending to the
//! connector, catching errors locally and producing actionable fix suggestions.

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::Value;

/// A single validation error with fix suggestion.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationError {
    /// JSON path to the error (e.g. "owner", "metadata.name").
    pub path: String,
    /// What went wrong.
    pub message: String,
    /// How to fix it.
    pub suggestion: String,
}

/// Result of validating input against schema.
#[derive(Debug)]
pub struct ValidationResult {
    pub errors: Vec<ValidationError>,
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validate an input value against a JSON Schema.
pub fn validate(input: &Value, schema: &Value) -> ValidationResult {
    validate_partial(input, schema, &BTreeSet::new())
}

/// Validate known template values while deferring exact unresolved paths.
///
/// Paths use unescaped object keys and decimal array indices. Only a value at
/// an exact deferred path is unknown; its ancestors retain their type, required
/// fields and container-size checks, and siblings retain ordinary validation.
/// Ancestor value comparisons such as enum cannot be decided until every
/// descendant is known. This is a local preview, not a host preflight decision.
pub fn validate_partial(
    input: &Value,
    schema: &Value,
    deferred_paths: &BTreeSet<Vec<String>>,
) -> ValidationResult {
    let mut errors = Vec::new();
    validate_value(input, schema, &[], &[], deferred_paths, &mut errors);
    ValidationResult { errors }
}

fn validate_value(
    input: &Value,
    schema: &Value,
    path: &[String],
    pointer_path: &[String],
    deferred_paths: &BTreeSet<Vec<String>>,
    errors: &mut Vec<ValidationError>,
) {
    if deferred_paths.contains(pointer_path) {
        return;
    }
    let path_str = if path.is_empty() {
        "<root>".to_string()
    } else {
        path.join(".")
    };

    // Check type constraint.
    if let Some(expected_type) = schema.get("type").and_then(Value::as_str) {
        if !type_matches(input, expected_type) {
            let actual = json_type_name(input);
            errors.push(ValidationError {
                path: path_str.clone(),
                message: format!("expected {expected_type}, got {actual}"),
                suggestion: type_fix_suggestion(expected_type, input),
            });
            return; // Don't recurse into wrong type.
        }
    }

    // A partial object/array cannot be compared to a complete enum value yet.
    // Its known type, shape and literal descendants still require validation.
    let contains_deferred = deferred_paths
        .iter()
        .any(|deferred| deferred.starts_with(pointer_path));
    if !contains_deferred && let Some(enum_values) = schema.get("enum").and_then(Value::as_array) {
        if !enum_values.contains(input) {
            let allowed = enum_values
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            errors.push(ValidationError {
                path: path_str.clone(),
                message: "value not in allowed set".to_string(),
                suggestion: format!("use one of: {allowed}"),
            });
        }
    }

    // For objects: check required fields and recurse into properties.
    if input.is_object() {
        validate_object(input, schema, path, pointer_path, deferred_paths, errors);
    }

    // For arrays: validate items against items schema.
    if input.is_array() {
        validate_array(input, schema, path, pointer_path, deferred_paths, errors);
    }

    // Check string constraints.
    if let Some(s) = input.as_str() {
        validate_string(s, schema, &path_str, errors);
    }

    // Check numeric constraints.
    if let Some(n) = input.as_f64() {
        validate_number(n, schema, &path_str, errors);
    }
}

fn validate_object(
    input: &Value,
    schema: &Value,
    path: &[String],
    pointer_path: &[String],
    deferred_paths: &BTreeSet<Vec<String>>,
    errors: &mut Vec<ValidationError>,
) {
    let Some(input_obj) = input.as_object() else {
        return;
    };

    // Check required fields.
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for req in required.iter().filter_map(Value::as_str) {
            if !input_obj.contains_key(req) {
                let mut field_path = path.to_vec();
                field_path.push(req.to_string());
                let type_hint = schema
                    .get("properties")
                    .and_then(|p| p.get(req))
                    .and_then(|p| p.get("type"))
                    .and_then(Value::as_str)
                    .unwrap_or("value");
                errors.push(ValidationError {
                    path: field_path.join("."),
                    message: "required field missing".to_string(),
                    suggestion: format!("add '{req}' with a {type_hint} value"),
                });
            }
        }
    }

    // Recurse into properties.
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (key, prop_schema) in properties {
            if let Some(value) = input_obj.get(key) {
                let mut child_path = path.to_vec();
                child_path.push(key.clone());
                let mut child_pointer = pointer_path.to_vec();
                child_pointer.push(key.clone());
                validate_value(
                    value,
                    prop_schema,
                    &child_path,
                    &child_pointer,
                    deferred_paths,
                    errors,
                );
            }
        }
    }
}

fn validate_array(
    input: &Value,
    schema: &Value,
    path: &[String],
    pointer_path: &[String],
    deferred_paths: &BTreeSet<Vec<String>>,
    errors: &mut Vec<ValidationError>,
) {
    let Some(arr) = input.as_array() else {
        return;
    };

    // Check minItems / maxItems.
    if let Some(min) = schema.get("minItems").and_then(Value::as_u64) {
        if (arr.len() as u64) < min {
            let path_str = if path.is_empty() {
                "<root>".to_string()
            } else {
                path.join(".")
            };
            errors.push(ValidationError {
                path: path_str,
                message: format!("array too short: {} items, minimum {min}", arr.len()),
                suggestion: format!(
                    "add at least {} more item(s)",
                    usize::try_from(min).unwrap_or(usize::MAX) - arr.len()
                ),
            });
        }
    }
    if let Some(max) = schema.get("maxItems").and_then(Value::as_u64) {
        if (arr.len() as u64) > max {
            let path_str = if path.is_empty() {
                "<root>".to_string()
            } else {
                path.join(".")
            };
            errors.push(ValidationError {
                path: path_str,
                message: format!("array too long: {} items, maximum {max}", arr.len()),
                suggestion: format!(
                    "remove {} item(s)",
                    arr.len() - usize::try_from(max).unwrap_or(0)
                ),
            });
        }
    }

    // Validate each item against items schema.
    if let Some(item_schema) = schema.get("items") {
        for (i, item) in arr.iter().enumerate() {
            let mut item_path = path.to_vec();
            item_path.push(format!("[{i}]"));
            let mut item_pointer = pointer_path.to_vec();
            item_pointer.push(i.to_string());
            validate_value(
                item,
                item_schema,
                &item_path,
                &item_pointer,
                deferred_paths,
                errors,
            );
        }
    }
}

fn validate_string(s: &str, schema: &Value, path: &str, errors: &mut Vec<ValidationError>) {
    if let Some(min_len) = schema.get("minLength").and_then(Value::as_u64) {
        if (s.len() as u64) < min_len {
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("string too short: {} chars, minimum {min_len}", s.len()),
                suggestion: format!("provide at least {min_len} characters"),
            });
        }
    }
    if let Some(max_len) = schema.get("maxLength").and_then(Value::as_u64) {
        if (s.len() as u64) > max_len {
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("string too long: {} chars, maximum {max_len}", s.len()),
                suggestion: format!("shorten to at most {max_len} characters"),
            });
        }
    }
}

fn validate_number(n: f64, schema: &Value, path: &str, errors: &mut Vec<ValidationError>) {
    if let Some(min) = schema.get("minimum").and_then(Value::as_f64) {
        if n < min {
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("value {n} is below minimum {min}"),
                suggestion: format!("use a value >= {min}"),
            });
        }
    }
    if let Some(max) = schema.get("maximum").and_then(Value::as_f64) {
        if n > max {
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("value {n} exceeds maximum {max}"),
                suggestion: format!("use a value <= {max}"),
            });
        }
    }
}

fn type_matches(value: &Value, expected: &str) -> bool {
    match expected {
        "string" => value.is_string(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "null" => value.is_null(),
        _ => true,
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn type_fix_suggestion(expected: &str, actual: &Value) -> String {
    match (expected, actual) {
        ("array", Value::String(s)) => format!("wrap in array: [\"{s}\"]"),
        ("array", _) => "wrap the value in an array: [value]".to_string(),
        ("string", Value::Number(n)) => format!("use string: \"{n}\""),
        ("integer" | "number", Value::String(s)) => format!("use number: {s}"),
        ("boolean", Value::String(s)) if s == "true" || s == "false" => {
            format!("use boolean: {s} (without quotes)")
        }
        _ => format!("provide a {expected} value"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn partial_validation_defers_only_the_unknown_value() {
        let input = json!({"id": null, "literal_null": null, "title": 7});
        let schema = json!({
            "type": "object",
            "required": ["id", "title", "missing"],
            "properties": {
                "id": {"type": "integer", "minimum": 1},
                "literal_null": {"type": "string"},
                "title": {"type": "string"},
                "missing": {"type": "boolean"},
            },
        });
        let deferred = BTreeSet::from([vec!["id".to_owned()]]);
        let result = validate_partial(&input, &schema, &deferred);
        let paths = result
            .errors
            .iter()
            .map(|error| error.path.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(paths, BTreeSet::from(["literal_null", "missing", "title"]));
        assert!(
            validate(&input, &schema)
                .errors
                .iter()
                .any(|error| error.path == "id")
        );
    }

    #[test]
    fn partial_validation_keeps_ancestor_shape_and_literal_enum_checks() {
        let input = json!({"id": null, "mode": "invalid", "items": [null]});
        let schema = json!({
            "type": "object",
            "enum": [{"id": "eventual", "mode": "valid", "items": [1, 2]}],
            "properties": {
                "id": {"type": "string", "minLength": 5},
                "mode": {"type": "string", "enum": ["valid"]},
                "items": {"type": "array", "minItems": 2, "items": {"type": "integer"}},
            },
        });
        let deferred = BTreeSet::from([
            vec!["id".to_owned()],
            vec!["items".to_owned(), "0".to_owned()],
        ]);
        let result = validate_partial(&input, &schema, &deferred);
        assert_eq!(result.errors.len(), 2);
        assert!(result.errors.iter().any(|error| error.path == "mode"));
        assert!(result.errors.iter().any(|error| error.path == "items"));
        assert!(!result.errors.iter().any(|error| error.path == "<root>"));

        let wrong_container = json!({"type": "array"});
        let result = validate_partial(&input, &wrong_container, &deferred);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].path, "<root>");
        assert!(result.errors[0].message.contains("expected array"));
    }

    #[test]
    fn partial_validation_uses_exact_segments_for_arrays_and_unusual_keys() {
        let input = json!({"a.b": null, "a": {"b": null}, "items": [null, null]});
        let schema = json!({
            "type": "object",
            "properties": {
                "a.b": {"type": "integer"},
                "a": {"type": "object", "properties": {"b": {"type": "integer"}}},
                "items": {"type": "array", "maxItems": 1, "items": {"type": "integer"}},
            },
        });
        let deferred = BTreeSet::from([
            vec!["a.b".to_owned()],
            vec!["items".to_owned(), "0".to_owned()],
        ]);
        let result = validate_partial(&input, &schema, &deferred);
        assert_eq!(result.errors.len(), 3);
        assert!(result.errors.iter().any(|error| error.path == "a.b"));
        assert!(result.errors.iter().any(|error| error.path == "items"));
        assert!(result.errors.iter().any(|error| error.path == "items.[1]"));
        assert!(!result.errors.iter().any(|error| error.path == "items.[0]"));
    }

    #[test]
    fn partial_validation_accepts_unknown_root_without_treating_literal_null_as_unknown() {
        let schema = json!({"type": "object", "required": ["id"]});
        assert!(validate_partial(&Value::Null, &schema, &BTreeSet::from([Vec::new()])).is_valid());
        assert!(!validate_partial(&Value::Null, &schema, &BTreeSet::new()).is_valid());

        let input = json!({"id": 7, "name": "valid"});
        let schema = json!({
            "type": "object",
            "required": ["missing"],
            "properties": {"id": {"type": "string"}, "name": {"enum": ["other"]}},
        });
        assert_eq!(
            serde_json::to_value(validate(&input, &schema).errors).unwrap(),
            serde_json::to_value(validate_partial(&input, &schema, &BTreeSet::new()).errors)
                .unwrap()
        );
    }

    fn issue_schema() -> Value {
        json!({
            "type": "object",
            "required": ["owner", "repo", "title"],
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "title": { "type": "string" },
                "body": { "type": "string" },
                "labels": {
                    "type": "array",
                    "items": { "type": "string" }
                },
                "milestone": { "type": "integer" }
            }
        })
    }

    // ── Valid input tests ─────────────────────────────────────────────

    #[test]
    fn valid_input_passes() {
        let input = json!({
            "owner": "octocat",
            "repo": "hello-world",
            "title": "Bug report"
        });
        let result = validate(&input, &issue_schema());
        assert!(result.is_valid(), "errors: {:?}", result.errors);
    }

    #[test]
    fn valid_input_with_optional_fields() {
        let input = json!({
            "owner": "octocat",
            "repo": "hello-world",
            "title": "Bug report",
            "body": "Description",
            "labels": ["bug"],
            "milestone": 3
        });
        let result = validate(&input, &issue_schema());
        assert!(result.is_valid());
    }

    // ── Missing required fields ──────────────────────────────────────

    #[test]
    fn missing_required_field() {
        let input = json!({
            "owner": "octocat",
            "repo": "hello-world"
        });
        let result = validate(&input, &issue_schema());
        assert!(!result.is_valid());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].path, "title");
        assert!(result.errors[0].message.contains("required"));
        assert!(result.errors[0].suggestion.contains("title"));
    }

    #[test]
    fn multiple_missing_required() {
        let input = json!({});
        let result = validate(&input, &issue_schema());
        assert_eq!(result.errors.len(), 3);
    }

    // ── Type mismatch tests ─────────────────────────────────────────

    #[test]
    fn wrong_type_string_for_integer() {
        let input = json!({
            "owner": "octocat",
            "repo": "hello-world",
            "title": "Bug",
            "milestone": "3"
        });
        let result = validate(&input, &issue_schema());
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "milestone");
        assert!(result.errors[0].message.contains("integer"));
        assert!(result.errors[0].suggestion.contains('3'));
    }

    #[test]
    fn wrong_type_string_for_array() {
        let input = json!({
            "owner": "octocat",
            "repo": "hello-world",
            "title": "Bug",
            "labels": "bug"
        });
        let result = validate(&input, &issue_schema());
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("array"));
        assert!(result.errors[0].suggestion.contains("[\"bug\"]"));
    }

    // ── Enum validation ─────────────────────────────────────────────

    #[test]
    fn enum_invalid_value() {
        let schema = json!({
            "type": "object",
            "properties": {
                "state": { "type": "string", "enum": ["open", "closed", "all"] }
            }
        });
        let input = json!({"state": "invalid"});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].suggestion.contains("open"));
        assert!(result.errors[0].suggestion.contains("closed"));
    }

    #[test]
    fn enum_valid_value() {
        let schema = json!({
            "type": "object",
            "properties": {
                "state": { "type": "string", "enum": ["open", "closed"] }
            }
        });
        let input = json!({"state": "open"});
        assert!(validate(&input, &schema).is_valid());
    }

    // ── Nested object validation ────────────────────────────────────

    #[test]
    fn nested_required_field_missing() {
        let schema = json!({
            "type": "object",
            "required": ["metadata"],
            "properties": {
                "metadata": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "name": { "type": "string" }
                    }
                }
            }
        });
        let input = json!({"metadata": {}});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "metadata.name");
    }

    #[test]
    fn nested_type_mismatch() {
        let schema = json!({
            "type": "object",
            "properties": {
                "config": {
                    "type": "object",
                    "properties": {
                        "port": { "type": "integer" }
                    }
                }
            }
        });
        let input = json!({"config": {"port": "8080"}});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "config.port");
    }

    // ── Array validation ────────────────────────────────────────────

    #[test]
    fn array_item_type_mismatch() {
        let schema = json!({
            "type": "object",
            "properties": {
                "tags": {
                    "type": "array",
                    "items": { "type": "string" }
                }
            }
        });
        let input = json!({"tags": ["valid", 42]});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].path.contains("[1]"));
    }

    #[test]
    fn array_min_items() {
        let schema = json!({
            "type": "object",
            "properties": {
                "items": { "type": "array", "minItems": 2, "items": {"type": "string"} }
            }
        });
        let input = json!({"items": ["one"]});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("too short"));
    }

    // ── String constraints ──────────────────────────────────────────

    #[test]
    fn string_min_length() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "minLength": 3 }
            }
        });
        let input = json!({"name": "ab"});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("too short"));
    }

    // ── Number constraints ──────────────────────────────────────────

    #[test]
    fn number_minimum() {
        let schema = json!({
            "type": "object",
            "properties": {
                "page": { "type": "integer", "minimum": 1 }
            }
        });
        let input = json!({"page": 0});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("below minimum"));
    }

    #[test]
    fn number_maximum() {
        let schema = json!({
            "type": "object",
            "properties": {
                "limit": { "type": "integer", "maximum": 100 }
            }
        });
        let input = json!({"limit": 200});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("exceeds maximum"));
    }

    // ── Empty/edge cases ────────────────────────────────────────────

    #[test]
    fn empty_schema_accepts_anything() {
        let schema = json!({});
        let input = json!({"anything": "goes"});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn empty_input_with_no_required() {
        let schema = json!({
            "type": "object",
            "properties": {
                "optional": { "type": "string" }
            }
        });
        assert!(validate(&json!({}), &schema).is_valid());
    }

    // ── Error has actionable suggestion ──────────────────────────────

    #[test]
    fn suggestion_is_not_empty() {
        let input = json!({});
        let result = validate(&input, &issue_schema());
        for error in &result.errors {
            assert!(
                !error.suggestion.is_empty(),
                "suggestion should not be empty for: {}",
                error.path
            );
        }
    }

    #[test]
    fn boolean_string_fix_suggestion() {
        let schema = json!({
            "type": "object",
            "properties": {
                "verbose": { "type": "boolean" }
            }
        });
        let input = json!({"verbose": "true"});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].suggestion.contains("true"));
        assert!(result.errors[0].suggestion.contains("without quotes"));
    }

    // ── Additional type mismatch tests ───────────────────────────────

    #[test]
    fn wrong_type_number_for_string() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" }
            }
        });
        let input = json!({"name": 42});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "name");
        assert!(result.errors[0].message.contains("string"));
        assert!(result.errors[0].suggestion.contains("42"));
    }

    #[test]
    fn wrong_type_integer_for_boolean() {
        let schema = json!({
            "type": "object",
            "properties": {
                "flag": { "type": "boolean" }
            }
        });
        let input = json!({"flag": 1});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("boolean"));
        assert!(result.errors[0].suggestion.contains("boolean"));
    }

    #[test]
    fn wrong_type_object_for_array() {
        let schema = json!({
            "type": "object",
            "properties": {
                "items": { "type": "array" }
            }
        });
        let input = json!({"items": {"key": "val"}});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("array"));
        assert!(result.errors[0].suggestion.contains("[value]"));
    }

    #[test]
    fn wrong_type_array_for_object() {
        let schema = json!({
            "type": "object",
            "properties": {
                "config": { "type": "object" }
            }
        });
        let input = json!({"config": [1, 2, 3]});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("object"));
    }

    #[test]
    fn wrong_type_boolean_for_string() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" }
            }
        });
        let input = json!({"name": true});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("string"));
    }

    #[test]
    fn wrong_type_null_for_integer() {
        let schema = json!({
            "type": "object",
            "properties": {
                "count": { "type": "integer" }
            }
        });
        let input = json!({"count": null});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("integer"));
        assert!(result.errors[0].message.contains("null"));
    }

    #[test]
    fn boolean_string_false_suggestion() {
        let schema = json!({
            "type": "object",
            "properties": {
                "verbose": { "type": "boolean" }
            }
        });
        let input = json!({"verbose": "false"});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].suggestion.contains("false"));
        assert!(result.errors[0].suggestion.contains("without quotes"));
    }

    #[test]
    fn number_string_suggestion_for_number_type() {
        let schema = json!({
            "type": "object",
            "properties": {
                "amount": { "type": "number" }
            }
        });
        let input = json!({"amount": "3.14"});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].suggestion.contains("3.14"));
    }

    // ── Additional string constraint tests ──────────────────────────

    #[test]
    fn string_max_length() {
        let schema = json!({
            "type": "object",
            "properties": {
                "code": { "type": "string", "maxLength": 5 }
            }
        });
        let input = json!({"code": "toolong"});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("too long"));
        assert!(result.errors[0].suggestion.contains('5'));
    }

    #[test]
    fn string_exact_min_length_valid() {
        let schema = json!({
            "type": "object",
            "properties": {
                "code": { "type": "string", "minLength": 3 }
            }
        });
        let input = json!({"code": "abc"});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn string_both_min_and_max_length_valid() {
        let schema = json!({
            "type": "object",
            "properties": {
                "token": { "type": "string", "minLength": 3, "maxLength": 10 }
            }
        });
        let input = json!({"token": "hello"});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn string_empty_below_min_length() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "minLength": 1 }
            }
        });
        let input = json!({"name": ""});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("too short"));
    }

    // ── Additional number constraint tests ──────────────────────────

    #[test]
    fn number_exact_minimum_valid() {
        let schema = json!({
            "type": "object",
            "properties": {
                "page": { "type": "integer", "minimum": 1 }
            }
        });
        let input = json!({"page": 1});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn number_exact_maximum_valid() {
        let schema = json!({
            "type": "object",
            "properties": {
                "limit": { "type": "integer", "maximum": 100 }
            }
        });
        let input = json!({"limit": 100});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn number_both_minimum_and_maximum() {
        let schema = json!({
            "type": "object",
            "properties": {
                "count": { "type": "integer", "minimum": 1, "maximum": 50 }
            }
        });
        let input = json!({"count": 25});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn number_below_minimum_suggestion() {
        let schema = json!({
            "type": "object",
            "properties": {
                "page": { "type": "integer", "minimum": 1 }
            }
        });
        let input = json!({"page": -5});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].suggestion.contains(">= 1"));
    }

    #[test]
    fn number_above_maximum_suggestion() {
        let schema = json!({
            "type": "object",
            "properties": {
                "limit": { "type": "integer", "maximum": 100 }
            }
        });
        let input = json!({"limit": 500});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].suggestion.contains("<= 100"));
    }

    #[test]
    fn float_number_minimum() {
        let schema = json!({
            "type": "object",
            "properties": {
                "threshold": { "type": "number", "minimum": 0.0 }
            }
        });
        let input = json!({"threshold": -0.5});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("below minimum"));
    }

    #[test]
    fn float_number_maximum() {
        let schema = json!({
            "type": "object",
            "properties": {
                "score": { "type": "number", "maximum": 1.0 }
            }
        });
        let input = json!({"score": 1.5});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("exceeds maximum"));
    }

    // ── Array constraint tests ──────────────────────────────────────

    #[test]
    fn array_max_items() {
        let schema = json!({
            "type": "object",
            "properties": {
                "tags": { "type": "array", "maxItems": 3, "items": {"type": "string"} }
            }
        });
        let input = json!({"tags": ["a", "b", "c", "d"]});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("too long"));
        assert!(result.errors[0].suggestion.contains("remove"));
    }

    #[test]
    fn array_exact_min_items_valid() {
        let schema = json!({
            "type": "object",
            "properties": {
                "items": { "type": "array", "minItems": 2, "items": {"type": "string"} }
            }
        });
        let input = json!({"items": ["one", "two"]});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn array_exact_max_items_valid() {
        let schema = json!({
            "type": "object",
            "properties": {
                "items": { "type": "array", "maxItems": 2, "items": {"type": "string"} }
            }
        });
        let input = json!({"items": ["one", "two"]});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn array_empty_below_min() {
        let schema = json!({
            "type": "object",
            "properties": {
                "items": { "type": "array", "minItems": 1, "items": {"type": "string"} }
            }
        });
        let input = json!({"items": []});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("too short"));
    }

    #[test]
    fn array_multiple_item_type_mismatches() {
        let schema = json!({
            "type": "object",
            "properties": {
                "ids": { "type": "array", "items": { "type": "integer" } }
            }
        });
        let input = json!({"ids": ["a", "b", 3]});
        let result = validate(&input, &schema);
        assert_eq!(result.errors.len(), 2);
        assert!(result.errors[0].path.contains("[0]"));
        assert!(result.errors[1].path.contains("[1]"));
    }

    // ── Deeply nested validation tests ──────────────────────────────

    #[test]
    fn three_level_nested_required() {
        let schema = json!({
            "type": "object",
            "required": ["a"],
            "properties": {
                "a": {
                    "type": "object",
                    "required": ["b"],
                    "properties": {
                        "b": {
                            "type": "object",
                            "required": ["c"],
                            "properties": {
                                "c": { "type": "string" }
                            }
                        }
                    }
                }
            }
        });
        let input = json!({"a": {"b": {}}});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "a.b.c");
    }

    #[test]
    fn nested_type_mismatch_in_array_of_objects() {
        let schema = json!({
            "type": "object",
            "properties": {
                "users": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "age": { "type": "integer" }
                        }
                    }
                }
            }
        });
        let input = json!({"users": [{"age": "thirty"}]});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].path.contains("users"));
        assert!(result.errors[0].path.contains("[0]"));
        assert!(result.errors[0].path.contains("age"));
    }

    // ── Enum edge cases ─────────────────────────────────────────────

    #[test]
    fn enum_with_integer_values() {
        let schema = json!({
            "type": "object",
            "properties": {
                "priority": { "type": "integer", "enum": [1, 2, 3] }
            }
        });
        let input = json!({"priority": 4});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("not in allowed set"));
    }

    #[test]
    fn enum_with_valid_integer() {
        let schema = json!({
            "type": "object",
            "properties": {
                "priority": { "type": "integer", "enum": [1, 2, 3] }
            }
        });
        let input = json!({"priority": 2});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn enum_empty_string_invalid() {
        let schema = json!({
            "type": "object",
            "properties": {
                "state": { "type": "string", "enum": ["open", "closed"] }
            }
        });
        let input = json!({"state": ""});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
    }

    // ── Validation result API tests ─────────────────────────────────

    #[test]
    fn validation_result_is_valid_when_no_errors() {
        let result = ValidationResult { errors: Vec::new() };
        assert!(result.is_valid());
    }

    #[test]
    fn validation_result_not_valid_with_errors() {
        let result = ValidationResult {
            errors: vec![ValidationError {
                path: "field".to_string(),
                message: "bad".to_string(),
                suggestion: "fix it".to_string(),
            }],
        };
        assert!(!result.is_valid());
    }

    #[test]
    fn validation_error_debug_format() {
        let err = ValidationError {
            path: "name".to_string(),
            message: "required".to_string(),
            suggestion: "add it".to_string(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("name"));
        assert!(debug.contains("required"));
    }

    #[test]
    fn validation_error_clone() {
        let err = ValidationError {
            path: "f".to_string(),
            message: "m".to_string(),
            suggestion: "s".to_string(),
        };
        let cloned = err.clone();
        assert_eq!(err.path, cloned.path);
        assert_eq!(err.message, cloned.message);
        assert_eq!(err.suggestion, cloned.suggestion);
    }

    #[test]
    fn validation_error_serializes() {
        let err = ValidationError {
            path: "x".to_string(),
            message: "bad".to_string(),
            suggestion: "fix".to_string(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["path"], "x");
        assert_eq!(json["message"], "bad");
        assert_eq!(json["suggestion"], "fix");
    }

    // ── Type matching helper tests ──────────────────────────────────

    #[test]
    fn type_matches_null() {
        assert!(type_matches(&Value::Null, "null"));
        assert!(!type_matches(&Value::Null, "string"));
    }

    #[test]
    fn type_matches_unknown_type_accepted() {
        assert!(type_matches(&json!(42), "unknown_type"));
    }

    #[test]
    fn type_matches_number_includes_integers() {
        assert!(type_matches(&json!(42), "number"));
        assert!(type_matches(&json!(1.5), "number"));
    }

    #[test]
    fn type_matches_integer_rejects_float() {
        assert!(!type_matches(&json!(1.5), "integer"));
    }

    // ── json_type_name helper tests ─────────────────────────────────

    #[test]
    fn json_type_name_all_types() {
        assert_eq!(json_type_name(&Value::Null), "null");
        assert_eq!(json_type_name(&json!(true)), "boolean");
        assert_eq!(json_type_name(&json!(42)), "integer");
        assert_eq!(json_type_name(&json!(1.5)), "number");
        assert_eq!(json_type_name(&json!("hello")), "string");
        assert_eq!(json_type_name(&json!([1, 2])), "array");
        assert_eq!(json_type_name(&json!({"a": 1})), "object");
    }

    // ── Root-level type mismatch ────────────────────────────────────

    #[test]
    fn root_type_mismatch_string_for_object() {
        let schema = json!({"type": "object"});
        let input = json!("hello");
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "<root>");
        assert!(result.errors[0].message.contains("object"));
    }

    #[test]
    fn root_type_mismatch_array_for_object() {
        let schema = json!({"type": "object"});
        let input = json!([1, 2, 3]);
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "<root>");
    }

    #[test]
    fn root_valid_array() {
        let schema = json!({
            "type": "array",
            "items": { "type": "string" }
        });
        let input = json!(["a", "b", "c"]);
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn root_array_with_invalid_items() {
        let schema = json!({
            "type": "array",
            "items": { "type": "string" }
        });
        let input = json!(["a", 42, "c"]);
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].path.contains("[1]"));
    }

    // ── Extra properties (no additionalProperties enforcement) ─────

    #[test]
    fn extra_properties_accepted() {
        let input = json!({
            "owner": "octocat",
            "repo": "hello-world",
            "title": "Bug",
            "extra_field": "ignored"
        });
        let result = validate(&input, &issue_schema());
        assert!(result.is_valid());
    }

    #[test]
    fn null_input_with_object_schema() {
        let schema = json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string" }
            }
        });
        let input = json!(null);
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "<root>");
    }

    // ── Additional type_fix_suggestion coverage ─────────────────────

    #[test]
    fn fix_suggestion_number_for_array() {
        let suggestion = type_fix_suggestion("array", &json!(42));
        assert!(suggestion.contains("[value]"));
    }

    #[test]
    fn fix_suggestion_bool_for_array() {
        let suggestion = type_fix_suggestion("array", &json!(true));
        assert!(suggestion.contains("[value]"));
    }

    #[test]
    fn fix_suggestion_null_for_array() {
        let suggestion = type_fix_suggestion("array", &Value::Null);
        assert!(suggestion.contains("[value]"));
    }

    #[test]
    fn fix_suggestion_object_for_array() {
        let suggestion = type_fix_suggestion("array", &json!({"a": 1}));
        assert!(suggestion.contains("[value]"));
    }

    #[test]
    fn fix_suggestion_string_for_integer() {
        let suggestion = type_fix_suggestion("integer", &json!("99"));
        assert!(suggestion.contains("99"));
        assert!(suggestion.contains("number"));
    }

    #[test]
    fn fix_suggestion_default_fallback() {
        let suggestion = type_fix_suggestion("object", &json!("hello"));
        assert!(suggestion.contains("object"));
        assert!(suggestion.contains("provide"));
    }

    #[test]
    fn fix_suggestion_null_for_string() {
        let suggestion = type_fix_suggestion("string", &Value::Null);
        assert!(suggestion.contains("string"));
    }

    #[test]
    fn fix_suggestion_boolean_for_object() {
        let suggestion = type_fix_suggestion("object", &json!(true));
        assert!(suggestion.contains("object"));
    }

    // ── type_matches exhaustive coverage ────────────────────────────

    #[test]
    fn type_matches_string_positive() {
        assert!(type_matches(&json!("hello"), "string"));
    }

    #[test]
    fn type_matches_string_negative() {
        assert!(!type_matches(&json!(42), "string"));
        assert!(!type_matches(&json!(true), "string"));
        assert!(!type_matches(&json!([1]), "string"));
        assert!(!type_matches(&json!({"a":1}), "string"));
        assert!(!type_matches(&Value::Null, "string"));
    }

    #[test]
    fn type_matches_boolean_positive() {
        assert!(type_matches(&json!(true), "boolean"));
        assert!(type_matches(&json!(false), "boolean"));
    }

    #[test]
    fn type_matches_boolean_negative() {
        assert!(!type_matches(&json!(0), "boolean"));
        assert!(!type_matches(&json!("true"), "boolean"));
        assert!(!type_matches(&Value::Null, "boolean"));
    }

    #[test]
    fn type_matches_object_positive() {
        assert!(type_matches(&json!({}), "object"));
        assert!(type_matches(&json!({"key": "val"}), "object"));
    }

    #[test]
    fn type_matches_object_negative() {
        assert!(!type_matches(&json!([]), "object"));
        assert!(!type_matches(&json!("str"), "object"));
        assert!(!type_matches(&json!(42), "object"));
    }

    #[test]
    fn type_matches_array_positive() {
        assert!(type_matches(&json!([]), "array"));
        assert!(type_matches(&json!([1, 2]), "array"));
    }

    #[test]
    fn type_matches_array_negative() {
        assert!(!type_matches(&json!({}), "array"));
        assert!(!type_matches(&json!("arr"), "array"));
    }

    #[test]
    fn type_matches_null_negative() {
        assert!(!type_matches(&json!(0), "null"));
        assert!(!type_matches(&json!(false), "null"));
        assert!(!type_matches(&json!(""), "null"));
    }

    #[test]
    fn type_matches_integer_u64() {
        // large unsigned integers are u64
        assert!(type_matches(&json!(u64::MAX), "integer"));
    }

    // ── json_type_name edge cases ──────────────────────────────────

    #[test]
    fn json_type_name_u64_is_integer() {
        assert_eq!(json_type_name(&json!(u64::MAX)), "integer");
    }

    #[test]
    fn json_type_name_negative_integer() {
        assert_eq!(json_type_name(&json!(-42)), "integer");
    }

    #[test]
    fn json_type_name_zero() {
        assert_eq!(json_type_name(&json!(0)), "integer");
    }

    #[test]
    fn json_type_name_empty_string() {
        assert_eq!(json_type_name(&json!("")), "string");
    }

    #[test]
    fn json_type_name_empty_array() {
        assert_eq!(json_type_name(&json!([])), "array");
    }

    #[test]
    fn json_type_name_empty_object() {
        assert_eq!(json_type_name(&json!({})), "object");
    }

    #[test]
    fn json_type_name_false() {
        assert_eq!(json_type_name(&json!(false)), "boolean");
    }

    // ── Root-level primitive validation ─────────────────────────────

    #[test]
    fn root_string_valid() {
        let schema = json!({"type": "string", "minLength": 2});
        let input = json!("hello");
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn root_string_too_short() {
        let schema = json!({"type": "string", "minLength": 5});
        let input = json!("hi");
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "<root>");
        assert!(result.errors[0].message.contains("too short"));
    }

    #[test]
    fn root_number_below_minimum() {
        let schema = json!({"type": "number", "minimum": 10.0});
        let input = json!(5.0);
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "<root>");
    }

    #[test]
    fn root_number_valid() {
        let schema = json!({"type": "number", "minimum": 0.0, "maximum": 100.0});
        let input = json!(50.0);
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn root_boolean_valid() {
        let schema = json!({"type": "boolean"});
        let input = json!(true);
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn root_null_valid() {
        let schema = json!({"type": "null"});
        let input = json!(null);
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn root_integer_for_string_schema() {
        let schema = json!({"type": "string"});
        let input = json!(42);
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "<root>");
    }

    // ── Root-level enum validation ──────────────────────────────────

    #[test]
    fn root_enum_valid() {
        let schema = json!({"type": "string", "enum": ["a", "b", "c"]});
        let input = json!("b");
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn root_enum_invalid() {
        let schema = json!({"type": "string", "enum": ["a", "b", "c"]});
        let input = json!("d");
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("not in allowed set"));
    }

    // ── Root-level array constraints ────────────────────────────────

    #[test]
    fn root_array_min_items_fail() {
        let schema = json!({"type": "array", "minItems": 3, "items": {"type": "integer"}});
        let input = json!([1]);
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "<root>");
        assert!(result.errors[0].message.contains("too short"));
    }

    #[test]
    fn root_array_max_items_fail() {
        let schema = json!({"type": "array", "maxItems": 2, "items": {"type": "integer"}});
        let input = json!([1, 2, 3, 4]);
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "<root>");
        assert!(result.errors[0].message.contains("too long"));
    }

    // ── Combined constraints within single field ────────────────────

    #[test]
    fn string_min_and_max_both_violated_only_min() {
        // When both min and max constraints exist, both can fire
        let schema = json!({
            "type": "object",
            "properties": {
                "code": { "type": "string", "minLength": 5, "maxLength": 10 }
            }
        });
        let input = json!({"code": "ab"});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("too short"));
    }

    #[test]
    fn string_min_and_max_both_violated_only_max() {
        let schema = json!({
            "type": "object",
            "properties": {
                "code": { "type": "string", "minLength": 2, "maxLength": 5 }
            }
        });
        let input = json!({"code": "waytoolong"});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("too long"));
    }

    #[test]
    fn number_both_min_max_violated_below() {
        let schema = json!({
            "type": "object",
            "properties": {
                "val": { "type": "number", "minimum": 10.0, "maximum": 20.0 }
            }
        });
        let input = json!({"val": 5.0});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("below minimum"));
    }

    #[test]
    fn number_both_min_max_violated_above() {
        let schema = json!({
            "type": "object",
            "properties": {
                "val": { "type": "number", "minimum": 10.0, "maximum": 20.0 }
            }
        });
        let input = json!({"val": 25.0});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("exceeds maximum"));
    }

    // ── Multiple errors in single input ─────────────────────────────

    #[test]
    fn multiple_field_errors_required_and_type() {
        let schema = json!({
            "type": "object",
            "required": ["a", "b"],
            "properties": {
                "a": { "type": "string" },
                "b": { "type": "integer" },
                "c": { "type": "boolean" }
            }
        });
        // missing a, missing b, wrong type for c
        let input = json!({"c": "not_bool"});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors.len() >= 3);
    }

    #[test]
    fn required_field_type_hint_from_schema() {
        let schema = json!({
            "type": "object",
            "required": ["age"],
            "properties": {
                "age": { "type": "integer" }
            }
        });
        let input = json!({});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        // Suggestion should reference the type hint from the schema
        assert!(result.errors[0].suggestion.contains("integer"));
    }

    #[test]
    fn required_field_no_properties_uses_value_fallback() {
        let schema = json!({
            "type": "object",
            "required": ["x"]
        });
        let input = json!({});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        // Without properties, the type_hint defaults to "value"
        assert!(result.errors[0].suggestion.contains("value"));
    }

    // ── Array with nested object validation ─────────────────────────

    #[test]
    fn array_of_objects_missing_required() {
        let schema = json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["id"],
                        "properties": {
                            "id": { "type": "integer" }
                        }
                    }
                }
            }
        });
        let input = json!({"items": [{"id": 1}, {}, {"id": 3}]});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].path.contains("[1]"));
        assert!(result.errors[0].path.contains("id"));
    }

    #[test]
    fn array_of_objects_multiple_missing_required() {
        let schema = json!({
            "type": "object",
            "properties": {
                "records": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["name", "value"],
                        "properties": {
                            "name": { "type": "string" },
                            "value": { "type": "number" }
                        }
                    }
                }
            }
        });
        let input = json!({"records": [{}]});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        // Missing both name and value in records[0]
        assert_eq!(result.errors.len(), 2);
    }

    // ── Deeply nested array in object in array ──────────────────────

    #[test]
    fn deeply_nested_array_in_object_in_array() {
        let schema = json!({
            "type": "object",
            "properties": {
                "groups": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "members": {
                                "type": "array",
                                "items": { "type": "string" }
                            }
                        }
                    }
                }
            }
        });
        let input = json!({"groups": [{"members": ["alice", 42]}]});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].path.contains("groups"));
        assert!(result.errors[0].path.contains("[0]"));
        assert!(result.errors[0].path.contains("members"));
        assert!(result.errors[0].path.contains("[1]"));
    }

    // ── Schema with no type constraint ──────────────────────────────

    #[test]
    fn schema_without_type_accepts_any_value() {
        let schema = json!({"enum": ["yes", "no"]});
        let input = json!("yes");
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn schema_without_type_still_checks_enum() {
        let schema = json!({"enum": ["yes", "no"]});
        let input = json!("maybe");
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
    }

    // ── ValidationError field access ────────────────────────────────

    #[test]
    fn validation_error_fields_match_construction() {
        let err = ValidationError {
            path: "a.b.c".to_string(),
            message: "type mismatch".to_string(),
            suggestion: "use string".to_string(),
        };
        assert_eq!(err.path, "a.b.c");
        assert_eq!(err.message, "type mismatch");
        assert_eq!(err.suggestion, "use string");
    }

    #[test]
    fn validation_error_serializes_all_fields() {
        let err = ValidationError {
            path: "deep.nested.path".to_string(),
            message: "wrong type".to_string(),
            suggestion: "convert to int".to_string(),
        };
        let s = serde_json::to_string(&err).unwrap();
        assert!(s.contains("deep.nested.path"));
        assert!(s.contains("wrong type"));
        assert!(s.contains("convert to int"));
    }

    #[test]
    fn validation_result_debug_format() {
        let result = ValidationResult {
            errors: vec![ValidationError {
                path: "x".to_string(),
                message: "bad".to_string(),
                suggestion: "fix".to_string(),
            }],
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("ValidationResult"));
        assert!(debug.contains("bad"));
    }

    #[test]
    fn validation_error_clone_independence() {
        let err = ValidationError {
            path: "original".to_string(),
            message: "msg".to_string(),
            suggestion: "sug".to_string(),
        };
        let mut cloned = err.clone();
        cloned.path = "modified".to_string();
        // Original unchanged
        assert_eq!(err.path, "original");
        assert_eq!(cloned.path, "modified");
    }

    // ── Multiple errors serialization ───────────────────────────────

    #[test]
    fn multiple_errors_serialize_as_array() {
        let errors = vec![
            ValidationError {
                path: "a".to_string(),
                message: "m1".to_string(),
                suggestion: "s1".to_string(),
            },
            ValidationError {
                path: "b".to_string(),
                message: "m2".to_string(),
                suggestion: "s2".to_string(),
            },
        ];
        let json = serde_json::to_value(&errors).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["path"], "a");
        assert_eq!(arr[1]["path"], "b");
    }

    // ── Edge case: properties not in schema are not validated ────────

    #[test]
    fn unknown_property_not_validated() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" }
            }
        });
        // "age" is not in properties, so no validation happens for it
        let input = json!({"name": "test", "age": "not_a_number"});
        assert!(validate(&input, &schema).is_valid());
    }

    // ── Array items schema absent means no item validation ──────────

    #[test]
    fn array_without_items_schema_accepts_mixed() {
        let schema = json!({
            "type": "object",
            "properties": {
                "data": { "type": "array" }
            }
        });
        let input = json!({"data": [1, "two", true, null, [3], {"k": 4}]});
        assert!(validate(&input, &schema).is_valid());
    }

    // ── Enum with null value ────────────────────────────────────────

    #[test]
    fn enum_with_null_valid() {
        let schema = json!({
            "type": "object",
            "properties": {
                "status": { "enum": [null, "active", "inactive"] }
            }
        });
        let input = json!({"status": null});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn enum_with_boolean_values() {
        let schema = json!({
            "type": "object",
            "properties": {
                "flag": { "enum": [true, false] }
            }
        });
        let input = json!({"flag": true});
        assert!(validate(&input, &schema).is_valid());
    }

    // ── String constraints at exact boundaries ──────────────────────

    #[test]
    fn string_exact_max_length_valid() {
        let schema = json!({
            "type": "object",
            "properties": {
                "code": { "type": "string", "maxLength": 5 }
            }
        });
        let input = json!({"code": "abcde"});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn string_one_over_max_length() {
        let schema = json!({
            "type": "object",
            "properties": {
                "code": { "type": "string", "maxLength": 5 }
            }
        });
        let input = json!({"code": "abcdef"});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
    }

    #[test]
    fn string_one_under_min_length() {
        let schema = json!({
            "type": "object",
            "properties": {
                "code": { "type": "string", "minLength": 5 }
            }
        });
        let input = json!({"code": "abcd"});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
    }

    // ── Number constraint boundaries ────────────────────────────────

    #[test]
    fn number_just_below_minimum() {
        let schema = json!({
            "type": "object",
            "properties": {
                "val": { "type": "number", "minimum": 10.0 }
            }
        });
        let input = json!({"val": 9.999});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
    }

    #[test]
    fn number_just_above_maximum() {
        let schema = json!({
            "type": "object",
            "properties": {
                "val": { "type": "number", "maximum": 10.0 }
            }
        });
        let input = json!({"val": 10.001});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
    }

    #[test]
    fn negative_number_within_range() {
        let schema = json!({
            "type": "object",
            "properties": {
                "temp": { "type": "number", "minimum": -50.0, "maximum": 50.0 }
            }
        });
        let input = json!({"temp": -25.0});
        assert!(validate(&input, &schema).is_valid());
    }

    // ── min_items suggestion accuracy ───────────────────────────────

    #[test]
    fn array_min_items_suggestion_count() {
        let schema = json!({
            "type": "array",
            "minItems": 5,
            "items": { "type": "integer" }
        });
        let input = json!([1, 2]);
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        // Should suggest adding 3 more items
        assert!(result.errors[0].suggestion.contains('3'));
    }

    #[test]
    fn array_max_items_suggestion_count() {
        let schema = json!({
            "type": "array",
            "maxItems": 2,
            "items": { "type": "integer" }
        });
        let input = json!([1, 2, 3, 4, 5]);
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        // Should suggest removing 3 items
        assert!(result.errors[0].suggestion.contains('3'));
    }

    // ── Empty array passes with no constraints ──────────────────────

    #[test]
    fn empty_array_valid_no_constraints() {
        let schema = json!({
            "type": "array",
            "items": { "type": "string" }
        });
        let input = json!([]);
        assert!(validate(&input, &schema).is_valid());
    }

    // ── Object with all optional fields empty ───────────────────────

    #[test]
    fn object_all_optional_empty_valid() {
        let schema = json!({
            "type": "object",
            "properties": {
                "a": { "type": "string" },
                "b": { "type": "integer" },
                "c": { "type": "boolean" }
            }
        });
        let input = json!({});
        assert!(validate(&input, &schema).is_valid());
    }

    // ── Enum with mixed types ───────────────────────────────────────

    #[test]
    fn enum_mixed_types_string_match() {
        let schema = json!({
            "properties": {
                "val": { "enum": [1, "two", true, null] }
            }
        });
        let input = json!({"val": "two"});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn enum_mixed_types_no_match() {
        let schema = json!({
            "properties": {
                "val": { "enum": [1, "two", true] }
            }
        });
        let input = json!({"val": "three"});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
    }

    // ── Type mismatch early return prevents further checks ──────────

    #[test]
    fn type_mismatch_stops_checking_constraints() {
        // If type doesn't match, minLength/maxLength shouldn't fire
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "minLength": 100 }
            }
        });
        let input = json!({"name": 42});
        let result = validate(&input, &schema);
        // Only 1 error (type mismatch), not 2 (type + minLength)
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].message.contains("string"));
    }

    // ── Four-level deep nesting ─────────────────────────────────────

    #[test]
    fn four_level_nesting_type_error() {
        let schema = json!({
            "type": "object",
            "properties": {
                "l1": {
                    "type": "object",
                    "properties": {
                        "l2": {
                            "type": "object",
                            "properties": {
                                "l3": {
                                    "type": "object",
                                    "properties": {
                                        "l4": { "type": "integer" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        let input = json!({"l1": {"l2": {"l3": {"l4": "not_int"}}}});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "l1.l2.l3.l4");
    }

    // ── Schema with only required, no properties ────────────────────

    #[test]
    fn required_without_properties_definition() {
        let schema = json!({
            "type": "object",
            "required": ["id"]
        });
        let input = json!({});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "id");
        // type_hint defaults to "value" since no properties defined
        assert!(result.errors[0].suggestion.contains("value"));
    }

    // ── Validate with all issue_schema fields correct types ─────────

    #[test]
    fn issue_schema_labels_wrong_item_type() {
        let input = json!({
            "owner": "octocat",
            "repo": "hello-world",
            "title": "Bug",
            "labels": [42, true]
        });
        let result = validate(&input, &issue_schema());
        assert!(!result.is_valid());
        assert_eq!(result.errors.len(), 2);
    }

    #[test]
    fn issue_schema_all_fields_wrong_type() {
        let input = json!({
            "owner": 1,
            "repo": 2,
            "title": 3,
            "milestone": "one"
        });
        let result = validate(&input, &issue_schema());
        // owner, repo, title, milestone all wrong type
        assert_eq!(result.errors.len(), 4);
    }
}
