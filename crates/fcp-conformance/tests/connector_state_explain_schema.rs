//! Conformance coverage for `fwc connector state explain --json`.

use fwc::connector_state::{
    CONNECTOR_STATE_EXPLAIN_SCHEMA_VERSION, ConnectorStateExplainRequest,
    connector_state_explain_payload,
};
use fwc::readiness::DiscoveryCatalog;
use jsonschema::Validator;
use serde_json::{Value, json};
use std::path::PathBuf;

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fwc")
        .join("schemas")
        .join("connector_state_explain.schema.json")
}

fn load_schema() -> Value {
    let schema =
        std::fs::read_to_string(schema_path()).expect("failed to read connector state schema");
    serde_json::from_str(&schema).expect("failed to parse connector state schema JSON")
}

fn validator() -> Validator {
    Validator::new(&load_schema()).expect("connector state explain schema must compile")
}

fn state_root_fixture() -> PathBuf {
    std::env::temp_dir().join(format!(
        "fcp-connector-state-schema-nonexistent-{}",
        uuid::Uuid::new_v4()
    ))
}

fn github_explain_payload(zone: Option<&str>, explicit_host: Option<&str>) -> Value {
    let state_root = state_root_fixture();
    let catalog = DiscoveryCatalog::load_for_connector_filter(Some("github"))
        .expect("github connector catalog should load");
    let connector = catalog
        .resolve_connector("github")
        .expect("github connector should resolve");
    let request = ConnectorStateExplainRequest {
        connector_selector: "github",
        zone,
        state_root: Some(&state_root),
        explicit_host,
    };

    connector_state_explain_payload(connector, &request)
}

fn availability(availability: &str, command: &str, authoritative: bool) -> Value {
    json!({
        "availability": availability,
        "command": command,
        "authoritative": authoritative,
        "explanation": "fixture availability",
        "recoverable": availability != "live-runtime",
        "next_actions": ["inspect fixture provenance"]
    })
}

fn host_backed_payload() -> Value {
    json!({
        "status": "ok",
        "command": "connector",
        "subcommand": "state explain",
        "schema_version": CONNECTOR_STATE_EXPLAIN_SCHEMA_VERSION,
        "_truth_source": "host",
        "source": "host-admin-api",
        "host_payload_source": "host-canonical-state",
        "host_registry_version": 1,
        "message": "Explained connector state storage for `github` from live fcp-host canonical fcp-store state.",
        "connector": {
            "requested_selector": "github",
            "slug": "github",
            "canonical_id": "fcp.github:enterprise:v1",
            "name": "GitHub Connector",
            "version": "1.0.0"
        },
        "connector_id": "fcp.github:enterprise:v1",
        "state_root": {
            "path": "/srv/fcp/state",
            "source": "host"
        },
        "canonical_storage": "mesh",
        "last_canonical_seq": 7,
        "mesh_replica_count": 3,
        "canonical_state": {
            "root_present": true,
            "connector_id": "fcp.github:enterprise:v1",
            "zone_id": "z:work",
            "instance_id": null,
            "model": "singleton_writer",
            "root_object_id": "1111111111111111111111111111111111111111111111111111111111111111",
            "head_object_id": "2222222222222222222222222222222222222222222222222222222222222222",
            "state_schema_version": 1,
            "status_source": "fcp-store"
        },
        "local_cache_path": "/srv/fcp/state/fcp.github_enterprise_v1/cache",
        "local_cache_present": true,
        "local_cache_marker_present": true,
        "cache_marker": {
            "filename": ".fcp-cache-only",
            "path": "/srv/fcp/state/fcp.github_enterprise_v1/cache/.fcp-cache-only",
            "present": true,
            "status": "present"
        },
        "zone": {
            "requested": "z:work",
            "local_cache_path": "/srv/fcp/state/fcp.github_enterprise_v1/cache/z_work",
            "local_cache_marker_present": true,
            "cache_marker_status": "present"
        },
        "live_host": {
            "requested": true,
            "endpoint_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "state": "queried",
            "route_available": true,
            "route": "/rpc/admin/connectors/{connector_id}/state/explain"
        },
        "telemetry": {
            "cache_hit_counter": "fcp_connector_state_cache_hits_total",
            "fall_through_counter": "fcp_connector_state_fall_through_total",
            "fall_through_event": "fcp.connector_state.fall_through"
        },
        "warnings": [],
        "availability": availability("live-runtime", "connector", true)
    })
}

fn connector_resolution_error_payload() -> Value {
    json!({
        "status": "error",
        "command": "connector",
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": "offline",
        "error": {
            "type": "connector-not-found",
            "message": "`missing` did not match any connector in the workspace catalog.",
            "recoverable": true,
            "selector": "missing",
            "did_you_mean": [],
            "examples": ["fwc list"],
            "next_actions": [
                "Use `fwc list` or `fwc search <term>` to narrow the connector first."
            ]
        }
    })
}

fn truth_source_unavailable_payload() -> Value {
    json!({
        "status": "error",
        "command": "connector",
        "subcommand": "state explain",
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": "host",
        "error": {
            "type": "truth-source-unavailable",
            "required": "mesh",
            "actual": "host",
            "message": "`fwc connector state explain` resolved from `host` truth, which does not satisfy `--require-source mesh`.",
            "recoverable": true
        },
        "next_actions": ["Retry after the required live truth source is reachable."],
        "availability": availability("unavailable", "connector", false)
    })
}

fn truth_resolver_internal_error_payload() -> Value {
    json!({
        "status": "error",
        "command": "connector",
        "subcommand": "state explain",
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": "unavailable",
        "error": {
            "type": "truth-resolver-internal-error",
            "message": "`fwc connector state explain` could not classify live truth because the resolver failed internally.",
            "recoverable": false,
            "redacted_cause": "resolver panicked after redaction",
            "log_event": "fcp.truth_resolver.internal_error",
            "correlation_id": "00000000-0000-4000-8000-000000000000",
            "bead_reference": "flywheel_connectors-hr0rr.2.5"
        },
        "next_actions": ["Inspect logs for `fcp.truth_resolver.internal_error`."],
        "availability": availability("unavailable", "connector", false)
    })
}

fn assert_valid(instance: &Value) {
    let validator = validator();
    let errors = validator
        .iter_errors(instance)
        .map(|error| format!("{} at {}", error, error.instance_path()))
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "connector state explain payload must validate: {errors:?}"
    );
}

fn assert_invalid(instance: &Value, reason: &str) {
    let validator = validator();
    assert!(
        !validator.is_valid(instance),
        "connector state explain payload must be invalid: {reason}"
    );
}

#[test]
fn connector_state_explain_schema_validates_local_payload() {
    let payload = github_explain_payload(Some("z:work"), None);

    assert_valid(&payload);
    assert_eq!(
        payload["schema_version"],
        CONNECTOR_STATE_EXPLAIN_SCHEMA_VERSION
    );
    assert_eq!(payload["_truth_source"], "offline");
    assert_eq!(payload["command"], "connector");
    assert_eq!(payload["subcommand"], "state explain");
    assert_eq!(payload["canonical_storage"], "local");
    assert_eq!(payload["connector"]["canonical_id"], "fcp.github");
    assert_eq!(payload["zone"]["requested"], "z:work");
    assert_eq!(payload["live_host"]["state"], "not-requested");
    assert_eq!(payload["availability"]["availability"], "offline-artifact");
}

#[test]
fn connector_state_explain_schema_validates_host_requested_payload() {
    let payload = github_explain_payload(None, Some("https://host.example.invalid:8443"));

    assert_valid(&payload);
    assert_eq!(payload["zone"]["requested"], Value::Null);
    assert_eq!(payload["live_host"]["requested"], true);
    assert_eq!(payload["live_host"]["state"], "not-queried");
    assert!(
        payload["live_host"]["endpoint_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:") && hash.len() == 71)
    );
}

#[test]
fn connector_state_explain_schema_validates_host_backed_payload() {
    let payload = host_backed_payload();

    assert_valid(&payload);
    assert_eq!(payload["_truth_source"], "host");
    assert_eq!(payload["source"], "host-admin-api");
    assert_eq!(payload["host_payload_source"], "host-canonical-state");
    assert_eq!(payload["canonical_state"]["status_source"], "fcp-store");
    assert_eq!(payload["live_host"]["state"], "queried");
}

#[test]
fn connector_state_explain_schema_validates_connector_resolution_error() {
    let payload = connector_resolution_error_payload();

    assert_valid(&payload);
    assert_eq!(payload["status"], "error");
    assert_eq!(payload["error"]["type"], "connector-not-found");
}

#[test]
fn connector_state_explain_schema_validates_truth_source_unavailable() {
    let payload = truth_source_unavailable_payload();

    assert_valid(&payload);
    assert_eq!(payload["error"]["required"], "mesh");
    assert_eq!(payload["error"]["actual"], "host");
}

#[test]
fn connector_state_explain_schema_validates_truth_resolver_internal_error() {
    let payload = truth_resolver_internal_error_payload();

    assert_valid(&payload);
    assert_eq!(payload["_truth_source"], "unavailable");
    assert_eq!(
        payload["error"]["log_event"],
        "fcp.truth_resolver.internal_error"
    );
}

#[test]
fn connector_state_explain_schema_rejects_missing_schema_version() {
    let mut payload = github_explain_payload(Some("z:work"), None);
    payload
        .as_object_mut()
        .expect("payload must be an object")
        .remove("schema_version");

    assert_invalid(&payload, "schema_version is required");
}

#[test]
fn connector_state_explain_schema_rejects_missing_truth_source() {
    let mut payload = github_explain_payload(Some("z:work"), None);
    payload
        .as_object_mut()
        .expect("payload must be an object")
        .remove("_truth_source");

    assert_invalid(&payload, "_truth_source is required");
}

#[test]
fn connector_state_explain_schema_rejects_unknown_truth_source() {
    let mut payload = github_explain_payload(Some("z:work"), None);
    payload["_truth_source"] = json!("probably-live");

    assert_invalid(&payload, "_truth_source is a closed enum");
}

#[test]
fn connector_state_explain_schema_rejects_unknown_top_level_fields() {
    let mut payload = github_explain_payload(Some("z:work"), None);
    payload["undocumented_field"] = json!(true);

    assert_invalid(&payload, "top-level schema is fail-closed");
}

#[test]
fn connector_state_explain_schema_rejects_unknown_canonical_storage() {
    let mut payload = github_explain_payload(Some("z:work"), None);
    payload["canonical_storage"] = json!("maybe");

    assert_invalid(&payload, "canonical storage is a closed enum");
}

#[test]
fn connector_state_explain_schema_rejects_host_payload_without_canonical_state() {
    let mut payload = host_backed_payload();
    payload
        .as_object_mut()
        .expect("payload must be an object")
        .remove("canonical_state");

    assert_invalid(
        &payload,
        "host-backed payload must carry canonical state evidence",
    );
}

#[test]
fn connector_state_explain_schema_rejects_offline_payload_with_host_only_fields() {
    let mut payload = github_explain_payload(Some("z:work"), None);
    payload["telemetry"] = json!({
        "cache_hit_counter": "fcp_connector_state_cache_hits_total",
        "fall_through_counter": "fcp_connector_state_fall_through_total",
        "fall_through_event": "fcp.connector_state.fall_through"
    });

    assert_invalid(&payload, "offline payload cannot claim host telemetry");
}

#[test]
fn connector_state_explain_schema_rejects_incomplete_resolver_internal_error() {
    let mut payload = truth_resolver_internal_error_payload();
    payload["error"]
        .as_object_mut()
        .expect("error must be an object")
        .remove("redacted_cause");

    assert_invalid(
        &payload,
        "resolver internal errors must carry redacted cause",
    );
}

#[test]
fn connector_state_explain_schema_rejects_non_numeric_sequence() {
    let mut payload = github_explain_payload(Some("z:work"), None);
    payload["last_canonical_seq"] = json!("100");

    assert_invalid(
        &payload,
        "last canonical sequence must be null or an integer",
    );
}

#[test]
fn connector_state_explain_schema_is_fail_closed() {
    let schema = load_schema();

    assert_eq!(
        schema.get("additionalProperties"),
        Some(&Value::Bool(false)),
        "top-level connector state explain schema must reject unknown fields"
    );
    assert!(
        schema.get("$defs").is_some(),
        "schema should define reusable closed shapes"
    );
}
