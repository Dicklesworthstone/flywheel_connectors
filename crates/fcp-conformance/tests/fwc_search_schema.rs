//! Conformance coverage for `fwc search --json`.

use fwc::readiness::{CommandAvailability, CommandEnvelope};
use jsonschema::Validator;
use serde_json::{Value, json};
use std::path::PathBuf;

const SEARCH_SCHEMA_VERSION: &str = "fcp.fwc.truth-source.v1";

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fwc")
        .join("schemas")
        .join("search.schema.json")
}

fn load_schema() -> Value {
    let schema = std::fs::read_to_string(schema_path()).expect("failed to read search schema");
    serde_json::from_str(&schema).expect("failed to parse search schema JSON")
}

fn validator() -> Validator {
    Validator::new(&load_schema()).expect("search schema must compile")
}

fn availability(availability: CommandAvailability) -> Value {
    serde_json::to_value(CommandEnvelope::new(availability, "search"))
        .expect("availability envelope must serialize")
}

fn search_result() -> Value {
    json!({
        "connector": "github",
        "connector_name": "GitHub",
        "connector_status": "proven",
        "hidden_by_default": false,
        "non_live_rationale": null,
        "graduation_guidance": null,
        "operation": "github.create_issue",
        "selector": "create_issue",
        "summary": "Create a GitHub issue.",
        "capability": "github.write",
        "risk_level": "medium",
        "safety_tier": "risky",
        "idempotency": "strict",
        "score": 42,
        "match_reasons": ["operation id exact match"]
    })
}

fn provenance(source: &str, authoritative: bool) -> Value {
    json!({
        "command": "search",
        "source": source,
        "authoritative": authoritative,
        "mode": if authoritative { "live-introspection" } else { "offline-artifact" }
    })
}

fn cache_evidence() -> Value {
    json!({
        "hit": false,
        "validated": true,
        "etag": "blake3-256:0123456789abcdef",
        "age_ms": 0,
        "source": "workspace-manifests"
    })
}

fn offline_success_payload() -> Value {
    json!({
        "status": "ok",
        "command": "search",
        "source": "workspace-manifests",
        "mode": "offline-artifact",
        "message": "Found 1 matching operations (1 shown).",
        "query": "github issue",
        "filters": ["include_hidden=false"],
        "hidden_connectors_in_catalog": 3,
        "total_results": 1,
        "results": [search_result()],
        "next_actions": [
            "Use `fwc show <connector> --offline` to inspect a connector in more detail."
        ],
        "schema_version": SEARCH_SCHEMA_VERSION,
        "_truth_source": "offline",
        "availability": availability(CommandAvailability::OfflineArtifact),
        "provenance": provenance("workspace_manifest", false),
        "_cache": cache_evidence()
    })
}

fn host_success_payload() -> Value {
    json!({
        "status": "ok",
        "command": "search",
        "source": "host-admin-api",
        "mode": "live-introspection",
        "message": "Found 1 live matching operations (1 shown).",
        "query": "github issue",
        "filters": ["connector=github"],
        "filter_gaps": [],
        "metadata_gaps": [],
        "total_results": 1,
        "results": [search_result()],
        "next_actions": [
            "Use `fwc show <connector> --host <endpoint>` to inspect a connector in more detail."
        ],
        "schema_version": SEARCH_SCHEMA_VERSION,
        "_truth_source": "host",
        "availability": availability(CommandAvailability::LiveRuntime),
        "provenance": provenance("live_host_introspection", true)
    })
}

fn missing_host_payload() -> Value {
    json!({
        "status": "error",
        "command": "search",
        "schema_version": SEARCH_SCHEMA_VERSION,
        "_truth_source": "offline",
        "error": {
            "type": "missing-host-endpoint",
            "message": "`search` requires a live `fcp-host` endpoint.",
            "recoverable": true
        },
        "details": {
            "query": "github issue",
            "filters": {
                "zone": null,
                "connector": null,
                "capability": null,
                "risk": null,
                "safety": null,
                "archetype": null,
                "category": null,
                "idempotent": false,
                "include_hidden": false
            },
            "require_source": null
        },
        "next_actions": [
            "fwc search <query> --host <endpoint>",
            "fwc search <query> --offline"
        ],
        "availability": availability(CommandAvailability::Unavailable)
    })
}

fn ambiguous_catalog_source_payload() -> Value {
    json!({
        "status": "error",
        "command": "search",
        "schema_version": SEARCH_SCHEMA_VERSION,
        "_truth_source": "offline",
        "error": {
            "type": "ambiguous-catalog-source",
            "message": "`search` cannot combine live host mode with `--offline`.",
            "recoverable": true
        },
        "next_actions": [
            "Retry `search` with `--host <endpoint>` for live host truth.",
            "Retry `search` with `--offline` to inspect workspace manifests explicitly."
        ],
        "availability": availability(CommandAvailability::Denied)
    })
}

fn truth_source_unavailable_payload() -> Value {
    json!({
        "status": "error",
        "command": "search",
        "schema_version": SEARCH_SCHEMA_VERSION,
        "_truth_source": "offline",
        "error": {
            "type": "truth-source-unavailable",
            "required": "any-live",
            "actual": "offline",
            "message": "`fwc search` resolved from `offline` truth, which does not satisfy `--require-source any-live`.",
            "recoverable": true
        },
        "next_actions": [
            "Retry after the required live truth source is reachable.",
            "Relax the requirement if `offline` truth is acceptable for this workflow."
        ],
        "availability": availability(CommandAvailability::Unavailable)
    })
}

fn truth_resolver_internal_error_payload() -> Value {
    json!({
        "status": "error",
        "command": "search",
        "schema_version": SEARCH_SCHEMA_VERSION,
        "_truth_source": "unavailable",
        "error": {
            "type": "truth-resolver-internal-error",
            "message": "`fwc search` could not classify live truth because the resolver failed internally.",
            "recoverable": false,
            "redacted_cause": "best-available strategy exhausted 1 source(s): mesh:error",
            "log_event": "fcp.truth_resolver.internal_error",
            "correlation_id": "01234567-89ab-cdef-0123-456789abcdef",
            "bead_reference": "flywheel_connectors-hr0rr.2.5"
        },
        "next_actions": [
            "Inspect logs for `fcp.truth_resolver.internal_error` with the returned correlation_id.",
            "Treat this response as non-authoritative until the resolver bug is fixed."
        ],
        "availability": availability(CommandAvailability::Unavailable)
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
        "search payload must validate: {errors:?}"
    );
}

fn assert_invalid(instance: &Value, reason: &str) {
    let validator = validator();
    assert!(
        !validator.is_valid(instance),
        "search payload must be invalid: {reason}"
    );
}

#[test]
fn search_schema_validates_offline_success_payload() {
    let payload = offline_success_payload();

    assert_valid(&payload);
    assert_eq!(payload["schema_version"], SEARCH_SCHEMA_VERSION);
    assert_eq!(payload["_truth_source"], "offline");
    assert_eq!(payload["source"], "workspace-manifests");
}

#[test]
fn search_schema_validates_host_success_payload() {
    let payload = host_success_payload();

    assert_valid(&payload);
    assert_eq!(payload["_truth_source"], "host");
    assert_eq!(payload["source"], "host-admin-api");
}

#[test]
fn search_schema_accepts_registered_truth_source_tags() {
    for source in [
        "mesh",
        "host",
        "node-local",
        "offline",
        "degraded",
        "fallback-derived",
        "simulated",
        "unavailable",
    ] {
        let mut payload = offline_success_payload();
        payload["_truth_source"] = json!(source);

        assert_valid(&payload);
    }
}

#[test]
fn search_schema_validates_missing_host_payload() {
    let payload = missing_host_payload();

    assert_valid(&payload);
    assert_eq!(payload["error"]["type"], "missing-host-endpoint");
}

#[test]
fn search_schema_validates_ambiguous_catalog_source_payload() {
    let payload = ambiguous_catalog_source_payload();

    assert_valid(&payload);
    assert_eq!(payload["error"]["type"], "ambiguous-catalog-source");
}

#[test]
fn search_schema_validates_truth_source_unavailable_payload() {
    let payload = truth_source_unavailable_payload();

    assert_valid(&payload);
    assert_eq!(payload["error"]["type"], "truth-source-unavailable");
}

#[test]
fn search_schema_validates_truth_resolver_internal_error_payload() {
    let payload = truth_resolver_internal_error_payload();

    assert_valid(&payload);
    assert_eq!(payload["_truth_source"], "unavailable");
    assert_eq!(payload["error"]["type"], "truth-resolver-internal-error");
    assert_eq!(
        payload["error"]["log_event"],
        "fcp.truth_resolver.internal_error"
    );
}

#[test]
fn search_schema_rejects_unknown_top_level_field() {
    let mut payload = offline_success_payload();
    payload["undocumented"] = json!(true);

    assert_invalid(&payload, "top-level schema is fail-closed");
}

#[test]
fn search_schema_rejects_result_missing_selector() {
    let mut payload = offline_success_payload();
    payload["results"][0]
        .as_object_mut()
        .expect("result must be an object")
        .remove("selector");

    assert_invalid(&payload, "search result selector is required");
}

#[test]
fn search_schema_rejects_unknown_truth_source_requirement() {
    let mut payload = truth_source_unavailable_payload();
    payload["error"]["required"] = json!("offline");

    assert_invalid(&payload, "require-source values are a closed enum");
}

#[test]
fn search_schema_rejects_internal_error_without_redacted_cause() {
    let mut payload = truth_resolver_internal_error_payload();
    payload["error"]
        .as_object_mut()
        .expect("error payload must be an object")
        .remove("redacted_cause");

    assert_invalid(
        &payload,
        "internal resolver errors must carry redacted cause",
    );
}
