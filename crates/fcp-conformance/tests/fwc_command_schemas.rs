//! Conformance coverage for A.5 `fwc` truth-source command envelopes.

use fwc::readiness::{CommandAvailability, CommandEnvelope};
use jsonschema::Validator;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const TRUTH_SOURCES: &[&str] = &[
    "mesh",
    "host",
    "node-local",
    "offline",
    "degraded",
    "fallback-derived",
    "simulated",
    "unavailable",
];

#[derive(Clone, Copy)]
struct CommandSchemaCase {
    file: &'static str,
    command: &'static str,
    subcommand: Option<&'static str>,
    command_required_on_success: bool,
    success_schema_version: &'static str,
    error_schema_version: &'static str,
}

const CASES: &[CommandSchemaCase] = &[
    CommandSchemaCase {
        file: "list.schema.json",
        command: "list",
        subcommand: None,
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.truth-source.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "show.schema.json",
        command: "show",
        subcommand: None,
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.truth-source.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "status.schema.json",
        command: "status",
        subcommand: None,
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.truth-source.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "doctor.schema.json",
        command: "doctor",
        subcommand: None,
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.truth-source.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "context_current.schema.json",
        command: "context",
        subcommand: Some("current"),
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.truth-source.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "schema.schema.json",
        command: "schema",
        subcommand: None,
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.truth-source.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "history.schema.json",
        command: "history",
        subcommand: None,
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.truth-source.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "search.schema.json",
        command: "search",
        subcommand: None,
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.truth-source.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "audit_chain_status.schema.json",
        command: "audit",
        subcommand: Some("chain status"),
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.audit_chain_status.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "audit_verify.schema.json",
        command: "audit",
        subcommand: Some("verify"),
        command_required_on_success: false,
        success_schema_version: "fcp.fwc.audit_verify.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "mesh_explain_availability.schema.json",
        command: "mesh",
        subcommand: Some("explain-availability"),
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.truth-source.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "connector_lease_status.schema.json",
        command: "connector",
        subcommand: Some("lease status"),
        command_required_on_success: true,
        success_schema_version: "1.0.0",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
];

fn schema_path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fwc")
        .join("schemas")
        .join(file)
}

fn schema_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fwc")
        .join("schemas")
}

fn load_schema(file: &str) -> Value {
    let schema =
        std::fs::read_to_string(schema_path(file)).expect("failed to read fwc command schema");
    serde_json::from_str(&schema).expect("failed to parse fwc command schema JSON")
}

fn validator(file: &str) -> Validator {
    Validator::new(&load_schema(file)).expect("fwc command schema must compile")
}

fn fwc_schema_files() -> BTreeSet<String> {
    fs::read_dir(schema_dir())
        .expect("fwc schemas directory must be readable")
        .map(|entry| {
            let entry = entry.expect("fwc schema directory entry must be readable");
            entry
                .file_name()
                .to_str()
                .expect("fwc schema filename must be UTF-8")
                .to_owned()
        })
        .filter(|filename| filename.ends_with(".schema.json"))
        .collect()
}

fn collect_rust_sources(dir: &Path, sources: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|err| {
        panic!(
            "expected Rust source directory {} to be readable: {err}",
            dir.display()
        )
    }) {
        let entry = entry.expect("Rust source directory entry must be readable");
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, sources);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            sources.push(path);
        }
    }
}

fn schema_reference_sources() -> Vec<PathBuf> {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("fcp-conformance manifest should live below crates/")
        .to_path_buf();
    let mut sources = Vec::new();
    for relative in [
        "crates/fcp-conformance/tests",
        "crates/fwc/tests",
        "crates/fwc/src",
    ] {
        collect_rust_sources(&repo_root.join(relative), &mut sources);
    }
    sources
}

fn referenced_schema_files(schema_files: &BTreeSet<String>) -> BTreeSet<String> {
    let mut referenced = BTreeSet::new();
    for source_path in schema_reference_sources() {
        let source = fs::read_to_string(&source_path).unwrap_or_else(|err| {
            panic!(
                "expected Rust source {} to be readable: {err}",
                source_path.display()
            )
        });
        for schema_file in schema_files {
            if source.contains(schema_file) {
                referenced.insert(schema_file.clone());
            }
        }
    }
    referenced
}

fn envelope_payload(
    case: CommandSchemaCase,
    status: &str,
    schema_version: &str,
    truth_source: &str,
) -> Value {
    let mut payload = json!({
        "status": status,
        "schema_version": schema_version,
        "_truth_source": truth_source,
    });
    if status == "error" || case.command_required_on_success {
        payload["command"] = json!(case.command);
        if let Some(subcommand) = case.subcommand {
            payload["subcommand"] = json!(subcommand);
        }
    }
    payload
}

fn availability(availability: &str) -> Value {
    json!({
        "availability": availability,
        "command": "history",
        "authoritative": false,
        "explanation": "History is resolved from local CLI history artifacts.",
        "recoverable": true,
        "next_actions": ["fwc history"]
    })
}

fn command_availability(command: &str, availability: CommandAvailability) -> Value {
    serde_json::to_value(CommandEnvelope::new(availability, command))
        .expect("availability envelope must serialize")
}

fn command_invocation(case: CommandSchemaCase) -> String {
    case.subcommand.map_or_else(
        || case.command.to_owned(),
        |subcommand| format!("{} {subcommand}", case.command),
    )
}

fn truth_source_unavailable_availability(case: CommandSchemaCase) -> Option<Value> {
    match case.file {
        "list.schema.json" => Some(command_availability(
            "list",
            CommandAvailability::Unavailable,
        )),
        "show.schema.json" => Some(command_availability(
            "show",
            CommandAvailability::Unavailable,
        )),
        "search.schema.json" => Some(command_availability(
            "search",
            CommandAvailability::Unavailable,
        )),
        "status.schema.json" => Some(command_availability(
            "status",
            CommandAvailability::Unavailable,
        )),
        "schema.schema.json" => Some(command_availability(
            "schema",
            CommandAvailability::Unavailable,
        )),
        "doctor.schema.json" => Some(command_availability(
            "doctor",
            CommandAvailability::Unavailable,
        )),
        "context_current.schema.json" => Some(command_availability(
            "context current",
            CommandAvailability::Unavailable,
        )),
        "history.schema.json" => Some(availability("unavailable")),
        _ => None,
    }
}

fn resolver_internal_error_availability(case: CommandSchemaCase) -> Option<Value> {
    match case.file {
        "list.schema.json" => Some(command_availability(
            "list",
            CommandAvailability::Unavailable,
        )),
        "show.schema.json" => Some(command_availability(
            "show",
            CommandAvailability::Unavailable,
        )),
        "search.schema.json" => Some(command_availability(
            "search",
            CommandAvailability::Unavailable,
        )),
        "status.schema.json" => Some(command_availability(
            "status",
            CommandAvailability::Unavailable,
        )),
        "schema.schema.json" => Some(command_availability(
            "schema",
            CommandAvailability::Unavailable,
        )),
        "doctor.schema.json" => Some(command_availability(
            "doctor",
            CommandAvailability::Unavailable,
        )),
        "context_current.schema.json" => Some(command_availability(
            "context current",
            CommandAvailability::Unavailable,
        )),
        _ => None,
    }
}

fn metadata_field_unknown() -> Value {
    json!({
        "status": "unknown"
    })
}

fn list_connector() -> Value {
    json!({
        "slug": "github",
        "canonical_id": "fcp.github",
        "name": "GitHub",
        "description": "GitHub connector.",
        "version": "1.0.0",
        "cohort": "batch-1",
        "status": "proven",
        "hidden_by_default": false,
        "non_live_rationale": null,
        "graduation_guidance": null,
        "format": "native",
        "state": "ready",
        "archetypes": ["request-response", "webhook"],
        "home_zone": "z:work",
        "operation_count": 7,
        "max_risk": "medium",
        "has_events": metadata_field_unknown(),
        "next_actions": [
            "fwc show github",
            "fwc ops github"
        ]
    })
}

fn history_entry_payload() -> Value {
    json!({
        "entry_id": "hist_0123456789abcdef",
        "timestamp": "2026-06-07T11:46:00Z",
        "connector_id": "fcp.github",
        "operation_id": "github.list_issues",
        "zone": "z:work",
        "input_hash": "blake3-256:1111111111111111",
        "input_summary": "owner=acme repo=api",
        "output_hash": "blake3-256:2222222222222222",
        "output_summary": "total_count=7",
        "status": "success",
        "latency_ms": 12,
        "idempotency_key": "idem-123",
        "agent_session": "session-abc"
    })
}

fn history_success_payload(truth_source: &str) -> Value {
    json!({
        "status": "ok",
        "command": "history",
        "scope": "list",
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": truth_source,
        "total_entries": 0,
        "returned": 0,
        "filter": {
            "connector": null,
            "status": null,
            "since": null,
            "limit": 20
        },
        "entries": [],
        "next_actions": ["fwc history <entry_id>"],
        "availability": availability("offline-artifact")
    })
}

fn history_entry_lookup_payload(truth_source: &str) -> Value {
    json!({
        "status": "ok",
        "command": "history",
        "scope": "entry",
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": truth_source,
        "entry": history_entry_payload(),
        "availability": availability("offline-artifact")
    })
}

fn history_not_found_payload() -> Value {
    json!({
        "status": "error",
        "command": "history",
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": "offline",
        "error": {
            "type": "not-found",
            "message": "`hist_missing` was not found in local CLI history."
        },
        "next_actions": [
            "fwc history",
            "fwc history --connector <connector>"
        ]
    })
}

fn list_success_payload(truth_source: &str) -> Value {
    json!({
        "status": "ok",
        "command": "list",
        "source": "workspace-manifests",
        "mode": "offline-artifact",
        "message": "Listed 1 connectors from workspace manifests.",
        "filters": {
            "zone": null,
            "category": null,
            "include_hidden": false
        },
        "hidden_by_default_omitted": 0,
        "connectors": [list_connector()],
        "next_actions": [
            "Use `fwc show <connector> --offline` to inspect one connector in detail."
        ],
        "provenance": {
            "command": "list",
            "source": "workspace_manifest",
            "authoritative": false,
            "caveat": "Data is from workspace manifests and may not reflect current host state."
        },
        "_cache": {
            "hit": false,
            "validated": true,
            "etag": "blake3-256:0123456789abcdef",
            "age_ms": 0,
            "source": "workspace-manifests"
        },
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": truth_source,
        "availability": command_availability("list", CommandAvailability::OfflineArtifact)
    })
}

fn show_operation_preview() -> Value {
    json!({
        "selector": "github.create_issue",
        "canonical_id": "github.create_issue",
        "local_id": "create_issue",
        "aliases": ["issues.create"],
        "summary": "Create a GitHub issue.",
        "capability": "github.write",
        "risk_level": "medium",
        "safety_tier": "risky",
        "idempotency": "strict",
        "requires_approval": false,
        "supports_simulate": {
            "status": "known",
            "value": true
        },
        "example_count": 2,
        "rate_limits": []
    })
}

fn show_success_payload(truth_source: &str) -> Value {
    json!({
        "status": "ok",
        "command": "show",
        "source": "workspace-manifests",
        "mode": "offline-artifact",
        "message": "Loaded connector detail from the workspace manifest.",
        "connector": {
            "slug": "github",
            "canonical_id": "fcp.github",
            "name": "GitHub",
            "version": "1.0.0",
            "description": "GitHub connector.",
            "cohort": "batch-1",
            "status": "proven",
            "hidden_by_default": false,
            "non_live_rationale": null,
            "graduation_guidance": null,
            "format": "native",
            "state": "ready",
            "state_model": null,
            "archetypes": ["request-response", "webhook"],
            "operation_count": 1,
            "max_risk": "medium",
            "has_events": metadata_field_unknown(),
            "manifest_path": "connectors/github/manifest.toml"
        },
        "zones": {
            "home": "z:work"
        },
        "capabilities": {
            "read": ["github.issues.read"],
            "write": ["github.issues.write"]
        },
        "rate_limits": [],
        "shared_descriptor": {
            "connector_id": "fcp.github",
            "auth": { "status": "unverifiable" },
            "readiness": { "status": "unverifiable" }
        },
        "operations": {
            "preview": [show_operation_preview()],
            "preview_truncated": false,
            "risky_count": 1,
            "safe_count": 0
        },
        "next_actions": [
            "fwc ops github --offline",
            "fwc schema github github.create_issue --offline"
        ],
        "provenance": {
            "command": "show",
            "source": "workspace_manifest",
            "authoritative": false,
            "caveat": "Data is from workspace manifests and may not reflect current host state."
        },
        "_cache": {
            "hit": false,
            "validated": true,
            "etag": "blake3-256:0123456789abcdef",
            "age_ms": 0,
            "source": "workspace-manifests"
        },
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": truth_source,
        "availability": command_availability("show", CommandAvailability::OfflineArtifact)
    })
}

fn status_provenance(scope: &str) -> Value {
    json!({
        "command": "status",
        "source": "host-admin-api",
        "transport": "node-local-root-app",
        "scope": scope,
        "endpoint": "http://127.0.0.1:34123",
        "authoritative": true,
        "mesh_backed": false,
        "fallback_derived": false,
        "degraded": false,
        "caveat": "Live host-admin API answers are authoritative for the current node."
    })
}

fn status_success_payload(truth_source: &str) -> Value {
    json!({
        "status": "ok",
        "command": "status",
        "scope": "fleet",
        "source": "host-admin-api",
        "message": "Loaded live fleet status for 1 connectors from `fcp-host`.",
        "host_health": {
            "status": "healthy",
            "connectors": {},
            "uptime_seconds": 3600,
            "active_connections": 2,
            "timestamp": "2026-03-12T00:00:00Z"
        },
        "registry_version": 7,
        "connectors": [
            {
                "slug": "github",
                "canonical_id": "fcp.github:enterprise:v1",
                "name": "GitHub Enterprise",
                "enabled": true,
                "health": "healthy",
                "state": "ready",
                "version": "1.2.3",
                "tool_count": 2,
                "max_safety_tier": "risky"
            }
        ],
        "next_actions": [
            "fwc status github --host http://127.0.0.1:34123",
            "fwc list --host http://127.0.0.1:34123"
        ],
        "provenance": status_provenance("fleet-status"),
        "evidence_handles": [
            {
                "kind": "fleet-status",
                "timestamp": "2026-03-12T00:00:00Z",
                "registry_version": 7,
                "connector_count": 1
            }
        ],
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": truth_source,
        "availability": command_availability("status", CommandAvailability::LiveRuntime)
    })
}

fn status_connector_success_payload(truth_source: &str) -> Value {
    json!({
        "status": "ok",
        "command": "status",
        "scope": "connector",
        "source": "host-admin-api",
        "message": "Loaded live connector admin status for `github` from `fcp-host`.",
        "connector": {
            "slug": "github",
            "canonical_id": "fcp.github:enterprise:v1",
            "name": "GitHub Enterprise",
            "version": "1.2.3",
            "enabled": true,
            "health": "healthy"
        },
        "admin": {
            "connector_id": "fcp.github:enterprise:v1",
            "desired_state": "enabled",
            "observed_state": "running",
            "active_config_revision_id": 41,
            "config_revision_count": 1,
            "last_journal_sequence": 9,
            "evaluated_at": "2026-03-12T00:00:00Z"
        },
        "pin": {
            "connector_id": "fcp.github:enterprise:v1",
            "pinned": false
        },
        "rollout": {
            "connector_id": "fcp.github:enterprise:v1",
            "state": "production",
            "version": "1.2.3",
            "health": {
                "successes": 100,
                "failures": 0
            },
            "pinned": false,
            "canary_percent": 0
        },
        "host_health": {
            "status": "healthy",
            "timestamp": "2026-03-12T00:00:00Z"
        },
        "registry_version": 7,
        "next_actions": [
            "fwc show github --host http://127.0.0.1:34123",
            "fwc ops github --host http://127.0.0.1:34123"
        ],
        "provenance": status_provenance("connector-status"),
        "evidence_handles": [
            {
                "kind": "connector-status",
                "connector_id": "fcp.github:enterprise:v1",
                "evaluated_at": "2026-03-12T00:00:00Z"
            },
            {
                "kind": "host-health-snapshot",
                "timestamp": "2026-03-12T00:00:00Z"
            }
        ],
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": truth_source,
        "availability": command_availability("status", CommandAvailability::LiveRuntime)
    })
}

fn doctor_provenance() -> Value {
    json!({
        "command": "doctor",
        "source": "host-admin-api",
        "transport": "node-local-root-app",
        "scope": "zone-diagnostics",
        "endpoint": "http://127.0.0.1:34123",
        "authoritative": true,
        "mesh_backed": false,
        "fallback_derived": false,
        "degraded": false,
        "caveat": "Live host-admin API answers are authoritative for the current node."
    })
}

fn doctor_host_report() -> Value {
    json!({
        "schema_version": "1.1.0",
        "generated_at": "2026-03-12T00:00:00Z",
        "zone_id": "z:work",
        "overall_status": "OK",
        "checkpoint": { "freshness": "fresh" },
        "revocation": { "freshness": "fresh" },
        "audit": { "freshness": "fresh" },
        "transport_policy": {
            "allow_lan": true,
            "allow_derp": false,
            "allow_funnel": false
        },
        "store_coverage": {
            "store_healthy": true
        },
        "degraded_mode": {
            "is_degraded": false
        },
        "checks": []
    })
}

fn doctor_success_payload(truth_source: &str) -> Value {
    json!({
        "status": "ok",
        "command": "doctor",
        "source": "host-admin-api",
        "message": "Loaded a live doctor report for `z:work` from `fcp-host`.",
        "zone": "z:work",
        "requested_connectors": [],
        "self_check": false,
        "summary": {
            "overall_status": "OK",
            "check_count": 0,
            "connector_self_check_count": 0,
            "is_degraded": false
        },
        "report": doctor_host_report(),
        "diagnosis": {
            "reports": [],
            "auto_fixes": [],
            "fix_mode": false
        },
        "toon": "",
        "next_actions": [
            "fwc status --host http://127.0.0.1:34123",
            "fwc list --host http://127.0.0.1:34123"
        ],
        "provenance": doctor_provenance(),
        "evidence_handles": [
            {
                "kind": "doctor-report",
                "zone_id": "z:work",
                "generated_at": "2026-03-12T00:00:00Z",
                "check_count": 0,
                "connector_self_check_count": 0
            }
        ],
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": truth_source,
        "availability": command_availability("doctor", CommandAvailability::LiveRuntime)
    })
}

fn doctor_local_probe_success_payload() -> Value {
    json!({
        "status": "warn",
        "command": "doctor",
        "probe": "hlc",
        "source": "local-algorithm-probe",
        "message": "HLC and HierVV local invariants crossed one or more doctor warning thresholds.",
        "report": {
            "schema_version": "fcp.fwc.doctor.hlc.v1",
            "metrics": {
                "hlc_l_max": 1_700_000_000_000u64,
                "hlc_c_max": 1,
                "skew_observed_ms": 500,
                "hiervv_size_bytes": 128
            },
            "thresholds": {
                "skew_observed_ms_warn": 2_000,
                "hiervv_size_bytes_warn": 4_096,
                "hlc_c_counter_within_1s_warn": 1_000
            },
            "warnings": ["sample-warning"],
            "commands": ["fwc audit chain inspect --last 10"]
        },
        "next_actions": ["fwc audit chain inspect --last 10"],
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": "offline",
        "availability": command_availability("doctor", CommandAvailability::OfflineArtifact)
    })
}

fn context_current_success_payload(truth_source: &str) -> Value {
    json!({
        "status": "ok",
        "command": "context",
        "subcommand": "current",
        "config_path": "/tmp/fcp-context/contexts.toml",
        "current_context": "local",
        "context": {
            "name": "local",
            "endpoint": "unix:///tmp/fcp-dev.sock",
            "default_zone": "z:work",
            "node_identity": null,
            "config_overrides": {}
        },
        "next_actions": [
            "fwc context list",
            "fwc list"
        ],
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": truth_source,
        "availability": command_availability("context", CommandAvailability::OfflineArtifact)
    })
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

fn search_success_payload(truth_source: &str) -> Value {
    json!({
        "status": "ok",
        "command": "search",
        "source": "workspace-manifests",
        "mode": "offline-artifact",
        "message": "Found 1 matching operations (1 shown).",
        "query": "github issue",
        "filters": ["include_hidden=false"],
        "hidden_connectors_in_catalog": 0,
        "total_results": 1,
        "results": [search_result()],
        "next_actions": [
            "Use `fwc show <connector> --offline` to inspect a connector in more detail."
        ],
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": truth_source,
        "availability": command_availability("search", CommandAvailability::OfflineArtifact),
        "provenance": {
            "command": "search",
            "source": "workspace_manifest",
            "authoritative": false
        },
        "_cache": {
            "hit": false,
            "validated": true,
            "etag": "blake3-256:0123456789abcdef",
            "age_ms": 0,
            "source": "workspace-manifests"
        }
    })
}

fn schema_operation_ref() -> Value {
    json!({
        "requested_selector": "issues.create",
        "selector": "issues.create",
        "canonical_id": "github.create_issue",
        "aliases": ["github.create_issue"],
        "summary": "Create a GitHub issue.",
        "capability": "github.write",
        "risk_level": "medium",
        "safety_tier": "risky",
        "approval_mode": "none"
    })
}

fn schema_connector_ref() -> Value {
    json!({
        "slug": "github",
        "canonical_id": "fcp.github",
        "name": "GitHub"
    })
}

fn schema_success_base(truth_source: &str, scope: &str) -> Value {
    json!({
        "status": "ok",
        "command": "schema",
        "source": "workspace-manifests",
        "mode": "offline-artifact",
        "scope": scope,
        "connector": schema_connector_ref(),
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": truth_source,
        "availability": command_availability("schema", CommandAvailability::OfflineArtifact),
        "provenance": {
            "command": "schema",
            "source": "workspace_manifest",
            "authoritative": false,
            "caveat": "Data is from workspace manifests and may not reflect current host state."
        },
        "_cache": {
            "hit": false,
            "validated": true,
            "etag": "blake3-256:0123456789abcdef",
            "age_ms": 0,
            "source": "workspace-manifests"
        }
    })
}

fn schema_success_payload(truth_source: &str) -> Value {
    let mut payload = schema_success_base(truth_source, "operation");
    payload["message"] = json!("Loaded one operation schema from the connector manifest.");
    payload["operation"] = schema_operation_ref();
    payload["input_schema"] = json!({
        "type": "object",
        "required": ["title"],
        "properties": {
            "title": { "type": "string" }
        }
    });
    payload["output_schema"] = json!({ "type": "object" });
    payload["guidance"] = json!({
        "when_to_use": "Create a new issue in a GitHub repository.",
        "common_mistakes": ["Missing owner."],
        "related": ["github.list_issues"]
    });
    payload["next_actions"] = json!([
        "fwc examples github issues.create --offline",
        "fwc schema github issues.create --required-only --offline"
    ]);
    payload
}

fn schema_fields_success_payload(truth_source: &str) -> Value {
    let mut payload = schema_success_base(truth_source, "fields");
    payload["operation"] = schema_operation_ref();
    payload["field_count"] = json!(1);
    payload["fields"] = json!([
        {
            "path": "title",
            "required": true,
            "type": "string",
            "description": "Issue title."
        }
    ]);
    payload["next_actions"] = json!(["fwc schema github issues.create --scaffold --offline"]);
    payload
}

fn schema_scaffold_success_payload(truth_source: &str) -> Value {
    let mut payload = schema_success_base(truth_source, "scaffold");
    payload["operation"] = json!({ "selector": "issues.create" });
    payload["scaffold"] = json!({ "title": "<string>" });
    payload
}

fn schema_connector_success_payload(truth_source: &str) -> Value {
    let mut payload = schema_success_base(truth_source, "connector");
    payload["message"] = json!("Loaded the connector contract schema from the manifest.");
    payload["schema"] = json!({
        "type": "object",
        "properties": {
            "operation_count": { "type": "integer" }
        }
    });
    payload["next_actions"] = json!(["fwc ops github --offline"]);
    payload
}

fn schema_connector_resolution_error_payload() -> Value {
    json!({
        "status": "error",
        "command": "schema",
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": "offline",
        "error": {
            "type": "connector-not-found",
            "message": "`githuub` did not match any connector in the workspace catalog.",
            "recoverable": true,
            "selector": "githuub",
            "did_you_mean": ["github"],
            "examples": ["fwc schema github"],
            "next_actions": [
                "Use `fwc list` or `fwc search <term>` to narrow the connector first.",
                "Use `fwc ops <connector>` before `schema` or `examples` when the operation name is uncertain."
            ]
        }
    })
}

fn schema_operation_resolution_error_payload() -> Value {
    json!({
        "status": "error",
        "command": "schema",
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": "offline",
        "error": {
            "type": "operation-not-found",
            "message": "`issues.creat` did not match any operation exposed by `github`.",
            "recoverable": true,
            "selector": "issues.creat",
            "did_you_mean": ["issues.create"],
            "examples": ["fwc schema github issues.create", "fwc ops github"],
            "next_actions": [
                "Use `fwc list` or `fwc search <term>` to narrow the connector first.",
                "Use `fwc ops <connector>` before `schema` or `examples` when the operation name is uncertain."
            ]
        }
    })
}

fn audit_chain_status_success_payload(truth_source: &str) -> Value {
    json!({
        "status": "fresh",
        "command": "audit",
        "subcommand": "chain status",
        "schema_version": "fcp.fwc.audit_chain_status.v1",
        "_truth_source": truth_source,
        "telemetry_state": "artifact",
        "source": {
            "kind": "signed-head-artifact",
            "live": false,
            "head_path": "/tmp/fcp-audit/head.json",
            "events_path": "/tmp/fcp-audit/events.jsonl"
        },
        "zone_id": "z:work",
        "head_seq": 42,
        "head_entry": "audit-entry-42",
        "last_quorum_height": 42,
        "quorum_signed_checkpoints": 1,
        "quorum_signers": 2,
        "quorum_signer_ids": ["kid-alpha", "kid-beta"],
        "producer_signature_count": 2,
        "signature_count_consistent": true,
        "coverage": 1.0,
        "quorum_freshness_secs": 5,
        "quorum_rotation_epoch": "epoch-2026-06",
        "next_rotation_eta_secs": 300,
        "hlc_physical_drift_ms": 0,
        "max_age_seconds": 60,
        "live_quorum_checkpoint_snapshot": {
            "height": 42,
            "signers": 2
        },
        "warnings": []
    })
}

fn audit_verify_success_payload(truth_source: &str) -> Value {
    json!({
        "status": "ok",
        "zone_id": "z:work",
        "chain_len": 2,
        "head_seq": 1,
        "head_event": "audit-entry-1",
        "issues": [
            {
                "code": "audit.signature_invalid",
                "message": "signature verification failed",
                "seq": 1,
                "object_id": "audit-entry-1"
            }
        ],
        "schema_version": "fcp.fwc.audit_verify.v1",
        "_truth_source": truth_source
    })
}

fn mesh_explain_availability_success_payload(truth_source: &str) -> Value {
    json!({
        "status": "ok",
        "command": "mesh",
        "subcommand": "explain-availability",
        "source": "workspace-manifests",
        "mode": "offline-artifact",
        "message": "Explained offline availability for `github` from workspace manifests only.",
        "connector": {
            "requested_selector": "github",
            "slug": "github",
            "canonical_id": "fcp.github",
            "name": "GitHub",
            "version": "0.1.0"
        },
        "availability_fact": {
            "state": "offline-planning-only",
            "authoritative_scope": "workspace-manifests",
            "live_runtime_proven": false,
            "silent_fallback": false,
            "explanation": "No live host was requested, so placement is derived from workspace manifests."
        },
        "source_selection": {
            "state": "workspace-manifest",
            "selection_mode": "offline-artifact",
            "silent_fallback": false,
            "provenance_recorded": false,
            "source_kind": null,
            "source_uri": null
        },
        "offline_readiness": {
            "state": "manifest-declared",
            "requested_zone": null,
            "supported_by_manifest": null,
            "supported_zones": ["z:work"],
            "manifest_zones": ["z:work"],
            "explanation": "The connector declares a work-zone surface, but no live mesh route was queried."
        },
        "repair_hints": [
            "Use `fwc mesh availability github --host <endpoint>` when you need authoritative live runtime state."
        ],
        "resolution": {
            "knowledge_state": "offline",
            "resolver_branch": "offline-manifest",
            "authoritative_scope": "workspace-manifests",
            "mesh_backed": false,
            "degraded": false,
            "fallback_derived": false,
            "reason": "Resolved from workspace manifests without a live host query."
        },
        "evidence_handles": [
            {
                "kind": "workspace-manifest",
                "connector_id": "fcp.github",
                "manifest_path": "connectors/github/manifest.toml"
            }
        ],
        "next_actions": [
            "Run with `--host <endpoint>` to prove live placement.",
            "Use `--require-source any-live` when offline planning data is insufficient."
        ],
        "provenance": {
            "command": "mesh",
            "source": "workspace_manifest",
            "availability": "offline-artifact",
            "authoritative": false,
            "caveat": "Workspace manifests do not prove live placement."
        },
        "explanation": [
            "Offline evidence can explain declared placement only.",
            "A live host query is required for authoritative routing state."
        ],
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": truth_source,
        "availability": command_availability("mesh", CommandAvailability::OfflineArtifact)
    })
}

fn connector_lease_status_success_payload(truth_source: &str) -> Value {
    json!({
        "status": "ok",
        "command": "connector",
        "subcommand": "lease status",
        "schema_version": "1.0.0",
        "source": "offline-mesh-context",
        "message": "Computed offline singleton-writer lease ladder for `github` from persisted mesh context.",
        "connector": {
            "requested_selector": "github",
            "slug": "github",
            "canonical_id": "fcp.github",
            "name": "GitHub",
            "version": "0.1.0"
        },
        "config_path": "/tmp/fcp-context/contexts.toml",
        "current_context": "local",
        "context": {
            "name": "local",
            "endpoint": "unix:///tmp/fcp-dev.sock",
            "default_zone": "z:work",
            "node_identity": null,
            "config_overrides": {}
        },
        "zone_id": "z:work",
        "subject_id": "1111111111111111111111111111111111111111111111111111111111111111",
        "purpose": "connector_state_write",
        "holder_node_id_hash": "blake3:holder",
        "fencing_token": null,
        "expiry": null,
        "quorum_signers_count": 0,
        "ranked_holders": [
            {
                "rank": 1,
                "node": "node-alpha",
                "node_id_hash": "blake3:alpha"
            }
        ],
        "effective_target": {
            "connector": "github",
            "requested_selector": "github",
            "node": "node-alpha",
            "source": "active-default"
        },
        "live_host": {
            "requested": false,
            "route_available": false,
            "state": "offline"
        },
        "warnings": [
            "Offline lease status is derived from local mesh context and does not prove live quorum state."
        ],
        "next_actions": [
            "fwc --host <endpoint> connector lease status --connector github --zone z:work --json"
        ],
        "_truth_source": truth_source,
        "availability": command_availability("connector", CommandAvailability::OfflineArtifact)
    })
}

fn success_payload(case: CommandSchemaCase, truth_source: &str) -> Value {
    if case.file == "list.schema.json" {
        return list_success_payload(truth_source);
    }
    if case.file == "show.schema.json" {
        return show_success_payload(truth_source);
    }
    if case.file == "status.schema.json" {
        return status_success_payload(truth_source);
    }
    if case.file == "doctor.schema.json" {
        return doctor_success_payload(truth_source);
    }
    if case.file == "context_current.schema.json" {
        return context_current_success_payload(truth_source);
    }
    if case.file == "history.schema.json" {
        return history_success_payload(truth_source);
    }
    if case.file == "search.schema.json" {
        return search_success_payload(truth_source);
    }
    if case.file == "schema.schema.json" {
        return schema_success_payload(truth_source);
    }
    if case.file == "audit_chain_status.schema.json" {
        return audit_chain_status_success_payload(truth_source);
    }
    if case.file == "audit_verify.schema.json" {
        return audit_verify_success_payload(truth_source);
    }
    if case.file == "mesh_explain_availability.schema.json" {
        return mesh_explain_availability_success_payload(truth_source);
    }
    if case.file == "connector_lease_status.schema.json" {
        return connector_lease_status_success_payload(truth_source);
    }
    envelope_payload(case, "ok", case.success_schema_version, truth_source)
}

fn error_payload(case: CommandSchemaCase) -> Value {
    let mut payload = envelope_payload(case, "error", case.error_schema_version, "offline");
    payload["error"] = json!({
        "type": "truth-source-unavailable",
        "required": "any-live",
        "actual": "offline",
        "message": format!(
            "`fwc {}` resolved from `offline` truth, which does not satisfy `--require-source any-live`.",
            command_invocation(case)
        ),
        "recoverable": true,
    });
    payload["next_actions"] = json!([
        "Retry after the required live truth source is reachable.",
        "Relax the requirement if `offline` truth is acceptable for this workflow."
    ]);
    if let Some(availability) = truth_source_unavailable_availability(case) {
        payload["availability"] = availability;
    }
    payload
}

fn show_connector_resolution_error_payload() -> Value {
    json!({
        "status": "error",
        "command": "show",
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": "offline",
        "error": {
            "type": "connector-not-found",
            "message": "`githuub` did not match any connector in the workspace catalog.",
            "recoverable": true,
            "selector": "githuub",
            "did_you_mean": ["github"],
            "examples": ["fwc show github"],
            "next_actions": [
                "Use `fwc list` or `fwc search <term>` to narrow the connector first.",
                "Use `fwc ops <connector>` before `schema` or `examples` when the operation name is uncertain."
            ]
        }
    })
}

fn status_connector_resolution_error_payload() -> Value {
    json!({
        "status": "error",
        "command": "status",
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": "host",
        "error": {
            "type": "connector-not-found",
            "message": "`githuub` did not match any connector in the workspace catalog.",
            "recoverable": true,
            "selector": "githuub",
            "did_you_mean": ["github"],
            "examples": ["fwc status github"],
            "next_actions": [
                "Use `fwc list` or `fwc search <term>` to narrow the connector first.",
                "Use `fwc ops <connector>` before `schema` or `examples` when the operation name is uncertain."
            ]
        }
    })
}

fn resolver_internal_error_payload(case: CommandSchemaCase) -> Value {
    let mut payload = envelope_payload(case, "error", case.error_schema_version, "unavailable");
    let availability = resolver_internal_error_availability(case);
    let message = if availability.is_some() {
        format!(
            "`fwc {}` could not classify live truth because the resolver failed internally.",
            command_invocation(case)
        )
    } else {
        "`fwc` could not classify live truth because the resolver failed internally.".to_owned()
    };
    payload["error"] = json!({
        "type": "truth-resolver-internal-error",
        "message": message,
        "recoverable": false,
        "redacted_cause": "best-available strategy exhausted 1 source(s): mesh:error",
        "log_event": "fcp.truth_resolver.internal_error",
        "correlation_id": "01234567-89ab-cdef-0123-456789abcdef",
        "bead_reference": "flywheel_connectors-hr0rr.2.5",
    });
    payload["next_actions"] = json!([
        "Inspect logs for `fcp.truth_resolver.internal_error` with the returned correlation_id.",
        "Treat this response as non-authoritative until the resolver bug is fixed.",
        "If the workflow cannot wait, use a lower-level host-backed command and record the weaker truth source.",
    ]);
    if let Some(availability) = availability {
        payload["availability"] = availability;
    }
    payload
}

fn context_current_runtime_truth_source_unavailable_payload() -> Value {
    json!({
        "status": "error",
        "command": "context current",
        "schema_version": "fcp.fwc.truth-source.v1",
        "_truth_source": "node-local",
        "error": {
            "type": "truth-source-unavailable",
            "required": "any-live",
            "actual": "node-local",
            "message": "`fwc context current` resolved from `node-local` truth, which does not satisfy `--require-source any-live`.",
            "recoverable": true
        },
        "next_actions": [
            "Retry after the required live truth source is reachable.",
            "Relax the requirement if `node-local` truth is acceptable for this workflow."
        ],
        "availability": command_availability("context current", CommandAvailability::Unavailable)
    })
}

fn assert_valid(validator: &Validator, payload: &Value, label: &str) {
    let errors = validator
        .iter_errors(payload)
        .map(|error| format!("{} at {}", error, error.instance_path()))
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "{label} should validate against fwc command schema: {errors:?}"
    );
}

#[test]
fn fwc_command_truth_source_schemas_compile_and_validate_envelopes() {
    for case in CASES {
        let validator = validator(case.file);
        for truth_source in TRUTH_SOURCES {
            let payload = success_payload(*case, truth_source);
            assert_valid(&validator, &payload, case.file);
        }

        assert_valid(&validator, &error_payload(*case), case.file);
    }
}

#[test]
fn fwc_command_truth_source_schemas_validate_resolver_internal_error_envelopes() {
    for case in CASES {
        let validator = validator(case.file);
        let payload = resolver_internal_error_payload(*case);

        assert_valid(&validator, &payload, case.file);
        assert_eq!(payload["status"], "error");
        assert_eq!(payload["_truth_source"], "unavailable");
        assert_eq!(payload["error"]["type"], "truth-resolver-internal-error");
        assert_eq!(
            payload["error"]["log_event"],
            "fcp.truth_resolver.internal_error"
        );
        assert_eq!(
            payload["error"]["bead_reference"],
            "flywheel_connectors-hr0rr.2.5"
        );
        assert!(
            payload["error"]["redacted_cause"]
                .as_str()
                .is_some_and(|cause| !cause.is_empty())
        );
        assert!(
            payload["error"]["correlation_id"]
                .as_str()
                .is_some_and(|id| !id.is_empty())
        );
    }
}

#[test]
fn fwc_command_truth_source_schemas_reject_missing_truth_source() {
    for case in CASES {
        let validator = validator(case.file);
        let mut payload = success_payload(*case, "offline");
        payload
            .as_object_mut()
            .expect("envelope payload must be an object")
            .remove("_truth_source");

        assert!(
            !validator.is_valid(&payload),
            "{} should reject envelopes missing _truth_source",
            case.file
        );
    }
}

#[test]
fn fwc_command_truth_source_schemas_reject_unknown_truth_source() {
    for case in CASES {
        let validator = validator(case.file);
        let payload = success_payload(*case, "probably-live");

        assert!(
            !validator.is_valid(&payload),
            "{} should reject unknown truth sources",
            case.file
        );
    }
}

#[test]
fn fwc_command_truth_source_schemas_reject_incomplete_truth_source_unavailable_errors() {
    for case in CASES {
        let validator = validator(case.file);
        let mut payload = error_payload(*case);
        payload["error"]
            .as_object_mut()
            .expect("truth-source error must be an object")
            .remove("required");

        assert!(
            !validator.is_valid(&payload),
            "{} should reject truth-source-unavailable errors missing required fields",
            case.file
        );
    }
}

#[test]
fn fwc_command_truth_source_schemas_reject_incomplete_resolver_internal_errors() {
    for case in CASES {
        let validator = validator(case.file);
        let mut payload = resolver_internal_error_payload(*case);
        payload["error"]
            .as_object_mut()
            .expect("resolver-internal error must be an object")
            .remove("correlation_id");

        assert!(
            !validator.is_valid(&payload),
            "{} should reject resolver-internal errors missing correlation_id",
            case.file
        );
    }
}

#[test]
fn fwc_command_truth_source_schemas_reject_wrong_command_identity() {
    for case in CASES.iter().filter(|case| case.command_required_on_success) {
        let validator = validator(case.file);
        let mut payload = success_payload(*case, "offline");
        payload["command"] = json!("wrong");

        assert!(
            !validator.is_valid(&payload),
            "{} should reject the wrong command identity",
            case.file
        );
    }
}

#[test]
fn fwc_command_truth_source_schemas_reject_wrong_subcommand_identity() {
    for case in CASES
        .iter()
        .filter(|case| case.command_required_on_success && case.subcommand.is_some())
    {
        let validator = validator(case.file);
        let mut payload = success_payload(*case, "offline");
        payload["subcommand"] = json!("wrong");

        assert!(
            !validator.is_valid(&payload),
            "{} should reject the wrong subcommand identity",
            case.file
        );
    }
}

#[test]
fn fwc_context_current_schema_validates_runtime_truth_source_unavailable_error() {
    let validator = validator("context_current.schema.json");
    let payload = context_current_runtime_truth_source_unavailable_payload();

    assert_valid(
        &validator,
        &payload,
        "context_current.schema.json runtime truth-source error",
    );
    assert_eq!(payload["command"], "context current");
    assert_eq!(payload["error"]["actual"], "node-local");
}

#[test]
fn fwc_context_current_schema_rejects_unknown_top_level_success_fields() {
    let validator = validator("context_current.schema.json");
    let mut payload = context_current_success_payload("node-local");
    payload["surprise"] = json!("not part of the context current contract");

    assert!(
        !validator.is_valid(&payload),
        "context current schema should reject unknown top-level success fields"
    );
}

#[test]
fn fwc_context_current_schema_rejects_success_without_context() {
    let validator = validator("context_current.schema.json");
    let mut payload = context_current_success_payload("node-local");
    payload
        .as_object_mut()
        .expect("context current success payload must be an object")
        .remove("context");

    assert!(
        !validator.is_valid(&payload),
        "context current schema should reject success payloads missing active context detail"
    );
}

#[test]
fn fwc_context_current_schema_rejects_success_without_config_path() {
    let validator = validator("context_current.schema.json");
    let mut payload = context_current_success_payload("node-local");
    payload
        .as_object_mut()
        .expect("context current success payload must be an object")
        .remove("config_path");

    assert!(
        !validator.is_valid(&payload),
        "context current schema should reject success payloads missing config_path"
    );
}

#[test]
fn fwc_audit_chain_status_schema_rejects_unknown_top_level_success_fields() {
    let validator = validator("audit_chain_status.schema.json");
    let mut payload = audit_chain_status_success_payload("offline");
    payload["surprise"] = json!("not part of the audit chain status contract");

    assert!(
        !validator.is_valid(&payload),
        "audit chain status schema should reject unknown top-level success fields"
    );
}

#[test]
fn fwc_audit_chain_status_schema_rejects_success_without_source() {
    let validator = validator("audit_chain_status.schema.json");
    let mut payload = audit_chain_status_success_payload("offline");
    payload
        .as_object_mut()
        .expect("audit chain status success payload must be an object")
        .remove("source");

    assert!(
        !validator.is_valid(&payload),
        "audit chain status schema should reject success payloads missing source detail"
    );
}

#[test]
fn fwc_audit_chain_status_schema_rejects_source_without_kind() {
    let validator = validator("audit_chain_status.schema.json");
    let mut payload = audit_chain_status_success_payload("offline");
    payload["source"]
        .as_object_mut()
        .expect("audit chain status source must be an object")
        .remove("kind");

    assert!(
        !validator.is_valid(&payload),
        "audit chain status schema should reject source payloads missing kind"
    );
}

#[test]
fn fwc_audit_verify_schema_rejects_unknown_top_level_success_fields() {
    let validator = validator("audit_verify.schema.json");
    let mut payload = audit_verify_success_payload("offline");
    payload["command"] = json!("audit");

    assert!(
        !validator.is_valid(&payload),
        "audit verify schema should reject command fields that runtime success does not emit"
    );
}

#[test]
fn fwc_audit_verify_schema_rejects_success_without_issues() {
    let validator = validator("audit_verify.schema.json");
    let mut payload = audit_verify_success_payload("offline");
    payload
        .as_object_mut()
        .expect("audit verify success payload must be an object")
        .remove("issues");

    assert!(
        !validator.is_valid(&payload),
        "audit verify schema should reject success payloads missing issues"
    );
}

#[test]
fn fwc_audit_verify_schema_rejects_issue_without_code() {
    let validator = validator("audit_verify.schema.json");
    let mut payload = audit_verify_success_payload("offline");
    payload["issues"][0]
        .as_object_mut()
        .expect("audit verify issue must be an object")
        .remove("code");

    assert!(
        !validator.is_valid(&payload),
        "audit verify schema should reject issues missing codes"
    );
}

#[test]
fn fwc_mesh_explain_availability_schema_rejects_unknown_top_level_success_fields() {
    let validator = validator("mesh_explain_availability.schema.json");
    let mut payload = mesh_explain_availability_success_payload("offline");
    payload["surprise"] = json!("not part of the mesh explain-availability contract");

    assert!(
        !validator.is_valid(&payload),
        "mesh explain-availability schema should reject unknown top-level success fields"
    );
}

#[test]
fn fwc_mesh_explain_availability_schema_rejects_success_without_availability_fact() {
    let validator = validator("mesh_explain_availability.schema.json");
    let mut payload = mesh_explain_availability_success_payload("offline");
    payload
        .as_object_mut()
        .expect("mesh explain-availability success payload must be an object")
        .remove("availability_fact");

    assert!(
        !validator.is_valid(&payload),
        "mesh explain-availability schema should reject payloads missing availability_fact"
    );
}

#[test]
fn fwc_mesh_explain_availability_schema_rejects_resolution_without_branch() {
    let validator = validator("mesh_explain_availability.schema.json");
    let mut payload = mesh_explain_availability_success_payload("offline");
    payload["resolution"]
        .as_object_mut()
        .expect("mesh explain-availability resolution must be an object")
        .remove("resolver_branch");

    assert!(
        !validator.is_valid(&payload),
        "mesh explain-availability schema should reject resolution payloads missing resolver_branch"
    );
}

#[test]
fn fwc_connector_lease_status_schema_rejects_unknown_top_level_success_fields() {
    let validator = validator("connector_lease_status.schema.json");
    let mut payload = connector_lease_status_success_payload("offline");
    payload["surprise"] = json!("not part of the connector lease status contract");

    assert!(
        !validator.is_valid(&payload),
        "connector lease status schema should reject unknown top-level success fields"
    );
}

#[test]
fn fwc_connector_lease_status_schema_rejects_success_without_ranked_holders() {
    let validator = validator("connector_lease_status.schema.json");
    let mut payload = connector_lease_status_success_payload("offline");
    payload
        .as_object_mut()
        .expect("connector lease status success payload must be an object")
        .remove("ranked_holders");

    assert!(
        !validator.is_valid(&payload),
        "connector lease status schema should reject payloads missing ranked_holders"
    );
}

#[test]
fn fwc_connector_lease_status_schema_rejects_live_host_without_route_flag() {
    let validator = validator("connector_lease_status.schema.json");
    let mut payload = connector_lease_status_success_payload("offline");
    payload["live_host"]
        .as_object_mut()
        .expect("connector lease status live_host must be an object")
        .remove("route_available");

    assert!(
        !validator.is_valid(&payload),
        "connector lease status schema should reject live_host payloads missing route availability"
    );
}

#[test]
fn fwc_list_schema_rejects_unknown_top_level_success_fields() {
    let validator = validator("list.schema.json");
    let mut payload = list_success_payload("offline");
    payload["surprise"] = json!("not part of the list contract");

    assert!(
        !validator.is_valid(&payload),
        "list schema should reject unknown top-level success fields"
    );
}

#[test]
fn fwc_list_schema_rejects_success_without_connectors() {
    let validator = validator("list.schema.json");
    let mut payload = list_success_payload("offline");
    payload
        .as_object_mut()
        .expect("list success payload must be an object")
        .remove("connectors");

    assert!(
        !validator.is_valid(&payload),
        "list schema should reject success payloads missing connectors"
    );
}

#[test]
fn fwc_history_schema_validates_entry_lookup_success() {
    let validator = validator("history.schema.json");
    let payload = history_entry_lookup_payload("offline");

    assert_valid(
        &validator,
        &payload,
        "history.schema.json entry lookup success",
    );
    assert_eq!(payload["scope"], "entry");
    assert_eq!(payload["entry"]["status"], "success");
}

#[test]
fn fwc_history_schema_validates_not_found_error() {
    let validator = validator("history.schema.json");
    let payload = history_not_found_payload();

    assert_valid(&validator, &payload, "history.schema.json not-found error");
    assert_eq!(payload["status"], "error");
    assert_eq!(payload["error"]["type"], "not-found");
    assert_eq!(payload["_truth_source"], "offline");
}

#[test]
fn fwc_history_schema_rejects_unknown_top_level_success_fields() {
    let validator = validator("history.schema.json");
    let mut payload = history_success_payload("offline");
    payload["surprise"] = json!("not part of the history contract");

    assert!(
        !validator.is_valid(&payload),
        "history schema should reject unknown top-level list fields"
    );
}

#[test]
fn fwc_history_schema_rejects_list_success_without_filter() {
    let validator = validator("history.schema.json");
    let mut payload = history_success_payload("offline");
    payload
        .as_object_mut()
        .expect("history list success payload must be an object")
        .remove("filter");

    assert!(
        !validator.is_valid(&payload),
        "history schema should reject list success payloads missing filters"
    );
}

#[test]
fn fwc_history_schema_rejects_entry_lookup_without_entry_id() {
    let validator = validator("history.schema.json");
    let mut payload = history_entry_lookup_payload("offline");
    payload["entry"]
        .as_object_mut()
        .expect("history entry payload must be an object")
        .remove("entry_id");

    assert!(
        !validator.is_valid(&payload),
        "history schema should reject entry lookup payloads missing entry_id"
    );
}

#[test]
fn fwc_history_schema_rejects_not_found_without_message() {
    let validator = validator("history.schema.json");
    let mut payload = history_not_found_payload();
    payload["error"]
        .as_object_mut()
        .expect("history not-found error must be an object")
        .remove("message");

    assert!(
        !validator.is_valid(&payload),
        "history schema should reject not-found errors missing message"
    );
}

#[test]
fn fwc_show_schema_validates_connector_resolution_errors() {
    let validator = validator("show.schema.json");
    let payload = show_connector_resolution_error_payload();

    assert_valid(
        &validator,
        &payload,
        "show.schema.json connector resolution error",
    );
    assert_eq!(payload["error"]["type"], "connector-not-found");
    assert_eq!(payload["_truth_source"], "offline");
}

#[test]
fn fwc_show_schema_rejects_unknown_top_level_success_fields() {
    let validator = validator("show.schema.json");
    let mut payload = show_success_payload("offline");
    payload["surprise"] = json!("not part of the show contract");

    assert!(
        !validator.is_valid(&payload),
        "show schema should reject unknown top-level success fields"
    );
}

#[test]
fn fwc_show_schema_rejects_success_without_connector() {
    let validator = validator("show.schema.json");
    let mut payload = show_success_payload("offline");
    payload
        .as_object_mut()
        .expect("show success payload must be an object")
        .remove("connector");

    assert!(
        !validator.is_valid(&payload),
        "show schema should reject success payloads missing connector detail"
    );
}

#[test]
fn fwc_show_schema_rejects_incomplete_operation_preview() {
    let validator = validator("show.schema.json");
    let mut payload = show_success_payload("offline");
    payload["operations"]["preview"][0]
        .as_object_mut()
        .expect("show operation preview must be an object")
        .remove("selector");

    assert!(
        !validator.is_valid(&payload),
        "show schema should reject operation previews missing selectors"
    );
}

#[test]
fn fwc_status_schema_validates_connector_success() {
    let validator = validator("status.schema.json");
    let payload = status_connector_success_payload("host");

    assert_valid(&validator, &payload, "status.schema.json connector success");
    assert_eq!(payload["scope"], "connector");
    assert_eq!(payload["provenance"]["scope"], "connector-status");
}

#[test]
fn fwc_status_schema_validates_connector_resolution_errors() {
    let validator = validator("status.schema.json");
    let payload = status_connector_resolution_error_payload();

    assert_valid(
        &validator,
        &payload,
        "status.schema.json connector resolution error",
    );
    assert_eq!(payload["error"]["type"], "connector-not-found");
    assert_eq!(payload["_truth_source"], "host");
}

#[test]
fn fwc_status_schema_rejects_unknown_top_level_success_fields() {
    let validator = validator("status.schema.json");
    let mut payload = status_success_payload("host");
    payload["surprise"] = json!("not part of the status contract");

    assert!(
        !validator.is_valid(&payload),
        "status schema should reject unknown top-level success fields"
    );
}

#[test]
fn fwc_status_schema_rejects_success_without_connectors() {
    let validator = validator("status.schema.json");
    let mut payload = status_success_payload("host");
    payload
        .as_object_mut()
        .expect("status success payload must be an object")
        .remove("connectors");

    assert!(
        !validator.is_valid(&payload),
        "status schema should reject fleet success payloads missing connectors"
    );
}

#[test]
fn fwc_status_schema_rejects_connector_success_without_admin() {
    let validator = validator("status.schema.json");
    let mut payload = status_connector_success_payload("host");
    payload
        .as_object_mut()
        .expect("status connector success payload must be an object")
        .remove("admin");

    assert!(
        !validator.is_valid(&payload),
        "status schema should reject connector success payloads missing admin status"
    );
}

#[test]
fn fwc_doctor_schema_validates_local_probe_success() {
    let validator = validator("doctor.schema.json");
    let payload = doctor_local_probe_success_payload();

    assert_valid(
        &validator,
        &payload,
        "doctor.schema.json local probe success",
    );
    assert_eq!(payload["probe"], "hlc");
    assert_eq!(payload["_truth_source"], "offline");
}

#[test]
fn fwc_doctor_schema_rejects_unknown_top_level_success_fields() {
    let validator = validator("doctor.schema.json");
    let mut payload = doctor_success_payload("host");
    payload["surprise"] = json!("not part of the doctor contract");

    assert!(
        !validator.is_valid(&payload),
        "doctor schema should reject unknown top-level success fields"
    );
}

#[test]
fn fwc_doctor_schema_rejects_success_without_report() {
    let validator = validator("doctor.schema.json");
    let mut payload = doctor_success_payload("host");
    payload
        .as_object_mut()
        .expect("doctor success payload must be an object")
        .remove("report");

    assert!(
        !validator.is_valid(&payload),
        "doctor schema should reject success payloads missing the host report"
    );
}

#[test]
fn fwc_doctor_schema_rejects_success_without_diagnosis() {
    let validator = validator("doctor.schema.json");
    let mut payload = doctor_success_payload("host");
    payload
        .as_object_mut()
        .expect("doctor success payload must be an object")
        .remove("diagnosis");

    assert!(
        !validator.is_valid(&payload),
        "doctor schema should reject host success payloads missing local diagnosis details"
    );
}

#[test]
fn fwc_schema_schema_validates_fields_success() {
    let validator = validator("schema.schema.json");
    let payload = schema_fields_success_payload("offline");

    assert_valid(&validator, &payload, "schema.schema.json fields success");
    assert_eq!(payload["scope"], "fields");
    assert_eq!(payload["field_count"], 1);
}

#[test]
fn fwc_schema_schema_validates_scaffold_success() {
    let validator = validator("schema.schema.json");
    let payload = schema_scaffold_success_payload("offline");

    assert_valid(&validator, &payload, "schema.schema.json scaffold success");
    assert_eq!(payload["scope"], "scaffold");
    assert!(payload["scaffold"].is_object());
}

#[test]
fn fwc_schema_schema_validates_connector_success() {
    let validator = validator("schema.schema.json");
    let payload = schema_connector_success_payload("offline");

    assert_valid(&validator, &payload, "schema.schema.json connector success");
    assert_eq!(payload["scope"], "connector");
    assert!(payload["schema"].is_object());
}

#[test]
fn fwc_schema_schema_validates_resolution_errors() {
    let validator = validator("schema.schema.json");
    let connector_payload = schema_connector_resolution_error_payload();
    let operation_payload = schema_operation_resolution_error_payload();

    assert_valid(
        &validator,
        &connector_payload,
        "schema.schema.json connector resolution error",
    );
    assert_valid(
        &validator,
        &operation_payload,
        "schema.schema.json operation resolution error",
    );
    assert_eq!(connector_payload["error"]["type"], "connector-not-found");
    assert_eq!(operation_payload["error"]["type"], "operation-not-found");
}

#[test]
fn fwc_schema_schema_rejects_unknown_top_level_success_fields() {
    let validator = validator("schema.schema.json");
    let mut payload = schema_success_payload("offline");
    payload["surprise"] = json!("not part of the schema contract");

    assert!(
        !validator.is_valid(&payload),
        "schema schema should reject unknown top-level success fields"
    );
}

#[test]
fn fwc_schema_schema_rejects_operation_success_without_input_schema() {
    let validator = validator("schema.schema.json");
    let mut payload = schema_success_payload("offline");
    payload
        .as_object_mut()
        .expect("schema operation success payload must be an object")
        .remove("input_schema");

    assert!(
        !validator.is_valid(&payload),
        "schema schema should reject operation success payloads missing input_schema"
    );
}

#[test]
fn fwc_schema_schema_rejects_fields_success_without_fields() {
    let validator = validator("schema.schema.json");
    let mut payload = schema_fields_success_payload("offline");
    payload
        .as_object_mut()
        .expect("schema fields success payload must be an object")
        .remove("fields");

    assert!(
        !validator.is_valid(&payload),
        "schema schema should reject fields success payloads missing fields"
    );
}

#[test]
fn fwc_schema_schema_rejects_scaffold_success_without_scaffold() {
    let validator = validator("schema.schema.json");
    let mut payload = schema_scaffold_success_payload("offline");
    payload
        .as_object_mut()
        .expect("schema scaffold success payload must be an object")
        .remove("scaffold");

    assert!(
        !validator.is_valid(&payload),
        "schema schema should reject scaffold success payloads missing scaffold"
    );
}

#[test]
fn fwc_swarm_pressure_schema_validates_redaction_safe_artifact() {
    let validator = validator("swarm_pressure.schema.json");
    let payload = json!({
        "status": "ok",
        "command": "swarm pressure",
        "schema_version": "fwc.swarm-pressure/v1",
        "generated_at": "2026-06-05T10:00:00Z",
        "source": {
            "fixture": "fixture:pressure_fixture.json",
            "mode": "fixture",
            "caveat": "This command is read-only and never starts Cargo work."
        },
        "pressure_score_0_100": 55,
        "verdict": "yellow",
        "signals": [
            {
                "name": "cpu_capacity",
                "status": "green",
                "value": "32 logical CPU(s)",
                "threshold": ">=8 green, >=2 yellow, 1 red",
                "evidence": {
                    "source": "fixture"
                }
            },
            {
                "name": "rch_status",
                "status": "degraded",
                "value": "unavailable",
                "threshold": "rch queued jobs known",
                "evidence": {
                    "source": "not-yet-wired",
                    "degraded_reason": "rch status unavailable"
                }
            }
        ],
        "recommended_agent_slots": 4,
        "recommended_cargo_lanes": 1,
        "remediation_commands": [
            "continue with normal rch-backed validation"
        ],
        "telemetry_event": {
            "name": "fwc.swarm_pressure.run",
            "fields": {
                "verdict": "yellow",
                "pressure_score": 55,
                "degraded_dependency_count": 1,
                "recommended_agent_slots": 4
            }
        },
        "message": "Swarm pressure is Yellow with score 55/100; 1 signal(s) are degraded.",
        "toon": "swarm pressure verdict=yellow score=55 degraded=1"
    });

    assert_valid(&validator, &payload, "swarm_pressure.schema.json");

    let mut unsafe_payload = payload;
    unsafe_payload["source"]["fixture"] = json!("/Users/operator/private/pressure.json");
    assert!(
        !validator.is_valid(&unsafe_payload),
        "swarm pressure schema should reject raw fixture paths"
    );
}

#[test]
fn fwc_agent_bootstrap_report_schema_validates_report() {
    let validator = validator("agent_bootstrap_report.schema.json");
    let payload = json!({
        "agent_name": "TestAgent",
        "mode": "fresh",
        "identity": {
            "created": true,
            "agent_mail_status": "registered",
            "owner_email": "operator@example.dev",
            "identity_id": "agent-test-id"
        },
        "reservation": {
            "scope": "crates/fwc/**",
            "ttl_seconds": 3600,
            "extended": false,
            "reason": "flywheel_connectors-angoc.6.2.1",
            "expires_at": "2026-06-07T16:10:05Z"
        },
        "ready_beads": [
            {
                "id": "flywheel_connectors-angoc.6.2.1",
                "title": "Agent bootstrap ratchet",
                "priority": 3,
                "score": 0.42
            }
        ],
        "commit_template": {
            "path": ".git/info/exclude_template",
            "written": true
        },
        "doctor": {
            "probes_run": 3,
            "passed": 2,
            "failed": 0,
            "skipped": 1,
            "by_probe": {
                "agent_mail": "pass",
                "beads": "pass",
                "cargo": "skipped"
            }
        },
        "total_duration_ms": 42,
        "exit_code": 0
    });

    assert_valid(
        &validator,
        &payload,
        "agent_bootstrap_report.schema.json success",
    );

    let mut missing_identity_created = payload.clone();
    missing_identity_created["identity"]
        .as_object_mut()
        .expect("identity must be an object")
        .remove("created");
    assert!(
        !validator.is_valid(&missing_identity_created),
        "agent bootstrap schema should reject identity reports without created"
    );

    let mut cli_wrapped_payload = payload;
    cli_wrapped_payload["command"] = json!("agent-bootstrap");
    assert!(
        !validator.is_valid(&cli_wrapped_payload),
        "agent bootstrap report schema should reject CLI wrapper fields"
    );
}

#[test]
fn fwc_proof_queue_schema_validates_queue_file() {
    let validator = validator("proof_queue.schema.json");
    let payload = json!({
        "schema_version": "fcp.fwc.proof.queue.v1",
        "jobs": [
            {
                "schema_version": "fcp.fwc.proof.queue.v1",
                "job_id": "job-001",
                "bead_id": "flywheel_connectors-angoc.6.3.2",
                "lane": "crate-test",
                "state": "active",
                "priority": 3,
                "estimated_slots": 1,
                "timeout_secs": 1800,
                "remote_required": true,
                "argv": ["cargo", "test", "-p", "fwc"],
                "working_directory": null,
                "target_dir_policy": "isolated-temp",
                "environment": {
                    "CARGO_INCREMENTAL": "0",
                    "CARGO_BUILD_JOBS": "2"
                },
                "redaction_policy": [
                    "omit provider credentials",
                    "omit raw request bodies"
                ],
                "admission": {
                    "decision": "accepted",
                    "capacity_decision": "green",
                    "worker_selection": "worker-a",
                    "blocker_reason": null,
                    "reason": "remote capacity accepted the proof job"
                },
                "created_at_unix_ms": 1,
                "updated_at_unix_ms": 2
            }
        ]
    });

    assert_valid(&validator, &payload, "proof_queue.schema.json queue file");

    let mut missing_argv = payload.clone();
    missing_argv["jobs"][0]
        .as_object_mut()
        .expect("proof job must be an object")
        .remove("argv");
    assert!(
        !validator.is_valid(&missing_argv),
        "proof queue schema should reject jobs without argv"
    );

    let mut unknown_top_level = payload;
    unknown_top_level["surprise"] = json!("not part of the proof queue contract");
    assert!(
        !validator.is_valid(&unknown_top_level),
        "proof queue schema should reject unknown top-level fields"
    );
}

#[test]
fn every_fwc_schema_file_has_validator_reference() {
    let schema_files = fwc_schema_files();
    let referenced = referenced_schema_files(&schema_files);
    let missing = schema_files
        .difference(&referenced)
        .cloned()
        .collect::<Vec<_>>();

    assert!(
        missing.is_empty(),
        "every crates/fwc/schemas/*.schema.json file must have a Rust validator reference; missing: {missing:?}"
    );
}
