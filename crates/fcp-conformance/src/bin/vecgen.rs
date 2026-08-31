//! Schema hash and canonical CBOR vector generator CLI.
//!
//! Generate deterministic golden vectors for FCP2 conformance testing.
//!
//! # Usage
//!
//! ```bash
//! # Generate all core schema vectors to default output
//! cargo run -p fcp-conformance --bin fcp-vecgen
//!
//! # Generate to specific directory
//! cargo run -p fcp-conformance --bin fcp-vecgen -- --out ./vectors
//!
//! # List available schemas
//! cargo run -p fcp-conformance --bin fcp-vecgen -- --list
//!
//! # Verify vectors against stored baseline (CI mode)
//! cargo run -p fcp-conformance --bin fcp-vecgen -- --verify --baseline tests/vectors/serialization/core_vectors.json
//! ```

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use chrono::{TimeZone, Utc};
use clap::Parser;
use fcp_cbor::SchemaId;
use fcp_conformance::vecgen::{
    GeneratedVector, PayloadVector, SchemaRegistration, VecGenError, core_schema_registrations,
    generate_schema_hash, serialize_to_canonical_cbor, write_vectors_to_file,
};
use fcp_prelude::{
    AuditEvent, CapabilityConstraints, CapabilityGrant, CapabilityId, CapabilityObject,
    ConnectorId, CorrelationId, EventData, EventEnvelope, InstanceId, NodeId, NodeSignature,
    ObjectHeader, ObjectId, OperationId, OperationIntent, OperationReceipt, Principal, PrincipalId,
    Provenance, TailscaleNodeId, TrustLevel, Uuid, ZoneId,
};
use semver::Version;
use serde::{Deserialize, Serialize};

/// FCP2 Schema Hash and Vector Generator.
///
/// Generates deterministic golden vectors for conformance testing.
/// Output is stable across runs and platforms.
#[derive(Parser, Debug)]
#[command(name = "fcp-vecgen")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Output directory for generated vectors.
    #[arg(short, long, default_value = "generated_vectors")]
    out: PathBuf,

    /// List available schemas without generating.
    #[arg(long, default_value_t = false)]
    list: bool,

    /// Generate only the specified schema (namespace:name@version).
    #[arg(long)]
    schema: Option<String>,

    /// Output format (json or cbor).
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    format: OutputFormat,

    /// Verify existing vectors instead of generating.
    #[arg(long, default_value_t = false)]
    verify: bool,

    /// Path to baseline vectors file for verification.
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Output JSONL log file for structured CI output.
    #[arg(long)]
    log_jsonl: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum OutputFormat {
    Json,
    Cbor,
}

/// Test struct matching the existing golden vector format.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GoldenStruct {
    id: u64,
    name: String,
    active: bool,
}

#[derive(Debug, Clone)]
enum SampleValue {
    GoldenStruct(GoldenStruct),
    CapabilityObject(CapabilityObject),
    ObjectHeader(ObjectHeader),
    OperationIntent(OperationIntent),
    OperationReceipt(OperationReceipt),
    AuditEvent(AuditEvent),
    EventEnvelope(EventEnvelope),
}

#[derive(Debug, Clone)]
struct SampleCase {
    description: String,
    value: SampleValue,
}

impl SampleCase {
    fn new(description: impl Into<String>, value: SampleValue) -> Self {
        Self {
            description: description.into(),
            value,
        }
    }

    fn to_json(&self) -> Result<serde_json::Value, VecGenError> {
        match &self.value {
            SampleValue::GoldenStruct(value) => serde_json::to_value(value),
            SampleValue::CapabilityObject(value) => serde_json::to_value(value),
            SampleValue::ObjectHeader(value) => serde_json::to_value(value),
            SampleValue::OperationIntent(value) => serde_json::to_value(value),
            SampleValue::OperationReceipt(value) => serde_json::to_value(value),
            SampleValue::AuditEvent(value) => serde_json::to_value(value),
            SampleValue::EventEnvelope(value) => serde_json::to_value(value),
        }
        .map_err(|e| VecGenError::new(format!("JSON conversion failed: {e}")))
    }

    fn serialize(&self, schema: &SchemaId) -> Result<(String, String), VecGenError> {
        match &self.value {
            SampleValue::GoldenStruct(value) => serialize_to_canonical_cbor(value, schema),
            SampleValue::CapabilityObject(value) => serialize_to_canonical_cbor(value, schema),
            SampleValue::ObjectHeader(value) => serialize_to_canonical_cbor(value, schema),
            SampleValue::OperationIntent(value) => serialize_to_canonical_cbor(value, schema),
            SampleValue::OperationReceipt(value) => serialize_to_canonical_cbor(value, schema),
            SampleValue::AuditEvent(value) => serialize_to_canonical_cbor(value, schema),
            SampleValue::EventEnvelope(value) => serialize_to_canonical_cbor(value, schema),
        }
    }
}

/// A single difference found during verification.
#[derive(Debug, Clone, Serialize)]
struct VectorDiff {
    schema: String,
    field: String,
    expected: String,
    actual: String,
}

/// Verification result summary.
#[derive(Debug, Clone, Serialize)]
struct VerificationResult {
    passed: bool,
    schemas_checked: usize,
    schemas_matched: usize,
    schemas_missing: Vec<String>,
    schemas_extra: Vec<String>,
    diffs: Vec<VectorDiff>,
}

/// Assertions summary for E2E logging.
#[derive(Debug, Clone, Serialize)]
struct LogAssertions {
    passed: u64,
    failed: u64,
}

/// Structured log entry for E2E logging per `STANDARD_Testing_Logging.md`.
#[derive(Debug, Clone, Serialize)]
struct LogEntry {
    timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    level: Option<String>,
    test_name: String,
    module: String,
    phase: String,
    correlation_id: String,
    result: String,
    duration_ms: u64,
    assertions: LogAssertions,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifacts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

fn emit_log_entry(entry: &LogEntry, log_file: &mut Option<fs::File>) {
    let json = serde_json::to_string(entry).unwrap_or_default();
    if let Some(f) = log_file {
        use std::io::Write;
        let _ = writeln!(f, "{json}");
    }
    // Also emit to stderr for visibility
    let message = entry
        .details
        .as_ref()
        .and_then(|value| value.get("message"))
        .and_then(|value| value.as_str())
        .unwrap_or(&json);
    eprintln!(
        "[{}] {}",
        entry.level.as_deref().unwrap_or("info").to_uppercase(),
        message
    );
}

fn emit_schema_log(
    log_file: &mut Option<fs::File>,
    correlation_id: &str,
    schema_id: &str,
    schema_hash: &str,
) {
    if log_file.is_none() {
        return;
    }

    emit_log_entry(
        &LogEntry {
            timestamp: Utc::now().to_rfc3339(),
            level: Some("info".into()),
            test_name: "schema_vector_generation".into(),
            module: "fcp-conformance".into(),
            phase: "generate".into(),
            correlation_id: correlation_id.into(),
            result: "pass".into(),
            duration_ms: 0,
            assertions: LogAssertions {
                passed: 1,
                failed: 0,
            },
            context: None,
            artifacts: None,
            error_code: None,
            details: Some(serde_json::json!({
                "schema_id": schema_id,
                "schema_hash": schema_hash,
                "message": "Generated schema vector"
            })),
        },
        log_file,
    );
}

fn default_baseline_path() -> Option<PathBuf> {
    let json_candidate = PathBuf::from("tests/vectors/serialization/core_vectors.json");
    if json_candidate.exists() {
        return Some(json_candidate);
    }
    let cbor_candidate = PathBuf::from("tests/vectors/serialization/core_vectors.cbor");
    if cbor_candidate.exists() {
        return Some(cbor_candidate);
    }
    None
}

fn read_vectors_from_file(path: &PathBuf) -> Result<BTreeMap<String, GeneratedVector>, String> {
    let bytes = fs::read(path).map_err(|e| format!("Failed to read baseline file: {e}"))?;
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("cbor") => ciborium::de::from_reader(bytes.as_slice())
            .map_err(|e| format!("Failed to parse baseline CBOR: {e}")),
        _ => serde_json::from_slice(&bytes)
            .map_err(|e| format!("Failed to parse baseline JSON: {e}")),
    }
}

fn write_vectors_to_cbor_file(
    vectors: &BTreeMap<String, GeneratedVector>,
    output_path: &PathBuf,
) -> Result<(), VecGenError> {
    let cbor = fcp_cbor::to_canonical_cbor(vectors)
        .map_err(|e| VecGenError::new(format!("CBOR serialization failed: {e}")))?;

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| VecGenError::new(format!("failed to create directory: {e}")))?;
    }

    fs::write(output_path, cbor)
        .map_err(|e| VecGenError::new(format!("failed to write file: {e}")))?;

    Ok(())
}

const fn fixed_timestamp_secs() -> u64 {
    1_700_000_000
}

fn fixed_datetime() -> chrono::DateTime<chrono::Utc> {
    let secs = i64::try_from(fixed_timestamp_secs()).expect("timestamp fits in i64");
    Utc.timestamp_opt(secs, 0)
        .single()
        .expect("fixed timestamp must be valid")
}

fn sample_node_signature() -> NodeSignature {
    NodeSignature::new(NodeId::new("node-1"), [7_u8; 64], fixed_timestamp_secs())
}

fn sample_zone() -> ZoneId {
    ZoneId::work()
}

fn sample_object_id(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
}

fn sample_object_header(schema: SchemaId) -> ObjectHeader {
    let zone = sample_zone();
    let provenance = Provenance::new(zone.clone());
    ObjectHeader {
        encryption_kind: Default::default(),
        schema,
        zone_id: zone,
        created_at: fixed_timestamp_secs(),
        provenance,
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn sample_capability_object() -> CapabilityObject {
    CapabilityObject {
        caps: vec![CapabilityGrant {
            capability: CapabilityId::from_static("cap.read"),
            operation: Some(OperationId::from_static("op.list")),
        }],
        constraints: CapabilityConstraints {
            max_calls: Some(10),
            ..CapabilityConstraints::default()
        },
        principal: Some(PrincipalId::new("user:alice").expect("principal id must be canonical")),
        valid_from: Some(fixed_timestamp_secs()),
        valid_until: Some(fixed_timestamp_secs() + 3_600),
    }
}

fn sample_operation_intent(schema: SchemaId) -> OperationIntent {
    OperationIntent {
        header: sample_object_header(schema),
        request_object_id: sample_object_id("request-1"),
        capability_token_jti: Uuid::from_bytes([1_u8; 16]),
        idempotency_key: Some("idem-key-123".to_string()),
        planned_at: fixed_timestamp_secs(),
        planned_by: TailscaleNodeId::new("ts-node-1"),
        lease_seq: Some(42),
        upstream_idempotency: None,
        signature: sample_node_signature(),
    }
}

fn sample_operation_receipt(schema: SchemaId) -> OperationReceipt {
    OperationReceipt {
        header: sample_object_header(schema),
        request_object_id: sample_object_id("request-1"),
        idempotency_key: Some("idem-key-123".to_string()),
        outcome_object_ids: vec![sample_object_id("outcome-1")],
        resource_object_ids: vec![],
        usage_metrics: None,
        executed_at: fixed_timestamp_secs() + 120,
        executed_by: TailscaleNodeId::new("ts-node-1"),
        signature: sample_node_signature(),
    }
}

fn sample_audit_event(schema: SchemaId) -> AuditEvent {
    let zone = sample_zone();
    AuditEvent {
        header: sample_object_header(schema),
        correlation_id: CorrelationId(Uuid::from_bytes([2_u8; 16])),
        trace_context: None,
        event_type: "capability.invoke".to_string(),
        actor: PrincipalId::new("user:alice").expect("principal id must be canonical"),
        zone_id: zone,
        connector_id: Some(ConnectorId::from_static("test.connector:stream:1")),
        operation: Some(OperationId::from_static("op.list")),
        capability_token_jti: Some(Uuid::from_bytes([3_u8; 16])),
        request_object_id: Some(sample_object_id("request-1")),
        result_object_id: None,
        prev: None,
        seq: 0,
        occurred_at: fixed_timestamp_secs(),
        signature: sample_node_signature(),
    }
}

fn sample_event_envelope() -> EventEnvelope {
    let connector_id = ConnectorId::from_static("test.connector:stream:1");
    let instance_id: InstanceId = "inst_test".parse().expect("instance id must be canonical");
    let zone = sample_zone();
    let principal = Principal {
        kind: "user".to_string(),
        id: "user:alice".to_string(),
        trust: TrustLevel::Paired,
        display: Some("Alice".to_string()),
    };
    let payload = serde_json::json!({
        "status": "ok",
        "value": 42,
    });
    let data = EventData::new(connector_id, instance_id, zone, principal, payload)
        .with_correlation_id(CorrelationId(Uuid::from_bytes([4_u8; 16])))
        .with_resource_uris(vec!["resource://demo".to_string()]);

    let mut envelope = EventEnvelope::new("events.test", data)
        .with_seq(1)
        .with_cursor_seq(1)
        .requiring_ack();
    envelope.timestamp = fixed_datetime();
    envelope
}

/// Verify generated vectors against a baseline file.
#[allow(clippy::too_many_lines)]
fn verify_vectors(
    baseline_path: &PathBuf,
    log_file: &mut Option<fs::File>,
    correlation_id: &str,
    schema_filter: Option<&str>,
) -> Result<VerificationResult, String> {
    // Setup phase
    emit_log_entry(
        &LogEntry {
            timestamp: Utc::now().to_rfc3339(),
            level: Some("info".into()),
            test_name: "schema_vector_verification".into(),
            module: "fcp-conformance".into(),
            phase: "setup".into(),
            correlation_id: correlation_id.into(),
            result: "pass".into(),
            duration_ms: 0,
            assertions: LogAssertions {
                passed: 1,
                failed: 0,
            },
            context: None,
            artifacts: None,
            error_code: None,
            details: Some(serde_json::json!({
                "message": format!("Loading baseline from {}", baseline_path.display())
            })),
        },
        log_file,
    );

    // Load baseline
    let mut baseline = read_vectors_from_file(baseline_path)?;

    if let Some(filter) = schema_filter {
        let Some(expected) = baseline.get(filter).cloned() else {
            return Err(format!("Baseline missing schema {filter}"));
        };
        baseline = BTreeMap::from([(filter.to_string(), expected)]);
    }

    // Execute phase - generate fresh vectors
    emit_log_entry(
        &LogEntry {
            timestamp: Utc::now().to_rfc3339(),
            level: Some("info".into()),
            test_name: "schema_vector_verification".into(),
            module: "fcp-conformance".into(),
            phase: "execute".into(),
            correlation_id: correlation_id.into(),
            result: "pass".into(),
            duration_ms: 0,
            assertions: LogAssertions {
                passed: 1,
                failed: 0,
            },
            context: None,
            artifacts: None,
            error_code: None,
            details: Some(serde_json::json!({
                "message": "Regenerating vectors for comparison"
            })),
        },
        log_file,
    );

    let generated =
        generate_all_vectors(schema_filter, log_file, correlation_id).map_err(|e| e.to_string())?;

    // Verify phase - compare
    let mut result = VerificationResult {
        passed: true,
        schemas_checked: 0,
        schemas_matched: 0,
        schemas_missing: vec![],
        schemas_extra: vec![],
        diffs: vec![],
    };

    // Check for missing schemas (in baseline but not generated)
    for key in baseline.keys() {
        if !generated.contains_key(key) {
            result.schemas_missing.push(key.clone());
            result.passed = false;
        }
    }

    // Check for extra schemas (generated but not in baseline)
    for key in generated.keys() {
        if !baseline.contains_key(key) {
            result.schemas_extra.push(key.clone());
            result.passed = false;
        }
    }

    // Compare matching schemas
    for (key, expected) in &baseline {
        if let Some(actual) = generated.get(key) {
            result.schemas_checked += 1;

            // Compare schema hash (positive branch first for clippy::if_not_else)
            if expected.expected_schema_hash == actual.expected_schema_hash {
                // Compare payloads only if schema hash matches
                let expected_payloads: BTreeMap<_, _> = expected
                    .payloads
                    .iter()
                    .map(|p| (&p.description, p))
                    .collect();
                let actual_payloads: BTreeMap<_, _> = actual
                    .payloads
                    .iter()
                    .map(|p| (&p.description, p))
                    .collect();

                for (desc, exp_payload) in &expected_payloads {
                    if let Some(act_payload) = actual_payloads.get(desc) {
                        if exp_payload.expected_cbor != act_payload.expected_cbor {
                            result.diffs.push(VectorDiff {
                                schema: key.clone(),
                                field: format!("payload[{desc}].cbor"),
                                expected: exp_payload.expected_cbor.clone(),
                                actual: act_payload.expected_cbor.clone(),
                            });
                            result.passed = false;
                        }
                        if exp_payload.expected_payload != act_payload.expected_payload {
                            result.diffs.push(VectorDiff {
                                schema: key.clone(),
                                field: format!("payload[{desc}].full_payload"),
                                expected: exp_payload.expected_payload.clone(),
                                actual: act_payload.expected_payload.clone(),
                            });
                            result.passed = false;
                        }
                    }
                }

                let expected_keys: BTreeSet<&String> = expected_payloads.keys().copied().collect();
                let actual_keys: BTreeSet<&String> = actual_payloads.keys().copied().collect();

                for desc in &expected_keys {
                    if !actual_keys.contains(desc) {
                        result.diffs.push(VectorDiff {
                            schema: key.clone(),
                            field: format!("payload[{desc}]"),
                            expected: "present".to_string(),
                            actual: "missing".to_string(),
                        });
                        result.passed = false;
                    }
                }

                for desc in &actual_keys {
                    if !expected_keys.contains(desc) {
                        result.diffs.push(VectorDiff {
                            schema: key.clone(),
                            field: format!("payload[{desc}]"),
                            expected: "missing".to_string(),
                            actual: "present".to_string(),
                        });
                        result.passed = false;
                    }
                }
                result.schemas_matched += 1;
            } else {
                // Schema hash mismatch
                result.diffs.push(VectorDiff {
                    schema: key.clone(),
                    field: "schema_hash".into(),
                    expected: expected.expected_schema_hash.clone(),
                    actual: actual.expected_schema_hash.clone(),
                });
                result.passed = false;
            }
        }
    }

    // Emit verification result log
    emit_log_entry(
        &LogEntry {
            timestamp: Utc::now().to_rfc3339(),
            level: Some(if result.passed { "info" } else { "error" }.into()),
            test_name: "schema_vector_verification".into(),
            module: "fcp-conformance".into(),
            phase: "verify".into(),
            correlation_id: correlation_id.into(),
            result: if result.passed { "pass" } else { "fail" }.into(),
            duration_ms: 0,
            assertions: LogAssertions {
                passed: u64::from(result.passed),
                failed: u64::from(!result.passed),
            },
            context: None,
            artifacts: None,
            error_code: None,
            details: Some(serde_json::json!({
                "message": if result.passed {
                    "All vectors match baseline"
                } else {
                    "Vector drift detected"
                },
                "schemas_checked": result.schemas_checked,
                "schemas_matched": result.schemas_matched,
                "diffs_found": result.diffs.len(),
                "schemas_missing": result.schemas_missing,
                "schemas_extra": result.schemas_extra,
            })),
        },
        log_file,
    );

    Ok(result)
}

/// Generate sample data for each registered schema.
fn generate_samples_for_schema(reg: &SchemaRegistration) -> Option<Vec<SampleCase>> {
    let key = format!("{}:{}", reg.namespace, reg.name);

    match key.as_str() {
        "fcp.test:GoldenStruct" => {
            let samples = vec![
                SampleCase::new(
                    "canonical basic",
                    SampleValue::GoldenStruct(GoldenStruct {
                        id: 12345,
                        name: "test".into(),
                        active: true,
                    }),
                ),
                SampleCase::new(
                    "canonical with unicode",
                    SampleValue::GoldenStruct(GoldenStruct {
                        id: 99999,
                        name: "hello\u{1F600}world".into(),
                        active: false,
                    }),
                ),
                SampleCase::new(
                    "canonical edge case",
                    SampleValue::GoldenStruct(GoldenStruct {
                        id: 0,
                        name: String::new(),
                        active: false,
                    }),
                ),
            ];
            Some(samples)
        }
        "fcp.core:CapabilityObject" => Some(vec![SampleCase::new(
            "basic capability",
            SampleValue::CapabilityObject(sample_capability_object()),
        )]),
        "fcp.core:ObjectHeader" => Some(vec![SampleCase::new(
            "basic header",
            SampleValue::ObjectHeader(sample_object_header(SchemaId::new(
                "fcp.core",
                "TestObject",
                Version::new(1, 0, 0),
            ))),
        )]),
        "fcp.operation:intent" => Some(vec![SampleCase::new(
            "basic intent",
            SampleValue::OperationIntent(sample_operation_intent(reg.schema_id())),
        )]),
        "fcp.operation:receipt" => Some(vec![SampleCase::new(
            "basic receipt",
            SampleValue::OperationReceipt(sample_operation_receipt(reg.schema_id())),
        )]),
        "fcp.core:AuditEvent" => Some(vec![SampleCase::new(
            "basic audit event",
            SampleValue::AuditEvent(sample_audit_event(reg.schema_id())),
        )]),
        "fcp.stream:EventEnvelope" => Some(vec![SampleCase::new(
            "basic event envelope",
            SampleValue::EventEnvelope(sample_event_envelope()),
        )]),
        _ => None, // No samples for other schemas yet
    }
}

/// Generate vectors for all core schemas.
fn generate_all_vectors(
    schema_filter: Option<&str>,
    log_file: &mut Option<fs::File>,
    correlation_id: &str,
) -> Result<BTreeMap<String, GeneratedVector>, VecGenError> {
    let mut vectors = BTreeMap::new();
    let mut matched_filter = false;

    for reg in core_schema_registrations() {
        let key = format!("{}:{}@{}", reg.namespace, reg.name, reg.version);
        if let Some(filter) = schema_filter {
            if filter != key {
                continue;
            }
            matched_filter = true;
        }

        if let Some(samples) = generate_samples_for_schema(&reg) {
            let schema = reg.schema_id();
            let schema_hash = generate_schema_hash(&schema);
            let schema_id = format!("{}:{}@{}", schema.namespace, schema.name, schema.version);
            emit_schema_log(log_file, correlation_id, &schema_id, &schema_hash);

            let mut payloads = Vec::new();
            for sample in samples {
                let (cbor_hex, payload_hex) = sample.serialize(&schema)?;
                let input_json = sample.to_json()?;
                payloads.push(PayloadVector {
                    description: sample.description,
                    input_json,
                    expected_cbor: cbor_hex,
                    expected_payload: payload_hex,
                });
            }

            vectors.insert(
                key,
                GeneratedVector {
                    description: reg.description.clone(),
                    schema_namespace: reg.namespace.clone(),
                    schema_name: reg.name.clone(),
                    schema_version: reg.version.to_string(),
                    expected_schema_hash: schema_hash,
                    payloads,
                },
            );
        } else {
            // Generate schema hash only vector (no payloads)
            let schema = reg.schema_id();
            let schema_hash = generate_schema_hash(&schema);
            let schema_id = format!("{}:{}@{}", schema.namespace, schema.name, schema.version);
            emit_schema_log(log_file, correlation_id, &schema_id, &schema_hash);
            vectors.insert(
                key,
                GeneratedVector {
                    description: reg.description.clone(),
                    schema_namespace: reg.namespace.clone(),
                    schema_name: reg.name.clone(),
                    schema_version: reg.version.to_string(),
                    expected_schema_hash: schema_hash,
                    payloads: vec![],
                },
            );
        }
    }

    if schema_filter.is_some() && !matched_filter {
        return Err(VecGenError::new("requested schema not found"));
    }

    Ok(vectors)
}

fn normalize_schema_filter(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    let (namespace, rest) = raw
        .split_once(':')
        .ok_or_else(|| "schema must be in namespace:name@version form".to_string())?;
    let (name, version) = rest
        .split_once('@')
        .ok_or_else(|| "schema must include @version".to_string())?;
    let version =
        Version::parse(version).map_err(|e| format!("invalid schema version '{version}': {e}"))?;
    if namespace.is_empty() || name.is_empty() {
        return Err("schema must include namespace and name".to_string());
    }
    Ok(format!("{namespace}:{name}@{version}"))
}

#[allow(clippy::too_many_lines)]
fn main() {
    let mut args = Args::parse();
    let schema_filter = args
        .schema
        .as_deref()
        .map(|raw| match normalize_schema_filter(raw) {
            Ok(filter) => filter,
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        });

    if args.list {
        println!("Available schemas:");
        println!();
        for reg in core_schema_registrations() {
            let schema = reg.schema_id();
            let hash = generate_schema_hash(&schema);
            println!("  {}:{}@{}", reg.namespace, reg.name, reg.version);
            println!("    Hash: {hash}");
            println!("    Description: {}", reg.description);
            println!();
        }
        return;
    }

    // Open log file if specified
    let mut log_file = args.log_jsonl.as_ref().and_then(|p| {
        if let Some(parent) = p.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::File::create(p).ok()
    });

    // Generate correlation ID
    let correlation_id = format!(
        "vecgen-{}-{}",
        std::process::id(),
        Utc::now().timestamp_millis()
    );

    if args.verify {
        let Some(baseline_path) = args.baseline.take().or_else(default_baseline_path) else {
            eprintln!(
                "Error: --baseline is required with --verify (default tests/vectors/serialization/core_vectors.json or .cbor not found)"
            );
            std::process::exit(1);
        };

        match verify_vectors(
            &baseline_path,
            &mut log_file,
            &correlation_id,
            schema_filter.as_deref(),
        ) {
            Ok(result) => {
                // Output JSON diff summary to stdout for CI artifact capture
                if !result.diffs.is_empty()
                    || !result.schemas_missing.is_empty()
                    || !result.schemas_extra.is_empty()
                {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&result).unwrap_or_default()
                    );
                }

                if result.passed {
                    eprintln!(
                        "✓ All {} schemas verified successfully",
                        result.schemas_checked
                    );
                    std::process::exit(0);
                }
                eprintln!("✗ Verification failed:");
                if !result.schemas_missing.is_empty() {
                    eprintln!("  Missing schemas: {:?}", result.schemas_missing);
                }
                if !result.schemas_extra.is_empty() {
                    eprintln!("  Extra schemas: {:?}", result.schemas_extra);
                }
                for diff in &result.diffs {
                    eprintln!(
                        "  {}.{}: expected {} != actual {}",
                        diff.schema,
                        diff.field,
                        &diff.expected[..diff.expected.len().min(32)],
                        &diff.actual[..diff.actual.len().min(32)]
                    );
                }
                eprintln!("\nTo update baseline, run:");
                eprintln!(
                    "  cargo run -p fcp-conformance --bin fcp-vecgen -- --out tests/vectors/serialization"
                );
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("Error during verification: {e}");
                std::process::exit(1);
            }
        }
    }

    // Generate vectors
    eprintln!("Generating schema vectors...");
    let vectors =
        match generate_all_vectors(schema_filter.as_deref(), &mut log_file, &correlation_id) {
            Ok(vectors) => vectors,
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        };

    // Write output
    let output_file = match args.format {
        OutputFormat::Json => args.out.join("core_vectors.json"),
        OutputFormat::Cbor => args.out.join("core_vectors.cbor"),
    };
    let write_result = match args.format {
        OutputFormat::Json => write_vectors_to_file(&vectors, &output_file),
        OutputFormat::Cbor => write_vectors_to_cbor_file(&vectors, &output_file),
    };
    match write_result {
        Ok(()) => {
            eprintln!(
                "Wrote {} vectors to {}",
                vectors.len(),
                output_file.display()
            );

            // Print summary
            for (key, vector) in &vectors {
                eprintln!(
                    "  {key}: {} payloads, hash={}",
                    vector.payloads.len(),
                    &vector.expected_schema_hash[..16]
                );
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }

    eprintln!("Done.");
}

#[cfg(test)]
mod tests {
    use super::*;

    use fcp_conformance::LogCapture;
    use serde_json::json;

    #[test]
    fn schema_log_entry_validates_against_e2e_schema() {
        let schema_id = "fcp.core:CapabilityObject@1.0.0";
        let schema_hash = "deadbeef";

        let entry = LogEntry {
            timestamp: Utc::now().to_rfc3339(),
            level: Some("info".into()),
            test_name: "schema_vector_generation".into(),
            module: "fcp-conformance".into(),
            phase: "generate".into(),
            correlation_id: "test-correlation".into(),
            result: "pass".into(),
            duration_ms: 0,
            assertions: LogAssertions {
                passed: 1,
                failed: 0,
            },
            context: None,
            artifacts: None,
            error_code: None,
            details: Some(json!({
                "schema_id": schema_id,
                "schema_hash": schema_hash,
                "message": "Generated schema vector"
            })),
        };

        let value = serde_json::to_value(&entry).expect("serialize log entry");
        assert_eq!(value["details"]["schema_id"], schema_id);
        assert_eq!(value["details"]["schema_hash"], schema_hash);

        let capture = LogCapture::new();
        capture
            .push_value(&value)
            .expect("push log entry to capture");
        capture.assert_valid();
    }
}
