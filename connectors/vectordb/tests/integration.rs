//! `VectorDB` connector integration tests (flywheel_connectors-lszk.26.3).
//!
//! Deterministic mock-only tests covering the bead acceptance criteria:
//! - Schema validation (collection names, dimension bounds, vector arrays, ID lengths)
//! - Error taxonomy mapping (error codes, error messages, error categories)
//! - Retry & idempotency rules (idempotency class declarations)
//! - Redaction (no credential leakage in errors, doctor output, logs)
//! - Payload bounds and timeouts (batch sizes, `top_k` limits, timeout configs)
//! - Introspection completeness (schemas, risk levels, capabilities, required fields)
//! - Capability verification (default deny, capability mismatch)

#![allow(clippy::too_many_lines)]

use chrono::{Duration, SecondsFormat, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpError, HandshakeRequest,
    IdempotencyClass, InstanceId, RiskLevel, SafetyTier, ZoneId,
};
use fcp_testkit::LogCapture;
use serde_json::json;
use std::time::Instant;

use fcp_vectordb::VectorDbConnector;
use fcp_vectordb::config::{DoctorStatus, VectorDbConfig, VectorDbProvider};

// ============================================================================
// Helpers
// ============================================================================

fn generate_token(
    signing_key: &Ed25519SigningKey,
    cap: &str,
    ops: &[&str],
    instance_id: &InstanceId,
) -> CapabilityToken {
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(cap)
        .zone_id("z:work")
        .principal("user:test")
        .operations(ops)
        .issuer("node:test")
        .target_instance(instance_id.as_str())
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints")
        .sign(signing_key)
        .expect("token sign");
    CapabilityToken::from_raw(cose)
}

fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [7u8; 32],
        capabilities_requested: capabilities
            .iter()
            .map(|cap| cap.parse::<CapabilityId>().expect("capability id"))
            .collect(),
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

async fn setup_connector(
    provider: &str,
    endpoint: &str,
    caps: &[&str],
) -> (VectorDbConnector, Ed25519SigningKey) {
    let mut connector = VectorDbConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    let mut params = json!({
        "provider": provider,
        "endpoint": endpoint,
        "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
    });
    if provider == "qdrant" && !endpoint.contains("pinecone") {
        params["use_tls"] = json!(false);
    }

    connector
        .handle_configure(params)
        .await
        .expect("configure should succeed");

    let hs = handshake_request(signing_key.verifying_key().to_bytes(), caps);
    connector
        .handle_handshake(serde_json::to_value(hs).expect("serialize"))
        .await
        .expect("handshake should succeed");

    (connector, signing_key)
}

async fn invoke(
    connector: &VectorDbConnector,
    operation: &str,
    input: serde_json::Value,
    token: &CapabilityToken,
) -> Result<serde_json::Value, FcpError> {
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": token
        }))
        .await
}

fn manifest() -> Result<toml::Table, String> {
    include_str!("../manifest.toml")
        .parse::<toml::Table>()
        .map_err(|err| format!("manifest.toml should parse: {err}"))
}

fn manifest_operations(
    manifest: &toml::Table,
) -> Result<&toml::map::Map<String, toml::Value>, String> {
    manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .ok_or_else(|| "manifest should declare provides.operations".to_owned())
}

fn manifest_operation_network_constraints<'a>(
    manifest: &'a toml::Table,
    operation_id: &str,
) -> Result<&'a toml::map::Map<String, toml::Value>, String> {
    manifest_operations(manifest)?
        .get(operation_id)
        .and_then(toml::Value::as_table)
        .and_then(|operation| operation.get("network_constraints"))
        .and_then(toml::Value::as_table)
        .ok_or_else(|| format!("{operation_id} should declare network_constraints"))
}

fn string_array(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
) -> Result<Vec<String>, String> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .ok_or_else(|| format!("{key} should be an array"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{key} entries should be strings"))
        })
        .collect()
}

fn integer_array(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
) -> Result<Vec<i64>, String> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .ok_or_else(|| format!("{key} should be an array"))?
        .iter()
        .map(|entry| {
            entry
                .as_integer()
                .ok_or_else(|| format!("{key} entries should be integers"))
        })
        .collect()
}

fn bool_value(table: &toml::map::Map<String, toml::Value>, key: &str) -> Result<bool, String> {
    table
        .get(key)
        .and_then(toml::Value::as_bool)
        .ok_or_else(|| format!("{key} should be a boolean"))
}

fn integer_value(table: &toml::map::Map<String, toml::Value>, key: &str) -> Result<i64, String> {
    table
        .get(key)
        .and_then(toml::Value::as_integer)
        .ok_or_else(|| format!("{key} should be an integer"))
}

fn assert_no_egress_network_constraints(
    manifest: &toml::Table,
    operation_id: &str,
) -> Result<(), String> {
    let constraints = manifest_operation_network_constraints(manifest, operation_id)?;
    assert_eq!(
        string_array(constraints, "host_allow")?,
        vec!["none.invalid"]
    );
    assert_eq!(integer_array(constraints, "port_allow")?, vec![0]);
    assert!(bool_value(constraints, "deny_localhost")?);
    assert!(bool_value(constraints, "deny_private_ranges")?);
    assert!(bool_value(constraints, "deny_tailnet_ranges")?);
    assert!(!bool_value(constraints, "require_sni")?);
    assert!(bool_value(constraints, "deny_ip_literals")?);
    assert!(bool_value(constraints, "require_host_canonicalization")?);
    assert_eq!(integer_value(constraints, "dns_max_ips")?, 0);
    assert_eq!(integer_value(constraints, "max_redirects")?, 0);
    assert_eq!(integer_value(constraints, "connect_timeout_ms")?, 1_000);
    assert_eq!(integer_value(constraints, "total_timeout_ms")?, 30_000);
    assert_eq!(integer_value(constraints, "max_response_bytes")?, 1_048_576);
    Ok(())
}

#[test]
fn manifest_declares_per_operation_network_constraints() -> Result<(), String> {
    let manifest = manifest()?;
    let operations = manifest_operations(&manifest)?;

    for operation_id in operations.keys() {
        let constraints = manifest_operation_network_constraints(&manifest, operation_id)?;
        assert!(
            !string_array(constraints, "host_allow")?.is_empty(),
            "{operation_id} host_allow should not be empty"
        );
        assert!(
            !integer_array(constraints, "port_allow")?.is_empty(),
            "{operation_id} port_allow should not be empty"
        );
        let _deny_private_ranges = bool_value(constraints, "deny_private_ranges")?;
        let _require_sni = bool_value(constraints, "require_sni")?;
    }

    assert_no_egress_network_constraints(&manifest, "list_collections")?;
    assert_no_egress_network_constraints(&manifest, "describe_collection")?;
    Ok(())
}

// ============================================================================
// Schema Validation: Collection Names
// ============================================================================

#[fcp_async_core::runtime::test]
async fn schema_create_collection_valid_name() {
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.write",
        &["vectordb.create_collection"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.create_collection",
        json!({"collection": "my-docs-123", "dimension": 768}),
        &token,
    )
    .await;
    assert!(result.is_ok(), "valid name should succeed: {result:?}");
}

#[fcp_async_core::runtime::test]
async fn schema_create_collection_name_must_start_lowercase() {
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.write",
        &["vectordb.create_collection"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.create_collection",
        json!({"collection": "Uppercase", "dimension": 768}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_create_collection_name_rejects_spaces() {
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.write",
        &["vectordb.create_collection"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.create_collection",
        json!({"collection": "my collection", "dimension": 768}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_create_collection_name_rejects_dots() {
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.write",
        &["vectordb.create_collection"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.create_collection",
        json!({"collection": "my.collection", "dimension": 768}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_create_collection_name_rejects_numeric_start() {
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.write",
        &["vectordb.create_collection"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.create_collection",
        json!({"collection": "123abc", "dimension": 768}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_create_collection_name_allows_hyphens_underscores() {
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.write",
        &["vectordb.create_collection"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.create_collection",
        json!({"collection": "my_doc-store", "dimension": 768}),
        &token,
    )
    .await;
    assert!(result.is_ok(), "hyphens/underscores should be valid");
}

// ============================================================================
// Schema Validation: Dimension Bounds
// ============================================================================

#[fcp_async_core::runtime::test]
async fn schema_create_collection_dimension_min() {
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.write",
        &["vectordb.create_collection"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.create_collection",
        json!({"collection": "test", "dimension": 1}),
        &token,
    )
    .await;
    assert!(result.is_ok(), "dimension 1 should be valid");
}

#[fcp_async_core::runtime::test]
async fn schema_create_collection_dimension_max() {
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.write",
        &["vectordb.create_collection"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.create_collection",
        json!({"collection": "test", "dimension": 10000}),
        &token,
    )
    .await;
    assert!(result.is_ok(), "dimension 10000 should be valid");
}

#[fcp_async_core::runtime::test]
async fn schema_create_collection_dimension_zero() {
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.write",
        &["vectordb.create_collection"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.create_collection",
        json!({"collection": "test", "dimension": 0}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_create_collection_dimension_exceeds_max() {
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.write",
        &["vectordb.create_collection"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.create_collection",
        json!({"collection": "test", "dimension": 10001}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

// ============================================================================
// Schema Validation: Metric Values
// ============================================================================

#[fcp_async_core::runtime::test]
async fn schema_create_collection_valid_metrics() {
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.write",
        &["vectordb.create_collection"],
        c.instance_id(),
    );

    for metric in ["cosine", "euclidean", "dotproduct"] {
        let result = invoke(
            &c,
            "vectordb.create_collection",
            json!({"collection": "test", "dimension": 768, "metric": metric}),
            &token,
        )
        .await;
        assert!(result.is_ok(), "metric '{metric}' should be valid");
    }
}

#[fcp_async_core::runtime::test]
async fn schema_create_collection_invalid_metric() {
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.write",
        &["vectordb.create_collection"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.create_collection",
        json!({"collection": "test", "dimension": 768, "metric": "manhattan"}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

// ============================================================================
// Schema Validation: Query Vectors
// ============================================================================

#[fcp_async_core::runtime::test]
async fn schema_query_vectors_top_k_min() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.read",
        &["vectordb.query_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.query_vectors",
        json!({"collection": "docs", "vector": [0.1, 0.2, 0.3], "top_k": 1}),
        &token,
    )
    .await;
    assert!(result.is_ok(), "top_k 1 should be valid");
}

#[fcp_async_core::runtime::test]
async fn schema_query_vectors_top_k_max() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.read",
        &["vectordb.query_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.query_vectors",
        json!({"collection": "docs", "vector": [0.1, 0.2, 0.3], "top_k": 10000}),
        &token,
    )
    .await;
    assert!(result.is_ok(), "top_k 10000 should be valid");
}

#[fcp_async_core::runtime::test]
async fn schema_query_vectors_top_k_zero() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.read",
        &["vectordb.query_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.query_vectors",
        json!({"collection": "docs", "vector": [0.1, 0.2, 0.3], "top_k": 0}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_query_vectors_top_k_exceeds_max() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.read",
        &["vectordb.query_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.query_vectors",
        json!({"collection": "docs", "vector": [0.1, 0.2, 0.3], "top_k": 10001}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_query_vectors_empty_vector() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.read",
        &["vectordb.query_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.query_vectors",
        json!({"collection": "docs", "vector": []}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_query_vectors_non_numeric() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.read",
        &["vectordb.query_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.query_vectors",
        json!({"collection": "docs", "vector": ["not", "numbers"]}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_query_vectors_default_top_k() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.read",
        &["vectordb.query_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.query_vectors",
        json!({"collection": "docs", "vector": [0.1, 0.2, 0.3]}),
        &token,
    )
    .await;
    assert!(result.is_ok(), "default top_k should work");
}

// ============================================================================
// Schema Validation: Upsert Vectors
// ============================================================================

#[fcp_async_core::runtime::test]
async fn schema_upsert_vectors_single() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.write",
        &["vectordb.upsert_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.upsert_vectors",
        json!({"collection": "docs", "vectors": [{"id": "v1", "values": [0.1, 0.2]}]}),
        &token,
    )
    .await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap()["upserted_count"], 1);
}

#[fcp_async_core::runtime::test]
async fn schema_upsert_vectors_empty_batch() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.write",
        &["vectordb.upsert_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.upsert_vectors",
        json!({"collection": "docs", "vectors": []}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_upsert_vectors_exceeds_max_batch() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.write",
        &["vectordb.upsert_vectors"],
        c.instance_id(),
    );

    let vectors: Vec<serde_json::Value> = (0..1001)
        .map(|i| json!({"id": format!("v{i}"), "values": [0.1]}))
        .collect();

    let result = invoke(
        &c,
        "vectordb.upsert_vectors",
        json!({"collection": "docs", "vectors": vectors}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_upsert_vectors_max_batch_ok() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.write",
        &["vectordb.upsert_vectors"],
        c.instance_id(),
    );

    let vectors: Vec<serde_json::Value> = (0..1000)
        .map(|i| json!({"id": format!("v{i}"), "values": [0.1]}))
        .collect();

    let result = invoke(
        &c,
        "vectordb.upsert_vectors",
        json!({"collection": "docs", "vectors": vectors}),
        &token,
    )
    .await;
    assert!(result.is_ok(), "1000 vectors should be within limit");
    assert_eq!(result.unwrap()["upserted_count"], 1000);
}

#[fcp_async_core::runtime::test]
async fn schema_upsert_vectors_id_empty() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.write",
        &["vectordb.upsert_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.upsert_vectors",
        json!({"collection": "docs", "vectors": [{"id": "", "values": [0.1]}]}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_upsert_vectors_id_max_length() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.write",
        &["vectordb.upsert_vectors"],
        c.instance_id(),
    );

    let id_512 = "a".repeat(512);
    let result = invoke(
        &c,
        "vectordb.upsert_vectors",
        json!({"collection": "docs", "vectors": [{"id": id_512, "values": [0.1]}]}),
        &token,
    )
    .await;
    assert!(result.is_ok(), "512-char ID should be valid");
}

#[fcp_async_core::runtime::test]
async fn schema_upsert_vectors_id_exceeds_max_length() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.write",
        &["vectordb.upsert_vectors"],
        c.instance_id(),
    );

    let id_513 = "a".repeat(513);
    let result = invoke(
        &c,
        "vectordb.upsert_vectors",
        json!({"collection": "docs", "vectors": [{"id": id_513, "values": [0.1]}]}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_upsert_vectors_missing_id() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.write",
        &["vectordb.upsert_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.upsert_vectors",
        json!({"collection": "docs", "vectors": [{"values": [0.1]}]}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_upsert_vectors_missing_values() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.write",
        &["vectordb.upsert_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.upsert_vectors",
        json!({"collection": "docs", "vectors": [{"id": "v1"}]}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_upsert_vectors_empty_values() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.write",
        &["vectordb.upsert_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.upsert_vectors",
        json!({"collection": "docs", "vectors": [{"id": "v1", "values": []}]}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_upsert_vectors_non_numeric_values() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.write",
        &["vectordb.upsert_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.upsert_vectors",
        json!({"collection": "docs", "vectors": [{"id": "v1", "values": ["a", "b"]}]}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_upsert_vectors_metadata_must_be_object() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.write",
        &["vectordb.upsert_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.upsert_vectors",
        json!({"collection": "docs", "vectors": [{"id": "v1", "values": [0.1], "metadata": "string"}]}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_upsert_vectors_sparse_values_must_be_object() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.write",
        &["vectordb.upsert_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.upsert_vectors",
        json!({"collection": "docs", "vectors": [{"id": "v1", "values": [0.1], "sparse_values": [1, 2]}]}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_upsert_vectors_element_must_be_object() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.write",
        &["vectordb.upsert_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.upsert_vectors",
        json!({"collection": "docs", "vectors": ["not_an_object"]}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_upsert_vectors_with_metadata() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.write",
        &["vectordb.upsert_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.upsert_vectors",
        json!({
            "collection": "docs",
            "vectors": [{"id": "v1", "values": [0.1, 0.2], "metadata": {"category": "test"}}]
        }),
        &token,
    )
    .await;
    assert!(result.is_ok());
}

// ============================================================================
// Schema Validation: Fetch Vectors
// ============================================================================

#[fcp_async_core::runtime::test]
async fn schema_fetch_vectors_valid() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.read",
        &["vectordb.fetch_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.fetch_vectors",
        json!({"collection": "docs", "ids": ["id1", "id2"]}),
        &token,
    )
    .await;
    assert!(result.is_ok());
    let resp = result.unwrap();
    assert!(resp["vectors"]["id1"].is_object());
    assert!(resp["vectors"]["id2"].is_object());
}

#[fcp_async_core::runtime::test]
async fn schema_fetch_vectors_empty_ids() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.read",
        &["vectordb.fetch_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.fetch_vectors",
        json!({"collection": "docs", "ids": []}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_fetch_vectors_ids_non_string() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.read",
        &["vectordb.fetch_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.fetch_vectors",
        json!({"collection": "docs", "ids": [123, 456]}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_fetch_vectors_exceeds_max_ids() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.read",
        &["vectordb.fetch_vectors"],
        c.instance_id(),
    );

    let ids: Vec<String> = (0..1001).map(|i| format!("id{i}")).collect();
    let result = invoke(
        &c,
        "vectordb.fetch_vectors",
        json!({"collection": "docs", "ids": ids}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

// ============================================================================
// Schema Validation: Delete Vectors
// ============================================================================

#[fcp_async_core::runtime::test]
async fn schema_delete_vectors_by_ids() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.delete"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.delete",
        &["vectordb.delete_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.delete_vectors",
        json!({"collection": "docs", "ids": ["id1", "id2"]}),
        &token,
    )
    .await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap()["deleted_count"], 2);
}

#[fcp_async_core::runtime::test]
async fn schema_delete_vectors_by_filter() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.delete"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.delete",
        &["vectordb.delete_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.delete_vectors",
        json!({"collection": "docs", "filter": {"category": "stale"}}),
        &token,
    )
    .await;
    assert!(result.is_ok());
}

#[fcp_async_core::runtime::test]
async fn schema_delete_vectors_by_delete_all() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.delete"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.delete",
        &["vectordb.delete_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.delete_vectors",
        json!({"collection": "docs", "delete_all": true}),
        &token,
    )
    .await;
    assert!(result.is_ok());
}

#[fcp_async_core::runtime::test]
async fn schema_delete_vectors_no_criteria() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.delete"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.delete",
        &["vectordb.delete_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.delete_vectors",
        json!({"collection": "docs"}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_delete_vectors_ids_type_validation() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.delete"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.delete",
        &["vectordb.delete_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.delete_vectors",
        json!({"collection": "docs", "ids": [123, 456]}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_delete_vectors_filter_type_validation() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.delete"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.delete",
        &["vectordb.delete_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.delete_vectors",
        json!({"collection": "docs", "filter": "not_an_object"}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

// ============================================================================
// Schema Validation: Update Vector Metadata
// ============================================================================

#[fcp_async_core::runtime::test]
async fn schema_update_metadata_valid() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.write",
        &["vectordb.update_vector_metadata"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.update_vector_metadata",
        json!({"collection": "docs", "id": "v1", "metadata": {"key": "value"}}),
        &token,
    )
    .await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap()["updated"], true);
}

#[fcp_async_core::runtime::test]
async fn schema_update_metadata_missing_id() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.write",
        &["vectordb.update_vector_metadata"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.update_vector_metadata",
        json!({"collection": "docs", "metadata": {"key": "value"}}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn schema_update_metadata_missing_metadata() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.write",
        &["vectordb.update_vector_metadata"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.update_vector_metadata",
        json!({"collection": "docs", "id": "v1"}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

// ============================================================================
// Error Taxonomy
// ============================================================================

#[fcp_async_core::runtime::test]
async fn error_not_configured() {
    let connector = VectorDbConnector::new();
    let result = connector
        .handle_invoke(json!({
            "operation": "vectordb.list_collections",
            "input": {},
            "capability_token": {"raw": []}
        }))
        .await;
    assert!(matches!(result, Err(FcpError::NotConfigured)));
}

#[fcp_async_core::runtime::test]
async fn error_missing_operation() {
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.read",
        &["vectordb.list_collections"],
        c.instance_id(),
    );

    let result = c
        .handle_invoke(json!({"input": {}, "capability_token": token}))
        .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn error_unknown_operation() {
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.read",
        &["vectordb.nonexistent"],
        c.instance_id(),
    );

    let result = invoke(&c, "vectordb.nonexistent", json!({}), &token).await;
    assert!(matches!(result, Err(FcpError::OperationNotGranted { .. })));
}

#[fcp_async_core::runtime::test]
async fn error_input_not_object() {
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.read",
        &["vectordb.list_collections"],
        c.instance_id(),
    );

    let result = c
        .handle_invoke(json!({
            "operation": "vectordb.list_collections",
            "input": "not_an_object",
            "capability_token": token
        }))
        .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn error_missing_capability_token() {
    let (c, _) = setup_connector("qdrant", "localhost:6333", &["vectordb.collections.read"]).await;

    let result = c
        .handle_invoke(json!({
            "operation": "vectordb.list_collections",
            "input": {}
        }))
        .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

#[fcp_async_core::runtime::test]
async fn error_capability_mismatch() {
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.read",
        &["vectordb.create_collection"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.create_collection",
        json!({"collection": "test", "dimension": 768}),
        &token,
    )
    .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn error_missing_required_field_message() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.read",
        &["vectordb.query_vectors"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.query_vectors",
        json!({"collection": "docs"}),
        &token,
    )
    .await;

    if let Err(FcpError::InvalidRequest { code, message }) = result {
        assert_eq!(code, 1003);
        assert!(
            message.contains("vector"),
            "message should mention missing field: {message}"
        );
    } else {
        panic!("expected InvalidRequest, got {result:?}");
    }
}

// ============================================================================
// Idempotency Rules
// ============================================================================

#[test]
fn idempotency_read_ops_are_none() {
    let connector = VectorDbConnector::new();
    let introspection = connector.handle_introspect();

    for op_id in [
        "vectordb.list_collections",
        "vectordb.describe_collection",
        "vectordb.query_vectors",
        "vectordb.fetch_vectors",
    ] {
        let op = introspection
            .operations
            .iter()
            .find(|o| o.id.as_str() == op_id)
            .unwrap_or_else(|| panic!("missing {op_id}"));
        assert_eq!(op.idempotency, IdempotencyClass::None, "{op_id}");
    }
}

#[test]
fn idempotency_write_ops_are_best_effort() {
    let connector = VectorDbConnector::new();
    let introspection = connector.handle_introspect();

    for op_id in [
        "vectordb.create_collection",
        "vectordb.delete_collection",
        "vectordb.upsert_vectors",
        "vectordb.delete_vectors",
        "vectordb.update_vector_metadata",
    ] {
        let op = introspection
            .operations
            .iter()
            .find(|o| o.id.as_str() == op_id)
            .unwrap_or_else(|| panic!("missing {op_id}"));
        assert_eq!(op.idempotency, IdempotencyClass::BestEffort, "{op_id}");
    }
}

// ============================================================================
// Redaction: No Credential Leakage
// ============================================================================

#[fcp_async_core::runtime::test]
async fn redaction_doctor_does_not_leak_credential_id() {
    let mut connector = VectorDbConnector::new();
    let cred = "aabbccdd-1122-3344-5566-778899aabbcc";
    connector
        .handle_configure(json!({
            "provider": "pinecone",
            "endpoint": "my-index.svc.us-east-1.pinecone.io",
            "credential_id": cred
        }))
        .await
        .expect("configure ok");

    let result = connector.handle_doctor().await.expect("doctor ok");
    let serialized = serde_json::to_string(&result).expect("serialize");
    assert!(
        !serialized.contains(cred),
        "doctor output must not contain full credential id"
    );
}

#[fcp_async_core::runtime::test]
async fn redaction_configure_error_does_not_leak_credential() {
    let mut connector = VectorDbConnector::new();
    let cred = "aabbccdd-1122-3344-5566-778899aabbcc";

    let result = connector
        .handle_configure(json!({
            "provider": "pinecone",
            "endpoint": "",
            "credential_id": cred
        }))
        .await;

    if let Err(err) = result {
        let err_str = format!("{err}");
        assert!(
            !err_str.contains(cred),
            "error must not contain credential id: {err_str}"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn redaction_health_does_not_leak_credential() {
    let mut connector = VectorDbConnector::new();
    let cred = "aabbccdd-1122-3344-5566-778899aabbcc";
    connector
        .handle_configure(json!({
            "provider": "qdrant",
            "endpoint": "localhost:6333",
            "credential_id": cred,
            "use_tls": false
        }))
        .await
        .expect("configure ok");

    let health = connector.handle_health();
    let serialized = serde_json::to_string(&health).expect("serialize");
    assert!(
        !serialized.contains(cred),
        "health output must not contain full credential id"
    );
}

// ============================================================================
// Introspection Completeness
// ============================================================================

#[test]
fn introspect_all_ops_have_input_schema() {
    let connector = VectorDbConnector::new();
    let introspection = connector.handle_introspect();

    for op in &introspection.operations {
        assert!(op.input_schema.is_object(), "{}: input_schema", op.id);
        assert_eq!(op.input_schema["type"], "object", "{}: type", op.id);
    }
}

#[test]
fn introspect_all_ops_have_output_schema() {
    let connector = VectorDbConnector::new();
    let introspection = connector.handle_introspect();

    for op in &introspection.operations {
        assert!(op.output_schema.is_object(), "{}: output_schema", op.id);
        assert_eq!(op.output_schema["type"], "object", "{}: type", op.id);
    }
}

#[test]
fn introspect_all_ops_have_summary() {
    let connector = VectorDbConnector::new();
    let introspection = connector.handle_introspect();

    for op in &introspection.operations {
        assert!(!op.summary.is_empty(), "{}: summary empty", op.id);
    }
}

#[test]
fn introspect_read_ops_are_safe() {
    let connector = VectorDbConnector::new();
    let introspection = connector.handle_introspect();

    for op_id in [
        "vectordb.list_collections",
        "vectordb.describe_collection",
        "vectordb.query_vectors",
        "vectordb.fetch_vectors",
    ] {
        let op = introspection
            .operations
            .iter()
            .find(|o| o.id.as_str() == op_id)
            .unwrap_or_else(|| panic!("missing {op_id}"));
        assert_eq!(op.safety_tier, SafetyTier::Safe, "{op_id}");
        assert_eq!(op.risk_level, RiskLevel::Low, "{op_id}");
    }
}

#[test]
fn introspect_dangerous_ops_require_interactive_approval() {
    let connector = VectorDbConnector::new();
    let introspection = connector.handle_introspect();

    let op = introspection
        .operations
        .iter()
        .find(|o| o.id.as_str() == "vectordb.delete_collection")
        .expect("delete_collection must exist");

    assert_eq!(op.safety_tier, SafetyTier::Dangerous);
    assert_eq!(op.risk_level, RiskLevel::High);
    assert_eq!(
        op.requires_approval,
        Some(fcp_core::ApprovalMode::Interactive)
    );
}

#[test]
fn introspect_risky_ops_require_policy_approval() {
    let connector = VectorDbConnector::new();
    let introspection = connector.handle_introspect();

    for op_id in [
        "vectordb.create_collection",
        "vectordb.upsert_vectors",
        "vectordb.delete_vectors",
    ] {
        let op = introspection
            .operations
            .iter()
            .find(|o| o.id.as_str() == op_id)
            .unwrap_or_else(|| panic!("missing {op_id}"));
        assert_eq!(op.safety_tier, SafetyTier::Risky, "{op_id}");
        assert_eq!(
            op.requires_approval,
            Some(fcp_core::ApprovalMode::Policy),
            "{op_id}"
        );
    }
}

#[test]
fn introspect_required_fields_documented_in_schema() {
    let connector = VectorDbConnector::new();
    let introspection = connector.handle_introspect();

    let ops_with_required: &[(&str, &[&str])] = &[
        ("vectordb.describe_collection", &["collection"]),
        ("vectordb.create_collection", &["collection", "dimension"]),
        ("vectordb.delete_collection", &["collection"]),
        ("vectordb.query_vectors", &["collection", "vector"]),
        ("vectordb.fetch_vectors", &["collection", "ids"]),
        ("vectordb.upsert_vectors", &["collection", "vectors"]),
        ("vectordb.delete_vectors", &["collection"]),
        (
            "vectordb.update_vector_metadata",
            &["collection", "id", "metadata"],
        ),
    ];

    for (op_id, required_fields) in ops_with_required {
        let op = introspection
            .operations
            .iter()
            .find(|o| o.id.as_str() == *op_id)
            .unwrap_or_else(|| panic!("missing {op_id}"));

        let schema_required = op
            .input_schema
            .get("required")
            .and_then(|r| r.as_array())
            .unwrap_or_else(|| panic!("{op_id}: missing required array"));

        for field in *required_fields {
            assert!(
                schema_required.iter().any(|r| r.as_str() == Some(field)),
                "{op_id}: field '{field}' not in schema required"
            );
        }
    }
}

#[test]
fn introspect_capability_mapping_per_operation() {
    let connector = VectorDbConnector::new();
    let introspection = connector.handle_introspect();

    let expected: &[(&str, &str)] = &[
        ("vectordb.list_collections", "vectordb.collections.read"),
        ("vectordb.describe_collection", "vectordb.collections.read"),
        ("vectordb.create_collection", "vectordb.collections.write"),
        ("vectordb.delete_collection", "vectordb.collections.delete"),
        ("vectordb.query_vectors", "vectordb.vectors.read"),
        ("vectordb.fetch_vectors", "vectordb.vectors.read"),
        ("vectordb.upsert_vectors", "vectordb.vectors.write"),
        ("vectordb.delete_vectors", "vectordb.vectors.delete"),
        ("vectordb.update_vector_metadata", "vectordb.vectors.write"),
    ];

    for (op_id, cap) in expected {
        let op = introspection
            .operations
            .iter()
            .find(|o| o.id.as_str() == *op_id)
            .unwrap_or_else(|| panic!("missing {op_id}"));
        assert_eq!(op.capability.as_str(), *cap, "{op_id}");
    }
}

#[test]
fn introspect_deterministic_output() {
    let c1 = VectorDbConnector::new();
    let c2 = VectorDbConnector::new();
    let i1 = c1.handle_introspect();
    let i2 = c2.handle_introspect();

    assert_eq!(i1.operations.len(), i2.operations.len());
    for (a, b) in i1.operations.iter().zip(i2.operations.iter()) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.input_schema, b.input_schema);
        assert_eq!(a.output_schema, b.output_schema);
    }
}

// ============================================================================
// Payload Bounds: Schema-Declared Limits
// ============================================================================

#[test]
fn payload_bounds_upsert_schema_declares_max_items() {
    let connector = VectorDbConnector::new();
    let introspection = connector.handle_introspect();

    let upsert = introspection
        .operations
        .iter()
        .find(|o| o.id.as_str() == "vectordb.upsert_vectors")
        .expect("upsert must exist");

    let max_items = upsert.input_schema["properties"]["vectors"]["maxItems"]
        .as_i64()
        .expect("maxItems missing");
    assert_eq!(max_items, 1000);
}

#[test]
fn payload_bounds_fetch_schema_declares_id_limits() {
    let connector = VectorDbConnector::new();
    let introspection = connector.handle_introspect();

    let fetch = introspection
        .operations
        .iter()
        .find(|o| o.id.as_str() == "vectordb.fetch_vectors")
        .expect("fetch must exist");

    assert_eq!(fetch.input_schema["properties"]["ids"]["maxItems"], 1000);
    assert_eq!(fetch.input_schema["properties"]["ids"]["minItems"], 1);
}

#[test]
fn payload_bounds_create_collection_dimension_range() {
    let connector = VectorDbConnector::new();
    let introspection = connector.handle_introspect();

    let create = introspection
        .operations
        .iter()
        .find(|o| o.id.as_str() == "vectordb.create_collection")
        .expect("create must exist");

    let dim = &create.input_schema["properties"]["dimension"];
    assert_eq!(dim["minimum"], 1);
    assert_eq!(dim["maximum"], 10000);
}

#[test]
fn payload_bounds_query_top_k_range() {
    let connector = VectorDbConnector::new();
    let introspection = connector.handle_introspect();

    let query = introspection
        .operations
        .iter()
        .find(|o| o.id.as_str() == "vectordb.query_vectors")
        .expect("query must exist");

    let top_k = &query.input_schema["properties"]["top_k"];
    assert_eq!(top_k["minimum"], 1);
    assert_eq!(top_k["maximum"], 10000);
}

// ============================================================================
// Config Validation: Timeout Bounds
// ============================================================================

#[test]
fn config_timeout_boundaries() {
    // Zero connect timeout
    let config = VectorDbConfig {
        provider: VectorDbProvider::Qdrant,
        endpoint: "localhost:6333".into(),
        credential_id: fcp_core::CredentialId::new(),
        use_tls: false,
        namespace: None,
        connect_timeout_ms: 0,
        request_timeout_ms: 60_000,
    };
    assert!(config.validate().is_err());

    // Exceeds max connect timeout
    let config2 = VectorDbConfig {
        connect_timeout_ms: 300_001,
        ..config.clone()
    };
    assert!(config2.validate().is_err());

    // Zero request timeout
    let config3 = VectorDbConfig {
        connect_timeout_ms: 10_000,
        request_timeout_ms: 0,
        ..config.clone()
    };
    assert!(config3.validate().is_err());

    // Exceeds max request timeout
    let config4 = VectorDbConfig {
        connect_timeout_ms: 10_000,
        request_timeout_ms: 600_001,
        ..config.clone()
    };
    assert!(config4.validate().is_err());

    // Valid boundaries (min)
    let config5 = VectorDbConfig {
        connect_timeout_ms: 1,
        request_timeout_ms: 1,
        ..config.clone()
    };
    assert!(config5.validate().is_ok());

    // Valid boundaries (max)
    let config6 = VectorDbConfig {
        connect_timeout_ms: 300_000,
        request_timeout_ms: 600_000,
        ..config
    };
    assert!(config6.validate().is_ok());
}

// ============================================================================
// Config Validation: Provider-Specific
// ============================================================================

#[test]
fn config_provider_display() {
    assert_eq!(VectorDbProvider::Pinecone.to_string(), "pinecone");
    assert_eq!(VectorDbProvider::Qdrant.to_string(), "qdrant");
}

#[test]
fn config_provider_default_ports() {
    assert_eq!(VectorDbProvider::Pinecone.default_port(), 443);
    assert_eq!(VectorDbProvider::Qdrant.default_port(), 6333);
}

#[test]
fn config_provider_tls_requirements() {
    assert!(VectorDbProvider::Pinecone.requires_tls());
    assert!(!VectorDbProvider::Qdrant.requires_tls());
}

#[test]
fn config_endpoint_allowlist_qdrant_patterns() {
    let base = VectorDbConfig {
        provider: VectorDbProvider::Qdrant,
        endpoint: "my-cluster.qdrant.io".into(),
        credential_id: fcp_core::CredentialId::new(),
        use_tls: true,
        namespace: None,
        connect_timeout_ms: 10_000,
        request_timeout_ms: 60_000,
    };
    assert!(base.is_endpoint_allowed());

    let tech = VectorDbConfig {
        endpoint: "my-cluster.qdrant.tech".into(),
        ..base.clone()
    };
    assert!(tech.is_endpoint_allowed());

    let evil = VectorDbConfig {
        endpoint: "evil.com".into(),
        ..base.clone()
    };
    assert!(!evil.is_endpoint_allowed());

    // Port stripped for matching
    let with_port = VectorDbConfig {
        endpoint: "my-cluster.qdrant.io:6333".into(),
        ..base
    };
    assert!(with_port.is_endpoint_allowed());
}

#[test]
fn config_serde_round_trip() {
    let config = VectorDbConfig {
        provider: VectorDbProvider::Pinecone,
        endpoint: "my-index.svc.us-east-1.pinecone.io".into(),
        credential_id: fcp_core::CredentialId::new(),
        use_tls: true,
        namespace: Some("production".into()),
        connect_timeout_ms: 5_000,
        request_timeout_ms: 30_000,
    };

    let serialized = serde_json::to_value(&config).expect("serialize");
    let deserialized: VectorDbConfig = serde_json::from_value(serialized).expect("deserialize");

    assert_eq!(deserialized.provider, config.provider);
    assert_eq!(deserialized.endpoint, config.endpoint);
    assert_eq!(deserialized.use_tls, config.use_tls);
    assert_eq!(deserialized.namespace, config.namespace);
    assert_eq!(deserialized.connect_timeout_ms, config.connect_timeout_ms);
    assert_eq!(deserialized.request_timeout_ms, config.request_timeout_ms);
}

// ============================================================================
// Doctor Checks
// ============================================================================

#[test]
fn doctor_from_checks_all_pass() {
    let checks = vec![
        fcp_vectordb::config::DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: true,
        },
        fcp_vectordb::config::DoctorCheck {
            name: "b".into(),
            passed: true,
            message: None,
            critical: false,
        },
    ];
    let result = fcp_vectordb::config::DoctorResult::from_checks(checks);
    assert_eq!(result.status, DoctorStatus::Healthy);
    assert!(result.is_healthy());
}

#[test]
fn doctor_from_checks_non_critical_fail() {
    let checks = vec![
        fcp_vectordb::config::DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: true,
        },
        fcp_vectordb::config::DoctorCheck {
            name: "b".into(),
            passed: false,
            message: Some("minor issue".into()),
            critical: false,
        },
    ];
    let result = fcp_vectordb::config::DoctorResult::from_checks(checks);
    assert_eq!(result.status, DoctorStatus::Degraded);
}

#[test]
fn doctor_from_checks_critical_fail() {
    let checks = vec![fcp_vectordb::config::DoctorCheck {
        name: "a".into(),
        passed: false,
        message: Some("critical fail".into()),
        critical: true,
    }];
    let result = fcp_vectordb::config::DoctorResult::from_checks(checks);
    assert_eq!(result.status, DoctorStatus::Unhealthy);
}

// ============================================================================
// Describe Collection Output Shape
// ============================================================================

#[fcp_async_core::runtime::test]
async fn describe_collection_output_shape() {
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.read",
        &["vectordb.describe_collection"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.describe_collection",
        json!({"collection": "docs"}),
        &token,
    )
    .await
    .expect("describe should succeed");

    assert!(result["name"].is_string());
    assert!(result["dimension"].is_number());
    assert!(result["metric"].is_string());
    assert!(result["status"].is_string());
    assert!(result["created_at"].is_string());
    assert!(result["provider_metadata"].is_object());
}

// ============================================================================
// Delete Collection Confirm Semantics
// ============================================================================

#[fcp_async_core::runtime::test]
async fn delete_collection_confirm_true_succeeds() {
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.delete"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.delete",
        &["vectordb.delete_collection"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.delete_collection",
        json!({"collection": "old", "confirm": true}),
        &token,
    )
    .await;
    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp["deleted"], true);
    assert_eq!(resp["collection"], "old");
}

#[fcp_async_core::runtime::test]
async fn delete_collection_missing_confirm() {
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.delete"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.delete",
        &["vectordb.delete_collection"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.delete_collection",
        json!({"collection": "old"}),
        &token,
    )
    .await;
    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

// ============================================================================
// Connector Lifecycle
// ============================================================================

#[test]
fn connector_default_trait() {
    let c = VectorDbConnector::default();
    assert!(!c.is_configured());
    assert!(c.provider().is_none());
}

#[fcp_async_core::runtime::test]
async fn connector_handshake_sets_session() {
    let mut connector = VectorDbConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    connector
        .handle_configure(json!({
            "provider": "qdrant",
            "endpoint": "localhost:6333",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
            "use_tls": false
        }))
        .await
        .expect("configure ok");

    let hs = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["vectordb.collections.read"],
    );
    let result = connector
        .handle_handshake(serde_json::to_value(hs).expect("serialize"))
        .await;
    assert!(result.is_ok());

    let resp = result.unwrap();
    assert_eq!(resp["status"], "accepted");
    assert!(resp["session_id"].is_string());
}

// ============================================================================
// Metrics Tracking
// ============================================================================

#[fcp_async_core::runtime::test]
async fn metrics_track_successful_invoke() {
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.read",
        &["vectordb.list_collections"],
        c.instance_id(),
    );

    let health_before = c.handle_health();
    let total_before = health_before["metrics"]["requests_total"]
        .as_u64()
        .unwrap_or(0);

    invoke(&c, "vectordb.list_collections", json!({}), &token)
        .await
        .expect("invoke ok");

    let health_after = c.handle_health();
    let total_after = health_after["metrics"]["requests_total"]
        .as_u64()
        .unwrap_or(0);
    assert_eq!(total_after, total_before + 1);
}

#[fcp_async_core::runtime::test]
async fn metrics_track_failed_invoke() {
    let (c, key) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.vectors.read",
        &["vectordb.query_vectors"],
        c.instance_id(),
    );

    let health_before = c.handle_health();
    let errors_before = health_before["metrics"]["requests_error"]
        .as_u64()
        .unwrap_or(0);

    // Missing vector field → will fail
    let _ = invoke(
        &c,
        "vectordb.query_vectors",
        json!({"collection": "docs"}),
        &token,
    )
    .await;

    let health_after = c.handle_health();
    let errors_after = health_after["metrics"]["requests_error"]
        .as_u64()
        .unwrap_or(0);
    assert_eq!(errors_after, errors_before + 1);
}

// ============================================================================
// Structured JSON Logging Infrastructure (per 1n78.35)
// ============================================================================

struct TestLog {
    test_name: &'static str,
    module: &'static str,
    correlation_id: String,
    start: Instant,
    assertions_passed: u32,
    assertions_failed: u32,
    capture: LogCapture,
}

impl TestLog {
    fn new(test_name: &'static str) -> Self {
        Self {
            test_name,
            module: "fcp-vectordb-integration",
            correlation_id: uuid::Uuid::new_v4().to_string(),
            start: Instant::now(),
            assertions_passed: 0,
            assertions_failed: 0,
            capture: LogCapture::new(),
        }
    }

    fn check(&mut self, condition: bool, message: &str) -> Result<(), String> {
        if !condition {
            self.assertions_failed = self.assertions_failed.saturating_add(1);
            return Err(message.to_string());
        }
        self.assertions_passed = self.assertions_passed.saturating_add(1);
        Ok(())
    }

    #[allow(clippy::needless_pass_by_value)]
    fn check_eq<T: std::fmt::Debug + PartialEq>(
        &mut self,
        left: T,
        right: T,
        context: &str,
    ) -> Result<(), String> {
        if left != right {
            self.assertions_failed = self.assertions_failed.saturating_add(1);
            return Err(format!("{context}: left={left:?} right={right:?}"));
        }
        self.assertions_passed = self.assertions_passed.saturating_add(1);
        Ok(())
    }

    #[allow(clippy::needless_pass_by_value)]
    fn emit(&mut self, phase: &str, result: &str, context: serde_json::Value) {
        let duration_ms = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let entry = json!({
            "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            "log_version": "v1",
            "level": "info",
            "test_name": self.test_name,
            "module": self.module,
            "phase": phase,
            "correlation_id": self.correlation_id,
            "result": result,
            "duration_ms": duration_ms,
            "assertions": {
                "passed": self.assertions_passed,
                "failed": self.assertions_failed
            },
            "context": context
        });

        let serialized = serde_json::to_string(&entry).unwrap_or_else(|err| {
            self.assertions_failed = self.assertions_failed.saturating_add(1);
            format!("{{\"error\":\"log_serialization_failed\",\"detail\":\"{err}\"}}")
        });
        println!("{serialized}");
        let _ = self.capture.push_value(&entry);
        if !std::thread::panicking() {
            self.capture.assert_valid();
        }
    }
}

impl Drop for TestLog {
    fn drop(&mut self) {
        let result = if std::thread::panicking() {
            if self.assertions_failed == 0 {
                self.assertions_failed = 1;
            }
            "fail"
        } else {
            "pass"
        };
        self.emit("verify", result, json!({ "connector_id": "vectordb" }));
    }
}

// ============================================================================
// Logged: Schema Completeness
// ============================================================================

#[test]
fn logged_schema_completeness_all_ops_have_schemas() -> Result<(), String> {
    let mut log = TestLog::new("vectordb_schema_completeness");
    let connector = VectorDbConnector::new();
    let introspection = connector.handle_introspect();

    log.check_eq(introspection.operations.len(), 9usize, "operation count")?;

    for op in &introspection.operations {
        log.check(
            op.input_schema.is_object(),
            &format!("{}: input_schema must be object", op.id),
        )?;
        log.check_eq(
            op.input_schema["type"].as_str(),
            Some("object"),
            &format!("{}: input_schema type", op.id),
        )?;
        log.check(
            op.output_schema.is_object(),
            &format!("{}: output_schema must be object", op.id),
        )?;
        log.check_eq(
            op.output_schema["type"].as_str(),
            Some("object"),
            &format!("{}: output_schema type", op.id),
        )?;
        log.check(
            !op.summary.is_empty(),
            &format!("{}: summary must not be empty", op.id),
        )?;
        log.check(
            !op.capability.as_str().is_empty(),
            &format!("{}: capability must not be empty", op.id),
        )?;
    }

    log.emit(
        "verify",
        "pass",
        json!({
            "operations_checked": introspection.operations.len(),
            "checks": ["input_schema", "output_schema", "summary", "capabilities"]
        }),
    );
    Ok(())
}

#[test]
fn logged_schema_unknown_op_returns_none() -> Result<(), String> {
    let mut log = TestLog::new("vectordb_schema_unknown_op");
    let connector = VectorDbConnector::new();
    let introspection = connector.handle_introspect();

    let unknown = introspection
        .operations
        .iter()
        .find(|op| op.id.as_str() == "vectordb.nonexistent");
    log.check(
        unknown.is_none(),
        "unknown op should not appear in introspection",
    )?;
    Ok(())
}

// ============================================================================
// Logged: Error Taxonomy Mapping
// ============================================================================

#[fcp_async_core::runtime::test]
async fn logged_error_taxonomy_not_configured() -> Result<(), String> {
    let mut log = TestLog::new("vectordb_error_taxonomy_not_configured");
    let connector = VectorDbConnector::new();

    let result = connector
        .handle_invoke(json!({
            "operation": "vectordb.list_collections",
            "input": {},
            "capability_token": {"raw": []}
        }))
        .await;

    log.check(
        matches!(&result, Err(FcpError::NotConfigured)),
        "unconfigured connector must return NotConfigured",
    )?;
    log.emit(
        "verify",
        "pass",
        json!({
            "error_variant": "NotConfigured"
        }),
    );
    Ok(())
}

#[fcp_async_core::runtime::test]
async fn logged_error_taxonomy_invalid_request_codes() -> Result<(), String> {
    let mut log = TestLog::new("vectordb_error_taxonomy_invalid_request");
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.write"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.write",
        &["vectordb.create_collection"],
        c.instance_id(),
    );

    // Missing required field 'dimension'
    let result = invoke(
        &c,
        "vectordb.create_collection",
        json!({"collection": "test"}),
        &token,
    )
    .await;

    if let Err(FcpError::InvalidRequest { code, message }) = &result {
        log.check_eq(*code, 1003u16, "InvalidRequest code must be 1003")?;
        log.check(!message.is_empty(), "error message must not be empty")?;
    } else {
        log.check(false, &format!("expected InvalidRequest, got {result:?}"))?;
    }

    // Invalid collection name
    let result2 = invoke(
        &c,
        "vectordb.create_collection",
        json!({"collection": "INVALID", "dimension": 768}),
        &token,
    )
    .await;

    if let Err(FcpError::InvalidRequest { code, .. }) = &result2 {
        log.check_eq(
            *code,
            1003u16,
            "InvalidRequest code must be 1003 for name validation",
        )?;
    } else {
        log.check(false, &format!("expected InvalidRequest, got {result2:?}"))?;
    }

    log.emit(
        "verify",
        "pass",
        json!({
            "error_variant": "InvalidRequest",
            "expected_code": 1003,
            "scenarios_tested": 2
        }),
    );
    Ok(())
}

#[fcp_async_core::runtime::test]
async fn logged_error_taxonomy_operation_not_granted() -> Result<(), String> {
    let mut log = TestLog::new("vectordb_error_taxonomy_operation_not_granted");
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.read",
        &["vectordb.nonexistent"],
        c.instance_id(),
    );

    let result = invoke(&c, "vectordb.nonexistent", json!({}), &token).await;

    log.check(
        matches!(&result, Err(FcpError::OperationNotGranted { .. })),
        "unknown operation must return OperationNotGranted",
    )?;
    log.emit(
        "verify",
        "pass",
        json!({
            "error_variant": "OperationNotGranted"
        }),
    );
    Ok(())
}

// ============================================================================
// Logged: Capability Gating Matrix
// ============================================================================

#[fcp_async_core::runtime::test]
async fn logged_capability_gating_per_operation() -> Result<(), String> {
    let mut log = TestLog::new("vectordb_capability_gating_matrix");

    let cap_map: &[(&str, &str, serde_json::Value)] = &[
        (
            "vectordb.collections.read",
            "vectordb.list_collections",
            json!({}),
        ),
        (
            "vectordb.collections.read",
            "vectordb.describe_collection",
            json!({"collection": "test"}),
        ),
        (
            "vectordb.collections.write",
            "vectordb.create_collection",
            json!({"collection": "test", "dimension": 768}),
        ),
        (
            "vectordb.collections.delete",
            "vectordb.delete_collection",
            json!({"collection": "test", "confirm": true}),
        ),
        (
            "vectordb.vectors.read",
            "vectordb.query_vectors",
            json!({"collection": "test", "vector": [1.0, 2.0, 3.0]}),
        ),
        (
            "vectordb.vectors.read",
            "vectordb.fetch_vectors",
            json!({"collection": "test", "ids": ["v1"]}),
        ),
        (
            "vectordb.vectors.write",
            "vectordb.upsert_vectors",
            json!({"collection": "test", "vectors": [{"id": "v1", "values": [1.0]}]}),
        ),
        (
            "vectordb.vectors.delete",
            "vectordb.delete_vectors",
            json!({"collection": "test", "ids": ["v1"]}),
        ),
        (
            "vectordb.vectors.write",
            "vectordb.update_vector_metadata",
            json!({"collection": "test", "id": "v1", "metadata": {"key": "val"}}),
        ),
    ];

    let mut ops_verified = 0u32;
    for (cap, op, input) in cap_map {
        let (c, key) = setup_connector("qdrant", "localhost:6333", &[cap]).await;
        let token = generate_token(&key, cap, &[op], c.instance_id());

        let result = invoke(&c, op, input.clone(), &token).await;
        log.check(
            result.is_ok(),
            &format!("{op} with correct cap {cap} should succeed: {result:?}"),
        )?;
        ops_verified += 1;
    }

    log.check_eq(ops_verified, 9u32, "all 9 operations must be verified")?;
    log.emit(
        "verify",
        "pass",
        json!({
            "operations_verified": ops_verified,
            "check": "correct_capability_grants_access"
        }),
    );
    Ok(())
}

#[fcp_async_core::runtime::test]
async fn logged_capability_wrong_cap_denies_access() -> Result<(), String> {
    let mut log = TestLog::new("vectordb_capability_wrong_cap_denied");

    // Try write op with read capability
    let (c, key) =
        setup_connector("qdrant", "localhost:6333", &["vectordb.collections.read"]).await;
    let token = generate_token(
        &key,
        "vectordb.collections.read",
        &["vectordb.create_collection"],
        c.instance_id(),
    );

    let result = invoke(
        &c,
        "vectordb.create_collection",
        json!({"collection": "test", "dimension": 768}),
        &token,
    )
    .await;

    log.check(result.is_err(), "wrong capability must deny access")?;

    // Try delete op with write capability
    let (c2, key2) = setup_connector("qdrant", "localhost:6333", &["vectordb.vectors.write"]).await;
    let token2 = generate_token(
        &key2,
        "vectordb.vectors.write",
        &["vectordb.delete_vectors"],
        c.instance_id(),
    );

    let result2 = invoke(
        &c2,
        "vectordb.delete_vectors",
        json!({"collection": "test", "ids": ["v1"]}),
        &token2,
    )
    .await;

    log.check(result2.is_err(), "write cap must not grant delete access")?;
    log.emit(
        "verify",
        "pass",
        json!({
            "scenarios_tested": 2,
            "check": "wrong_capability_denies_access"
        }),
    );
    Ok(())
}

// ============================================================================
// Logged: Redaction Chain
// ============================================================================

#[fcp_async_core::runtime::test]
async fn logged_redaction_chain_no_credential_leakage() -> Result<(), String> {
    let mut log = TestLog::new("vectordb_redaction_chain");
    let cred = "aabbccdd-1122-3344-5566-778899aabbcc";
    let mut connector = VectorDbConnector::new();

    // Step 1: Configure successfully
    connector
        .handle_configure(json!({
            "provider": "pinecone",
            "endpoint": "my-index.svc.us-east-1.pinecone.io",
            "credential_id": cred
        }))
        .await
        .map_err(|err| format!("configure failed: {err}"))?;

    // Step 2: Check health output
    let health = connector.handle_health();
    let health_str = serde_json::to_string(&health).unwrap_or_default();
    log.check(
        !health_str.contains(cred),
        "health output must not leak full credential id",
    )?;

    // Step 3: Check doctor output
    let doctor = connector
        .handle_doctor()
        .await
        .map_err(|err| format!("doctor failed: {err}"))?;
    let doctor_str = serde_json::to_string(&doctor).unwrap_or_default();
    log.check(
        !doctor_str.contains(cred),
        "doctor output must not leak full credential id",
    )?;

    // Step 4: Check redacted form (first 8 chars only)
    log.check(
        doctor_str.contains("aabbccdd"),
        "doctor should show truncated credential prefix",
    )?;

    // Step 5: Configure with bad endpoint to trigger error path
    let mut connector2 = VectorDbConnector::new();
    let result = connector2
        .handle_configure(json!({
            "provider": "pinecone",
            "endpoint": "",
            "credential_id": cred
        }))
        .await;

    if let Err(err) = &result {
        let err_str = format!("{err}");
        log.check(
            !err_str.contains(cred),
            "error message must not leak full credential id",
        )?;
    }

    log.emit(
        "verify",
        "pass",
        json!({
            "credential_tested": "aabbccdd-...redacted...",
            "paths_checked": ["health", "doctor", "configure_error"]
        }),
    );
    Ok(())
}

// ============================================================================
// Logged: Retry & Idempotency Rules
// ============================================================================

#[test]
fn logged_retry_idempotency_classification() -> Result<(), String> {
    let mut log = TestLog::new("vectordb_retry_idempotency_rules");
    let connector = VectorDbConnector::new();
    let introspection = connector.handle_introspect();

    let find = |id: &str| {
        introspection
            .operations
            .iter()
            .find(|op| op.id.as_str() == id)
    };

    // Read operations: idempotent (class None = safe to retry, always same result)
    let read_ops = [
        "vectordb.list_collections",
        "vectordb.describe_collection",
        "vectordb.query_vectors",
        "vectordb.fetch_vectors",
    ];
    for op_id in &read_ops {
        let op = find(op_id).ok_or_else(|| format!("missing operation: {op_id}"))?;
        log.check_eq(op.idempotency, IdempotencyClass::None, op_id)?;
    }

    // Write/delete operations: best effort idempotency
    let write_ops = [
        "vectordb.create_collection",
        "vectordb.delete_collection",
        "vectordb.upsert_vectors",
        "vectordb.delete_vectors",
        "vectordb.update_vector_metadata",
    ];
    for op_id in &write_ops {
        let op = find(op_id).ok_or_else(|| format!("missing operation: {op_id}"))?;
        log.check_eq(op.idempotency, IdempotencyClass::BestEffort, op_id)?;
    }

    log.emit(
        "verify",
        "pass",
        json!({
            "read_ops_none": read_ops.len(),
            "write_ops_best_effort": write_ops.len()
        }),
    );
    Ok(())
}

// ============================================================================
// Logged: Risk Level & Safety Tier Validation
// ============================================================================

#[test]
fn logged_risk_levels_and_safety_tiers() -> Result<(), String> {
    let mut log = TestLog::new("vectordb_risk_levels");
    let connector = VectorDbConnector::new();
    let introspection = connector.handle_introspect();

    let find = |id: &str| {
        introspection
            .operations
            .iter()
            .find(|op| op.id.as_str() == id)
    };

    // Read ops: low risk, safe tier
    for op_id in &[
        "vectordb.list_collections",
        "vectordb.describe_collection",
        "vectordb.query_vectors",
        "vectordb.fetch_vectors",
        "vectordb.update_vector_metadata",
    ] {
        let op = find(op_id).ok_or_else(|| format!("missing: {op_id}"))?;
        log.check_eq(op.risk_level, RiskLevel::Low, &format!("{op_id} risk"))?;
        log.check_eq(op.safety_tier, SafetyTier::Safe, &format!("{op_id} safety"))?;
    }

    // Write ops: medium risk
    for op_id in &[
        "vectordb.create_collection",
        "vectordb.upsert_vectors",
        "vectordb.delete_vectors",
    ] {
        let op = find(op_id).ok_or_else(|| format!("missing: {op_id}"))?;
        log.check_eq(op.risk_level, RiskLevel::Medium, &format!("{op_id} risk"))?;
    }

    // Delete collection: high risk, requires interactive approval
    let delete = find("vectordb.delete_collection").ok_or("missing delete_collection")?;
    log.check_eq(delete.risk_level, RiskLevel::High, "delete_collection risk")?;
    log.check_eq(
        delete.safety_tier,
        SafetyTier::Dangerous,
        "delete_collection safety_tier",
    )?;

    log.emit(
        "verify",
        "pass",
        json!({
            "low_risk_ops": 5,
            "medium_risk_ops": 3,
            "high_risk_ops": 1
        }),
    );
    Ok(())
}

// ============================================================================
// Logged: Payload Bounds Enforcement
// ============================================================================

#[fcp_async_core::runtime::test]
async fn logged_payload_bounds_enforcement() -> Result<(), String> {
    let mut log = TestLog::new("vectordb_payload_bounds");
    let (c, key) = setup_connector(
        "qdrant",
        "localhost:6333",
        &[
            "vectordb.collections.write",
            "vectordb.vectors.read",
            "vectordb.vectors.write",
        ],
    )
    .await;

    // Dimension bounds: 0 rejected
    let token_w = generate_token(
        &key,
        "vectordb.collections.write",
        &["vectordb.create_collection"],
        c.instance_id(),
    );
    let result = invoke(
        &c,
        "vectordb.create_collection",
        json!({"collection": "test", "dimension": 0}),
        &token_w,
    )
    .await;
    log.check(result.is_err(), "dimension 0 must be rejected")?;

    // Dimension bounds: 10001 rejected
    let result = invoke(
        &c,
        "vectordb.create_collection",
        json!({"collection": "test", "dimension": 10001}),
        &token_w,
    )
    .await;
    log.check(result.is_err(), "dimension 10001 must be rejected")?;

    // top_k bounds: 0 rejected
    let token_r = generate_token(
        &key,
        "vectordb.vectors.read",
        &["vectordb.query_vectors"],
        c.instance_id(),
    );
    let result = invoke(
        &c,
        "vectordb.query_vectors",
        json!({"collection": "test", "vector": [1.0], "top_k": 0}),
        &token_r,
    )
    .await;
    log.check(result.is_err(), "top_k 0 must be rejected")?;

    // Upsert empty batch rejected
    let token_upsert = generate_token(
        &key,
        "vectordb.vectors.write",
        &["vectordb.upsert_vectors"],
        c.instance_id(),
    );
    let result = invoke(
        &c,
        "vectordb.upsert_vectors",
        json!({"collection": "test", "vectors": []}),
        &token_upsert,
    )
    .await;
    log.check(result.is_err(), "empty vector batch must be rejected")?;

    // Fetch empty IDs rejected
    let token_f = generate_token(
        &key,
        "vectordb.vectors.read",
        &["vectordb.fetch_vectors"],
        c.instance_id(),
    );
    let result = invoke(
        &c,
        "vectordb.fetch_vectors",
        json!({"collection": "test", "ids": []}),
        &token_f,
    )
    .await;
    log.check(result.is_err(), "empty IDs list must be rejected")?;

    log.emit("verify", "pass", json!({
        "bounds_tested": ["dimension_min", "dimension_max", "top_k_min", "upsert_empty", "fetch_empty"],
        "all_rejected": true
    }));
    Ok(())
}

// ============================================================================
// Logged: Config Timeout Validation
// ============================================================================

#[test]
fn logged_config_timeout_validation() -> Result<(), String> {
    let mut log = TestLog::new("vectordb_config_timeouts");
    let credential_id = fcp_core::CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00")
        .map_err(|err| format!("credential parse: {err}"))?;

    // Valid config
    let valid = VectorDbConfig {
        provider: VectorDbProvider::Qdrant,
        endpoint: "localhost:6333".into(),
        credential_id,
        use_tls: false,
        namespace: None,
        connect_timeout_ms: 10_000,
        request_timeout_ms: 60_000,
    };
    log.check(valid.validate().is_ok(), "valid config should pass")?;

    // Connect timeout too low
    let too_low = VectorDbConfig {
        connect_timeout_ms: 0,
        ..valid.clone()
    };
    log.check(
        too_low.validate().is_err(),
        "connect_timeout_ms=0 must fail",
    )?;

    // Request timeout too high
    let too_high = VectorDbConfig {
        request_timeout_ms: 700_000,
        ..valid.clone()
    };
    log.check(
        too_high.validate().is_err(),
        "request_timeout_ms=700000 must fail",
    )?;

    // Connect timeout at upper bound
    let upper = VectorDbConfig {
        connect_timeout_ms: 300_000,
        ..valid.clone()
    };
    log.check(
        upper.validate().is_ok(),
        "connect_timeout_ms=300000 should pass",
    )?;

    // Request timeout at upper bound
    let req_upper = VectorDbConfig {
        request_timeout_ms: 600_000,
        ..valid
    };
    log.check(
        req_upper.validate().is_ok(),
        "request_timeout_ms=600000 should pass",
    )?;

    log.emit("verify", "pass", json!({
        "scenarios": ["valid", "connect_too_low", "request_too_high", "connect_upper", "request_upper"]
    }));
    Ok(())
}

// ============================================================================
// Logged: Introspection Determinism
// ============================================================================

#[test]
fn logged_introspection_deterministic() -> Result<(), String> {
    let mut log = TestLog::new("vectordb_introspect_deterministic");
    let c1 = VectorDbConnector::new();
    let c2 = VectorDbConnector::new();

    let i1 = c1.handle_introspect();
    let i2 = c2.handle_introspect();

    let s1 = serde_json::to_string(&i1.operations).unwrap_or_default();
    let s2 = serde_json::to_string(&i2.operations).unwrap_or_default();

    log.check_eq(
        s1,
        s2,
        "introspection must be deterministic across instances",
    )?;
    log.emit(
        "verify",
        "pass",
        json!({
            "check": "deterministic_serialization"
        }),
    );
    Ok(())
}

// ============================================================================
// Logged: Full Lifecycle Smoke Test
// ============================================================================

#[fcp_async_core::runtime::test]
async fn logged_lifecycle_configure_handshake_invoke() -> Result<(), String> {
    let mut log = TestLog::new("vectordb_lifecycle_smoke");
    let mut connector = VectorDbConnector::new();

    // Step 1: Not configured
    log.check(!connector.is_configured(), "must start unconfigured")?;
    log.check(connector.provider().is_none(), "provider must be None")?;

    // Step 2: Configure
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handle_configure(json!({
            "provider": "qdrant",
            "endpoint": "localhost:6333",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
            "use_tls": false
        }))
        .await
        .map_err(|err| format!("configure failed: {err}"))?;

    log.check(
        connector.is_configured(),
        "must be configured after configure",
    )?;
    log.check_eq(
        connector.provider(),
        Some(VectorDbProvider::Qdrant),
        "provider must be qdrant",
    )?;

    // Step 3: Health check
    let health = connector.handle_health();
    log.check_eq(health["status"].as_str(), Some("healthy"), "health status")?;

    // Step 4: Handshake
    let hs = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["vectordb.collections.read"],
    );
    let hs_result = connector
        .handle_handshake(serde_json::to_value(hs).map_err(|e| format!("serialize: {e}"))?)
        .await
        .map_err(|err| format!("handshake failed: {err}"))?;

    log.check_eq(
        hs_result["status"].as_str(),
        Some("accepted"),
        "handshake accepted",
    )?;

    // Step 5: Invoke
    let token = generate_token(
        &signing_key,
        "vectordb.collections.read",
        &["vectordb.list_collections"],
        connector.instance_id(),
    );
    let result = invoke(&connector, "vectordb.list_collections", json!({}), &token)
        .await
        .map_err(|err| format!("invoke failed: {err}"))?;

    log.check(
        result
            .get("collections")
            .is_some_and(serde_json::Value::is_array),
        "collections must be an array",
    )?;

    // Step 6: Metrics after invoke
    let health_after = connector.handle_health();
    let total = health_after["metrics"]["requests_total"]
        .as_u64()
        .unwrap_or(0);
    log.check(total >= 1, "requests_total must be >= 1 after invoke")?;

    log.emit(
        "verify",
        "pass",
        json!({
            "steps": ["unconfigured", "configure", "health", "handshake", "invoke", "metrics"]
        }),
    );
    Ok(())
}

// ============================================================================
// Self-Check Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn self_check_unconfigured_returns_degraded() {
    let connector = VectorDbConnector::new();
    let result = connector
        .handle_self_check()
        .await
        .expect("self_check should not error");
    assert_eq!(result["status"], "degraded");
    assert_eq!(result["reason_code"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn self_check_configured_no_handshake_returns_degraded() {
    let mut connector = VectorDbConnector::new();
    connector
        .handle_configure(json!({
            "provider": "qdrant",
            "endpoint": "my-cluster.qdrant.io:6334",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
            "use_tls": false
        }))
        .await
        .expect("configure should succeed");

    let result = connector
        .handle_self_check()
        .await
        .expect("self_check should not error");
    assert_eq!(result["status"], "degraded");
    assert_eq!(result["reason_code"], "not_handshaken");
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_returns_ok() {
    let (connector, _key) = setup_connector(
        "qdrant",
        "my-cluster.qdrant.io:6334",
        &["vectordb.vectors.read"],
    )
    .await;

    let result = connector
        .handle_self_check()
        .await
        .expect("self_check should not error");
    assert_eq!(result["status"], "ok");
    assert_eq!(result["details"]["runtime_ready"], true);
    assert_eq!(result["details"]["provider"], "qdrant");
}

#[fcp_async_core::runtime::test]
async fn self_check_pinecone_ready() {
    let (connector, _key) = setup_connector(
        "pinecone",
        "my-index.svc.pinecone.io",
        &["vectordb.vectors.read"],
    )
    .await;

    let result = connector
        .handle_self_check()
        .await
        .expect("self_check should not error");
    assert_eq!(result["status"], "ok");
    assert_eq!(result["details"]["provider"], "pinecone");
    assert_eq!(result["details"]["tls"], true);
}

#[fcp_async_core::runtime::test]
async fn self_check_bad_endpoint_returns_failed() {
    let mut connector = VectorDbConnector::new();
    // Configure with bad endpoint but valid structure
    connector
        .handle_configure(json!({
            "provider": "pinecone",
            "endpoint": "evil.example.com",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        }))
        .await
        .expect("configure should succeed");

    // Handshake to initialise runtime
    let signing_key = Ed25519SigningKey::generate();
    let hs = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["vectordb.vectors.read"],
    );
    connector
        .handle_handshake(serde_json::to_value(hs).expect("serialize"))
        .await
        .expect("handshake should succeed");

    let result = connector
        .handle_self_check()
        .await
        .expect("self_check should not error");
    assert_eq!(result["status"], "failed");
    assert_eq!(result["reason_code"], "endpoint_mismatch");
}

// ============================================================================
// Simulate Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn simulate_known_operation_returns_allowed() {
    let (connector, signing_key) = setup_connector(
        "qdrant",
        "my-cluster.qdrant.io:6334",
        &["vectordb.vectors.read"],
    )
    .await;

    let token = generate_token(
        &signing_key,
        "vectordb.vectors.read",
        &["vectordb.query_vectors"],
        connector.instance_id(),
    );
    let result = connector
        .handle_simulate(json!({
            "type": "simulate",
            "id": "sim-001",
            "connector_id": "vectordb",
            "operation": "vectordb.query_vectors",
            "zone_id": "z:work",
            "input": { "collection": "test", "vector": [0.1, 0.2], "top_k": 5 },
            "capability_token": token
        }))
        .await
        .expect("simulate should succeed");

    assert_eq!(result["would_succeed"], true);
}

#[fcp_async_core::runtime::test]
async fn simulate_unknown_operation_returns_failure() {
    let (connector, signing_key) = setup_connector(
        "qdrant",
        "my-cluster.qdrant.io:6334",
        &["vectordb.vectors.read"],
    )
    .await;

    let token = generate_token(
        &signing_key,
        "vectordb.vectors.read",
        &["vectordb.nonexistent"],
        connector.instance_id(),
    );
    let result = connector
        .handle_simulate(json!({
            "type": "simulate",
            "id": "sim-002",
            "connector_id": "vectordb",
            "operation": "vectordb.nonexistent",
            "zone_id": "z:work",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect("simulate should succeed");

    assert_eq!(result["would_succeed"], false);
    assert!(
        result["failure_reason"]
            .as_str()
            .unwrap_or("")
            .contains("Unknown operation")
    );
    assert_eq!(result["denial_code"], "unknown_operation");
}

#[fcp_async_core::runtime::test]
async fn simulate_unconfigured_returns_not_configured() {
    let connector = VectorDbConnector::new();

    let signing_key = Ed25519SigningKey::generate();
    let token = generate_token(
        &signing_key,
        "vectordb.vectors.read",
        &["vectordb.query_vectors"],
        connector.instance_id(),
    );
    let result = connector
        .handle_simulate(json!({
            "type": "simulate",
            "id": "sim-003",
            "connector_id": "vectordb",
            "operation": "vectordb.query_vectors",
            "zone_id": "z:work",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect("simulate should succeed");

    assert_eq!(result["would_succeed"], false);
    assert_eq!(result["denial_code"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn simulate_all_nine_operations_allowed() {
    let (connector, signing_key) = setup_connector(
        "pinecone",
        "my-index.svc.pinecone.io",
        &[
            "vectordb.vectors.read",
            "vectordb.vectors.write",
            "vectordb.collections.read",
            "vectordb.collections.write",
            "vectordb.collections.delete",
        ],
    )
    .await;

    let ops = [
        "vectordb.list_collections",
        "vectordb.describe_collection",
        "vectordb.create_collection",
        "vectordb.delete_collection",
        "vectordb.query_vectors",
        "vectordb.fetch_vectors",
        "vectordb.upsert_vectors",
        "vectordb.delete_vectors",
        "vectordb.update_vector_metadata",
    ];

    for (i, op) in ops.iter().enumerate() {
        let token = generate_token(
            &signing_key,
            "vectordb.vectors.read",
            &[op],
            connector.instance_id(),
        );
        let result = connector
            .handle_simulate(json!({
                "type": "simulate",
                "id": format!("sim-all-{i}"),
                "connector_id": "vectordb",
                "operation": *op,
                "zone_id": "z:work",
                "input": {},
                "capability_token": token
            }))
            .await
            .unwrap_or_else(|e| panic!("simulate {op} should succeed: {e}"));

        assert_eq!(
            result["would_succeed"], true,
            "operation {op} should be allowed in simulation"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn simulate_invalid_request_returns_error() {
    let (connector, _key) = setup_connector(
        "qdrant",
        "my-cluster.qdrant.io:6334",
        &["vectordb.vectors.read"],
    )
    .await;

    // Malformed request — missing required fields
    let result = connector.handle_simulate(json!({"garbage": true})).await;
    assert!(result.is_err(), "malformed simulate should return error");
}

// ============================================================================
// Main.rs Dispatch Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn main_dispatch_self_check_and_simulate_exist() {
    // Verify that a new connector responds to self_check and simulate
    // before configuration (should not error, just report status)
    let connector = VectorDbConnector::new();

    let self_check = connector
        .handle_self_check()
        .await
        .expect("self_check dispatch must exist");
    assert!(
        self_check.get("status").is_some(),
        "self_check must return a status field"
    );

    let signing_key = Ed25519SigningKey::generate();
    let token = generate_token(
        &signing_key,
        "vectordb.vectors.read",
        &["vectordb.query_vectors"],
        connector.instance_id(),
    );
    let simulate = connector
        .handle_simulate(json!({
            "type": "simulate",
            "id": "dispatch-test",
            "connector_id": "vectordb",
            "operation": "vectordb.query_vectors",
            "zone_id": "z:work",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect("simulate dispatch must exist");
    assert!(
        simulate.get("would_succeed").is_some(),
        "simulate must return would_succeed field"
    );
}
