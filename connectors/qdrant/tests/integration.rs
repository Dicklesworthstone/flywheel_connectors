//! Qdrant connector integration tests.
//!
//! Deterministic integration tests using wiremock to mock the Qdrant REST API.
//! No real API calls. Covers:
//! - Happy-path operations (list_collections, search, upsert_points, collection_info)
//! - Error taxonomy (401/404/429 -> FcpError mapping)
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, handshake, introspect, shutdown)
//! - Input validation edge cases

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::CapabilityConstraints;
use fcp_testkit::AsyncTestContext;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use fcp_qdrant::connector::QdrantConnector;

// ============================================================================
// Helpers
// ============================================================================

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    op: &str,
) -> fcp_core::CapabilityToken {
    let cap = match op {
        "qdrant.create_collection" | "qdrant.delete_collection" => "qdrant.collections.write",
        "qdrant.upsert_points" | "qdrant.delete_points" => "qdrant.points.write",
        "qdrant.search"
        | "qdrant.query_points"
        | "qdrant.batch_query_points"
        | "qdrant.get_points"
        | "qdrant.scroll"
        | "qdrant.count" => "qdrant.points.read",
        _ => "qdrant.collections.read",
    };
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
        .operations(&[op])
        .issuer("node:test")
        .target_instance(instance_id)
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .unwrap();
    fcp_core::CapabilityToken::from_raw(cose)
}

async fn setup_configure(connector: &mut QdrantConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "api_key": "test-qdrant-key",
            "cluster_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

async fn setup_handshake(connector: &mut QdrantConnector, caps: &[&str]) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": caps
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

async fn full_setup(
    connector: &mut QdrantConnector,
    caps: &[&str],
) -> (MockServer, Ed25519SigningKey) {
    let mock_server = MockServer::start().await;
    setup_configure(connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(connector, caps).await;
    (mock_server, signing_key)
}

// ============================================================================
// Happy-path operation tests
// ============================================================================

#[fcp_async_core::test]
async fn list_collections_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.list_collections.happy_path");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.list_collections"]).await;

    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": {
                "collections": [
                    { "name": "embeddings" },
                    { "name": "documents" }
                ]
            },
            "status": "ok",
            "time": 0.001
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.list_collections",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.list_collections",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect("list_collections invoke should succeed");

    let collections = result["collections"].as_array().expect("collections array");
    assert_eq!(collections.len(), 2);
}

#[fcp_async_core::test]
async fn search_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.search.happy_path");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.search"]).await;

    Mock::given(method("POST"))
        .and(path("/collections/embeddings/points/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": [
                { "id": 1, "version": 0, "score": 0.95, "payload": { "text": "hello" } },
                { "id": 2, "version": 0, "score": 0.88, "payload": { "text": "world" } }
            ],
            "status": "ok",
            "time": 0.005
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.search");
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.search",
            "input": {
                "collection_name": "embeddings",
                "vector": [0.1, 0.2, 0.3],
                "limit": 5
            },
            "capability_token": token
        }))
        .await
        .expect("search invoke should succeed");

    let results = result["result"].as_array().expect("result array");
    assert_eq!(results.len(), 2);
}

#[fcp_async_core::test]
async fn upsert_points_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.upsert_points.happy_path");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.upsert_points"]).await;

    Mock::given(method("PUT"))
        .and(path("/collections/embeddings/points"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": { "operation_id": 0, "status": "completed" },
            "status": "ok",
            "time": 0.01
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.upsert_points",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.upsert_points",
            "input": {
                "collection_name": "embeddings",
                "points": [
                    { "id": 1, "vector": [0.1, 0.2, 0.3], "payload": { "text": "hello" } }
                ]
            },
            "capability_token": token
        }))
        .await
        .expect("upsert_points invoke should succeed");

    assert_eq!(result["status"], "completed");
}

#[fcp_async_core::test]
async fn collection_info_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.collection_info.happy_path");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.collection_info"]).await;

    Mock::given(method("GET"))
        .and(path("/collections/embeddings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": {
                "status": "green",
                "optimizer_status": "ok",
                "vectors_count": 1000,
                "points_count": 1000,
                "segments_count": 2,
                "config": {
                    "params": {
                        "vectors": { "size": 3, "distance": "Cosine" }
                    }
                }
            },
            "status": "ok",
            "time": 0.001
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.collection_info",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.collection_info",
            "input": { "collection_name": "embeddings" },
            "capability_token": token
        }))
        .await
        .expect("collection_info invoke should succeed");

    assert!(result.get("result").is_some());
}

// ============================================================================
// Error taxonomy tests
// ============================================================================

#[fcp_async_core::test]
async fn unauthorized_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.error.unauthorized");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.list_collections"]).await;

    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "status": { "error": "Invalid API key" },
            "time": 0.0
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.list_collections",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.list_collections",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::test]
async fn not_found_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.error.not_found");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.collection_info"]).await;

    Mock::given(method("GET"))
        .and(path("/collections/nonexistent"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "status": { "error": "Not found: Collection `nonexistent` doesn't exist!" },
            "time": 0.0
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.collection_info",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.collection_info",
            "input": { "collection_name": "nonexistent" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// FCP2 default-deny + capability verification
// ============================================================================

#[fcp_async_core::test]
async fn invoke_without_configure_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.deny.not_configured");
    let connector = QdrantConnector::new();

    let signing_key = Ed25519SigningKey::generate();
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.list_collections",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.list_collections",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::test]
async fn invoke_with_wrong_capability_denied() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.deny.wrong_capability");
    let mut connector = QdrantConnector::new();
    // Handshake grants search but we invoke list_collections
    let (_mock_server, signing_key) = full_setup(&mut connector, &["qdrant.search"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.search");

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.list_collections",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::test]
async fn invoke_unknown_operation_denied() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.deny.unknown_operation");
    let mut connector = QdrantConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["qdrant.nonexistent"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.nonexistent");

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Lifecycle tests
// ============================================================================

#[fcp_async_core::test]
async fn health_not_configured() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.lifecycle.health_not_configured");
    let connector = QdrantConnector::new();
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "not_configured");
}

#[fcp_async_core::test]
async fn health_configured() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.lifecycle.health_configured");
    let mock_server = MockServer::start().await;
    let mut connector = QdrantConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "healthy");
}

#[fcp_async_core::test]
async fn introspect_lists_all_operations() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.lifecycle.introspect");
    let connector = QdrantConnector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().expect("operations array");
    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

    assert!(op_ids.contains(&"qdrant.list_collections"));
    assert!(op_ids.contains(&"qdrant.search"));
    assert!(op_ids.contains(&"qdrant.upsert_points"));
    assert!(op_ids.contains(&"qdrant.delete_points"));
    assert_eq!(ops.len(), 12);
}

#[fcp_async_core::test]
async fn shutdown_succeeds() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.lifecycle.shutdown");
    let connector = QdrantConnector::new();
    let result = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    assert_eq!(result["status"], "shutdown");
}

// ============================================================================
// Input validation edge cases
// ============================================================================

#[fcp_async_core::test]
async fn search_missing_collection_name_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.validation.search_missing_collection");
    let mut connector = QdrantConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["qdrant.search"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.search");

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.search",
            "input": { "vector": [0.1, 0.2, 0.3], "limit": 5 },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("collection_name"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn upsert_points_missing_points_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.validation.upsert_missing_points");
    let mut connector = QdrantConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["qdrant.upsert_points"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.upsert_points",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.upsert_points",
            "input": { "collection_name": "test" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("points"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

// ============================================================================
// Happy-path tests for remaining operations
// ============================================================================

#[fcp_async_core::test]
async fn query_points_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.query_points.happy_path");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.query_points"]).await;

    Mock::given(method("POST"))
        .and(path("/collections/embeddings/points/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": {
                "points": [
                    { "id": 1, "score": 0.92, "payload": { "text": "hello" } },
                    { "id": 2, "score": 0.88, "payload": { "text": "world" } }
                ]
            },
            "status": "ok",
            "time": 0.003
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.query_points");
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.query_points",
            "input": {
                "collection_name": "embeddings",
                "query": [0.1, 0.2, 0.3],
                "limit": 5
            },
            "capability_token": token
        }))
        .await
        .expect("query_points invoke should succeed");

    let points = result["result"].as_array().expect("result array");
    assert_eq!(points.len(), 2);
}

#[fcp_async_core::test]
async fn query_points_array_result_format() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.query_points.array_result");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.query_points"]).await;

    Mock::given(method("POST"))
        .and(path("/collections/embeddings/points/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": [
                { "id": 10, "score": 0.91 },
                { "id": 11, "score": 0.84 }
            ],
            "status": "ok",
            "time": 0.002
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.query_points");
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.query_points",
            "input": {
                "collection_name": "embeddings",
                "query": [0.1, 0.2, 0.3]
            },
            "capability_token": token
        }))
        .await
        .expect("query_points invoke should succeed");

    let points = result["result"].as_array().expect("result array");
    assert_eq!(points.len(), 2);
    assert_eq!(points[0]["id"], 10);
}

#[fcp_async_core::test]
async fn batch_query_points_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.batch_query_points.happy_path");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) =
        full_setup(&mut connector, &["qdrant.batch_query_points"]).await;

    Mock::given(method("POST"))
        .and(path("/collections/embeddings/points/query/batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": [
                { "points": [{ "id": 1, "score": 0.9 }] },
                { "points": [{ "id": 2, "score": 0.8 }] }
            ],
            "status": "ok",
            "time": 0.01
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.batch_query_points",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.batch_query_points",
            "input": {
                "collection_name": "embeddings",
                "queries": [
                    { "query": [0.1, 0.2, 0.3], "limit": 1 },
                    { "query": [0.4, 0.5, 0.6], "limit": 1 }
                ]
            },
            "capability_token": token
        }))
        .await
        .expect("batch_query_points invoke should succeed");

    let batches = result["result"].as_array().expect("result array");
    assert_eq!(batches.len(), 2);
}

#[fcp_async_core::test]
async fn get_points_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.get_points.happy_path");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.get_points"]).await;

    Mock::given(method("POST"))
        .and(path("/collections/embeddings/points"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": [
                { "id": 1, "payload": { "text": "hello" }, "vector": [0.1, 0.2, 0.3] },
                { "id": 2, "payload": { "text": "world" }, "vector": [0.4, 0.5, 0.6] }
            ],
            "status": "ok",
            "time": 0.002
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.get_points");
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.get_points",
            "input": {
                "collection_name": "embeddings",
                "ids": [1, 2],
                "with_payload": true,
                "with_vectors": true
            },
            "capability_token": token
        }))
        .await
        .expect("get_points invoke should succeed");

    let points = result["result"].as_array().expect("result array");
    assert_eq!(points.len(), 2);
    assert_eq!(points[0]["id"], 1);
}

#[fcp_async_core::test]
async fn scroll_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.scroll.happy_path");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.scroll"]).await;

    Mock::given(method("POST"))
        .and(path("/collections/embeddings/points/scroll"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": {
                "points": [
                    { "id": 1, "payload": { "text": "hello" } },
                    { "id": 2, "payload": { "text": "world" } }
                ],
                "next_page_offset": 3
            },
            "status": "ok",
            "time": 0.003
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.scroll");
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.scroll",
            "input": {
                "collection_name": "embeddings",
                "limit": 2,
                "with_payload": true
            },
            "capability_token": token
        }))
        .await
        .expect("scroll invoke should succeed");

    assert!(result.get("result").is_some());
    let scroll_result = &result["result"];
    assert_eq!(scroll_result["points"].as_array().unwrap().len(), 2);
    assert_eq!(scroll_result["next_page_offset"], 3);
}

#[fcp_async_core::test]
async fn count_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.count.happy_path");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.count"]).await;

    Mock::given(method("POST"))
        .and(path("/collections/embeddings/points/count"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": { "count": 42 },
            "status": "ok",
            "time": 0.001
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.count");
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.count",
            "input": {
                "collection_name": "embeddings",
                "exact": true
            },
            "capability_token": token
        }))
        .await
        .expect("count invoke should succeed");

    assert_eq!(result["count"], 42);
}

#[fcp_async_core::test]
async fn create_collection_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.create_collection.happy_path");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) =
        full_setup(&mut connector, &["qdrant.create_collection"]).await;

    Mock::given(method("PUT"))
        .and(path("/collections/new_embeddings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": { "status": "acknowledged" },
            "status": "ok",
            "time": 0.05
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.create_collection",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.create_collection",
            "input": {
                "collection_name": "new_embeddings",
                "vectors": { "size": 384, "distance": "Cosine" }
            },
            "capability_token": token
        }))
        .await
        .expect("create_collection invoke should succeed");

    assert_eq!(result["status"], "acknowledged");
    assert_eq!(result["receipt"]["operation"], "qdrant.create_collection");
    assert!(
        result["receipt"]["resource"]
            .as_str()
            .unwrap()
            .contains("new_embeddings")
    );
}

#[fcp_async_core::test]
async fn delete_collection_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.delete_collection.happy_path");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) =
        full_setup(&mut connector, &["qdrant.delete_collection"]).await;

    Mock::given(method("DELETE"))
        .and(path("/collections/old_data"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": { "status": "completed" },
            "status": "ok",
            "time": 0.02
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.delete_collection",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.delete_collection",
            "input": { "collection_name": "old_data" },
            "capability_token": token
        }))
        .await
        .expect("delete_collection invoke should succeed");

    assert_eq!(result["status"], "completed");
    assert_eq!(result["receipt"]["operation"], "qdrant.delete_collection");
    assert!(
        result["receipt"]["effect"]
            .as_str()
            .unwrap()
            .contains("deleted")
    );
}

#[fcp_async_core::test]
async fn delete_points_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.delete_points.happy_path");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.delete_points"]).await;

    Mock::given(method("POST"))
        .and(path("/collections/embeddings/points/delete"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": { "operation_id": 5, "status": "completed" },
            "status": "ok",
            "time": 0.01
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.delete_points",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.delete_points",
            "input": {
                "collection_name": "embeddings",
                "points": [1, 2, 3]
            },
            "capability_token": token
        }))
        .await
        .expect("delete_points invoke should succeed");

    assert_eq!(result["status"], "completed");
    assert_eq!(result["receipt"]["operation"], "qdrant.delete_points");
}

#[fcp_async_core::test]
async fn delete_points_with_filter() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.delete_points.with_filter");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.delete_points"]).await;

    Mock::given(method("POST"))
        .and(path("/collections/embeddings/points/delete"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": { "operation_id": 6, "status": "completed" },
            "status": "ok",
            "time": 0.02
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.delete_points",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.delete_points",
            "input": {
                "collection_name": "embeddings",
                "filter": {
                    "must": [
                        { "key": "category", "match": { "value": "obsolete" } }
                    ]
                }
            },
            "capability_token": token
        }))
        .await
        .expect("delete_points with filter should succeed");

    assert_eq!(result["status"], "completed");
}

// ============================================================================
// Error taxonomy tests (extended)
// ============================================================================

#[fcp_async_core::test]
async fn rate_limit_429_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.error.rate_limit_429");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.list_collections"]).await;

    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(429).append_header("retry-after", "30"))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.list_collections",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.list_collections",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::RateLimited { .. } => {}
        e => panic!("Expected RateLimited, got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn server_error_500_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.error.server_500");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.list_collections"]).await;

    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "status": { "error": "internal server error" },
            "time": 0.0
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.list_collections",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.list_collections",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::External {
            service, retryable, ..
        } => {
            assert_eq!(service, "qdrant");
            assert!(retryable);
        }
        e => panic!("Expected External (retryable), got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn json_parse_failure_from_api() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.error.json_parse_failure");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.list_collections"]).await;

    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(200).set_body_string("this is not valid json{{{"))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.list_collections",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.list_collections",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::test]
async fn forbidden_403_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.error.forbidden_403");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.list_collections"]).await;

    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "status": { "error": "Forbidden" },
            "time": 0.0
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.list_collections",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.list_collections",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Configuration validation tests
// ============================================================================

#[fcp_async_core::test]
async fn configure_missing_cluster_url_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.config.missing_cluster_url");
    let mut connector = QdrantConnector::new();
    let result = connector
        .handle_configure(json!({
            "api_key": "test-key"
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("cluster_url"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn configure_missing_auth_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.config.missing_auth");
    let mut connector = QdrantConnector::new();
    let result = connector
        .handle_configure(json!({
            "cluster_url": "https://example.qdrant.io"
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("api_key") || message.contains("credential_id"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn configure_empty_api_key_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.config.empty_api_key");
    let mut connector = QdrantConnector::new();
    let result = connector
        .handle_configure(json!({
            "api_key": "",
            "cluster_url": "https://example.qdrant.io"
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("api_key") || message.contains("credential_id"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn configure_empty_cluster_url_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.config.empty_cluster_url");
    let mut connector = QdrantConnector::new();
    let result = connector
        .handle_configure(json!({
            "api_key": "test-key",
            "cluster_url": ""
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("cluster_url"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn configure_invalid_cluster_url_scheme_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.config.bad_url_scheme");
    let mut connector = QdrantConnector::new();
    let result = connector
        .handle_configure(json!({
            "api_key": "test-key",
            "cluster_url": "ftp://example.qdrant.io"
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("http") || message.contains("https"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn configure_credential_id_mode() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.config.credential_id");
    let mut connector = QdrantConnector::new();
    let result = connector
        .handle_configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "cluster_url": "https://example.qdrant.io"
        }))
        .await
        .expect("configure with credential_id should succeed");

    assert_eq!(result["status"], "configured_pending_token_materialization");
    assert_eq!(result["details"]["auth_mode"], "credential_id");
}

#[fcp_async_core::test]
async fn configure_both_auth_modes_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.config.both_auth");
    let mut connector = QdrantConnector::new();
    let result = connector
        .handle_configure(json!({
            "api_key": "test-key",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "cluster_url": "https://example.qdrant.io"
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("exactly one"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn configure_invalid_credential_id_format_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.config.bad_credential_id");
    let mut connector = QdrantConnector::new();
    let result = connector
        .handle_configure(json!({
            "credential_id": "not-a-valid-uuid",
            "cluster_url": "https://example.qdrant.io"
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("credential_id"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

// ============================================================================
// Missing required field validation tests
// ============================================================================

#[fcp_async_core::test]
async fn query_points_missing_query_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.validation.query_points_missing_query");
    let mut connector = QdrantConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["qdrant.query_points"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.query_points");

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.query_points",
            "input": { "collection_name": "embeddings" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("query"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn query_points_missing_collection_name_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.validation.query_points_missing_collection");
    let mut connector = QdrantConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["qdrant.query_points"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.query_points");

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.query_points",
            "input": { "query": [0.1, 0.2, 0.3] },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("collection_name"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn batch_query_points_missing_queries_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.validation.batch_query_missing_queries");
    let mut connector = QdrantConnector::new();
    let (_mock_server, signing_key) =
        full_setup(&mut connector, &["qdrant.batch_query_points"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.batch_query_points",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.batch_query_points",
            "input": { "collection_name": "embeddings" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("queries"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn batch_query_points_missing_collection_name_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.validation.batch_query_missing_collection");
    let mut connector = QdrantConnector::new();
    let (_mock_server, signing_key) =
        full_setup(&mut connector, &["qdrant.batch_query_points"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.batch_query_points",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.batch_query_points",
            "input": { "queries": [{ "query": [0.1] }] },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("collection_name"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn get_points_missing_collection_name_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.validation.get_points_missing_collection");
    let mut connector = QdrantConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["qdrant.get_points"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.get_points");

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.get_points",
            "input": { "ids": [1, 2, 3] },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("collection_name"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn scroll_missing_collection_name_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.validation.scroll_missing_collection");
    let mut connector = QdrantConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["qdrant.scroll"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.scroll");

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.scroll",
            "input": { "limit": 10 },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("collection_name"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn count_missing_collection_name_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.validation.count_missing_collection");
    let mut connector = QdrantConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["qdrant.count"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.count");

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.count",
            "input": { "exact": true },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("collection_name"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn create_collection_missing_vectors_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.validation.create_missing_vectors");
    let mut connector = QdrantConnector::new();
    let (_mock_server, signing_key) =
        full_setup(&mut connector, &["qdrant.create_collection"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.create_collection",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.create_collection",
            "input": { "collection_name": "test" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("vectors"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn create_collection_missing_name_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.validation.create_missing_name");
    let mut connector = QdrantConnector::new();
    let (_mock_server, signing_key) =
        full_setup(&mut connector, &["qdrant.create_collection"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.create_collection",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.create_collection",
            "input": { "vectors": { "size": 3, "distance": "Cosine" } },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("collection_name"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn delete_collection_missing_name_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.validation.delete_collection_missing_name");
    let mut connector = QdrantConnector::new();
    let (_mock_server, signing_key) =
        full_setup(&mut connector, &["qdrant.delete_collection"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.delete_collection",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.delete_collection",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("collection_name"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn delete_points_missing_collection_name_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.validation.delete_points_missing_collection");
    let mut connector = QdrantConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["qdrant.delete_points"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.delete_points",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.delete_points",
            "input": { "points": [1, 2] },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("collection_name"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn collection_info_missing_collection_name_fails() {
    let _ctx =
        AsyncTestContext::for_scenario("qdrant.validation.collection_info_missing_collection");
    let mut connector = QdrantConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["qdrant.collection_info"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.collection_info",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.collection_info",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("collection_name"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

// ============================================================================
// Empty results tests
// ============================================================================

#[fcp_async_core::test]
async fn list_collections_empty() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.list_collections.empty");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.list_collections"]).await;

    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": { "collections": [] },
            "status": "ok",
            "time": 0.001
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.list_collections",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.list_collections",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect("list_collections with empty result should succeed");

    let collections = result["collections"].as_array().expect("collections array");
    assert!(collections.is_empty());
}

#[fcp_async_core::test]
async fn search_empty_results() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.search.empty_results");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.search"]).await;

    Mock::given(method("POST"))
        .and(path("/collections/embeddings/points/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": [],
            "status": "ok",
            "time": 0.001
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.search");
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.search",
            "input": {
                "collection_name": "embeddings",
                "vector": [0.1, 0.2, 0.3],
                "limit": 5
            },
            "capability_token": token
        }))
        .await
        .expect("search with empty result should succeed");

    let results = result["result"].as_array().expect("result array");
    assert!(results.is_empty());
}

#[fcp_async_core::test]
async fn scroll_empty_results() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.scroll.empty_results");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.scroll"]).await;

    Mock::given(method("POST"))
        .and(path("/collections/embeddings/points/scroll"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": {
                "points": [],
                "next_page_offset": null
            },
            "status": "ok",
            "time": 0.001
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.scroll");
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.scroll",
            "input": {
                "collection_name": "embeddings",
                "limit": 10
            },
            "capability_token": token
        }))
        .await
        .expect("scroll with empty result should succeed");

    let scroll_result = &result["result"];
    assert!(scroll_result["points"].as_array().unwrap().is_empty());
    assert!(scroll_result["next_page_offset"].is_null());
}

#[fcp_async_core::test]
async fn count_zero_result() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.count.zero");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.count"]).await;

    Mock::given(method("POST"))
        .and(path("/collections/embeddings/points/count"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": { "count": 0 },
            "status": "ok",
            "time": 0.001
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.count");
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.count",
            "input": {
                "collection_name": "embeddings",
                "exact": true
            },
            "capability_token": token
        }))
        .await
        .expect("count zero should succeed");

    assert_eq!(result["count"], 0);
}

#[fcp_async_core::test]
async fn get_points_empty_results() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.get_points.empty_results");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.get_points"]).await;

    Mock::given(method("POST"))
        .and(path("/collections/embeddings/points"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": [],
            "status": "ok",
            "time": 0.001
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.get_points");
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.get_points",
            "input": {
                "collection_name": "embeddings",
                "ids": [999, 998]
            },
            "capability_token": token
        }))
        .await
        .expect("get_points with empty result should succeed");

    let points = result["result"].as_array().expect("result array");
    assert!(points.is_empty());
}

// ============================================================================
// Doctor / self-check tests
// ============================================================================

#[fcp_async_core::test]
async fn doctor_not_configured_is_unhealthy() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.doctor.not_configured");
    let connector = QdrantConnector::new();
    let result = connector
        .handle_doctor()
        .await
        .expect("doctor should succeed");

    assert_eq!(result["status"], "unhealthy");
    let checks = result["checks"].as_array().unwrap();
    let config_check = checks
        .iter()
        .find(|c| c["name"] == "configuration")
        .unwrap();
    assert!(!config_check["passed"].as_bool().unwrap());
    assert!(config_check["critical"].as_bool().unwrap());
}

#[fcp_async_core::test]
async fn doctor_healthy_when_configured_and_connected() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.doctor.healthy");
    let mock_server = MockServer::start().await;
    let mut connector = QdrantConnector::new();

    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": { "collections": [] },
            "status": "ok",
            "time": 0.001
        })))
        .mount(&mock_server)
        .await;

    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_doctor()
        .await
        .expect("doctor should succeed");

    assert_eq!(result["status"], "healthy");
    let checks = result["checks"].as_array().unwrap();
    assert!(checks.len() >= 4);

    let connectivity = checks
        .iter()
        .find(|c| c["name"] == "read_only_connectivity")
        .unwrap();
    assert!(connectivity["passed"].as_bool().unwrap());
}

#[fcp_async_core::test]
async fn doctor_degraded_with_credential_id() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.doctor.credential_id_degraded");
    let mut connector = QdrantConnector::new();
    connector
        .handle_configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "cluster_url": "https://example.qdrant.io"
        }))
        .await
        .expect("configure should succeed");

    let result = connector
        .handle_doctor()
        .await
        .expect("doctor should succeed");

    assert_eq!(result["status"], "degraded");
    let checks = result["checks"].as_array().unwrap();
    let materialization = checks
        .iter()
        .find(|c| c["name"] == "credential_materialization")
        .unwrap();
    assert!(!materialization["passed"].as_bool().unwrap());
    assert!(!materialization["critical"].as_bool().unwrap());
}

#[fcp_async_core::test]
async fn doctor_unhealthy_when_api_unreachable() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.doctor.api_unreachable");
    let mock_server = MockServer::start().await;
    let mut connector = QdrantConnector::new();

    // Mock returns 500 for list_collections check
    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
        .mount(&mock_server)
        .await;

    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_doctor()
        .await
        .expect("doctor should succeed");

    assert_eq!(result["status"], "unhealthy");
    let checks = result["checks"].as_array().unwrap();
    let connectivity = checks
        .iter()
        .find(|c| c["name"] == "read_only_connectivity")
        .unwrap();
    assert!(!connectivity["passed"].as_bool().unwrap());
}

// ============================================================================
// Lifecycle edge case tests
// ============================================================================

#[fcp_async_core::test]
async fn health_after_credential_id_configure() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.lifecycle.health_credential_id");
    let mut connector = QdrantConnector::new();
    connector
        .handle_configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "cluster_url": "https://example.qdrant.io"
        }))
        .await
        .expect("configure should succeed");

    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(
        result["status"],
        "degraded_pending_credential_materialization"
    );
}

#[fcp_async_core::test]
async fn invoke_without_handshake_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.deny.no_handshake");
    let mock_server = MockServer::start().await;
    let mut connector = QdrantConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let signing_key = Ed25519SigningKey::generate();
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.list_collections",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.list_collections",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::test]
async fn invoke_missing_operation_field_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.deny.missing_operation_field");
    let mut connector = QdrantConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["qdrant.search"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.search");

    let result = connector
        .handle_invoke(json!({
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("operation"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::test]
async fn invoke_missing_capability_token_fails() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.deny.missing_token");
    let mut connector = QdrantConnector::new();
    let (_mock_server, _signing_key) = full_setup(&mut connector, &["qdrant.search"]).await;

    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.search",
            "input": {
                "collection_name": "embeddings",
                "vector": [0.1, 0.2, 0.3],
                "limit": 5
            }
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("capability_token"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

// ============================================================================
// Search with optional parameters
// ============================================================================

#[fcp_async_core::test]
async fn search_with_filter_and_threshold() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.search.with_filter");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.search"]).await;

    Mock::given(method("POST"))
        .and(path("/collections/embeddings/points/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": [
                { "id": 1, "version": 0, "score": 0.97, "payload": { "category": "science" } }
            ],
            "status": "ok",
            "time": 0.003
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.search");
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.search",
            "input": {
                "collection_name": "embeddings",
                "vector": [0.1, 0.2, 0.3],
                "limit": 10,
                "score_threshold": 0.9,
                "filter": {
                    "must": [
                        { "key": "category", "match": { "value": "science" } }
                    ]
                },
                "with_payload": true,
                "with_vectors": false
            },
            "capability_token": token
        }))
        .await
        .expect("search with filter should succeed");

    let results = result["result"].as_array().expect("result array");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["payload"]["category"], "science");
}

// ============================================================================
// Scroll with pagination
// ============================================================================

#[fcp_async_core::test]
async fn scroll_with_offset_parameter() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.scroll.with_offset");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.scroll"]).await;

    Mock::given(method("POST"))
        .and(path("/collections/embeddings/points/scroll"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": {
                "points": [
                    { "id": 5, "payload": { "text": "page 2" } }
                ],
                "next_page_offset": null
            },
            "status": "ok",
            "time": 0.002
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.scroll");
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.scroll",
            "input": {
                "collection_name": "embeddings",
                "limit": 1,
                "offset": "3",
                "with_payload": true
            },
            "capability_token": token
        }))
        .await
        .expect("scroll with offset should succeed");

    let scroll_result = &result["result"];
    assert_eq!(scroll_result["points"].as_array().unwrap().len(), 1);
    assert!(scroll_result["next_page_offset"].is_null());
}

// ============================================================================
// Count with filter
// ============================================================================

#[fcp_async_core::test]
async fn count_with_filter() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.count.with_filter");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["qdrant.count"]).await;

    Mock::given(method("POST"))
        .and(path("/collections/embeddings/points/count"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": { "count": 7 },
            "status": "ok",
            "time": 0.001
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, connector.instance_id(), "qdrant.count");
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.count",
            "input": {
                "collection_name": "embeddings",
                "filter": {
                    "must": [
                        { "key": "category", "match": { "value": "active" } }
                    ]
                },
                "exact": true
            },
            "capability_token": token
        }))
        .await
        .expect("count with filter should succeed");

    assert_eq!(result["count"], 7);
}

// ============================================================================
// Simulate method tests
// ============================================================================

#[fcp_async_core::test]
async fn simulate_returns_allowed() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.simulate.allowed");
    let mut connector = QdrantConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["qdrant.upsert_points"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.upsert_points",
    );

    let result = connector
        .handle_simulate(json!({
            "type": "simulate",
            "id": "sim-123",
            "connector_id": "qdrant",
            "operation": "qdrant.upsert_points",
            "zone_id": "z:work",
            "input": {
                "collection_name": "test",
                "points": [{ "id": 1, "vector": [0.1] }]
            },
            "capability_token": token
        }))
        .await
        .expect("simulate should succeed");

    assert!(result.get("id").is_some());
}

// ============================================================================
// Create collection with optional config fields
// ============================================================================

#[fcp_async_core::test]
async fn create_collection_with_optional_config() {
    let _ctx = AsyncTestContext::for_scenario("qdrant.create_collection.with_config");
    let mut connector = QdrantConnector::new();
    let (mock_server, signing_key) =
        full_setup(&mut connector, &["qdrant.create_collection"]).await;

    Mock::given(method("PUT"))
        .and(path("/collections/configured_col"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": { "status": "acknowledged" },
            "status": "ok",
            "time": 0.1
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "qdrant.create_collection",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.create_collection",
            "input": {
                "collection_name": "configured_col",
                "vectors": { "size": 768, "distance": "Cosine" },
                "hnsw_config": { "m": 16, "ef_construct": 100 },
                "on_disk_payload": true,
                "shard_number": 2,
                "replication_factor": 1
            },
            "capability_token": token
        }))
        .await
        .expect("create_collection with config should succeed");

    assert_eq!(result["status"], "acknowledged");
    assert!(result["receipt"]["timestamp"].as_str().is_some());
}
