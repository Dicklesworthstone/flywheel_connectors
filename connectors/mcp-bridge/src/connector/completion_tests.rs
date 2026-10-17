//! Completion across manifest, provider dispatch and FCP authorization boundaries.

use fcp_core::{CapabilityToken, HandshakeResponse, Introspection};
use serde_json::Value;
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use super::*;

fn input(reference: Value) -> Value {
    json!({"ref": reference, "argument": {"name": "arg", "value": ""},
        "context": {"arguments": {"project": "opaque/context"}}, "_meta": {"keep": true}})
}

async fn configured(server: &MockServer) -> McpBridgeConnector {
    let mut connector = McpBridgeConnector::new();
    connector
        .handle_configure(json!({"mcp_url": server.uri()}))
        .await
        .unwrap();
    connector
        .handle_handshake(json!({"session_id": "provider-fixture"}))
        .await
        .unwrap();
    connector
}

async fn mount_server(server: &MockServer, result: Value) {
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method": "initialize"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0", "id": 0, "result": {
                "protocolVersion": "2025-06-18", "capabilities": {"completions": {}},
                "serverInfo": {"name": "completion", "version": "1"},
            },
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(body_partial_json(
            json!({"method": "notifications/initialized"}),
        ))
        .respond_with(ResponseTemplate::new(202))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method": "completion/complete"})))
        .respond_with(move |request: &Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            ResponseTemplate::new(200)
                .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
        })
        .mount(server)
        .await;
}

fn handshake(capability: &str) -> Value {
    json!({"protocol_version": "2.0.0", "zone": "z:work",
        "host_public_key": vec![1_u8; 32], "nonce": vec![9_u8; 32],
        "capabilities_requested": [capability]})
}

#[test]
fn completion_manifest_declares_narrow_capability_schema_and_rate_pool() {
    let manifest = ConnectorManifest::parse_str(MANIFEST_TOML).unwrap();
    assert_eq!(manifest.provides.operations.len(), 10);
    let operation = &manifest.provides.operations[OP_COMPLETION_COMPLETE];
    assert_eq!(operation.capability.as_str(), "mcp.completions.read");
    assert_eq!(
        operation.output_schema["properties"]["completion"]["properties"]["values"]["maxItems"],
        100
    );
    assert_eq!(
        operation.input_schema["required"],
        json!(["ref", "argument"])
    );
    assert_eq!(
        serde_json::to_value(operation.network_constraints.as_ref().unwrap()).unwrap(),
        serde_json::to_value(
            manifest.provides.operations[OP_PROMPTS_GET]
                .network_constraints
                .as_ref()
                .unwrap()
        )
        .unwrap()
    );
    let rate_limits = manifest.rate_limits.as_ref().unwrap();
    assert_eq!(
        rate_limits.operation_pools[OP_COMPLETION_COMPLETE],
        vec!["mcp.completions.read".to_owned()]
    );
    let catalog = typed_operations_info();
    assert_eq!(catalog.last().unwrap().id.as_str(), OP_COMPLETION_COMPLETE);
}

#[fcp_async_core::runtime::test]
async fn provider_dispatch_preserves_reference_context_rank_and_metadata() {
    let server = MockServer::start().await;
    let result = json!({"completion": {"values": ["b", "a", "b"], "hasMore": true}, "_meta": {"ranked": true}});
    mount_server(&server, result.clone()).await;
    let connector = configured(&server).await;
    for reference in [
        json!({"type": "ref/prompt", "name": "code_review"}),
        json!({"type": "ref/resource", "uri": "file:///{path}"}),
    ] {
        let input = input(reference);
        let output = connector
            .handle_invoke(json!({"operation_id": OP_COMPLETION_COMPLETE, "input": input}))
            .await
            .unwrap();
        assert_eq!(output, result);
        let requests = server.received_requests().await.unwrap();
        let body: Value = serde_json::from_slice(&requests.last().unwrap().body).unwrap();
        assert_eq!(body["method"], "completion/complete");
        assert_eq!(body["params"], input);
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 4);
    assert_eq!(connector.handle_health().await.unwrap()["requests"], 2);
    assert_eq!(
        connector.handle_health().await.unwrap()["sampling_requests"],
        0
    );
}

#[fcp_async_core::runtime::test]
async fn invalid_completion_never_initializes_the_upstream_provider() {
    let server = MockServer::start().await;
    let connector = configured(&server).await;
    for input in [
        json!({}),
        json!({"ref": {"type": "ref/tool", "name": "private-name"}}),
    ] {
        let error = connector
            .handle_invoke(json!({"operation_id": OP_COMPLETION_COMPLETE, "input": input}))
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("private-name"));
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn malformed_completion_result_is_not_a_successful_provider_response() {
    let server = MockServer::start().await;
    mount_server(&server, json!({"completion": {"values": ["valid", false]}})).await;
    let connector = configured(&server).await;
    assert!(
        connector
            .handle_invoke(json!({"operation_id": OP_COMPLETION_COMPLETE,
        "input": input(json!({"type": "ref/prompt", "name": "code_review"}))}))
            .await
            .is_err()
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
    assert_eq!(connector.handle_health().await.unwrap()["errors"], 1);
}

#[fcp_async_core::runtime::test]
async fn old_prompt_capability_does_not_authorize_the_new_completion_operation() {
    let upstream = MockServer::start().await;
    let mut boundary = crate::server::McpBridgeServer::new().unwrap();
    boundary
        .dispatch("configure", json!({"mcp_url": upstream.uri()}))
        .await
        .unwrap();
    boundary
        .dispatch("handshake", handshake("mcp.prompts.read"))
        .await
        .unwrap();
    let error = boundary
        .dispatch(
            "invoke",
            json!({
                "type": "invoke", "id": "completion-request", "connector_id": "fcp.mcp-bridge",
                "operation": OP_COMPLETION_COMPLETE, "zone_id": "z:work",
                "input": input(json!({"type": "ref/prompt", "name": "code_review"})),
                "capability_token": CapabilityToken::test_token(),
            }),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("not negotiated"));
    assert_eq!(
        boundary.dispatch("health", json!({})).await.unwrap()["requests"],
        0
    );
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn new_capability_negotiates_explicitly_and_introspection_matches() {
    let mut boundary = crate::server::McpBridgeServer::new().unwrap();
    boundary
        .dispatch("configure", json!({"mcp_url": "http://127.0.0.1:1"}))
        .await
        .unwrap();
    let response: HandshakeResponse = serde_json::from_value(
        boundary
            .dispatch("handshake", handshake("mcp.completions.read"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(response.capabilities_granted.len(), 1);
    assert_eq!(
        response.capabilities_granted[0].capability.as_str(),
        "mcp.completions.read"
    );
    let catalog: Introspection =
        serde_json::from_value(boundary.dispatch("introspect", json!({})).await.unwrap()).unwrap();
    let operation = catalog
        .operations
        .iter()
        .find(|operation| operation.id.as_str() == OP_COMPLETION_COMPLETE)
        .unwrap();
    assert_eq!(operation.capability.as_str(), "mcp.completions.read");
    assert_eq!(
        boundary.dispatch("health", json!({})).await.unwrap()["requests"],
        0
    );
}
