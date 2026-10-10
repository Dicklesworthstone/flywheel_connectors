use super::*;
use crate::client::McpAuth;
use crate::connector::McpBridgeConnector;
use fcp_prelude::FcpError;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

async fn server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "initialize"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0", "id": 0,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}, "resources": {}},
                "serverInfo": {"name": "outcome-test", "version": "1"}
            }
        })).insert_header("Mcp-Session-Id", "outcome-session"))
        .expect(1)
        .mount(&server).await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method": "notifications/initialized"})))
        .respond_with(ResponseTemplate::new(202))
        .expect(1)
        .mount(&server).await;
    server
}

async fn mount_result(server: &MockServer, rpc_method: &str, result: Value, streamed: bool) {
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": rpc_method})))
        .respond_with(move |request: &Request| {
            let request: Value = serde_json::from_slice(&request.body).unwrap();
            let reply = json!({"jsonrpc": "2.0", "id": request["id"], "result": result});
            if streamed {
                ResponseTemplate::new(200)
                    .set_body_string(format!("data: {reply}\n\n"))
                    .insert_header("Content-Type", "text/event-stream")
            } else {
                ResponseTemplate::new(200).set_body_json(reply)
            }
        })
        .expect(1)
        .mount(server).await;
}

fn client(server: &MockServer) -> McpClient {
    McpClient::new(McpAuth { api_key: None }, &server.uri()).unwrap()
}

fn failure() -> Value {
    json!({
        "isError": true,
        "content": [{"type": "text", "text": "session expired after writing one record"}],
        "structuredContent": {"written": 1, "retry_after_ms": 0},
        "_meta": {"diagnostic": "private-tool-output"}
    })
}

fn assert_tool_failure(error: &McpBridgeError, expected: &Value) {
    let McpBridgeError::ToolExecution(failure) = error else {
        panic!("expected ToolExecution, got {error:?}");
    };
    assert_eq!(failure.result(), expected);
    assert!(!error.is_retryable());
    assert!(!error.replay_is_safe());
    assert!(!error.is_session_expired());
    assert!(error.retry_after().is_none());
}

#[fcp_async_core::runtime::test]
async fn json_tool_failure_is_not_success_or_session_recovery() {
    let server = server().await;
    let expected = failure();
    mount_result(&server, "tools/call", expected.clone(), false).await;
    let client = client(&server);
    let error = client.tools_call("write", &json!({})).await.unwrap_err();
    assert_tool_failure(&error, &expected);
    assert_eq!(client.metrics().session_expired_retry_count, 0);
    assert_eq!(client.metrics().auth_retry_count, 0);
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn streamed_tool_failure_uses_the_same_terminal_outcome_path() {
    let server = server().await;
    let expected = failure();
    mount_result(&server, "tools/call", expected.clone(), true).await;
    let error = client(&server).tools_call("write", &json!({})).await.unwrap_err();
    assert_tool_failure(&error, &expected);
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn generic_rpc_tool_calls_cannot_bypass_outcome_classification() {
    let server = server().await;
    let expected = failure();
    mount_result(&server, "tools/call", expected.clone(), false).await;
    let error = client(&server)
        .rpc_call("tools/call", json!({"name": "write", "arguments": {}}))
        .await.unwrap_err();
    assert_tool_failure(&error, &expected);
}

#[fcp_async_core::runtime::test]
async fn connector_invoke_reports_failure_and_updates_error_metrics() {
    let server = server().await;
    let expected = failure();
    mount_result(&server, "tools/call", expected.clone(), false).await;
    let mut connector = McpBridgeConnector::new();
    connector.handle_configure(json!({"mcp_url": server.uri()})).await.unwrap();
    connector.handle_handshake(json!({"session_id": "fcp-session"})).await.unwrap();
    let error = connector.handle_invoke(json!({
        "operation_id": "mcp.tools.call", "input": {"name": "write", "arguments": {}}
    })).await.unwrap_err();
    let FcpError::External { message, retryable, retry_after, status_code, .. } = error else {
        panic!("expected a failed external tool invocation");
    };
    assert!(!retryable);
    assert!(retry_after.is_none());
    assert!(status_code.is_none());
    let payload = message.strip_prefix("MCP tool execution failed (isError=true): ").unwrap();
    assert_eq!(serde_json::from_str::<Value>(payload).unwrap(), expected);
    let metrics = connector.handle_invoke(json!({
        "operation_id": "mcp.server.metrics", "input": {}
    })).await.unwrap();
    assert_eq!(metrics["errors"], 1);
    assert_eq!(metrics["requests"], 2);
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn successful_tool_results_keep_all_content_and_extensions() {
    for explicit_flag in [false, true] {
        let server = server().await;
        let mut result = json!({
            "content": [{"type": "text", "text": "ok"}],
            "structuredContent": {"isError": true},
            "extension": [1, null, "opaque"]
        });
        if explicit_flag {
            result["isError"] = json!(false);
        }
        mount_result(&server, "tools/call", result.clone(), false).await;
        assert_eq!(client(&server).tools_call("read", &json!({})).await.unwrap(), result);
    }
}

#[fcp_async_core::runtime::test]
async fn non_boolean_tool_outcome_is_terminal_without_echoing_untrusted_data() {
    let server = server().await;
    mount_result(&server, "tools/call", json!({
        "content": [], "isError": "private-tool-output"
    }), false).await;
    let error = client(&server).tools_call("write", &json!({})).await.unwrap_err();
    assert!(matches!(&error, McpBridgeError::Json(_)));
    assert!(!error.is_retryable());
    assert!(!error.to_string().contains("private-tool-output"));
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn reported_tool_failure_does_not_destroy_a_usable_session() {
    let server = server().await;
    let result = failure();
    mount_result(&server, "tools/call", result.clone(), false).await;
    mount_result(&server, "resources/read", result.clone(), false).await;
    let client = client(&server);
    assert_tool_failure(&client.tools_call("write", &json!({})).await.unwrap_err(), &result);
    // Here isError is resource data, not a CallToolResult outcome flag.
    assert_eq!(client.resources_read("urn:diagnostics").await.unwrap(), result);
    assert_eq!(server.received_requests().await.unwrap().len(), 4);
    assert_eq!(client.metrics().session_expired_retry_count, 0);
}
