use super::*;
use crate::client::McpAuth;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::Poll;
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn initialization() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
        "serverInfo": {"name": "cursor-test", "version": "1"}
    })
}

async fn setup(server: &MockServer) -> McpClient {
    Mock::given(method("POST")).and(body_partial_json(json!({"method": "initialize"})))
        .respond_with(ResponseTemplate::new(200)
            .insert_header("Mcp-Session-Id", "same-id")
            .set_body_json(json!({"jsonrpc": "2.0", "id": 0, "result": initialization()})))
        .mount(server).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method": "notifications/initialized"})))
        .respond_with(ResponseTemplate::new(202)).mount(server).await;
    let mut client = McpClient::new(McpAuth { api_key: None }, &server.uri()).unwrap();
    client.retry_config.initial_delay_ms = 1;
    client.retry_config.max_delay_ms = 1;
    client.retry_config.jitter_enabled = false;
    client
}

async fn calls(server: &MockServer, rpc_method: &str) -> Vec<Value> {
    server.received_requests().await.unwrap().iter()
        .map(|request| serde_json::from_slice::<Value>(&request.body).unwrap())
        .filter(|body| body["method"] == rpc_method).collect()
}

#[test]
fn only_top_level_list_cursors_are_session_bound() {
    for method in ["tools/list", "resources/list", "resources/templates/list", "prompts/list"] {
        assert!(is_cursor_continuation(method, &json!({"cursor": ""})));
        assert!(!is_cursor_continuation(method, &json!({})));
    }
    assert!(!is_cursor_continuation("tools/call", &json!({"cursor": "tool-input"})));
    assert!(!is_cursor_continuation("tools/call", &json!({"arguments": {"cursor": "tool-input"}})));
    assert!(!is_cursor_continuation("resources/read", &json!({"cursor": "not-a-list"})));
}

#[fcp_async_core::runtime::test]
async fn cursor_expiry_invalidates_session_without_reinitializing_or_replaying() {
    for rpc_method in ["tools/list", "resources/list", "resources/templates/list", "prompts/list"] {
        let server = MockServer::start().await;
        let client = setup(&server).await;
        Mock::given(method("POST")).and(body_partial_json(json!({"method": rpc_method})))
            .respond_with(ResponseTemplate::new(404)).expect(1).mount(&server).await;
        let error = client.rpc_call(rpc_method, json!({"cursor": ""})).await.unwrap_err();
        assert!(!error.is_retryable());
        assert!(error.to_string().contains("restart discovery from page one"));
        assert_eq!(client.metrics().session_expired_retry_count, 0);
        assert!(client.session.lock().await.is_none());
        assert_eq!(calls(&server, "initialize").await.len(), 1);
        assert_eq!(calls(&server, rpc_method).await.len(), 1);
    }
}

#[fcp_async_core::runtime::test]
async fn transient_failure_can_retry_cursor_within_the_same_session() {
    let server = MockServer::start().await;
    let client = setup(&server).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(ResponseTemplate::new(503)).with_priority(0).up_to_n_times(1)
        .mount(&server).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(|request: &Request| {
            assert_eq!(request.headers.get("mcp-session-id").unwrap(), "same-id");
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(body["params"]["cursor"], "opaque-cursor");
            ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": body["id"], "result": {"tools": []}
            }))
        }).with_priority(1).mount(&server).await;
    assert_eq!(client.rpc_call("tools/list", json!({"cursor": "opaque-cursor"})).await.unwrap(), json!({"tools": []}));
    let requests = calls(&server, "tools/list").await;
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1]);
    assert_eq!(calls(&server, "initialize").await.len(), 1);
}

#[fcp_async_core::runtime::test]
async fn binding_cannot_adopt_a_replacement_that_reuses_the_same_header() {
    let server = MockServer::start().await;
    let client = setup(&server).await;
    let old = Arc::new(McpSession::from_initialize(initialization(), Some(HeaderValue::from_static("same-id"))).unwrap());
    let new = Arc::new(McpSession::from_initialize(initialization(), Some(HeaderValue::from_static("same-id"))).unwrap());
    let bound = OnceLock::new();
    *client.session.lock().await = Some(Arc::clone(&old));
    client.bind_continuation_session(&bound, &old).await.unwrap();
    *client.session.lock().await = Some(Arc::clone(&new));
    assert!(client.bind_continuation_session(&bound, &old).await.is_err());
    assert!(client.bind_continuation_session(&bound, &new).await.is_err());
    assert!(Arc::ptr_eq(client.session.lock().await.as_ref().unwrap(), &new));
}

#[fcp_async_core::runtime::test]
async fn session_rotation_during_io_rejects_old_reply_and_stops_retry_dispatch() {
    for status in [200, 503] {
        let server = MockServer::start().await;
        let client = setup(&server).await;
        client.initialize().await.unwrap();
        Mock::given(method("POST")).and(body_partial_json(json!({"method": "tools/list"})))
            .respond_with(move |request: &Request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                ResponseTemplate::new(status).set_body_json(json!({
                    "jsonrpc": "2.0", "id": body["id"], "result": {"tools": []}
                })).set_delay(Duration::from_millis(100))
            }).mount(&server).await;
        let mut operation = pin!(client.rpc_call("tools/list", json!({"cursor": "old-cursor"})));
        let mut rotation = pin!(async {
            while calls(&server, "tools/list").await.is_empty() {
                fcp_async_core::time::sleep(Duration::from_millis(1)).await;
            }
            *client.session.lock().await = Some(Arc::new(McpSession::from_initialize(
                initialization(), Some(HeaderValue::from_static("same-id")),
            ).unwrap()));
        });
        let mut rotated = false;
        let result = fcp_async_core::time::timeout(Duration::from_secs(2), poll_fn(|cx| {
            if !rotated && rotation.as_mut().poll(cx).is_ready() {
                rotated = true;
            }
            match operation.as_mut().poll(cx) {
                Poll::Ready(result) => Poll::Ready(result),
                Poll::Pending => Poll::Pending,
            }
        })).await.expect("test must remain bounded");
        assert!(rotated);
        let error = result.unwrap_err();
        assert!(!error.is_retryable());
        assert!(error.to_string().contains("session changed"));
        assert_eq!(calls(&server, "tools/list").await.len(), 1);
        assert_eq!(calls(&server, "initialize").await.len(), 1);
    }
}

#[test]
fn explicit_cursor_future_is_send() {
    fn assert_send<T: Send>(_: T) {}
    let client = McpClient::new(McpAuth { api_key: None }, "https://example.com").unwrap();
    assert_send(client.rpc_call("tools/list", json!({"cursor": "next"})));
}
