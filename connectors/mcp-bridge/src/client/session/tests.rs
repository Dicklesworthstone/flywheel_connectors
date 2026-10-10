use super::*;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::Poll;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};
use crate::client::McpAuth;

fn initialization() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {"tools":{},"resources":{},"prompts":{}},
        "serverInfo": {"name":"loopback","version":"1"}
    })
}

async fn mount_initialization(server: &MockServer, result: Value, session: Option<&'static str>, notification_status: u16) {
    let mut response = ResponseTemplate::new(200).set_body_json(json!({
        "jsonrpc":"2.0","id":0,"result":result
    }));
    if let Some(session) = session { response = response.insert_header("Mcp-Session-Id", session); }
    Mock::given(method("POST")).and(path("/mcp"))
        .and(body_partial_json(json!({"method":"initialize"})))
        .respond_with(response).with_priority(0).mount(server).await;
    Mock::given(method("POST")).and(path("/mcp"))
        .and(body_partial_json(json!({"method":"notifications/initialized"})))
        .respond_with(ResponseTemplate::new(notification_status)).with_priority(0).mount(server).await;
}

async fn mount_result(server: &MockServer, rpc_method: &str) {
    Mock::given(method("POST")).and(path("/mcp"))
        .and(body_partial_json(json!({"method":rpc_method})))
        .respond_with(|request: &Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc":"2.0","id":body["id"],"result":{"tools":[],"done":true}
            }))
        }).mount(server).await;
}

fn client(server: &MockServer) -> McpClient {
    let mut client = McpClient::new(McpAuth { api_key: None }, &server.uri()).unwrap();
    client.retry_config.initial_delay_ms = 1;
    client.retry_config.max_delay_ms = 1;
    client.retry_config.jitter_enabled = false;
    client
}

async fn methods(server: &MockServer) -> Vec<String> {
    server.received_requests().await.unwrap().iter().map(|request| {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        body["method"].as_str().unwrap_or("<response>").to_owned()
    }).collect()
}

#[test]
fn validates_and_marks_session_ids_sensitive() {
    for bytes in [b"".as_slice(), b"a b", b"\t", &[0x80], &[b'x'; 1025]] {
        let header = HeaderValue::from_bytes(bytes).unwrap();
        assert!(validate_session_id(Some(header)).is_err());
    }
    let id = validate_session_id(Some(HeaderValue::from_static("s!#$~"))).unwrap().unwrap();
    assert!(id.is_sensitive());
    assert!(validate_session_id(None).unwrap().is_none());
}

#[fcp_async_core::runtime::test]
async fn initializes_once_and_reuses_session_for_operations() {
    let server = MockServer::start().await;
    mount_initialization(&server, initialization(), Some("session-1"), 202).await;
    mount_result(&server, "tools/list").await;
    let client = client(&server);
    client.tools_list().await.unwrap();
    client.tools_list().await.unwrap();
    assert_eq!(methods(&server).await, ["initialize","notifications/initialized","tools/list","tools/list"]);
    let requests = server.received_requests().await.unwrap();
    assert!(!requests[0].headers.contains_key("mcp-session-id"));
    let initialize: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(initialize["params"]["capabilities"], json!({}));
    for request in &requests[1..] {
        assert_eq!(request.headers.get("mcp-session-id").unwrap(), "session-1");
        assert_eq!(request.headers.get("mcp-protocol-version").unwrap(), PROTOCOL_VERSION);
    }
    let notification: Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert!(notification.get("id").is_none());
    assert_eq!(client.initialize().await.unwrap(), initialization());
    assert_eq!(methods(&server).await.len(), 4);
}

#[fcp_async_core::runtime::test]
async fn concurrent_first_calls_share_single_initialization() {
    let server = MockServer::start().await;
    mount_initialization(&server, initialization(), Some("shared"), 202).await;
    mount_result(&server, "tools/list").await;
    let client = client(&server);
    let mut first = pin!(client.tools_list());
    let mut second = pin!(client.tools_list());
    let mut results = [None, None];
    poll_fn(|cx| {
        if results[0].is_none() {
            if let Poll::Ready(result) = first.as_mut().poll(cx) { results[0] = Some(result); }
        }
        if results[1].is_none() {
            if let Poll::Ready(result) = second.as_mut().poll(cx) { results[1] = Some(result); }
        }
        if results.iter().all(Option::is_some) { Poll::Ready(()) } else { Poll::Pending }
    }).await;
    for result in results { result.unwrap().unwrap(); }
    assert_eq!(methods(&server).await, ["initialize","notifications/initialized","tools/list","tools/list"]);
}

#[fcp_async_core::runtime::test]
async fn unsupported_version_or_capability_never_dispatches_operation() {
    for bad_version in [false, true] {
        let server = MockServer::start().await;
        let mut result = initialization();
        if bad_version { result["protocolVersion"] = json!("2099-01-01"); }
        else { result["capabilities"] = json!({}); }
        mount_initialization(&server, result, None, 202).await;
        let client = client(&server);
        assert!(client.tools_list().await.is_err());
        let expected = if bad_version { vec!["initialize"] } else { vec!["initialize","notifications/initialized"] };
        assert_eq!(methods(&server).await, expected);
    }
}

#[fcp_async_core::runtime::test]
async fn failed_initialized_notification_does_not_publish_session() {
    let server = MockServer::start().await;
    mount_initialization(&server, initialization(), Some("not-ready"), 503).await;
    let client = client(&server);
    assert!(client.tools_list().await.is_err());
    assert!(client.session.lock().await.is_none());
    assert_eq!(methods(&server).await, ["initialize","notifications/initialized"]);
}

#[fcp_async_core::runtime::test]
async fn timed_out_initializer_does_not_publish_or_dispatch() {
    let server = MockServer::start().await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"initialize"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":0,"result":initialization()
        })).set_delay(Duration::from_millis(500)))
        .with_priority(0).up_to_n_times(1).mount(&server).await;
    mount_initialization(&server, initialization(), None, 202).await;
    mount_result(&server, "tools/list").await;
    let mut client = client(&server);
    client.runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_millis(100)));
    assert!(client.tools_list().await.is_err());
    assert!(client.session.lock().await.is_none());
    assert!(!methods(&server).await.iter().any(|method| method == "tools/list"));
    client.runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(2)));
    client.tools_list().await.unwrap();
    assert_eq!(methods(&server).await, ["initialize","initialize","notifications/initialized","tools/list"]);
}

#[fcp_async_core::runtime::test]
async fn session_404_reinitializes_before_retrying_tool_once() {
    let server = MockServer::start().await;
    let generations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let generated = Arc::clone(&generations);
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"initialize"})))
        .respond_with(move |request: &Request| {
            assert!(!request.headers.contains_key("mcp-session-id"));
            let generation = generated.fetch_add(1, Ordering::SeqCst) + 1;
            ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":0,"result":initialization()}))
                .insert_header("Mcp-Session-Id", format!("session-{generation}"))
        }).mount(&server).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"notifications/initialized"})))
        .respond_with(ResponseTemplate::new(202)).mount(&server).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"tools/call"})))
        .and(header("Mcp-Session-Id", "session-1"))
        .respond_with(ResponseTemplate::new(404)).expect(1).mount(&server).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"tools/call"})))
        .and(header("Mcp-Session-Id", "session-2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":1,"result":{"done":true}})))
        .expect(1).mount(&server).await;
    let client = client(&server);
    assert_eq!(client.tools_call("create", &json!({})).await.unwrap(), json!({"done":true}));
    assert_eq!(client.metrics().session_expired_retry_count, 1);
    assert_eq!(methods(&server).await, ["initialize","notifications/initialized","tools/call","initialize","notifications/initialized","tools/call"]);
}

#[fcp_async_core::runtime::test]
async fn second_session_404_stops_without_unbounded_reinitialization() {
    let server = MockServer::start().await;
    mount_initialization(&server, initialization(), Some("expired"), 202).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"tools/call"})))
        .respond_with(ResponseTemplate::new(404)).expect(2).mount(&server).await;
    let client = client(&server);
    assert!(client.tools_call("create", &json!({})).await.is_err());
    assert_eq!(client.metrics().session_expired_retry_count, 1);
    assert_eq!(methods(&server).await.len(), 6);
    assert!(client.session.lock().await.is_none());
}

#[fcp_async_core::runtime::test]
async fn error_text_cannot_replay_an_arbitrary_tool() {
    for status in [200, 503] {
        let server = MockServer::start().await;
        mount_initialization(&server, initialization(), Some("active"), 202).await;
        let body = if status == 200 {
            json!({"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"session expired after side effect"}})
        } else { json!({"message":"session expired after side effect"}) };
        Mock::given(method("POST")).and(body_partial_json(json!({"method":"tools/call"})))
            .respond_with(ResponseTemplate::new(status).set_body_json(body)).expect(1).mount(&server).await;
        let client = client(&server);
        let error = client.tools_call("create", &json!({})).await.unwrap_err();
        assert!(!error.is_retryable());
        assert_eq!(client.metrics().session_expired_retry_count, 0);
        assert_eq!(methods(&server).await, ["initialize","notifications/initialized","tools/call"]);
    }
}

#[fcp_async_core::runtime::test]
async fn stateless_404_does_not_invent_a_session_recovery() {
    let server = MockServer::start().await;
    mount_initialization(&server, initialization(), None, 202).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"tools/call"})))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message":"session expired"})))
        .expect(1).mount(&server).await;
    let client = client(&server);
    assert!(client.tools_call("create", &json!({})).await.is_err());
    assert_eq!(client.metrics().session_expired_retry_count, 0);
}

#[fcp_async_core::runtime::test]
async fn old_expiry_cannot_clear_a_replacement_with_reused_session_id() {
    let server = MockServer::start().await;
    let client = client(&server);
    let old = Arc::new(McpSession::from_initialize(initialization(), Some(HeaderValue::from_static("same-id"))).unwrap());
    let current = Arc::new(McpSession::from_initialize(initialization(), Some(HeaderValue::from_static("same-id"))).unwrap());
    *client.session.lock().await = Some(Arc::clone(&current));
    client.invalidate_session(&old).await;
    assert!(Arc::ptr_eq(client.session.lock().await.as_ref().unwrap(), &current));
}

#[fcp_async_core::runtime::test]
async fn streamed_ping_uses_negotiated_session_and_failure_does_not_replay_tool() {
    for reply_status in [202, 404] {
        let server = MockServer::start().await;
        mount_initialization(&server, initialization(), Some("active"), 202).await;
        Mock::given(method("POST")).and(body_partial_json(json!({"method":"tools/call"})))
            .respond_with(ResponseTemplate::new(200).set_body_string(concat!(
                "data: {\"jsonrpc\":\"2.0\",\"id\":\"ping\",\"method\":\"ping\"}\n\n",
                "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"done\":true}}\n\n"
            )).insert_header("Content-Type", "text/event-stream"))
            .expect(1).mount(&server).await;
        Mock::given(method("POST")).and(body_partial_json(json!({"id":"ping","result":{}})))
            .and(header("Mcp-Session-Id", "active"))
            .respond_with(ResponseTemplate::new(reply_status)).expect(1).mount(&server).await;
        let client = client(&server);
        let result = client.tools_call("create", &json!({})).await;
        assert_eq!(result.is_ok(), reply_status == 202);
        assert_eq!(client.metrics().session_expired_retry_count, 0);
        assert_eq!(methods(&server).await.len(), 4);
    }
}

#[fcp_async_core::runtime::test]
async fn shutdown_blocks_initialization_before_network_io() {
    let server = MockServer::start().await;
    let client = client(&server);
    client.shutdown();
    assert!(client.tools_list().await.is_err());
    assert!(client.initialize().await.is_err());
    assert!(methods(&server).await.is_empty());
}
