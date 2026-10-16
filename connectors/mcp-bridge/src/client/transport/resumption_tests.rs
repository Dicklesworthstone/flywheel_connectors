//! Recover the original response with GET, never by repeating an operation POST.

use std::sync::Arc;
use std::time::Duration;

use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use super::*;
use super::super::{McpAuth, McpClient, PROTOCOL_VERSION};

fn progress(id: &str) -> String {
    format!("id: {id}\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{}}}}\n\n")
}

fn tool_result() -> Value {
    json!({"content":[{"type":"text","text":"created once"}],"isError":false,"_meta":{"kept":true}})
}

fn result_frame(value: Value) -> String {
    format!("data: {}\n\n", json!({"jsonrpc":"2.0","id":1,"result":value}))
}

fn sse(body: String) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_string(body)
        .insert_header("Content-Type", "text/event-stream; charset=utf-8")
}

async fn initialized(server: &MockServer, session: Option<&str>) -> McpClient {
    let mut response = ResponseTemplate::new(200).set_body_json(json!({
        "jsonrpc":"2.0","id":0,"result":{
            "protocolVersion":PROTOCOL_VERSION,
            "capabilities":{"tools":{},"resources":{},"prompts":{}},
            "serverInfo":{"name":"resume-fixture","version":"1"}
        }
    }));
    if let Some(id) = session {
        response = response.insert_header("Mcp-Session-Id", id);
    }
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"initialize"})))
        .respond_with(response).mount(server).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"notifications/initialized"})))
        .respond_with(ResponseTemplate::new(202)).mount(server).await;
    let client = McpClient::new(McpAuth {api_key:Some("private-key".into())}, &server.uri()).unwrap();
    client.initialize().await.unwrap();
    client
}

async fn mount_tool(server: &MockServer, body: String) {
    Mock::given(method("POST")).and(path("/mcp"))
        .and(body_partial_json(json!({"method":"tools/call"})))
        .respond_with(sse(body)).expect(1).mount(server).await;
}

async fn mount_resume(server: &MockServer, id: &str, body: String) {
    Mock::given(method("GET")).and(path("/mcp"))
        .and(header("Last-Event-ID", id))
        .respond_with(sse(body)).expect(1).mount(server).await;
}

async fn request_counts(server: &MockServer) -> (usize, usize) {
    let requests = server.received_requests().await.unwrap();
    let operations = requests.iter().filter(|request| {
        serde_json::from_slice::<Value>(&request.body).ok()
            .is_some_and(|body| body["method"] == "tools/call")
    }).count();
    let resumes = requests.iter().filter(|request| request.method.as_str() == "GET").count();
    (operations, resumes)
}

#[test]
fn cursor_commits_only_at_complete_blocks_and_empty_ids_clear_it() {
    let mut decoder = SseDecoder::new(1024);
    for byte in b"id: first\ndata: {}\n" {
        decoder.push(*byte).unwrap();
        assert!(decoder.checkpoint_id.is_none());
    }
    assert!(decoder.push(b'\n').unwrap().is_some());
    assert_eq!(decoder.checkpoint_id.take().as_deref(), Some("first"));
    for byte in b"id:\n\n" { decoder.push(*byte).unwrap(); }
    assert_eq!(decoder.checkpoint_id.take().as_deref(), Some(""));
    for byte in b"id: ignored\0id\n\n" { decoder.push(*byte).unwrap(); }
    assert!(decoder.checkpoint_id.is_none());
}

#[test]
fn cursor_is_opaque_bounded_and_not_a_retry_instruction() {
    let mut decoder = SseDecoder::new(MAX_EVENT_BYTES);
    for byte in b"id: opaque/%2F?x=1:2\r\nretry: 0\r\n\r\n" { decoder.push(*byte).unwrap(); }
    assert_eq!(decoder.checkpoint_id.take().as_deref(), Some("opaque/%2F?x=1:2"));
    let mut decoder = SseDecoder::new(MAX_EVENT_BYTES);
    let oversized = format!("id: {}\n\n", "x".repeat(MAX_RESUME_ID_BYTES + 1));
    assert!(oversized.bytes().try_for_each(|byte| decoder.push(byte).map(|_| ())).is_err());
}

#[fcp_async_core::runtime::test]
async fn interrupted_tool_response_resumes_with_original_auth_session_and_id() {
    let server = MockServer::start().await;
    let client = initialized(&server, Some("original-session")).await;
    mount_tool(&server, progress("opaque/%2F?x=1:2")).await;
    Mock::given(method("GET")).and(path("/mcp"))
        .and(header("Last-Event-ID", "opaque/%2F?x=1:2"))
        .and(header("Mcp-Session-Id", "original-session"))
        .and(header("MCP-Protocol-Version", PROTOCOL_VERSION))
        .and(header("Authorization", "Bearer private-key"))
        .and(header("Accept", "text/event-stream"))
        .respond_with(sse(result_frame(tool_result()))).expect(1).mount(&server).await;
    assert_eq!(client.tools_call("create", &json!({})).await.unwrap(), tool_result());
    assert_eq!(request_counts(&server).await, (1, 1));
    assert_eq!(client.metrics().session_expired_retry_count, 0);
    let requests = server.received_requests().await.unwrap();
    assert!(requests.last().unwrap().body.is_empty(), "GET must not carry the original tool request");
}

#[fcp_async_core::runtime::test]
async fn stateless_sessions_resume_without_inventing_a_session_header() {
    let server = MockServer::start().await;
    let client = initialized(&server, None).await;
    mount_tool(&server, progress("stateless-cursor")).await;
    mount_resume(&server, "stateless-cursor", result_frame(tool_result())).await;
    client.tools_call("create", &json!({})).await.unwrap();
    let requests = server.received_requests().await.unwrap();
    let resume = requests.iter().find(|r| r.method.as_str() == "GET").unwrap();
    assert!(!resume.headers.contains_key("mcp-session-id"));
    assert_eq!(request_counts(&server).await, (1, 1));
}

#[fcp_async_core::runtime::test]
async fn stateless_resume_404_does_not_invent_session_expiry() {
    let server = MockServer::start().await;
    let client = initialized(&server, None).await;
    let original = client.session.lock().await.as_ref().unwrap().clone();
    mount_tool(&server, progress("cursor")).await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(404))
        .expect(1).mount(&server).await;
    assert!(!client.tools_call("create", &json!({})).await.unwrap_err().is_retryable());
    assert!(Arc::ptr_eq(client.session.lock().await.as_ref().unwrap(), &original));
    assert_eq!(client.metrics().session_expired_retry_count, 0);
    assert_eq!(request_counts(&server).await, (1, 1));
}

#[fcp_async_core::runtime::test]
async fn truncated_next_event_never_advances_past_the_committed_cursor() {
    let server = MockServer::start().await;
    let client = initialized(&server, Some("active")).await;
    let body = format!("{}id: uncommitted\ndata: {{\"jsonrpc\":\"2.0\"", progress("committed"));
    mount_tool(&server, body).await;
    mount_resume(&server, "committed", result_frame(tool_result())).await;
    assert_eq!(client.tools_call("create", &json!({})).await.unwrap(), tool_result());
    assert_eq!(request_counts(&server).await, (1, 1));
}

#[fcp_async_core::runtime::test]
async fn absent_uncommitted_or_cleared_cursors_do_not_guess_a_resume() {
    for body in [
        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n".to_owned(),
        "id: incomplete\ndata: {}\n".to_owned(),
        format!("{}id:\n\n", progress("cleared")),
        "id: invalid\0id\nretry: 0\n\n".to_owned(),
    ] {
        let server = MockServer::start().await;
        let client = initialized(&server, Some("active")).await;
        mount_tool(&server, body).await;
        assert!(!client.tools_call("create", &json!({})).await.unwrap_err().is_retryable());
        assert_eq!(request_counts(&server).await, (1, 0));
    }
}

#[fcp_async_core::runtime::test]
async fn resume_refusals_are_terminal_and_never_replay_or_reauthenticate_the_tool() {
    for status in [302, 401, 403, 404, 405, 429, 503] {
        let server = MockServer::start().await;
        let client = initialized(&server, Some("active")).await;
        mount_tool(&server, progress("cursor")).await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(status).set_body_string("private-error-body")
                .insert_header("Location", "https://uncontacted.invalid/mcp"))
            .expect(1).mount(&server).await;
        let error = client.tools_call("create", &json!({})).await.unwrap_err();
        assert!(!error.is_retryable());
        assert!(!error.replay_is_safe());
        assert!(!error.to_string().contains("private-error-body"));
        assert_eq!(request_counts(&server).await, (1, 1));
        assert_eq!(client.metrics().auth_retry_count, 0);
        assert_eq!(client.metrics().session_expired_retry_count, 0);
        if status == 404 { assert!(client.session.lock().await.is_none()); }
    }
}

#[fcp_async_core::runtime::test]
async fn wrong_resume_content_type_or_response_id_is_not_released() {
    for wrong_id in [false, true] {
        let server = MockServer::start().await;
        let client = initialized(&server, Some("active")).await;
        mount_tool(&server, progress("cursor")).await;
        let response = if wrong_id {
            sse("data: {\"jsonrpc\":\"2.0\",\"id\":999,\"result\":{}}\n\n".into())
        } else {
            ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":1,"result":tool_result()}))
        };
        Mock::given(method("GET")).respond_with(response).expect(1).mount(&server).await;
        assert!(!client.tools_call("create", &json!({})).await.unwrap_err().is_retryable());
        assert_eq!(request_counts(&server).await, (1, 1));
    }
}

#[fcp_async_core::runtime::test]
async fn repeated_cursor_stops_after_one_resume_without_a_spin_loop() {
    let server = MockServer::start().await;
    let client = initialized(&server, Some("active")).await;
    mount_tool(&server, progress("unchanged")).await;
    mount_resume(&server, "unchanged", progress("unchanged")).await;
    let error = client.tools_call("create", &json!({})).await.unwrap_err();
    assert!(error.to_string().contains("no progress"));
    assert_eq!(request_counts(&server).await, (1, 1));
}

#[fcp_async_core::runtime::test]
async fn two_resumes_can_recover_but_never_reset_the_reconnection_limit() {
    for finish in [false, true] {
        let server = MockServer::start().await;
        let client = initialized(&server, Some("active")).await;
        mount_tool(&server, progress("first")).await;
        mount_resume(&server, "first", progress("second")).await;
        mount_resume(&server, "second", if finish { result_frame(tool_result()) } else { progress("third") }).await;
        assert_eq!(client.tools_call("create", &json!({})).await.is_ok(), finish);
        assert_eq!(request_counts(&server).await, (1, 2));
    }
}

#[fcp_async_core::runtime::test]
async fn aggregate_byte_and_message_bounds_survive_resumption() {
    for byte_limit in [false, true] {
        let server = MockServer::start().await;
        let first = progress("first");
        let last = result_frame(tool_result());
        let bytes = first.len() + last.len();
        Mock::given(method("POST")).respond_with(sse(first)).mount(&server).await;
        Mock::given(method("GET")).respond_with(sse(last)).expect(1).mount(&server).await;
        let http = reqwest::Client::new();
        let url = format!("{}/mcp", server.uri());
        let response = http.post(&url).send().await.unwrap();
        let limits = StreamLimits {
            bytes: if byte_limit { bytes - 1 } else { bytes },
            event_bytes: 1024,
            messages: if byte_limit { 2 } else { 1 },
            resumptions: MAX_RESUMPTIONS,
        };
        let error = read_rpc_response_inner(response, 1, |_| async { Ok(()) }, |id| {
            assert!(id.is_sensitive(), "opaque event IDs must not leak through header Debug");
            let request = http.get(&url).header("Last-Event-ID", id);
            async move { request.send().await.map_err(McpBridgeError::from) }
        }, limits).await.unwrap_err();
        assert!(error.to_string().contains(if byte_limit { "byte limit" } else { "too many messages" }));
    }
}

#[fcp_async_core::runtime::test]
async fn resumed_stream_processes_ping_and_preserves_tool_failure_semantics() {
    let server = MockServer::start().await;
    let client = initialized(&server, Some("active")).await;
    mount_tool(&server, progress("cursor")).await;
    mount_resume(&server, "cursor", format!(
        "data: {{\"jsonrpc\":\"2.0\",\"id\":\"server-ping\",\"method\":\"ping\"}}\n\n{}",
        result_frame(json!({"content":[{"type":"text","text":"private-tool-error"}],"isError":true})),
    )).await;
    Mock::given(method("POST")).and(header("Mcp-Session-Id", "active"))
        .and(body_partial_json(json!({"id":"server-ping","result":{}})))
        .respond_with(ResponseTemplate::new(202)).expect(1).mount(&server).await;
    let error = client.tools_call("create", &json!({})).await.unwrap_err();
    assert!(matches!(error, McpBridgeError::ToolExecution(_)));
    assert!(!error.is_retryable());
    assert_eq!(request_counts(&server).await, (1, 1));
}

#[fcp_async_core::runtime::test]
async fn initialization_does_not_resume_before_a_session_is_published() {
    let server = MockServer::start().await;
    Mock::given(method("POST")).respond_with(sse(progress("init-cursor")))
        .expect(1).mount(&server).await;
    let client = McpClient::new(McpAuth {api_key:None}, &server.uri()).unwrap();
    assert!(client.initialize().await.is_err());
    assert!(client.session.lock().await.is_none());
    assert!(server.received_requests().await.unwrap().iter().all(|r| r.method.as_str() != "GET"));
}

#[fcp_async_core::runtime::test]
async fn resumed_get_consumes_the_original_deadline() {
    let server = MockServer::start().await;
    let mut client = initialized(&server, Some("active")).await;
    mount_tool(&server, progress("cursor")).await;
    Mock::given(method("GET")).respond_with(sse(result_frame(tool_result())).set_delay(Duration::from_secs(2)))
        .expect(1).mount(&server).await;
    client.runtime = ConnectorRuntime::new(
        ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_millis(150)),
    );
    let error = fcp_async_core::time::timeout(Duration::from_secs(1), client.tools_call("create", &json!({})))
        .await.expect("recovery must not reset the request deadline").unwrap_err();
    assert!(!error.is_retryable());
    assert_eq!(request_counts(&server).await, (1, 1));
}

#[fcp_async_core::runtime::test]
async fn replacement_with_reused_session_header_cannot_receive_old_cursor() {
    let server = MockServer::start().await;
    let client = initialized(&server, Some("same-header")).await;
    let original = client.session.lock().await.as_ref().unwrap().clone();
    let replacement = initialized(&server, Some("same-header")).await;
    let next = replacement.session.lock().await.as_ref().unwrap().clone();
    *client.session.lock().await = Some(Arc::clone(&next));
    assert!(client.resume_server_stream(&client.rpc_endpoint(), Some(&original), HeaderValue::from_static("old-cursor"))
        .await.is_err());
    assert!(Arc::ptr_eq(client.session.lock().await.as_ref().unwrap(), &next));
    assert_eq!(request_counts(&server).await, (0, 0));
}

#[fcp_async_core::runtime::test]
async fn replacement_while_get_is_pending_withholds_old_response_without_clearing_new_session() {
    use std::future::{Future, poll_fn};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Poll;

    let server = MockServer::start().await;
    let client = initialized(&server, Some("same-header")).await;
    let replacement = initialized(&server, Some("same-header")).await;
    let next = replacement.session.lock().await.as_ref().unwrap().clone();
    mount_tool(&server, progress("cursor")).await;
    let entered = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&entered);
    Mock::given(method("GET")).respond_with(move |_: &Request| {
        observed.store(true, Ordering::SeqCst);
        sse(result_frame(tool_result())).set_delay(Duration::from_millis(500))
    }).expect(1).mount(&server).await;
    let input = json!({});
    let mut call = Box::pin(client.tools_call("create", &input));
    let mut signal = Box::pin(async {
        fcp_async_core::time::timeout(Duration::from_secs(2), async {
            while !entered.load(Ordering::SeqCst) {
                fcp_async_core::time::sleep(Duration::from_millis(2)).await;
            }
        }).await.unwrap();
    });
    poll_fn(|cx| {
        assert!(call.as_mut().poll(cx).is_pending());
        if signal.as_mut().poll(cx).is_ready() { Poll::Ready(()) } else { Poll::Pending }
    }).await;
    *client.session.lock().await = Some(Arc::clone(&next));
    assert!(!call.await.unwrap_err().is_retryable());
    assert!(Arc::ptr_eq(client.session.lock().await.as_ref().unwrap(), &next));
    assert_eq!(request_counts(&server).await, (1, 1));
}

#[fcp_async_core::runtime::test]
async fn shutdown_during_recovery_withholds_the_response_without_retry() {
    let server = MockServer::start().await;
    let client = initialized(&server, Some("active")).await;
    mount_tool(&server, progress("cursor")).await;
    let runtime = client.runtime.clone();
    Mock::given(method("GET")).respond_with(move |_: &Request| {
        runtime.shutdown();
        sse(result_frame(tool_result()))
    }).expect(1).mount(&server).await;
    assert!(client.tools_call("create", &json!({})).await.is_err());
    assert_eq!(request_counts(&server).await, (1, 1));
}

#[fcp_async_core::runtime::test]
async fn discovery_can_resume_a_page_then_continue_its_original_pagination() {
    let server = MockServer::start().await;
    let client = initialized(&server, Some("active")).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"tools/list","params":{}})))
        .respond_with(|request: &Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            if body["params"].get("cursor").is_none() {
                sse(progress("page-one"))
            } else {
                assert_eq!(body["params"]["cursor"], "page-two");
                ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":body["id"],
                    "result":{"tools":[{"name":"second"}]}}))
            }
        }).expect(2).mount(&server).await;
    mount_resume(&server, "page-one", result_frame(json!({"tools":[{"name":"first"}],"nextCursor":"page-two"}))).await;
    let catalog = client.tools_list().await.unwrap();
    assert_eq!(catalog["tools"], json!([{"name":"first"},{"name":"second"}]));
    assert!(catalog.get("nextCursor").is_none());
    assert_eq!(request_counts(&server).await, (0, 1));
}

#[fcp_async_core::runtime::test]
async fn a_broken_http_chunked_body_recovers_the_original_response_over_get() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Instant;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut captured = Vec::new();
        for index in 0..2 {
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "missing original POST or recovery GET");
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            };
            socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                headers.push(byte[0]);
                assert!(headers.len() < 8192);
            }
            let headers = String::from_utf8(headers).unwrap();
            let length = headers.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            }).unwrap_or(0);
            assert!(length < 8192);
            socket.read_exact(&mut vec![0; length]).unwrap();
            if index == 0 {
                let body = progress("raw-checkpoint");
                write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n", body.len()).unwrap();
                // Deliberately omit the zero-length terminating HTTP chunk.
                // The client sees a transport read error, not just normal EOF.
            } else {
                let body = result_frame(tool_result());
                write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            socket.flush().unwrap();
            captured.push(headers);
        }
        captured
    });
    let client = McpClient::new(McpAuth { api_key: None }, &format!("http://{address}")).unwrap();
    let request = crate::types::JsonRpcRequest {
        jsonrpc: "2.0", id: 1, method: "tools/call".into(), params: json!({"name":"create","arguments":{}}),
    };
    let result = fcp_async_core::time::timeout(
        Duration::from_secs(3), client.rpc_call_once(&client.rpc_endpoint(), &request, None),
    ).await;
    let requests = worker.join().unwrap();
    assert_eq!(result.unwrap().unwrap(), tool_result());
    assert!(requests[0].starts_with("POST /mcp "));
    assert!(requests[1].starts_with("GET /mcp "));
    assert!(requests[1].to_ascii_lowercase().contains("last-event-id: raw-checkpoint\r\n"));
}
