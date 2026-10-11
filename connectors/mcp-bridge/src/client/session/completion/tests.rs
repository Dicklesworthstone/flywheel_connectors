use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::time::Duration;

use fcp_sdk::{ConnectorErrorMapping, ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::json;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use super::*;
use super::super::PROTOCOL_VERSION;
use crate::client::McpAuth;

fn params() -> Value {
    json!({
        "ref": {"type": "ref/prompt", "name": "code_review"},
        "argument": {"name": "language", "value": "py"},
        "context": {"arguments": {"project": "opaque/project"}},
        "_meta": {"opaque": {"keep": true}},
    })
}

fn result() -> Value {
    json!({
        "completion": {"values": ["python", "pytorch", "python"], "total": 12, "hasMore": true},
        "_meta": {"ranked": true},
    })
}

fn initialization(capabilities: Value) -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": capabilities,
        "serverInfo": {"name": "completion-fixture", "version": "1"},
    })
}

fn client(server: &MockServer) -> McpClient {
    let mut client = McpClient::new(McpAuth { api_key: None }, &server.uri()).unwrap();
    client.retry_config.initial_delay_ms = 1;
    client.retry_config.max_delay_ms = 1;
    client.retry_config.jitter_enabled = false;
    client
}

async fn mount_session(server: &MockServer, capabilities: Value, session: Option<&str>) {
    let mut response = ResponseTemplate::new(200).set_body_json(json!({
        "jsonrpc": "2.0", "id": 0, "result": initialization(capabilities),
    }));
    if let Some(session) = session {
        response = response.insert_header("Mcp-Session-Id", session);
    }
    Mock::given(method("POST")).and(path("/mcp"))
        .and(body_partial_json(json!({"method": "initialize"})))
        .respond_with(response).mount(server).await;
    Mock::given(method("POST")).and(path("/mcp"))
        .and(body_partial_json(json!({"method": "notifications/initialized"})))
        .respond_with(ResponseTemplate::new(202)).mount(server).await;
}

async fn mount_result(server: &MockServer, value: Value) {
    Mock::given(method("POST")).and(path("/mcp"))
        .and(body_partial_json(json!({"method": "completion/complete"})))
        .respond_with(move |request: &Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": body["id"], "result": value,
            }))
        }).mount(server).await;
}

async fn methods(server: &MockServer) -> Vec<String> {
    server.received_requests().await.unwrap().iter().map(|request| {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        body["method"].as_str().unwrap_or("<response>").to_owned()
    }).collect()
}

#[test]
fn accepts_both_reference_kinds_empty_prefixes_and_opaque_context() {
    let prompt = params();
    validate_request(&prompt).unwrap();
    let mut resource = params();
    resource["ref"] = json!({"type": "ref/resource", "uri": "file:///{path}?x={value}"});
    resource["argument"]["value"] = json!("");
    resource["context"]["arguments"] = json!({"other": "雪/../%2F", "empty": ""});
    validate_request(&resource).unwrap();
    resource["context"] = json!({});
    validate_request(&resource).unwrap();
    resource.as_object_mut().unwrap().remove("context");
    validate_request(&resource).unwrap();
}

#[test]
fn malformed_references_are_not_coerced_or_echoed_in_errors() {
    for reference in [
        Value::Null, json!([]), json!({}), json!({"type": "ref/tool", "name": "private-marker"}),
        json!({"type": "ref/prompt", "name": ""}),
        json!({"type": "ref/prompt", "name": 9}),
        json!({"type": "ref/resource", "name": "wrong-field"}),
        json!({"type": "ref/resource", "uri": false}),
    ] {
        let mut request = params();
        request["ref"] = reference;
        let error = validate_request(&request).unwrap_err();
        assert!(matches!(error, McpBridgeError::McpError { code: -32602, .. }));
        assert!(!error.to_string().contains("private-marker"));
    }
}

#[test]
fn argument_and_context_values_must_be_named_strings() {
    for argument in [Value::Null, json!({}), json!({"name": "", "value": ""}),
        json!({"name": "arg", "value": []}), json!({"name": 2, "value": "prefix"})]
    {
        let mut request = params();
        request["argument"] = argument;
        assert!(validate_request(&request).is_err());
    }
    for context in [Value::Null, json!([]), json!({"arguments": []}),
        json!({"arguments": {"x": 1}}), json!({"arguments": {"": "value"}})]
    {
        let mut request = params();
        request["context"] = context;
        assert!(validate_request(&request).is_err());
    }
    for request in [Value::Null, json!([]), json!({})] {
        assert!(validate_request(&request).is_err());
    }
}

#[test]
fn suggestion_order_duplicates_and_extension_metadata_are_preserved() {
    let value = result();
    assert_eq!(validate_response(value.clone()).unwrap(), value);
    for values in [json!([]), json!([""]), json!(vec!["same"; 100])] {
        let value = json!({"completion": {"values": values, "vendor": {"rank": [3, 1]}}});
        assert_eq!(validate_response(value.clone()).unwrap(), value);
    }
}

#[test]
fn excessive_or_malformed_results_are_errors_not_partial_success() {
    for value in [Value::Null, json!([]), json!({}), json!({"completion": []}),
        json!({"completion": {}}), json!({"completion": {"values": {}}}),
        json!({"completion": {"values": ["good", 1]}}),
        json!({"completion": {"values": vec!["value"; 101]}})]
    {
        assert!(validate_response(value).is_err());
    }
}

#[test]
fn completion_counts_and_flags_follow_the_schema_without_number_coercion() {
    for total in [json!(-1), json!(1.5), json!("4"), Value::Null, json!(false), json!(1)] {
        assert!(validate_response(json!({"completion": {"values": ["a", "b"], "total": total}})).is_err());
    }
    for total in [json!(2), json!(2.0), json!(999), json!(u64::MAX)] {
        let value = json!({"completion": {"values": ["a", "b"], "total": total}});
        assert_eq!(validate_response(value.clone()).unwrap(), value);
    }
    for flag in [json!(0), json!("true"), Value::Null] {
        assert!(validate_response(json!({"completion": {"values": [], "hasMore": flag}})).is_err());
    }
}

#[fcp_async_core::runtime::test]
async fn complete_uses_managed_headers_and_forwards_the_exact_parameter_object() {
    let server = MockServer::start().await;
    mount_session(&server, json!({"completions": {}}), Some("completion-session")).await;
    mount_result(&server, result()).await;
    let client = client(&server);
    let request = params();
    assert_eq!(client.completion_complete(request.clone()).await.unwrap(), result());
    assert_eq!(methods(&server).await, ["initialize", "notifications/initialized", "completion/complete"]);
    let received = server.received_requests().await.unwrap();
    let sent: Value = serde_json::from_slice(&received[2].body).unwrap();
    assert_eq!(sent["params"], request);
    assert_eq!(received[2].headers.get("mcp-session-id").unwrap(), "completion-session");
    assert_eq!(received[2].headers.get("mcp-protocol-version").unwrap(), PROTOCOL_VERSION);
}

#[fcp_async_core::runtime::test]
async fn invalid_high_and_low_level_calls_never_initialize_or_allocate_a_request_id() {
    let server = MockServer::start().await;
    let client = client(&server);
    assert!(client.completion_complete(json!({"ref": "private-marker"})).await.is_err());
    assert!(client.rpc_call("completion/complete", json!({})).await.is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
    assert_eq!(client.request_id.load(Ordering::Relaxed), 1);
}

#[fcp_async_core::runtime::test]
async fn absent_or_malformed_completion_capability_prevents_dispatch() {
    for capabilities in [json!({}), json!({"completions": true}), json!({"completion": {}}),
        json!({"tools": {}, "prompts": {}, "resources": {}})]
    {
        let server = MockServer::start().await;
        mount_session(&server, capabilities, None).await;
        let client = client(&server);
        assert!(client.rpc_call("completion/complete", params()).await.is_err());
        assert_eq!(methods(&server).await, ["initialize", "notifications/initialized"]);
    }
}

#[fcp_async_core::runtime::test]
async fn resource_completion_is_not_resource_read_or_template_expansion() {
    let server = MockServer::start().await;
    mount_session(&server, json!({"completions": {}}), None).await;
    mount_result(&server, json!({"completion": {"values": ["file:///private", "https://example.invalid/"]}})).await;
    let client = client(&server);
    let mut request = params();
    request["ref"] = json!({"type": "ref/resource", "uri": "file:///{path}"});
    client.completion_complete(request).await.unwrap();
    assert_eq!(methods(&server).await, ["initialize", "notifications/initialized", "completion/complete"]);
}

#[fcp_async_core::runtime::test]
async fn same_session_transient_read_retry_preserves_argument_context() {
    let server = MockServer::start().await;
    mount_session(&server, json!({"completions": {}}), Some("retry")).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method": "completion/complete"})))
        .respond_with(ResponseTemplate::new(503)).with_priority(0).up_to_n_times(1)
        .mount(&server).await;
    mount_result(&server, result()).await;
    let client = client(&server);
    client.completion_complete(params()).await.unwrap();
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[2].body, requests[3].body);
    assert_eq!(methods(&server).await, ["initialize", "notifications/initialized", "completion/complete", "completion/complete"]);
}

async fn mount_rotating_session(server: &MockServer, replacement_supports_completion: bool) {
    let generation = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST")).and(body_partial_json(json!({"method": "initialize"})))
        .respond_with(move |_request: &Request| {
            let generation = generation.fetch_add(1, Ordering::SeqCst) + 1;
            let capabilities = if generation == 1 || replacement_supports_completion {
                json!({"completions": {}})
            } else { json!({}) };
            ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": 0, "result": initialization(capabilities),
            })).insert_header("Mcp-Session-Id", format!("session-{generation}"))
        }).mount(server).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method": "notifications/initialized"})))
        .respond_with(ResponseTemplate::new(202)).mount(server).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method": "completion/complete"})))
        .and(header("Mcp-Session-Id", "session-1"))
        .respond_with(ResponseTemplate::new(404)).with_priority(0).mount(server).await;
    mount_result(server, result()).await;
}

#[fcp_async_core::runtime::test]
async fn expired_session_recovery_rechecks_the_replacement_capability() {
    let server = MockServer::start().await;
    mount_rotating_session(&server, false).await;
    let client = client(&server);
    assert!(client.completion_complete(params()).await.is_err());
    assert_eq!(client.metrics().session_expired_retry_count, 1);
    assert_eq!(methods(&server).await, ["initialize", "notifications/initialized", "completion/complete", "initialize", "notifications/initialized"]);
}

#[fcp_async_core::runtime::test]
async fn expired_session_recovery_repeats_only_the_completion_with_its_original_context() {
    let server = MockServer::start().await;
    mount_rotating_session(&server, true).await;
    let client = client(&server);
    assert_eq!(client.completion_complete(params()).await.unwrap(), result());
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 6);
    assert_eq!(received[2].body, received[5].body);
    assert_eq!(received[5].headers.get("mcp-session-id").unwrap(), "session-2");
}

#[fcp_async_core::runtime::test]
async fn malformed_success_payloads_and_mismatched_ids_are_terminal() {
    for wrong_id in [false, true] {
        let server = MockServer::start().await;
        mount_session(&server, json!({"completions": {}}), None).await;
        Mock::given(method("POST")).and(body_partial_json(json!({"method": "completion/complete"})))
            .respond_with(move |request: &Request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0", "id": if wrong_id { json!(999) } else { body["id"].clone() },
                    "result": if wrong_id { result() } else { json!({"completion": {"values": [7]}}) },
                }))
            }).expect(1).mount(&server).await;
        let client = client(&server);
        let error = client.completion_complete(params()).await.unwrap_err();
        assert!(!error.is_retryable());
        assert_eq!(methods(&server).await.len(), 3);
    }
}

#[fcp_async_core::runtime::test]
async fn sse_completion_result_preserves_metadata_without_treating_has_more_as_a_cursor() {
    let server = MockServer::start().await;
    mount_session(&server, json!({"completions": {}}), Some("sse")).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method": "completion/complete"})))
        .respond_with(|request: &Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            let payload = json!({"jsonrpc": "2.0", "id": body["id"], "result": result()});
            ResponseTemplate::new(200).insert_header("Content-Type", "text/event-stream")
                .set_body_string(format!("data: {payload}\n\n"))
        }).expect(1).mount(&server).await;
    assert_eq!(client(&server).completion_complete(params()).await.unwrap(), result());
    assert_eq!(methods(&server).await.len(), 3);
}

#[fcp_async_core::runtime::test]
async fn initialization_and_read_share_one_overall_deadline() {
    let server = MockServer::start().await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method": "initialize"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0", "id": 0, "result": initialization(json!({"completions": {}})),
        })).set_delay(Duration::from_millis(500))).mount(&server).await;
    let mut client = client(&server);
    client.runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default()
        .with_request_timeout(Duration::from_millis(100)));
    assert!(client.completion_complete(params()).await.is_err());
    assert!(client.session.lock().await.is_none());
    assert_eq!(methods(&server).await, ["initialize"]);
}

#[fcp_async_core::runtime::test]
async fn completion_retry_classification_does_not_make_tool_side_effects_replayable() {
    let server = MockServer::start().await;
    mount_session(&server, json!({"tools": {}, "completions": {}}), Some("tools")).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method": "tools/call"})))
        .respond_with(ResponseTemplate::new(503)).expect(1).mount(&server).await;
    let error = client(&server).tools_call("write", &json!({})).await.unwrap_err();
    assert!(!error.is_retryable());
    assert_eq!(methods(&server).await, ["initialize", "notifications/initialized", "tools/call"]);
}
