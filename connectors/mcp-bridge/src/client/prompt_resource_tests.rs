//! Production-client and FCP dispatch regressions for prompt/template reads.
use super::*;
use std::sync::atomic::AtomicUsize;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::{Value, json};
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn client(server: &MockServer) -> McpClient {
    let mut client = McpClient::new(McpAuth { api_key: None }, &server.uri()).unwrap();
    client.retry_config.initial_delay_ms = 1;
    client.retry_config.max_delay_ms = 1;
    client.retry_config.jitter_enabled = false;
    client
}

fn initialization(capabilities: Value) -> Value {
    json!({
        "protocolVersion": session::PROTOCOL_VERSION,
        "capabilities": capabilities,
        "serverInfo": {"name": "prompt-resource-test", "version": "1"}
    })
}

async fn mount_initialization(server: &MockServer, capabilities: Value) {
    Mock::given(method("POST")).and(path("/mcp"))
        .and(body_partial_json(json!({"method":"initialize"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0", "id":0, "result":initialization(capabilities)
        })).insert_header("Mcp-Session-Id", "active"))
        .mount(server).await;
    mount_initialized(server).await;
}

async fn mount_initialized(server: &MockServer) {
    Mock::given(method("POST")).and(path("/mcp"))
        .and(body_partial_json(json!({"method":"notifications/initialized"})))
        .respond_with(ResponseTemplate::new(202)).mount(server).await;
}

fn rpc_response(request: &Request, result: Value) -> ResponseTemplate {
    let body: Value = serde_json::from_slice(&request.body).unwrap();
    ResponseTemplate::new(200).set_body_json(json!({
        "jsonrpc":"2.0", "id":body["id"], "result":result
    }))
}

async fn mount_result(server: &MockServer, rpc_method: &str, result: Value) {
    Mock::given(method("POST")).and(path("/mcp"))
        .and(body_partial_json(json!({"method":rpc_method})))
        .respond_with(move |request: &Request| rpc_response(request, result.clone()))
        .mount(server).await;
}

async fn requests(server: &MockServer) -> Vec<Value> {
    server.received_requests().await.unwrap().iter()
        .map(|request| serde_json::from_slice(&request.body).unwrap()).collect()
}

fn rich_prompt() -> Value {
    json!({
        "description":"Review the supplied example",
        "_meta":{"vendor":{"preserve":true}},
        "messages":[
            {"role":"user","content":{"type":"text","text":"héllo\n{code}","_meta":{"x":1}}},
            {"role":"assistant","content":{"type":"image","data":"AQ==","mimeType":"image/png"}},
            {"role":"user","content":{"type":"audio","data":"Ag==","mimeType":"audio/wav"}},
            {"role":"user","content":{"type":"resource","resource":{"uri":"file:///not-local","text":"embedded","mimeType":"text/plain"}}},
            {"role":"user","content":{"type":"resource","resource":{"uri":"opaque:blob","blob":"Aw=="}}},
            {"role":"user","content":{"type":"resource_link","name":"Do not fetch","uri":"https://uncontacted.invalid/secret","annotations":{"priority":0.5}}}
        ]
    })
}

#[test]
fn prompt_validation_accepts_all_negotiated_content_kinds_and_extensions() {
    validate_prompt_result(&rich_prompt()).unwrap();
    validate_prompt_result(&json!({"messages":[]})).unwrap();
}

#[test]
fn prompt_validation_refuses_malformed_core_envelopes_without_echoing_content() {
    for value in [
        Value::Null, json!([]), json!({}), json!({"messages":null}),
        json!({"messages":[],"description":false}),
        json!({"messages":[null]}),
        json!({"messages":[{"role":"system","content":{"type":"text","text":"PRIVATE"}}]}),
        json!({"messages":[{"role":"user","content":{"type":"text","text":42}}]}),
        json!({"messages":[{"role":"user","content":{"type":"image","data":"PRIVATE"}}]}),
        json!({"messages":[{"role":"user","content":{"type":"audio","mimeType":"audio/wav"}}]}),
        json!({"messages":[{"role":"user","content":{"type":"resource_link","uri":"PRIVATE"}}]}),
        json!({"messages":[{"role":"user","content":{"type":"resource","resource":{"uri":"PRIVATE"}}}]}),
        json!({"messages":[{"role":"user","content":{"type":"resource","resource":{"text":"PRIVATE"}}}]}),
        json!({"messages":[{"role":"user","content":{"type":"unknown","text":"PRIVATE"}}]}),
    ] {
        let error = validate_prompt_result(&value).unwrap_err();
        assert!(!error.is_retryable());
        assert!(!error.to_string().contains("PRIVATE"));
    }
}

#[fcp_async_core::runtime::test]
async fn prompt_get_preserves_arguments_and_multimodal_results_without_followup_io() {
    let server = MockServer::start().await;
    mount_initialization(&server, json!({"prompts":{}})).await;
    let expected = rich_prompt();
    mount_result(&server, "prompts/get", expected.clone()).await;
    let client = client(&server);
    let arguments = json!({"empty":"", "code":" \n\tß\"{x} "});
    let result = client.prompts_get("exact name", Some(&arguments)).await.unwrap();
    assert_eq!(result, expected);
    let bodies = requests(&server).await;
    assert_eq!(bodies.len(), 3, "must not fetch links, sample or execute tools");
    assert_eq!(bodies[2]["method"], "prompts/get");
    assert_eq!(bodies[2]["params"], json!({"name":"exact name","arguments":arguments}));
}

#[fcp_async_core::runtime::test]
async fn omitted_prompt_arguments_are_absent_not_null_or_an_invented_empty_map() {
    let server = MockServer::start().await;
    mount_initialization(&server, json!({"prompts":{}})).await;
    mount_result(&server, "prompts/get", json!({"messages":[]})).await;
    client(&server).prompts_get("plain", None).await.unwrap();
    assert_eq!(requests(&server).await[2]["params"], json!({"name":"plain"}));
}

#[fcp_async_core::runtime::test]
async fn invalid_prompt_arguments_are_rejected_before_initialization_or_network_io() {
    let server = MockServer::start().await;
    let client = client(&server);
    assert!(client.prompts_get("", None).await.is_err());
    for arguments in [Value::Null, json!(false), json!("{}"), json!([]),
        json!({"key":1}), json!({"key":null}), json!({"key":{"PRIVATE":true}})] {
        let error = client.prompts_get("valid", Some(&arguments)).await.unwrap_err();
        assert!(matches!(error, McpBridgeError::McpError {code:-32602,..}));
        assert!(!error.to_string().contains("PRIVATE"));
    }
    assert!(requests(&server).await.is_empty());
}

#[fcp_async_core::runtime::test]
async fn prompt_and_template_reads_require_their_negotiated_server_capabilities() {
    let server = MockServer::start().await;
    mount_initialization(&server, json!({"tools":{}})).await;
    let client = client(&server);
    assert!(client.prompts_get("missing", None).await.is_err());
    assert!(client.resource_templates_list().await.is_err());
    assert_eq!(requests(&server).await.len(), 2, "only initialization may be sent");
}

#[fcp_async_core::runtime::test]
async fn prompt_read_retries_a_transient_failure_but_never_reinitializes_unnecessarily() {
    let server = MockServer::start().await;
    mount_initialization(&server, json!({"prompts":{}})).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"prompts/get"})))
        .respond_with(ResponseTemplate::new(503)).with_priority(0).up_to_n_times(1)
        .expect(1).mount(&server).await;
    mount_result(&server, "prompts/get", json!({"messages":[]})).await;
    client(&server).prompts_get("read", None).await.unwrap();
    let bodies = requests(&server).await;
    assert_eq!(bodies.len(), 4);
    assert_eq!(bodies[2], bodies[3], "read retries retain request correlation and arguments");
}

#[fcp_async_core::runtime::test]
async fn malformed_prompt_success_is_terminal_not_retried_or_returned_as_success() {
    let server = MockServer::start().await;
    mount_initialization(&server, json!({"prompts":{}})).await;
    mount_result(&server, "prompts/get", json!({"messages":[{"role":"system"}]})).await;
    let error = client(&server).prompts_get("broken", None).await.unwrap_err();
    assert!(!error.is_retryable());
    assert_eq!(requests(&server).await.len(), 3);
}

#[fcp_async_core::runtime::test]
async fn prompt_read_deadline_is_not_refreshed_or_retried_after_expiration() {
    let server = MockServer::start().await;
    mount_initialization(&server, json!({"prompts":{}})).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"prompts/get"})))
        .respond_with(|request: &Request| {
            rpc_response(request, json!({"messages":[]})).set_delay(Duration::from_secs(1))
        }).expect(1).mount(&server).await;
    let mut client = client(&server);
    client.initialize().await.unwrap();
    client.runtime = ConnectorRuntime::new(
        ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_millis(100)),
    );
    let error = fcp_async_core::time::timeout(Duration::from_secs(2), client.prompts_get("slow", None))
        .await.expect("outer watchdog").unwrap_err();
    assert!(!error.is_retryable());
    assert_eq!(requests(&server).await.len(), 3);
}

#[fcp_async_core::runtime::test]
async fn resource_templates_collect_all_pages_without_expanding_uri_templates() {
    let server = MockServer::start().await;
    mount_initialization(&server, json!({"resources":{}})).await;
    let first = json!({"name":"Shared display name","uriTemplate":"file:///{name}{?version}","title":"first"});
    let second = json!({"name":"Shared display name","uriTemplate":"https://uncontacted.invalid/{+path}","mimeType":"text/plain"});
    let first_copy = first.clone();
    let second_copy = second.clone();
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"resources/templates/list"})))
        .respond_with(move |request: &Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            let page = if body["params"].get("cursor").is_none() {
                json!({"resourceTemplates":[first_copy.clone()],"nextCursor":" \nopaque/ß ","_meta":{"first":true}})
            } else {
                assert_eq!(body["params"]["cursor"], " \nopaque/ß ");
                json!({"resourceTemplates":[second_copy.clone()]})
            };
            rpc_response(request, page)
        }).expect(2).mount(&server).await;
    let result = client(&server).resource_templates_list().await.unwrap();
    assert_eq!(result, json!({"resourceTemplates":[first,second],"_meta":{"first":true}}));
    assert_eq!(requests(&server).await.len(), 4);
}

#[fcp_async_core::runtime::test]
async fn resource_template_identity_is_the_uri_template_not_the_display_name() {
    let server = MockServer::start().await;
    mount_initialization(&server, json!({"resources":{}})).await;
    mount_result(&server, "resources/templates/list", json!({"resourceTemplates":[
        {"name":"one","uriTemplate":"data:///{id}"},
        {"name":"two","uriTemplate":"data:///{id}"}
    ]})).await;
    let error = client(&server).resource_templates_list().await.unwrap_err();
    assert!(error.to_string().contains("duplicate discovery entry identity"));
    assert_eq!(requests(&server).await.len(), 3);
}

#[fcp_async_core::runtime::test]
async fn resource_template_cursor_cycles_fail_without_returning_partial_catalogs() {
    let server = MockServer::start().await;
    mount_initialization(&server, json!({"resources":{}})).await;
    mount_result(&server, "resources/templates/list", json!({"resourceTemplates":[],"nextCursor":"loop"})).await;
    let error = client(&server).resource_templates_list().await.unwrap_err();
    assert!(error.to_string().contains("cursor cycle"));
    assert_eq!(requests(&server).await.len(), 4);
}

#[fcp_async_core::runtime::test]
async fn invalid_resource_templates_fail_the_complete_read() {
    for entry in [json!({"uriTemplate":"x:{id}"}), json!({"name":"","uriTemplate":"x:{id}"}),
        json!({"name":42,"uriTemplate":"x:{id}"}), json!({"name":"x"}),
        json!({"name":"x","uriTemplate":""}), json!({"name":"x","uriTemplate":false})] {
        let server = MockServer::start().await;
        mount_initialization(&server, json!({"resources":{}})).await;
        mount_result(&server, "resources/templates/list", json!({"resourceTemplates":[entry]})).await;
        let error = client(&server).resource_templates_list().await.unwrap_err();
        assert!(!error.is_retryable());
        assert_eq!(requests(&server).await.len(), 3);
    }
}

#[fcp_async_core::runtime::test]
async fn template_session_expiry_discards_old_pages_and_restarts_without_a_cursor() {
    let server = MockServer::start().await;
    let generations = Arc::new(AtomicUsize::new(0));
    let generation = Arc::clone(&generations);
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"initialize"})))
        .respond_with(move |request: &Request| {
            let number = generation.fetch_add(1, Ordering::SeqCst) + 1;
            rpc_response(request, initialization(json!({"resources":{}})))
                .insert_header("Mcp-Session-Id", format!("generation-{number}"))
        }).expect(2).mount(&server).await;
    mount_initialized(&server).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"resources/templates/list"})))
        .and(header("Mcp-Session-Id", "generation-1"))
        .respond_with(|request: &Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            if body["params"].get("cursor").is_some() { ResponseTemplate::new(404) }
            else { rpc_response(request, json!({"resourceTemplates":[{"name":"old","uriTemplate":"old:{id}"}],"nextCursor":"old-cursor"})) }
        }).expect(2).mount(&server).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"resources/templates/list"})))
        .and(header("Mcp-Session-Id", "generation-2"))
        .respond_with(|request: &Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(body["params"], json!({}), "stale cursor must not cross sessions");
            rpc_response(request, json!({"resourceTemplates":[{"name":"new","uriTemplate":"new:{id}"}]}))
        }).expect(1).mount(&server).await;
    let client = client(&server);
    let result = client.resource_templates_list().await.unwrap();
    assert_eq!(result, json!({"resourceTemplates":[{"name":"new","uriTemplate":"new:{id}"}]}));
    assert_eq!(client.metrics().session_expired_retry_count, 1);
    assert_eq!(generations.load(Ordering::SeqCst), 2);
    assert_eq!(requests(&server).await.len(), 7);
}

#[fcp_async_core::runtime::test]
async fn explicit_template_cursor_is_not_replayed_into_a_reinitialized_session() {
    let server = MockServer::start().await;
    mount_initialization(&server, json!({"resources":{}})).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"resources/templates/list"})))
        .respond_with(ResponseTemplate::new(404)).expect(1).mount(&server).await;
    let client = client(&server);
    let error = client.rpc_call("resources/templates/list", json!({"cursor":"old"})).await.unwrap_err();
    assert!(!error.is_retryable());
    assert_eq!(client.metrics().session_expired_retry_count, 0);
    assert_eq!(requests(&server).await.len(), 3);
}

#[fcp_async_core::runtime::test]
async fn new_read_retries_do_not_authorize_unsafe_tool_replay() {
    let server = MockServer::start().await;
    mount_initialization(&server, json!({"prompts":{},"resources":{},"tools":{}})).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"tools/call"})))
        .respond_with(ResponseTemplate::new(503)).expect(1).mount(&server).await;
    let error = client(&server).tools_call("create", &json!({})).await.unwrap_err();
    assert!(!error.is_retryable());
    assert_eq!(requests(&server).await.len(), 3);
}

#[fcp_async_core::runtime::test]
async fn shutdown_refuses_new_prompt_and_template_reads_before_network_io() {
    let server = MockServer::start().await;
    let client = client(&server);
    client.shutdown();
    assert!(client.prompts_get("plain", None).await.is_err());
    assert!(client.resource_templates_list().await.is_err());
    assert!(requests(&server).await.is_empty());
}

#[fcp_async_core::runtime::test]
async fn template_catalog_enforces_entry_and_utf8_cursor_byte_limits() {
    for excessive_entries in [true, false] {
        let server = MockServer::start().await;
        mount_initialization(&server, json!({"resources":{}})).await;
        let result = if excessive_entries {
            let entries: Vec<_> = (0..10_001).map(|index| {
                json!({"name":format!("template-{index}"),"uriTemplate":format!("example:{index}:{{id}}")})
            }).collect();
            json!({"resourceTemplates":entries})
        } else {
            json!({"resourceTemplates":[],"nextCursor":"é".repeat(4097)})
        };
        mount_result(&server, "resources/templates/list", result).await;
        let error = client(&server).resource_templates_list().await.unwrap_err();
        let expected = if excessive_entries { "entry limit" } else { "oversized discovery cursor" };
        assert!(error.to_string().contains(expected));
        assert!(!error.is_retryable());
        assert_eq!(requests(&server).await.len(), 3, "must not request another page");
    }
}

#[fcp_async_core::runtime::test]
async fn explicit_template_page_retries_keep_the_same_session_and_opaque_cursor() {
    let server = MockServer::start().await;
    mount_initialization(&server, json!({"resources":{}})).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"resources/templates/list"})))
        .and(header("Mcp-Session-Id", "active"))
        .respond_with(ResponseTemplate::new(503)).with_priority(0).up_to_n_times(1)
        .expect(1).mount(&server).await;
    mount_result(&server, "resources/templates/list", json!({"resourceTemplates":[]})).await;
    client(&server).rpc_call("resources/templates/list", json!({"cursor":"  opaque/ß  "})).await.unwrap();
    let bodies = requests(&server).await;
    assert_eq!(bodies.len(), 4);
    assert_eq!(bodies[2], bodies[3]);
    assert_eq!(bodies[3]["params"]["cursor"], "  opaque/ß  ");
    let received = server.received_requests().await.unwrap();
    assert_eq!(received[3].headers.get("mcp-session-id").unwrap(), "active");
}

#[fcp_async_core::runtime::test]
async fn prompt_get_rejects_a_mismatched_json_rpc_response_id_without_replay() {
    let server = MockServer::start().await;
    mount_initialization(&server, json!({"prompts":{}})).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"prompts/get"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0", "id":9999, "result":{"messages":[]}
        }))).expect(1).mount(&server).await;
    let error = client(&server).prompts_get("plain", None).await.unwrap_err();
    assert!(!error.is_retryable());
    assert_eq!(requests(&server).await.len(), 3);
}
