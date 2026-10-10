use super::*;
use crate::client::McpAuth;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::header::HeaderValue;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn initialization() -> Value {
    json!({
        "protocolVersion": super::super::PROTOCOL_VERSION,
        "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
        "serverInfo": {"name": "discovery-test", "version": "1"}
    })
}

async fn mount_initialization(server: &MockServer, session: Option<&'static str>) {
    let mut response = ResponseTemplate::new(200).set_body_json(json!({
        "jsonrpc": "2.0", "id": 0, "result": initialization()
    }));
    if let Some(id) = session {
        response = response.insert_header("Mcp-Session-Id", id);
    }
    Mock::given(method("POST")).and(path("/mcp"))
        .and(body_partial_json(json!({"method": "initialize"})))
        .respond_with(response).mount(server).await;
    mount_notification(server).await;
}

async fn mount_notification(server: &MockServer) {
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method": "notifications/initialized"})))
        .respond_with(ResponseTemplate::new(202)).mount(server).await;
}

fn client(server: &MockServer) -> McpClient {
    let mut client = McpClient::new(McpAuth { api_key: None }, &server.uri()).unwrap();
    client.retry_config.initial_delay_ms = 1;
    client.retry_config.max_delay_ms = 1;
    client.retry_config.jitter_enabled = false;
    client
}

fn reply(body: &Value, result: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "jsonrpc": "2.0", "id": body["id"], "result": result
    }))
}

async fn list_requests(server: &MockServer, rpc_method: &str) -> Vec<Value> {
    server.received_requests().await.unwrap().iter()
        .map(|request| serde_json::from_slice::<Value>(&request.body).unwrap())
        .filter(|body| body["method"] == rpc_method).collect()
}

#[test]
fn preserves_order_extensions_and_initial_envelope_for_all_catalogs() {
    for (method, field, identity) in [
        ("tools/list", "tools", "name"),
        ("resources/list", "resources", "uri"),
        ("prompts/list", "prompts", "name"),
    ] {
        let mut catalog = Catalog::new(method).unwrap();
        let first = json!({identity: "first", "extension": {"keep": [1, null]}});
        let last = json!({identity: "last", "title": "Last entry"});
        assert_eq!(catalog.append(json!({
            field: [first.clone()], "nextCursor": "a", "_meta": {"page": 1}
        })).unwrap().as_deref(), Some("a"));
        assert_eq!(catalog.append(json!({field: [], "nextCursor": "b"})).unwrap().as_deref(), Some("b"));
        assert!(catalog.append(json!({field: [last.clone()], "_meta": {"page": 3}})).unwrap().is_none());
        assert_eq!(catalog.finish(), json!({field: [first, last], "_meta": {"page": 1}}));
    }
}

#[test]
fn cursors_are_opaque_including_empty_and_unicode() {
    let mut catalog = Catalog::new("tools/list").unwrap();
    for cursor in ["", "  ", "雪/../?token=a&b=%20"] {
        assert_eq!(catalog.append(json!({"tools": [], "nextCursor": cursor})).unwrap(), Some(cursor.to_owned()));
    }
    assert!(catalog.append(json!({"tools": []})).unwrap().is_none());
}

#[test]
fn rejects_cycles_through_empty_pages() {
    let mut catalog = Catalog::new("tools/list").unwrap();
    for cursor in ["a", "b"] {
        catalog.append(json!({"tools": [], "nextCursor": cursor})).unwrap();
    }
    let error = catalog.append(json!({"tools": [], "nextCursor": "a"})).unwrap_err();
    assert!(error.to_string().contains("cursor cycle"));
    assert!(!error.is_retryable());
}

#[test]
fn rejects_malformed_catalogs_and_cursors_without_echoing_them() {
    for page in [
        Value::Null, json!([]), json!({}), json!({"tools": {}}),
        json!({"tools": [null]}), json!({"tools": [{}]}),
        json!({"tools": [{"name": ""}]}), json!({"tools": [{"name": 3}]}),
        json!({"tools": [], "nextCursor": null}),
        json!({"tools": [], "nextCursor": 0}),
        json!({"tools": [], "nextCursor": "secret".repeat(MAX_CURSOR_BYTES)}),
    ] {
        let error = Catalog::new("tools/list").unwrap().append(page).unwrap_err();
        assert!(!error.is_retryable());
        assert!(!error.to_string().contains("secret"));
    }
}

#[test]
fn cursor_limit_counts_utf8_bytes_and_accepts_exact_boundary() {
    let mut catalog = Catalog::new("tools/list").unwrap();
    let cursor = "x".repeat(MAX_CURSOR_BYTES);
    assert_eq!(catalog.append(json!({"tools": [], "nextCursor": cursor})).unwrap(), Some(cursor));
    assert!(catalog.append(json!({"tools": [], "nextCursor": "雪".repeat(MAX_CURSOR_BYTES / 3 + 1)})).is_err());
}

#[test]
fn duplicate_entries_fail_instead_of_silently_selecting_a_definition() {
    let mut catalog = Catalog::new("tools/list").unwrap();
    catalog.append(json!({"tools": [{"name": "Read"}, {"name": "read"}], "nextCursor": "more"})).unwrap();
    let error = catalog.append(json!({"tools": [{"name": "read", "description": "different"}]})).unwrap_err();
    assert!(error.to_string().contains("duplicate"));
    assert!(!error.is_retryable());
}

#[test]
fn entry_limit_includes_all_pages_with_exact_boundary_allowed() {
    let mut catalog = Catalog::new("tools/list").unwrap();
    let entries: Vec<_> = (0..MAX_DISCOVERY_ENTRIES).map(|i| json!({"name": format!("tool-{i}")})).collect();
    catalog.append(json!({"tools": entries, "nextCursor": "extra"})).unwrap();
    assert!(catalog.append(json!({"tools": [{"name": "too-many"}]})).is_err());
}

#[test]
fn page_and_byte_budgets_cannot_be_renewed_or_overflowed() {
    let budget = DiscoveryBudget::default();
    for _ in 0..MAX_DISCOVERY_PAGES {
        budget.charge_page().unwrap();
    }
    assert!(budget.charge_page().is_err());
    assert_eq!(budget.pages.load(Ordering::Relaxed), MAX_DISCOVERY_PAGES);
    let counter = AtomicUsize::new(0);
    DiscoveryBudget::charge(&counter, MAX_DISCOVERY_BYTES, MAX_DISCOVERY_BYTES, "bytes").unwrap();
    assert!(DiscoveryBudget::charge(&counter, 1, MAX_DISCOVERY_BYTES, "bytes").is_err());
    assert!(DiscoveryBudget::charge(&counter, usize::MAX, MAX_DISCOVERY_BYTES, "bytes").is_err());
    assert_eq!(counter.load(Ordering::Relaxed), MAX_DISCOVERY_BYTES);
}

#[test]
fn response_budget_includes_metadata_and_prior_passes() {
    let page = json!({"tools": [], "_meta": {"large": "x".repeat(32)}});
    let size = serde_json::to_vec(&page).unwrap().len();
    let budget = DiscoveryBudget {
        pages: AtomicUsize::new(1),
        bytes: AtomicUsize::new(MAX_DISCOVERY_BYTES - size),
    };
    budget.charge_response(&page).unwrap();
    // A new Catalog (a retry) does not reset the outer budget.
    let _replacement = Catalog::new("tools/list").unwrap();
    assert!(budget.charge_response(&json!({"tools": []})).is_err());
}

#[test]
fn write_methods_cannot_enter_discovery_retry_policy() {
    for method in ["tools/call", "resources/read", "initialize", "notifications/initialized", ""] {
        assert!(Catalog::new(method).is_err());
    }
}

#[fcp_async_core::runtime::test]
async fn high_level_lists_follow_cursors_and_keep_single_page_rpc_available() {
    for (rpc_method, field, identity) in [
        ("tools/list", "tools", "name"),
        ("resources/list", "resources", "uri"),
        ("prompts/list", "prompts", "name"),
    ] {
        let server = MockServer::start().await;
        mount_initialization(&server, Some("catalog-session")).await;
        Mock::given(method("POST")).and(path("/mcp"))
            .and(body_partial_json(json!({"method": rpc_method})))
            .respond_with(move |request: &Request| {
                assert_eq!(request.headers.get("mcp-session-id").unwrap(), "catalog-session");
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let result = if body["params"].get("cursor").is_none() {
                    json!({field: [{identity: "one"}], "nextCursor": " 雪/%?= "})
                } else {
                    assert_eq!(body["params"]["cursor"], " 雪/%?= ");
                    json!({field: [{identity: "two"}]})
                };
                reply(&body, result)
            }).mount(&server).await;
        let client = client(&server);
        let result = match rpc_method {
            "tools/list" => client.tools_list().await,
            "resources/list" => client.resources_list().await,
            _ => client.prompts_list().await,
        }.unwrap();
        assert_eq!(result, json!({field: [{identity: "one"}, {identity: "two"}]}));
        let requests = list_requests(&server, rpc_method).await;
        assert_eq!(requests.len(), 2);
        assert_ne!(requests[0]["id"], requests[1]["id"]);
        let single = client.rpc_call(rpc_method, json!({})).await.unwrap();
        assert!(single.get("nextCursor").is_some());
        assert_eq!(list_requests(&server, rpc_method).await.len(), 3);
    }
}

#[fcp_async_core::runtime::test]
async fn stateless_pagination_follows_an_empty_cursor() {
    let server = MockServer::start().await;
    mount_initialization(&server, None).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(|request: &Request| {
            assert!(!request.headers.contains_key("mcp-session-id"));
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            reply(&body, if body["params"].get("cursor").is_some() {
                assert_eq!(body["params"]["cursor"], "");
                json!({"tools": [{"name": "last"}]})
            } else {
                json!({"tools": [], "nextCursor": ""})
            })
        }).mount(&server).await;
    assert_eq!(client(&server).tools_list().await.unwrap(), json!({"tools": [{"name": "last"}]}));
    assert_eq!(list_requests(&server, "tools/list").await.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn expired_session_restarts_without_reusing_cursor_or_partial_catalog() {
    let server = MockServer::start().await;
    let generations = Arc::new(AtomicUsize::new(0));
    let generated = Arc::clone(&generations);
    Mock::given(method("POST")).and(body_partial_json(json!({"method": "initialize"})))
        .respond_with(move |request: &Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            let generation = generated.fetch_add(1, Ordering::Relaxed) + 1;
            reply(&body, initialization()).insert_header("Mcp-Session-Id", format!("session-{generation}"))
        }).mount(&server).await;
    mount_notification(&server).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(|request: &Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            let cursor = body["params"].get("cursor");
            if request.headers.get("mcp-session-id").unwrap() == "session-1" {
                if cursor.is_some() {
                    assert_eq!(cursor.unwrap(), "expired-cursor");
                    return ResponseTemplate::new(404);
                }
                return reply(&body, json!({"tools": [{"name": "discard-me"}], "nextCursor": "expired-cursor"}));
            }
            assert_eq!(request.headers.get("mcp-session-id").unwrap(), "session-2");
            if let Some(cursor) = cursor {
                assert_eq!(cursor, "fresh-cursor");
                reply(&body, json!({"tools": [{"name": "fresh-two"}]}))
            } else {
                reply(&body, json!({"tools": [{"name": "fresh-one"}], "nextCursor": "fresh-cursor"}))
            }
        }).mount(&server).await;
    let client = client(&server);
    assert_eq!(client.tools_list().await.unwrap(), json!({"tools": [{"name": "fresh-one"}, {"name": "fresh-two"}]}));
    assert_eq!(client.metrics().session_expired_retry_count, 1);
    assert_eq!(generations.load(Ordering::Relaxed), 2);
    assert_eq!(list_requests(&server, "tools/list").await.len(), 4);
}

#[fcp_async_core::runtime::test]
async fn later_page_protocol_failure_returns_no_partial_success_or_retry() {
    for bad_id in [false, true] {
        let server = MockServer::start().await;
        mount_initialization(&server, None).await;
        Mock::given(method("POST")).and(body_partial_json(json!({"method": "tools/list"})))
            .respond_with(move |request: &Request| {
                let mut body: Value = serde_json::from_slice(&request.body).unwrap();
                if body["params"].get("cursor").is_none() {
                    return reply(&body, json!({"tools": [{"name": "not-partial-success"}], "nextCursor": "next"}));
                }
                if bad_id {
                    body["id"] = json!("mismatched");
                    reply(&body, json!({"tools": []}))
                } else {
                    reply(&body, json!({"wrongArray": []}))
                }
            }).mount(&server).await;
        let error = client(&server).tools_list().await.unwrap_err();
        assert!(!error.is_retryable());
        assert_eq!(list_requests(&server, "tools/list").await.len(), 2);
    }
}

#[fcp_async_core::runtime::test]
async fn deadline_is_shared_across_pages_not_refreshed_per_request() {
    let server = MockServer::start().await;
    mount_initialization(&server, None).await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(|request: &Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            let result = match body["params"]["cursor"].as_str() {
                None => json!({"tools": [{"name": "one"}], "nextCursor": "two"}),
                Some("two") => json!({"tools": [{"name": "two"}], "nextCursor": "three"}),
                _ => json!({"tools": [{"name": "three"}]}),
            };
            reply(&body, result).set_delay(Duration::from_millis(100))
        }).mount(&server).await;
    let mut client = client(&server);
    client.initialize().await.unwrap();
    client.runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default()
        .with_request_timeout(Duration::from_millis(180)));
    assert!(client.tools_list().await.is_err());
    assert!(list_requests(&server, "tools/list").await.len() <= 2);
}

#[fcp_async_core::runtime::test]
async fn generation_check_rejects_reused_session_header() {
    let server = MockServer::start().await;
    let client = client(&server);
    let old = Arc::new(McpSession::from_initialize(initialization(), Some(HeaderValue::from_static("same"))).unwrap());
    let new = Arc::new(McpSession::from_initialize(initialization(), Some(HeaderValue::from_static("same"))).unwrap());
    *client.session.lock().await = Some(Arc::clone(&new));
    assert!(client.require_catalog_session(&old).await.is_err());
    client.require_catalog_session(&new).await.unwrap();
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[test]
fn discovery_future_is_send() {
    fn assert_send<T: Send>(_: T) {}
    let client = McpClient::new(McpAuth { api_key: None }, "https://example.com").unwrap();
    assert_send(client.tools_list());
}
