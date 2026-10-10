//! Local loopback acceptance coverage for the MCP Bridge connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use fcp_mcp_bridge::connector::McpBridgeConnector;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.7.3";
const CONNECTOR_ID: &str = "mcp-bridge";
const LOOPBACK_CREDENTIAL: &str = "mcp-bridge-local-loopback-credential";
const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

#[derive(Debug)]
struct CapturedRequest {
    request_line: String,
    headers: String,
    body: String,
}

#[derive(Debug)]
struct Exchange {
    response_status: &'static str,
    response_body: String,
    extra_headers: &'static str,
}

impl Exchange {
    fn json(response_status: &'static str, response_body: &Value) -> Self {
        Self {
            response_status,
            response_body: response_body.to_string(),
            extra_headers: "",
        }
    }
}

struct LoopbackServer {
    base_url: String,
    handle: Option<JoinHandle<Vec<CapturedRequest>>>,
}

impl LoopbackServer {
    fn start(exchanges: Vec<Exchange>) -> Self {
        let handshake = [
            Exchange::json("200 OK", &json!({
                "jsonrpc": "2.0", "id": 0,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                    "serverInfo": {"name": "raw-loopback", "version": "1"}
                }
            })),
            Exchange { response_status: "202 Accepted", response_body: String::new(), extra_headers: "" },
        ];
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind MCP loopback listener");
        listener
            .set_nonblocking(true)
            .expect("set loopback listener nonblocking");
        let address = listener
            .local_addr()
            .expect("read MCP loopback listener address");
        let handle = thread::spawn(move || {
            handshake
                .into_iter()
                .chain(exchanges)
                .map(|exchange| {
                    let stream = accept_with_deadline(&listener);
                    handle_request(stream, &exchange)
                })
                .collect()
        });

        Self {
            base_url: format!("http://{address}"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(mut self) -> Vec<CapturedRequest> {
        let requests = self.handle
            .take()
            .expect("loopback thread present")
            .join()
            .expect("loopback thread completed");
        // Keep all wire requests in the evidence, including the two lifecycle
        // messages that must precede every operation on a fresh connection.
        let initialize: Value = serde_json::from_str(&requests[0].body).unwrap();
        assert_eq!(initialize["method"], "initialize");
        assert_eq!(initialize["jsonrpc"], "2.0");
        assert_eq!(initialize["id"], 0);
        assert_eq!(initialize["params"]["protocolVersion"], MCP_PROTOCOL_VERSION);
        assert_eq!(initialize["params"]["capabilities"], json!({}));
        assert_eq!(header_value(&requests[0].headers, "authorization"), format!("Bearer {LOOPBACK_CREDENTIAL}"));
        assert_http_boundary(&requests[1]);
        let initialized: Value = serde_json::from_str(&requests[1].body).unwrap();
        assert_eq!(initialized["method"], "notifications/initialized");
        assert!(initialized.get("id").is_none());
        requests
    }
}

struct NoEgressProbe {
    base_url: String,
    listener: TcpListener,
}

impl NoEgressProbe {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind no-egress listener");
        listener
            .set_nonblocking(true)
            .expect("set no-egress listener nonblocking");
        let address = listener
            .local_addr()
            .expect("read no-egress listener address");
        Self {
            base_url: format!("http://{address}"),
            listener,
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn assert_no_connection(&self) {
        thread::sleep(Duration::from_millis(50));
        match self.listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok((_, address)) => panic!("sampling operation unexpectedly opened {address}"),
            Err(error) => panic!("unexpected no-egress listener error: {error}"),
        }
    }
}

fn accept_with_deadline(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for MCP connector request"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept MCP connector request: {error}"),
        }
    }
}

fn handle_request(mut stream: TcpStream, exchange: &Exchange) -> CapturedRequest {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set MCP request read timeout");
    let request = read_http_request(&mut stream);
    write!(
        stream,
        "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n{}\r\n{}",
        exchange.response_status,
        exchange.response_body.len(),
        exchange.extra_headers,
        exchange.response_body
    )
    .expect("write MCP loopback response");
    request
}

fn read_http_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    let header_end = loop {
        let bytes_read = stream.read(&mut buffer).expect("read MCP request");
        assert!(bytes_read > 0, "connector should send request bytes");
        request.extend_from_slice(&buffer[..bytes_read]);
        if let Some(header_end) = find_header_end(&request) {
            break header_end;
        }
        assert!(
            request.len() < 8192,
            "MCP request headers should stay bounded"
        );
    };

    let header_bytes = &request[..header_end + 4];
    let headers = String::from_utf8_lossy(header_bytes).to_string();
    let content_length = content_length_from_headers(&headers);
    let mut body = request[header_end + 4..].to_vec();
    while body.len() < content_length {
        let bytes_read = stream.read(&mut buffer).expect("read MCP request body");
        assert!(bytes_read > 0, "connector body should match content-length");
        body.extend_from_slice(&buffer[..bytes_read]);
        assert!(body.len() <= 8192, "MCP request body should stay bounded");
    }
    body.truncate(content_length);

    CapturedRequest {
        request_line: headers.lines().next().unwrap_or_default().to_string(),
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    }
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length_from_headers(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

fn header_value<'a>(headers: &'a str, expected_name: &str) -> &'a str {
    headers
        .lines()
        .skip(1)
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case(expected_name) {
                Some(value.trim())
            } else {
                None
            }
        })
        .unwrap_or_else(|| panic!("missing header {expected_name} in {headers}"))
}

fn assert_http_boundary(request: &CapturedRequest) {
    let mut parts = request.request_line.split_whitespace();
    assert_eq!(parts.next(), Some("POST"));
    assert_eq!(parts.next(), Some("/mcp"));
    assert_eq!(parts.next(), Some("HTTP/1.1"));
    assert_eq!(parts.next(), None);
    assert!(header_value(&request.headers, "content-type").contains("application/json"));
    assert_eq!(
        header_value(&request.headers, "authorization"),
        format!("Bearer {LOOPBACK_CREDENTIAL}")
    );
    assert_eq!(
        header_value(&request.headers, "mcp-protocol-version"),
        MCP_PROTOCOL_VERSION
    );
    let accept = header_value(&request.headers, "accept");
    assert!(accept.contains("application/json"));
    assert!(accept.contains("text/event-stream"));
    assert!(
        header_value(&request.headers, "user-agent")
            .contains("fcp-mcp-bridge/0.1.0 (FCP connector)")
    );
}

fn assert_rpc_request(request: &CapturedRequest, expected_method: &str) -> Value {
    assert_http_boundary(request);
    let body = serde_json::from_str::<Value>(&request.body).expect("parse JSON-RPC request body");
    assert_eq!(body["jsonrpc"], "2.0");
    assert!(
        body["id"].as_u64().is_some(),
        "JSON-RPC request id should be numeric"
    );
    assert_eq!(body["method"], expected_method);
    body
}

async fn configured_connector(base_url: &str) -> McpBridgeConnector {
    configured_connector_with(base_url, json!({})).await
}

async fn configured_connector_with(base_url: &str, extra: Value) -> McpBridgeConnector {
    let mut params = json!({
        "mcp_url": base_url,
        "api_key": LOOPBACK_CREDENTIAL,
    });
    let params_object = params
        .as_object_mut()
        .expect("connector params should be an object");
    for (key, value) in extra
        .as_object()
        .expect("extra connector params should be an object")
    {
        params_object.insert(key.clone(), value.clone());
    }

    let mut connector = McpBridgeConnector::new();
    connector
        .handle_configure(params)
        .await
        .expect("configure MCP Bridge connector");
    connector
        .handle_handshake(json!({"session_id": "mcp-bridge-local-acceptance"}))
        .await
        .expect("handshake MCP Bridge connector");
    connector
}

fn emit_acceptance_evidence(operation: &str, result: &str, detail: &Value) {
    println!(
        "{}",
        json!({
            "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
            "suite_class": ACCEPTANCE_SUITE_CLASS,
            "bead_id": BEAD_ID,
            "connector": CONNECTOR_ID,
            "operation": operation,
            "fixture_mode": "raw_loopback_http",
            "provider_class": "local_sufficient",
            "result": result,
            "detail": detail,
        })
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_tools_list_posts_streamable_http_boundary_and_scans_catalog() {
    let server = LoopbackServer::start(vec![Exchange::json(
        "200 OK",
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {
                        "name": "search_workspace",
                        "description": "Search project documents and return ranked snippets.",
                        "inputSchema": {"type": "object"}
                    },
                    {
                        "name": "evaluate_expression",
                        "description": "Evaluate a user formula with eval(user_input).",
                        "inputSchema": {"type": "object"}
                    }
                ]
            }
        }),
    )]);
    let connector = configured_connector(server.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "operation_id": "mcp.tools.list",
            "input": {}
        }))
        .await
        .expect("list MCP tools");
    let requests = server.join();
    let body = assert_rpc_request(&requests[2], "tools/list");

    assert_eq!(body["params"], json!({}));
    let tools = result["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0]["name"], "search_workspace");
    assert!(
        tools[0]["injection_findings"]
            .as_array()
            .expect("safe tool findings")
            .is_empty()
    );
    let suspicious_findings = tools[1]["injection_findings"]
        .as_array()
        .expect("suspicious tool findings");
    assert!(
        suspicious_findings
            .iter()
            .any(|finding| finding["pattern_id"] == "code_execution_reference")
    );

    let metrics = connector
        .handle_invoke(json!({"operation_id": "mcp.server.metrics", "input": {}}))
        .await
        .expect("read MCP bridge metrics");
    assert_eq!(metrics["requests"], 2);
    assert_eq!(metrics["injection_scans"], 2);
    assert!(metrics["injection_findings"].as_u64().unwrap_or(0) >= 1);

    emit_acceptance_evidence(
        "mcp.tools.list",
        "pass",
        &json!({
            "requests_observed": requests.len(),
            "catalog_entries": tools.len(),
            "scanner_findings": metrics["injection_findings"],
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_tools_call_posts_arguments_boundary() {
    let server = LoopbackServer::start(vec![Exchange::json(
        "200 OK",
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [
                    {"type": "text", "text": "release note result"}
                ],
                "isError": false
            }
        }),
    )]);
    let connector = configured_connector(server.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "operation_id": "mcp.tools.call",
            "input": {
                "name": "search_workspace",
                "arguments": {
                    "query": "release",
                    "limit": 3
                }
            }
        }))
        .await
        .expect("call MCP tool");
    let requests = server.join();
    let body = assert_rpc_request(&requests[2], "tools/call");

    assert_eq!(body["params"]["name"], "search_workspace");
    assert_eq!(body["params"]["arguments"]["query"], "release");
    assert_eq!(body["params"]["arguments"]["limit"], 3);
    assert_eq!(result["content"][0]["text"], "release note result");

    emit_acceptance_evidence(
        "mcp.tools.call",
        "pass",
        &json!({
            "requests_observed": requests.len(),
            "arguments_forwarded": body["params"]["arguments"].is_object(),
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_resources_read_and_prompts_list_use_json_rpc_boundary() {
    let server = LoopbackServer::start(vec![
        Exchange::json(
            "200 OK",
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "contents": [
                        {
                            "uri": "file:///workspace/README.md",
                            "mimeType": "text/markdown",
                            "text": "# Workspace"
                        }
                    ]
                }
            }),
        ),
        Exchange::json(
            "200 OK",
            &json!({
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "prompts": [
                        {
                            "name": "summarize_project",
                            "description": "Summarize project status with cited resources."
                        }
                    ]
                }
            }),
        ),
    ]);
    let connector = configured_connector(server.base_url()).await;

    let resource = connector
        .handle_invoke(json!({
            "operation_id": "mcp.resources.read",
            "input": {"uri": "file:///workspace/README.md"}
        }))
        .await
        .expect("read MCP resource");
    let prompts = connector
        .handle_invoke(json!({
            "operation_id": "mcp.prompts.list",
            "input": {}
        }))
        .await
        .expect("list MCP prompts");
    let requests = server.join();

    let resource_body = assert_rpc_request(&requests[2], "resources/read");
    assert_eq!(
        resource_body["params"]["uri"],
        "file:///workspace/README.md"
    );
    assert_eq!(resource["contents"][0]["text"], "# Workspace");

    let prompts_body = assert_rpc_request(&requests[3], "prompts/list");
    assert_eq!(prompts_body["params"], json!({}));
    assert_eq!(prompts["prompts"][0]["name"], "summarize_project");
    assert!(
        prompts["prompts"][0]["injection_findings"]
            .as_array()
            .expect("prompt findings")
            .is_empty()
    );

    emit_acceptance_evidence(
        "mcp.resources.read+mcp.prompts.list",
        "pass",
        &json!({
            "requests_observed": requests.len(),
            "resource_uri": resource_body["params"]["uri"],
            "prompt_entries": prompts["prompts"].as_array().map_or(0, Vec::len),
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_block_mode_rejects_suspicious_provider_descriptions() {
    let server = LoopbackServer::start(vec![Exchange::json(
        "200 OK",
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {
                        "name": "unsafe_runner",
                        "description": "Execute operator text with eval(user_input)."
                    }
                ]
            }
        }),
    )]);
    let connector = configured_connector_with(
        server.base_url(),
        json!({
            "security": {"description_scan": "block"}
        }),
    )
    .await;

    let error = connector
        .handle_invoke(json!({
            "operation_id": "mcp.tools.list",
            "input": {}
        }))
        .await
        .expect_err("suspicious MCP tool description should be blocked");
    let requests = server.join();
    assert_rpc_request(&requests[2], "tools/list");
    let error_text = format!("{error:?}");
    assert!(error_text.contains("blocked by description scanner"));

    emit_acceptance_evidence(
        "mcp.tools.list.security",
        "pass",
        &json!({
            "requests_observed": requests.len(),
            "blocked": true,
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_provider_unauthorized_redacts_auth_material_and_counts_retry() {
    let server = LoopbackServer::start(vec![
        Exchange::json(
            "401 Unauthorized",
            &json!({
                "error": format!("provider saw {LOOPBACK_CREDENTIAL}")
            }),
        ),
        Exchange::json(
            "401 Unauthorized",
            &json!({
                "error": format!("provider still saw {LOOPBACK_CREDENTIAL}")
            }),
        ),
    ]);
    let connector = configured_connector(server.base_url()).await;

    let error = connector
        .handle_invoke(json!({
            "operation_id": "mcp.tools.list",
            "input": {}
        }))
        .await
        .expect_err("provider auth failure should propagate as redacted FCP error");
    let requests = server.join();
    assert_eq!(requests.len(), 4);
    for request in &requests[2..] {
        assert_rpc_request(request, "tools/list");
        assert_eq!(
            header_value(&request.headers, "authorization"),
            format!("Bearer {LOOPBACK_CREDENTIAL}")
        );
    }

    let error_text = format!("{error:?}");
    assert!(error_text.contains("Authentication failed"));
    assert!(!error_text.contains(LOOPBACK_CREDENTIAL));
    assert!(!error_text.contains("provider saw"));

    let metrics = connector
        .handle_invoke(json!({"operation_id": "mcp.server.metrics", "input": {}}))
        .await
        .expect("read retry metrics");
    assert_eq!(metrics["requests"], 2);
    assert_eq!(metrics["errors"], 1);
    assert_eq!(metrics["auth_retries"], 1);

    emit_acceptance_evidence(
        "mcp.tools.list.auth_failure",
        "pass",
        &json!({
            "requests_observed": requests.len(),
            "auth_retries": metrics["auth_retries"],
            "secret_redacted": true,
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_sampling_handle_is_local_and_does_not_contact_provider() {
    let probe = NoEgressProbe::start();
    let connector = configured_connector_with(
        probe.base_url(),
        json!({
            "sampling": {
                "enabled": true,
                "llm_connector": "groq",
                "max_tokens_cap": 256,
                "allowed_models": ["llama-3.3"]
            }
        }),
    )
    .await;

    let result = connector
        .handle_invoke(json!({
            "operation_id": "mcp.sampling.handle",
            "input": {
                "request": {
                    "method": "sampling/createMessage",
                    "params": {
                        "messages": [
                            {
                                "role": "user",
                                "content": {"type": "text", "text": "summarize the local transcript"}
                            }
                        ],
                        "maxTokens": 128
                    }
                }
            }
        }))
        .await
        .expect("handle MCP sampling request locally");
    probe.assert_no_connection();

    assert_eq!(result["dispatch"], "agent_event");
    assert_eq!(result["host_orchestrated"], false);
    assert_eq!(result["requires_human_approval"], true);
    assert_eq!(result["llm_connector"], "groq");
    assert_eq!(result["redaction"]["prompt_logged"], false);

    let metrics = connector
        .handle_invoke(json!({"operation_id": "mcp.server.metrics", "input": {}}))
        .await
        .expect("read sampling metrics");
    assert_eq!(metrics["requests"], 2);
    assert_eq!(metrics["sampling_requests"], 1);

    emit_acceptance_evidence(
        "mcp.sampling.handle",
        "pass",
        &json!({
            "provider_egress": "none_observed",
            "sampling_requests": metrics["sampling_requests"],
            "requires_human_approval": result["requires_human_approval"],
        }),
    );
}
