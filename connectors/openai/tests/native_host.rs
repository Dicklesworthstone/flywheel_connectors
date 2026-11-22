//! Acceptance tests for the shipped OpenAI JSONL executable and real loopback HTTP.

#![allow(
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines
)]

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::{Duration as StdDuration, Instant},
};

use chrono::{Duration, Utc};
use fcp_core::{
    CapabilityConstraints, CapabilityToken, HealthSnapshot, InstanceId, Introspection,
    InvokeResponse, InvokeStatus, SimulateResponse,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use serde_json::{Value, json};

const MODEL: &str = "gpt-4o-mini";
const API_KEY: &str = "openai-loopback-key";

struct CapturedRequest {
    headers: String,
    body: Value,
}

struct LoopbackServer {
    url: String,
    requests: Receiver<CapturedRequest>,
    thread: Option<JoinHandle<()>>,
}

impl LoopbackServer {
    fn start(responses: Vec<Value>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (sender, requests) = mpsc::channel();
        let thread = thread::spawn(move || {
            for response in responses {
                let deadline = Instant::now() + StdDuration::from_secs(15);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "provider request timed out");
                            thread::sleep(StdDuration::from_millis(5));
                        }
                        Err(error) => panic!("provider accept failed: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(StdDuration::from_secs(5)))
                    .unwrap();
                sender.send(read_request(&mut stream)).unwrap();
                let body = serde_json::to_string(&response).unwrap();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                ).unwrap();
                stream.flush().unwrap();
            }
        });
        Self {
            url,
            requests,
            thread: Some(thread),
        }
    }

    fn assert_no_requests(&self) {
        assert!(matches!(
            self.requests.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }

    fn receive(&self) -> CapturedRequest {
        self.requests
            .recv_timeout(StdDuration::from_secs(5))
            .unwrap()
    }

    fn finish(mut self) {
        self.thread.take().unwrap().join().unwrap();
    }
}

impl Drop for LoopbackServer {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0, "provider request closed before its body");
        bytes.extend_from_slice(&buffer[..read]);
        assert!(bytes.len() <= 65_536, "test request exceeded its bound");
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            let headers = String::from_utf8(bytes[..end].to_vec()).unwrap();
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .expect("request content-length");
            if bytes.len() >= end + 4 + length {
                return CapturedRequest {
                    headers,
                    body: serde_json::from_slice(&bytes[end + 4..end + 4 + length]).unwrap(),
                };
            }
        }
    }
}

fn has_header(headers: &str, name: &str, value: &str) -> bool {
    headers.lines().any(|line| {
        line.split_once(':')
            .is_some_and(|(actual_name, actual_value)| {
                actual_name.eq_ignore_ascii_case(name) && actual_value.trim() == value
            })
    })
}

struct NativeProcess {
    child: Child,
    input: Option<ChildStdin>,
    output: Receiver<Result<Value, String>>,
    reader: Option<JoinHandle<()>>,
}

impl NativeProcess {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fcp-openai"))
            .env("RUST_LOG", "off")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("shipped OpenAI executable should start");
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, output) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let response = line.map_err(|error| error.to_string()).and_then(|line| {
                    serde_json::from_str(&line).map_err(|error| error.to_string())
                });
                if sender.send(response).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            input: Some(input),
            output,
            reader: Some(reader),
        }
    }

    fn send_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let input = self.input.as_mut().unwrap();
        input.write_all(bytes)?;
        input.flush()
    }

    fn receive(&self) -> Value {
        self.output
            .recv_timeout(StdDuration::from_secs(10))
            .expect("native response deadline")
            .expect("stdout must contain only JSONL responses")
    }

    fn rpc(&mut self, id: &str, method: &str, params: Value) -> Value {
        let mut bytes = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": id, "method": method, "params": params
        }))
        .unwrap();
        bytes.push(b'\n');
        self.send_bytes(&bytes).unwrap();
        let response = self.receive();
        assert_eq!(response["id"], id);
        response
    }

    fn wait_for_exit(&mut self) -> ExitStatus {
        // Keep stdin open: shutdown must terminate without depending on EOF.
        let deadline = Instant::now() + StdDuration::from_secs(5);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "native process did not exit");
            thread::sleep(StdDuration::from_millis(10));
        };
        self.input.take();
        self.reader.take().unwrap().join().unwrap();
        status
    }
}

impl Drop for NativeProcess {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn grant(
    key: &Ed25519SigningKey,
    instance: &InstanceId,
    operation: &str,
    token_id: &[u8],
    constraints: &CapabilityConstraints,
) -> CapabilityToken {
    let mut cbor = Vec::new();
    ciborium::into_writer(constraints, &mut cbor).unwrap();
    let now = Utc::now();
    let capability = match operation {
        "openai.simple_chat" | "openai.get_usage" => "openai.chat",
        _ => operation,
    };
    let signed = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .operations(&[operation])
        .zone_id("z:work")
        .principal("user:native-test")
        .issuer("node:native-test")
        .target_instance(instance.as_str())
        .token_id(token_id)
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .unwrap()
        .sign(key)
        .unwrap();
    CapabilityToken::from_raw(signed)
}

fn completion(id: &str, content: Value, calls: Value, finish_reason: &str) -> Value {
    json!({
        "id": id,
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": MODEL,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content, "tool_calls": calls},
            "finish_reason": finish_reason
        }],
        "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20}
    })
}

#[test]
fn native_chat_completes_tool_conversation_and_enforces_signed_budgets() {
    let tool_calls = json!([{
        "id": "call_weather",
        "type": "function",
        "function": {"name": "weather", "arguments": r#"{"city":"Paris"}"#}
    }]);
    let server = LoopbackServer::start(vec![
        completion(
            "chatcmpl-tools",
            Value::Null,
            tool_calls.clone(),
            "tool_calls",
        ),
        completion(
            "chatcmpl-final",
            json!("It is 18 C in Paris."),
            json!([]),
            "stop",
        ),
    ]);
    let mut process = NativeProcess::start();
    let initial: HealthSnapshot =
        serde_json::from_value(process.rpc("boot", "health", json!({}))["result"].clone()).unwrap();
    assert!(!initial.is_ready());
    assert_eq!(initial.details.unwrap()["configured"], false);
    let configured = process.rpc(
        "config",
        "configure",
        json!({"api_key": API_KEY, "base_url": server.url, "default_model": MODEL}),
    );
    assert_eq!(configured["result"]["status"], "configured");
    let awaiting: HealthSnapshot =
        serde_json::from_value(process.rpc("awaiting", "health", json!({}))["result"].clone())
            .unwrap();
    assert!(!awaiting.is_ready());

    let key = Ed25519SigningKey::generate();
    let handshake = process.rpc(
        "handshake",
        "handshake",
        json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "host_public_key": key.verifying_key().to_bytes(),
            "nonce": vec![3_u8; 32],
            "capabilities_requested": ["openai.chat", "openai.chat", "openai.unknown"]
        }),
    );
    assert_eq!(
        handshake["result"]["capabilities_granted"],
        json!([{"capability": "openai.chat"}])
    );
    assert_eq!(handshake["result"]["connector_id"], "fcp.openai");
    assert_eq!(handshake["result"]["event_caps"]["streaming"], false);
    let instance: InstanceId =
        serde_json::from_value(handshake["result"]["instance_id"].clone()).unwrap();
    let ready: HealthSnapshot =
        serde_json::from_value(process.rpc("ready", "health", json!({}))["result"].clone())
            .unwrap();
    assert!(ready.is_ready());
    assert_eq!(
        ready.details.unwrap()["instance_id"],
        handshake["result"]["instance_id"]
    );
    let catalog: Introspection =
        serde_json::from_value(process.rpc("catalog", "introspect", json!({}))["result"].clone())
            .unwrap();
    assert_eq!(catalog.operations.len(), 28);
    assert!(
        catalog
            .operations
            .iter()
            .all(|op| op.id.as_str().starts_with("openai."))
    );
    assert!(
        catalog
            .operations
            .iter()
            .any(|op| op.id.as_str() == "openai.realtime.voice")
    );
    assert!(
        catalog
            .operations
            .iter()
            .any(|op| op.id.as_str() == "openai.responses.create")
    );

    let token = grant(
        &key,
        &instance,
        "openai.chat",
        b"two-turns",
        &CapabilityConstraints {
            resource_allow: vec![format!("openai:model:{MODEL}")],
            max_calls: Some(2),
            max_bytes: Some(1_000_000),
            ..Default::default()
        },
    );
    let mut request = json!({
        "type": "simulate",
        "id": "preview-chat",
        "connector_id": "fcp.openai",
        "zone_id": "z:work",
        "operation": "openai.chat",
        "input": {
            "messages": [{"role": "user", "content": "Weather in Paris?"}],
            "tools": [{"type": "function", "function": {
                "name": "weather",
                "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}
            }}],
            "tool_choice": "auto",
            "max_tokens": 256
        },
        "capability_token": token
    });
    for _ in 0..3 {
        let preview: SimulateResponse = serde_json::from_value(
            process.rpc("preview", "simulate", request.clone())["result"].clone(),
        )
        .unwrap();
        assert!(preview.would_succeed);
    }
    server.assert_no_requests();
    request["type"] = json!("invoke");
    request["id"] = json!("chat-first");
    let mut malformed = request.clone();
    malformed.as_object_mut().unwrap().remove("connector_id");
    assert_eq!(
        process.rpc("malformed", "invoke", malformed)["error"]["code"],
        "FCP-1003"
    );
    for (field, value) in [("connector_id", "fcp.other"), ("zone_id", "z:private")] {
        let mut wrong = request.clone();
        wrong[field] = json!(value);
        assert_eq!(
            process.rpc("target", "invoke", wrong)["error"]["code"],
            "FCP-3001"
        );
    }
    let mut wrong_model = request.clone();
    wrong_model["input"]["model"] = json!("gpt-4o");
    assert_eq!(
        process.rpc("model", "invoke", wrong_model)["error"]["code"],
        "FCP-3004"
    );
    let mut zero_deadline = request.clone();
    zero_deadline["deadline_ms"] = json!(0);
    assert_eq!(
        process.rpc("deadline", "invoke", zero_deadline)["error"]["code"],
        "FCP-1003"
    );
    let mut invalid = request.clone();
    invalid["input"]["messages"] = json!([{"role": "user", "content": null}]);
    assert_eq!(
        process.rpc("input", "invoke", invalid)["error"]["code"],
        "FCP-1003"
    );
    let mut short_budget = request.clone();
    short_budget["capability_token"] = json!(grant(
        &key,
        &instance,
        "openai.chat",
        b"few-bytes",
        &CapabilityConstraints {
            resource_allow: vec!["*".into()],
            max_bytes: Some(1),
            ..Default::default()
        }
    ));
    assert_eq!(
        process.rpc("bytes", "invoke", short_budget)["error"]["code"],
        "FCP-3001"
    );
    server.assert_no_requests();

    let first: InvokeResponse = serde_json::from_value(
        process.rpc("outer-first", "invoke", request.clone())["result"].clone(),
    )
    .expect("native invocation must carry a typed host result");
    assert_eq!(first.r#type, "response");
    assert_eq!(first.id.0, "chat-first");
    assert_eq!(first.status, InvokeStatus::Ok);
    let result = first.result.unwrap();
    assert_eq!(result["content"], "");
    assert_eq!(result["tool_calls"], tool_calls);
    assert_eq!(result["finish_reason"], "tool_calls");
    let captured = server.receive();
    assert_eq!(
        captured.headers.lines().next(),
        Some("POST /v1/chat/completions HTTP/1.1")
    );
    assert!(has_header(
        &captured.headers,
        "authorization",
        &format!("Bearer {API_KEY}")
    ));
    assert_eq!(
        captured.body["model"], MODEL,
        "configured default must match model scope"
    );
    assert_eq!(captured.body["tool_choice"], "auto");

    request["id"] = json!("chat-second");
    request["input"] = json!({"messages": [
        {"role": "user", "content": "Weather in Paris?"},
        {"role": "assistant", "tool_calls": result["tool_calls"]},
        {"role": "tool", "content": "18 C", "tool_call_id": "call_weather"}
    ]});
    let second: InvokeResponse = serde_json::from_value(
        process.rpc("outer-second", "invoke", request.clone())["result"].clone(),
    )
    .unwrap();
    assert_eq!(second.id.0, "chat-second");
    assert_eq!(second.status, InvokeStatus::Ok);
    let result = second.result.unwrap();
    assert_eq!(result["content"], "It is 18 C in Paris.");
    assert_eq!(result["tool_calls"], json!([]));
    let follow_up = server.receive();
    assert!(follow_up.body["messages"][1]["content"].is_null());
    assert_eq!(follow_up.body["messages"][1]["tool_calls"], tool_calls);
    assert_eq!(
        follow_up.body["messages"][2]["tool_call_id"],
        "call_weather"
    );

    assert_eq!(
        process.rpc("spent", "invoke", request.clone())["error"]["code"],
        "FCP-3001"
    );
    request["type"] = json!("simulate");
    let spent: SimulateResponse =
        serde_json::from_value(process.rpc("spent-preview", "simulate", request)["result"].clone())
            .unwrap();
    assert!(!spent.would_succeed);
    assert_eq!(
        process.rpc("shutdown", "shutdown", json!({}))["result"]["status"],
        "shutdown"
    );
    assert!(process.wait_for_exit().success());
    assert!(process.output.try_recv().is_err());
    server.finish();
}

#[test]
fn native_responses_preserve_function_continuation_and_enforce_all_reference_scopes() {
    const RESPONSES_MODEL: &str = "model-from-provider-catalog";
    const INPUT_URL: &str = "HTTPS://EXAMPLE.INVALID/a?b=1";
    let first_payload = json!({
        "id": "resp-native-first",
        "object": "response",
        "created_at": 1_800_000_000,
        "status": "completed",
        "model": RESPONSES_MODEL,
        "output": [
            {
                "id": "reasoning-first",
                "type": "reasoning",
                "summary": [],
                "encrypted_content": "opaque-first"
            },
            {
                "id": "function-item-first",
                "type": "function_call",
                "call_id": "call-weather",
                "name": "weather",
                "arguments": "{ \"city\" : \"Paris\" }"
            }
        ],
        "usage": {
            "input_tokens": 31,
            "output_tokens": 7,
            "total_tokens": 38,
            "input_tokens_details": {"cached_tokens": 3},
            "output_tokens_details": {"reasoning_tokens": 2},
            "future_usage_field": "retained"
        },
        "error": null,
        "incomplete_details": null,
        "future_response_field": {"retained": ["provider", "metadata"]}
    });
    let second_payload = json!({
        "id": "resp-native-second",
        "object": "response",
        "created_at": 1_800_000_001,
        "status": "completed",
        "model": RESPONSES_MODEL,
        "output": [
            {
                "id": "message-final",
                "type": "message",
                "role": "assistant",
                "content": [
                    {"type": "output_text", "text": "It is ", "annotations": []},
                    {"type": "output_text", "text": "18 C in Paris.", "annotations": []}
                ]
            },
            {"type": "future_provider_item", "payload": {"preserved": true}}
        ],
        "usage": {
            "input_tokens": 19,
            "output_tokens": 5,
            "total_tokens": 24,
            "input_tokens_details": {"cached_tokens": 9},
            "output_tokens_details": {"reasoning_tokens": 1}
        },
        "error": null,
        "incomplete_details": null,
        "future_response_field": "retained again"
    });
    let server = LoopbackServer::start(vec![first_payload.clone(), second_payload.clone()]);
    let mut process = NativeProcess::start();
    assert_eq!(
        process.rpc(
            "responses-config",
            "configure",
            json!({"api_key": API_KEY, "base_url": server.url}),
        )["result"]["status"],
        "configured"
    );
    let key = Ed25519SigningKey::generate();
    let handshake = process.rpc(
        "responses-handshake",
        "handshake",
        json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "host_public_key": key.verifying_key().to_bytes(),
            "nonce": vec![7_u8; 32],
            "capabilities_requested": ["openai.responses.create", "openai.chat"]
        }),
    );
    let instance: InstanceId =
        serde_json::from_value(handshake["result"]["instance_id"].clone()).unwrap();
    assert!(
        handshake["result"]["capabilities_granted"]
            .as_array()
            .unwrap()
            .contains(&json!({"capability": "openai.responses.create"}))
    );
    let token = grant(
        &key,
        &instance,
        "openai.responses.create",
        b"responses-two-turns",
        &CapabilityConstraints {
            resource_allow: vec![
                format!("openai:model:{RESPONSES_MODEL}"),
                "openai:response:resp-native-first".into(),
                "openai:response_item:reasoning-context".into(),
                "openai:response_item:item-context".into(),
                "openai:file:file-weather".into(),
                "openai:file:file-tool-result".into(),
                // The literal query delimiter must not become a policy wildcard.
                "openai:input_url:https://example.invalid/a%3Fb=1".into(),
            ],
            max_calls: Some(2),
            max_bytes: Some(1_000_000),
            ..Default::default()
        },
    );
    let first_input = json!({
        "model": RESPONSES_MODEL,
        "input": [
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": "Weather in Paris? Read the reference."},
                    {"type": "input_file", "file_id": "file-weather"},
                    {"type": "input_image", "image_url": INPUT_URL},
                    {"type": "input_image", "image_url": "data:image/png;base64,AA=="}
                ]
            },
            {
                "id": "reasoning-context",
                "type": "reasoning",
                "summary": [],
                "encrypted_content": "opaque-request-context"
            },
            {"type": "item_reference", "id": "item-context"}
        ],
        "tools": [{
            "type": "function",
            "name": "weather",
            "description": "Read the weather for a city.",
            "parameters": {
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"],
                "additionalProperties": false
            },
            "strict": true
        }],
        "tool_choice": "auto",
        "max_output_tokens": 128,
        "store": true,
        "include": ["reasoning.encrypted_content"]
    });
    let mut request = json!({
        "type": "simulate",
        "id": "responses-preview",
        "connector_id": "fcp.openai",
        "zone_id": "z:work",
        "operation": "openai.responses.create",
        "input": first_input,
        "capability_token": token
    });
    for _ in 0..3 {
        let preview: SimulateResponse = serde_json::from_value(
            process.rpc("responses-preview", "simulate", request.clone())["result"].clone(),
        )
        .unwrap();
        assert!(preview.would_succeed);
    }
    server.assert_no_requests();
    request["type"] = json!("invoke");
    request["id"] = json!("responses-first");

    for (id, input) in [
        ("responses-wrong-model", {
            let mut input = first_input.clone();
            input["model"] = json!("another-provider-model");
            input
        }),
        ("responses-wrong-previous", {
            let mut input = first_input.clone();
            input["previous_response_id"] = json!("resp-not-granted");
            input
        }),
        ("responses-wrong-reasoning", {
            let mut input = first_input.clone();
            input["input"][1]["id"] = json!("reasoning-not-granted");
            input
        }),
        ("responses-wrong-item", {
            let mut input = first_input.clone();
            input["input"][2]["id"] = json!("item-not-granted");
            input
        }),
        ("responses-wrong-file", {
            let mut input = first_input.clone();
            input["input"][0]["content"][1]["file_id"] = json!("file-not-granted");
            input
        }),
        ("responses-query-is-not-path", {
            let mut input = first_input.clone();
            input["input"][0]["content"][2]["image_url"] = json!("https://example.invalid/axb=1");
            input
        }),
        ("responses-escaped-query-is-not-path", {
            let mut input = first_input.clone();
            input["input"][0]["content"][2]["image_url"] = json!("https://example.invalid/a%3Fb=1");
            input
        }),
    ] {
        let mut denied = request.clone();
        denied["id"] = json!(id);
        denied["input"] = input;
        assert_eq!(
            process.rpc(id, "invoke", denied.clone())["error"]["code"],
            "FCP-3004",
            "reference denial must precede provider work for {id}"
        );
        denied["type"] = json!("simulate");
        let preview: SimulateResponse =
            serde_json::from_value(process.rpc(id, "simulate", denied)["result"].clone()).unwrap();
        assert!(!preview.would_succeed, "preview must deny {id}");
    }
    let mut hosted_tool = request.clone();
    hosted_tool["input"]["tools"] = json!([{
        "type": "mcp",
        "server_label": "remote",
        "server_url": "https://example.invalid/mcp"
    }]);
    assert_eq!(
        process.rpc("responses-hosted-tool", "invoke", hosted_tool.clone())["error"]["code"],
        "FCP-1003"
    );
    hosted_tool["type"] = json!("simulate");
    let denied: SimulateResponse = serde_json::from_value(
        process.rpc("responses-hosted-preview", "simulate", hosted_tool)["result"].clone(),
    )
    .unwrap();
    assert!(!denied.would_succeed);
    server.assert_no_requests();

    let first: InvokeResponse = serde_json::from_value(
        process.rpc("responses-outer-first", "invoke", request.clone())["result"].clone(),
    )
    .unwrap();
    assert_eq!(first.id.0, "responses-first");
    assert_eq!(first.status, InvokeStatus::Ok);
    let first_result = first.result.unwrap();
    assert_eq!(first_result["response"], first_payload);
    assert_eq!(first_result["output_text"], "");
    assert!(first_result["cost_usd"].is_null());
    let captured = server.receive();
    assert_eq!(
        captured.headers.lines().next(),
        Some("POST /v1/responses HTTP/1.1")
    );
    assert!(has_header(
        &captured.headers,
        "authorization",
        &format!("Bearer {API_KEY}")
    ));
    assert_eq!(captured.body, first_input);
    assert_eq!(
        captured.body["input"][0]["content"][2]["image_url"], INPUT_URL,
        "resource canonicalization must preserve the caller's provider payload"
    );

    let second_input = json!({
        "model": RESPONSES_MODEL,
        "previous_response_id": first_result["response"]["id"],
        "input": [{
            "type": "function_call_output",
            "call_id": first_result["response"]["output"][1]["call_id"],
            "output": [
                {"type": "input_text", "text": "18 C"},
                {"type": "input_file", "file_id": "file-tool-result"},
                {"type": "input_image", "image_url": INPUT_URL}
            ]
        }],
        "max_output_tokens": 128
    });
    request["id"] = json!("responses-second");
    request["input"] = second_input.clone();
    for (id, input) in [
        ("responses-tool-output-file", {
            let mut input = second_input.clone();
            input["input"][0]["output"][1]["file_id"] = json!("file-not-granted");
            input
        }),
        ("responses-tool-output-url", {
            let mut input = second_input.clone();
            input["input"][0]["output"][2]["image_url"] = json!("https://example.invalid/axb=1");
            input
        }),
    ] {
        let mut denied = request.clone();
        denied["input"] = input;
        assert_eq!(
            process.rpc(id, "invoke", denied)["error"]["code"],
            "FCP-3004"
        );
    }
    server.assert_no_requests();
    let second: InvokeResponse = serde_json::from_value(
        process.rpc("responses-outer-second", "invoke", request.clone())["result"].clone(),
    )
    .unwrap();
    assert_eq!(second.id.0, "responses-second");
    assert_eq!(second.status, InvokeStatus::Ok);
    let second_result = second.result.unwrap();
    assert_eq!(second_result["response"], second_payload);
    assert_eq!(second_result["output_text"], "It is 18 C in Paris.");
    assert!(second_result["cost_usd"].is_null());
    let follow_up = server.receive();
    assert_eq!(
        follow_up.headers.lines().next(),
        Some("POST /v1/responses HTTP/1.1")
    );
    assert_eq!(follow_up.body, second_input);
    assert_eq!(follow_up.body["previous_response_id"], "resp-native-first");
    assert_eq!(follow_up.body["input"][0]["call_id"], "call-weather");

    assert_eq!(
        process.rpc("responses-spent", "invoke", request.clone())["error"]["code"],
        "FCP-3001"
    );
    request["type"] = json!("simulate");
    let spent: SimulateResponse = serde_json::from_value(
        process.rpc("responses-spent-preview", "simulate", request)["result"].clone(),
    )
    .unwrap();
    assert!(!spent.would_succeed);

    let usage_token = grant(
        &key,
        &instance,
        "openai.get_usage",
        b"responses-usage",
        &CapabilityConstraints {
            resource_allow: vec!["*".into()],
            max_calls: Some(1),
            ..Default::default()
        },
    );
    let usage: InvokeResponse = serde_json::from_value(
        process.rpc(
            "responses-usage",
            "invoke",
            json!({
                "type": "invoke",
                "id": "responses-usage",
                "connector_id": "fcp.openai",
                "zone_id": "z:work",
                "operation": "openai.get_usage",
                "input": {},
                "capability_token": usage_token
            }),
        )["result"]
            .clone(),
    )
    .unwrap();
    assert_eq!(usage.status, InvokeStatus::Ok);
    let usage = usage.result.unwrap();
    assert_eq!(usage["total_prompt_tokens"], 50);
    assert_eq!(usage["total_completion_tokens"], 12);
    assert_eq!(usage["unpriced_response_requests"], 2);
    assert!(server.requests.try_recv().is_err());
    assert_eq!(
        process.rpc("responses-shutdown", "shutdown", json!({}))["result"]["status"],
        "shutdown"
    );
    assert!(process.wait_for_exit().success());
    server.finish();
}

#[test]
fn native_framing_recovers_and_shutdown_stops_buffered_work() {
    let mut process = NativeProcess::start();
    process.send_bytes(b"{bad json\n").unwrap();
    assert_eq!(process.receive()["error"]["code"], "FCP-1001");
    process
        .send_bytes(b"{\"jsonrpc\":\"2.0\",\"id\":{},\"method\":\"health\",\"params\":{}}\n")
        .unwrap();
    assert_eq!(process.receive()["error"]["code"], "FCP-1001");
    process
        .send_bytes(b"{\"jsonrpc\":\"1.0\",\"id\":7,\"method\":\"health\",\"params\":{}}\n")
        .unwrap();
    assert_eq!(process.receive()["error"]["code"], "FCP-1001");
    let health: HealthSnapshot =
        serde_json::from_value(process.rpc("after-errors", "health", json!({}))["result"].clone())
            .unwrap();
    assert!(!health.is_ready());
    process.send_bytes(
        b"{\"jsonrpc\":\"2.0\",\"id\":\"quit\",\"method\":\"shutdown\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"id\":\"must-not-run\",\"method\":\"health\",\"params\":{}}\n"
    ).unwrap();
    assert_eq!(process.receive()["id"], "quit");
    assert!(process.wait_for_exit().success());
    assert!(process.output.try_recv().is_err());
}
