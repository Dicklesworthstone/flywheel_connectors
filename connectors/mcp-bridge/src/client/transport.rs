//! Bounded Streamable HTTP reply decoding for the MCP bridge.
//!
//! A POST may return one JSON response or an SSE stream containing notifications,
//! server requests, and finally the response to that POST. Stop at that response,
//! not at HTTP EOF: a server may keep the connection open after delivering it.

use std::future::Future;

use reqwest::Response;
use serde_json::{Value, json};

use crate::error::{McpBridgeError, McpBridgeResult};
use crate::types::JsonRpcError;

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_EVENT_BYTES: usize = 8 * 1024 * 1024;
const MAX_STREAM_MESSAGES: usize = 1024;

/// Deserialization contract failures are terminal, even for read-only methods.
/// Never include untrusted response bodies, request ids, or credentials here.
pub(super) fn invalid_response(message: &str) -> McpBridgeError {
    McpBridgeError::Json(<serde_json::Error as serde::de::Error>::custom(format!(
        "invalid MCP response: {message}"
    )))
}

pub(super) async fn read_bounded(mut response: Response, limit: usize) -> McpBridgeResult<Vec<u8>> {
    if response.content_length().is_some_and(|length| length > limit as u64) {
        return Err(invalid_response("HTTP body exceeds byte limit"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(invalid_response("HTTP body exceeds byte limit"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// `respond` sends a JSON-RPC response to a server-initiated request using a new
/// POST under the originating call's authority and deadline. Only ping is
/// implemented; unsupported capabilities get -32601, never local side effects.
pub(super) async fn read_rpc_response<F, Fut>(
    mut response: Response,
    expected_id: u64,
    mut respond: F,
) -> McpBridgeResult<Value>
where
    F: FnMut(Value) -> Fut,
    Fut: Future<Output = McpBridgeResult<()>>,
{
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .ok_or_else(|| invalid_response("missing Content-Type"))?;
    if content_type.eq_ignore_ascii_case("application/json") {
        let body = read_bounded(response, MAX_RESPONSE_BYTES).await?;
        return match classify_message(serde_json::from_slice(&body)?, expected_id)? {
            Message::Result(value) => Ok(value),
            Message::Error(error) => Err(error),
            _ => Err(invalid_response("JSON body is not the requested response")),
        };
    }
    if !content_type.eq_ignore_ascii_case("text/event-stream") {
        return Err(invalid_response("unsupported Content-Type"));
    }

    let mut decoder = SseDecoder::new(MAX_EVENT_BYTES);
    let mut received = 0_usize;
    let mut messages = 0_usize;
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(received) {
            return Err(invalid_response("SSE stream exceeds byte limit"));
        }
        received += chunk.len();
        for &byte in chunk.as_ref() {
            let Some(data) = decoder.push(byte)? else {
                continue;
            };
            messages += 1;
            if messages > MAX_STREAM_MESSAGES {
                return Err(invalid_response("too many messages before response"));
            }
            match classify_message(serde_json::from_slice(&data)?, expected_id)? {
                Message::Result(value) => return Ok(value),
                Message::Error(error) => return Err(error),
                Message::Notification => {}
                Message::Respond(reply) => respond(reply).await?,
            }
        }
    }
    // EOF is not an SSE event delimiter and is not a successful null result.
    Err(invalid_response("SSE ended before the requested response"))
}

#[derive(Debug)]
enum Message {
    Result(Value),
    Error(McpBridgeError),
    Notification,
    Respond(Value),
}

fn classify_message(mut value: Value, expected_id: u64) -> McpBridgeResult<Message> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| invalid_response("expected one JSON-RPC object"))?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(invalid_response("jsonrpc must be 2.0"));
    }
    if let Some(method) = object.get("method") {
        let method = method
            .as_str()
            .filter(|method| !method.is_empty())
            .ok_or_else(|| invalid_response("invalid server method"))?;
        if object.contains_key("result") || object.contains_key("error") {
            return Err(invalid_response("message mixes request and response fields"));
        }
        if object.get("params").is_some_and(|params| !params.is_object()) {
            return Err(invalid_response("server params must be an object"));
        }
        let Some(id) = object.get("id") else {
            return Ok(Message::Notification);
        };
        if !(id.is_string() || id.as_i64().is_some() || id.as_u64().is_some()) {
            return Err(invalid_response("invalid server request id"));
        }
        let reply = if method == "ping" {
            json!({"jsonrpc": "2.0", "id": id, "result": {}})
        } else {
            json!({
                "jsonrpc": "2.0", "id": id,
                "error": {"code": -32601, "message": "Client method not supported"}
            })
        };
        return Ok(Message::Respond(reply));
    }
    if object.get("id") != Some(&Value::from(expected_id)) {
        return Err(invalid_response("response id does not match request"));
    }
    if object.contains_key("result") == object.contains_key("error") {
        return Err(invalid_response("expected exactly one of result or error"));
    }
    if let Some(error) = object.remove("error") {
        let error: JsonRpcError = serde_json::from_value(error)?;
        return Ok(Message::Error(McpBridgeError::McpError {
            code: error.code,
            message: error.message,
        }));
    }
    Ok(Message::Result(
        object.remove("result").expect("result presence checked"),
    ))
}

/// Incremental UTF-8 SSE framing, including CRLF split across HTTP chunks,
/// bare CR, comments, multiline data, and the optional leading UTF-8 BOM.
/// Bounds are applied before extending a line or event, not after allocation.
struct SseDecoder {
    line: Vec<u8>,
    data: Vec<u8>,
    limit: usize,
    first_line: bool,
    skip_lf: bool,
    message_event: bool,
}

impl SseDecoder {
    fn new(limit: usize) -> Self {
        Self {
            line: Vec::new(),
            data: Vec::new(),
            limit,
            first_line: true,
            skip_lf: false,
            message_event: true,
        }
    }

    fn push(&mut self, byte: u8) -> McpBridgeResult<Option<Vec<u8>>> {
        if self.skip_lf {
            self.skip_lf = false;
            if byte == b'\n' {
                return Ok(None);
            }
        }
        if byte == b'\r' || byte == b'\n' {
            self.skip_lf = byte == b'\r';
            return self.finish_line();
        }
        if self.line.len() >= self.limit {
            return Err(invalid_response("SSE line exceeds byte limit"));
        }
        self.line.push(byte);
        Ok(None)
    }

    fn finish_line(&mut self) -> McpBridgeResult<Option<Vec<u8>>> {
        let line = std::mem::take(&mut self.line);
        let line = if self.first_line && line.starts_with(&[0xef, 0xbb, 0xbf]) {
            &line[3..]
        } else {
            line.as_slice()
        };
        self.first_line = false;
        let line = std::str::from_utf8(line)
            .map_err(|_| invalid_response("SSE contains invalid UTF-8"))?;
        if line.is_empty() {
            let emit = self.message_event && !self.data.is_empty();
            self.message_event = true;
            if emit {
                self.data.pop(); // SSE removes exactly one final data newline.
                return Ok(Some(std::mem::take(&mut self.data)));
            }
            self.data.clear();
            return Ok(None);
        }
        if line.starts_with(':') {
            return Ok(None);
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "data" => {
                if value.len() >= self.limit.saturating_sub(self.data.len()) {
                    return Err(invalid_response("SSE event exceeds byte limit"));
                }
                self.data.extend_from_slice(value.as_bytes());
                self.data.push(b'\n');
            }
            "event" => self.message_event = value.is_empty() || value == "message",
            // id/retry are not replay instructions for a POST. Reissuing a
            // tools/call after a disconnect could repeat an external effect.
            _ => {}
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(bytes: &[u8], limit: usize) -> McpBridgeResult<Vec<Vec<u8>>> {
        let mut decoder = SseDecoder::new(limit);
        let mut messages = Vec::new();
        for &byte in bytes {
            if let Some(message) = decoder.push(byte)? {
                messages.push(message);
            }
        }
        Ok(messages)
    }

    #[test]
    fn sse_multiline_unicode_comments_and_bom() {
        let bytes = "\u{feff}: heartbeat\r\nevent: message\r\ndata: {\r\ndata: \"name\":\"café\"}\r\n\r\n";
        assert_eq!(
            decode(bytes.as_bytes(), 128).unwrap(),
            vec!["{\n\"name\":\"café\"}".as_bytes().to_vec()]
        );
    }

    #[test]
    fn sse_cr_lf_and_crlf_delimiters_work_byte_by_byte() {
        for newline in ["\n", "\r", "\r\n"] {
            let input = format!("data: one{newline}{newline}data: two{newline}{newline}");
            assert_eq!(
                decode(input.as_bytes(), 64).unwrap(),
                vec![b"one".to_vec(), b"two".to_vec()]
            );
        }
    }

    #[test]
    fn sse_does_not_dispatch_unterminated_event_at_eof() {
        assert!(decode(b"data: {\"result\":1}\n", 64).unwrap().is_empty());
        assert!(decode(b"data: {\"result\":1}", 64).unwrap().is_empty());
    }

    #[test]
    fn sse_unknown_event_is_ignored_without_poisoning_next_event() {
        let input = b"event: extension\ndata: not json\n\ndata: {}\n\n";
        assert_eq!(decode(input, 64).unwrap(), vec![b"{}".to_vec()]);
    }

    #[test]
    fn sse_enforces_line_and_multiline_event_limits() {
        assert!(decode(b"data: 12345\n\n", 10).is_err());
        assert!(decode(b"data: 12345\ndata: 67890\n\n", 11).is_err());
        assert_eq!(decode(b"data: 1234\n\n", 10).unwrap(), vec![b"1234".to_vec()]);
    }

    #[test]
    fn sse_rejects_invalid_utf8_instead_of_replacing_bytes() {
        assert!(decode(b"data: \xff\n\n", 64).is_err());
    }

    #[test]
    fn response_requires_exact_version_id_and_one_outcome() {
        for value in [
            json!([]),
            json!({"id": 7, "result": {}}),
            json!({"jsonrpc": "1.0", "id": 7, "result": {}}),
            json!({"jsonrpc": "2.0", "id": "7", "result": {}}),
            json!({"jsonrpc": "2.0", "id": 8, "result": {}}),
            json!({"jsonrpc": "2.0", "result": {}}),
            json!({"jsonrpc": "2.0", "id": 7}),
            json!({"jsonrpc": "2.0", "id": 7, "result": null, "error": null}),
            json!({"jsonrpc": "2.0", "id": 7, "error": null}),
        ] {
            assert!(classify_message(value, 7).is_err());
        }
        assert!(matches!(
            classify_message(json!({"jsonrpc":"2.0","id":7,"result":null}), 7).unwrap(),
            Message::Result(Value::Null)
        ));
    }

    #[test]
    fn rpc_error_is_not_a_successful_null_result() {
        let result = classify_message(json!({
            "jsonrpc": "2.0", "id": 7,
            "error": {"code": -32601, "message": "not found"}
        }), 7).unwrap();
        assert!(matches!(result, Message::Error(McpBridgeError::McpError { code: -32601, .. })));
    }

    #[test]
    fn progress_is_a_notification_and_ping_is_answered() {
        assert!(matches!(
            classify_message(json!({"jsonrpc":"2.0","method":"notifications/progress","params":{}}), 7).unwrap(),
            Message::Notification
        ));
        let Message::Respond(reply) = classify_message(
            json!({"jsonrpc":"2.0","id":"server-ping","method":"ping"}), 7,
        ).unwrap() else { panic!("expected ping response") };
        assert_eq!(reply, json!({"jsonrpc":"2.0","id":"server-ping","result":{}}));
    }

    #[test]
    fn unsolicited_capabilities_are_refused_not_executed() {
        for method in ["sampling/createMessage", "roots/list", "elicitation/create", "tools/call"] {
            let Message::Respond(reply) = classify_message(
                json!({"jsonrpc":"2.0","id":0,"method":method,"params":{}}), 7,
            ).unwrap() else { panic!("expected method refusal") };
            assert_eq!(reply["error"]["code"], -32601);
            assert_eq!(reply["id"], 0);
        }
    }

    #[test]
    fn malformed_server_requests_are_rejected() {
        for value in [
            json!({"jsonrpc":"2.0","id":null,"method":"ping"}),
            json!({"jsonrpc":"2.0","id":true,"method":"ping"}),
            json!({"jsonrpc":"2.0","id":1.5,"method":"ping"}),
            json!({"jsonrpc":"2.0","id":1,"method":"ping","result":{}}),
            json!({"jsonrpc":"2.0","method":"notifications/progress","params":[]}),
        ] {
            assert!(classify_message(value, 7).is_err());
        }
    }

    #[test]
    fn transport_contract_errors_are_terminal() {
        let error = invalid_response("wrong request id");
        assert!(!error.is_retryable());
        assert!(!error.is_session_expired());
        assert!(!error.replay_is_safe());
    }

    #[fcp_async_core::runtime::test]
    async fn production_decoder_handles_sse_notifications_then_result() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST")).and(path("/mcp"))
            .respond_with(ResponseTemplate::new(200).set_body_string(concat!(
                ": heartbeat\n\n",
                "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n",
                "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n\n"
            )).insert_header("Content-Type", "text/event-stream; charset=utf-8"))
            .expect(1).mount(&server).await;
        let client = super::super::McpClient::new(super::super::McpAuth { api_key: None }, &server.uri()).unwrap();
        let request = crate::types::JsonRpcRequest {
            jsonrpc: "2.0", id: 1, method: "tools/list".into(), params: json!({}),
        };
        assert_eq!(client.rpc_call_once(&format!("{}/mcp", server.uri()), &request, None).await.unwrap(), json!({"tools":[]}));
    }

    #[fcp_async_core::runtime::test]
    async fn returns_matching_response_without_waiting_for_http_eof() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                headers.push(byte[0]);
                assert!(headers.len() < 8192);
            }
            let body = b"data: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"done\":true}}\n\n";
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n", body.len()).unwrap();
            socket.write_all(body).unwrap();
            socket.write_all(b"\r\n").unwrap();
            socket.flush().unwrap();
            // Intentionally never send the terminating HTTP chunk. The client
            // must finish on its JSON-RPC response, not on connection closure.
            done_rx.recv_timeout(Duration::from_secs(5)).is_ok()
        });
        let http = reqwest::Client::builder().timeout(Duration::from_secs(2)).build().unwrap();
        let response = http.post(format!("http://{address}/mcp")).send().await.unwrap();
        let result = read_rpc_response(response, 9, |_| async { Ok(()) }).await;
        let _ = done_tx.send(());
        assert!(worker.join().unwrap());
        assert_eq!(result.unwrap(), json!({"done":true}));
    }
}
