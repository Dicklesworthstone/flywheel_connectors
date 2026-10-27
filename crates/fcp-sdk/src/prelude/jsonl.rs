//! Bounded JSONL transport for standalone connector processes.
//!
//! The caller supplies the operation dispatcher and owns its async runtime.
//! This keeps the same configure, handshake, invoke, and shutdown handlers on
//! the production stdio path without duplicating framing in every connector.
//!
//! Requests are bounded before JSON parsing. Malformed frames receive an FCP
//! error and do not reach the dispatcher. Oversized frames terminate the stream
//! after an error response: their unread suffix must never become a request.
//! Responses are serialized directly to the writer, avoiding a second complete
//! allocation for large results. Successful shutdown is acknowledged and flushed
//! before returning, without waiting for stdin to close.
//!
//! For compatibility with existing FCP subprocess clients, `jsonrpc` and `id`
//! may be omitted. An omitted ID remains omitted in the response; an explicit
//! null ID is retained. This is the existing FCP request/reply convention, not
//! JSON-RPC notification semantics. Supplied versions must be `"2.0"`, and IDs
//! must be strings, numbers, or null. Operation handlers validate their params.

use std::io::{self, BufRead, Read, Write};

use serde_json::{Value, json};

use crate::{FcpError, FcpResult, InvokeResponse, RequestId};

/// Dispatch one raw operation handler and encode its canonical invoke response.
///
/// Use this explicitly for handlers returning an operation's output value.
/// Typed handlers already returning an [`InvokeResponse`] must not use it.
/// Provider output is always nested as result data, even when it contains keys
/// such as `type`, `id`, `status`, or `error`.
///
/// The inner invocation ID is required before dispatch and is independent of
/// the outer JSON-RPC correlation ID. Only that identifier is copied;
/// ownership of the original params, including large inputs, passes to the
/// handler. The adapter never retries a handler or interprets its output shape.
///
/// # Errors
///
/// Missing or non-string invocation IDs fail before the handler runs. Handler
/// errors propagate unchanged: a reported failure can still represent an
/// uncertain external side effect and must not become a successful RPC result.
pub async fn dispatch_raw_invoke<F, Fut>(params: Value, invoke: F) -> FcpResult<Value>
where
    F: FnOnce(Value) -> Fut,
    Fut: std::future::Future<Output = FcpResult<Value>>,
{
    let id = params
        .get("id")
        .and_then(Value::as_str)
        .map(RequestId::new)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: "invoke params.id must be a string".into(),
        })?;
    let output = invoke(params).await?;
    serde_json::to_value(InvokeResponse::ok(id, output)).map_err(|error| FcpError::Internal {
        message: format!("Failed to serialize invoke response: {error}"),
    })
}

/// Resource limits for the standalone JSONL request stream.
#[derive(Debug, Clone, Copy)]
pub struct JsonlConfig {
    /// Maximum request size in bytes, excluding its LF or CRLF terminator.
    ///
    /// This is an envelope limit, not a replacement for operation input limits.
    pub max_request_bytes: usize,
}

impl Default for JsonlConfig {
    fn default() -> Self {
        Self {
            max_request_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Serve FCP requests until EOF or a successfully acknowledged shutdown.
///
/// The dispatcher runs once per valid request. It can use its existing runtime
/// to block on an async connector handler. The transport never retries it:
/// neither a failed response write nor a handler error proves that an external
/// side effect did not happen.
///
/// # Errors
///
/// Returns an I/O error if reading, writing, or flushing fails, the configured
/// limit is invalid, or a request exceeds the limit. An oversized request gets
/// a best-effort `FCP-1004` response before the transport terminates. Malformed
/// JSON and invalid envelopes get `FCP-1001` responses and do not end the stream.
pub fn serve_jsonl<R, W, F>(
    mut reader: R,
    mut writer: W,
    config: JsonlConfig,
    mut dispatch: F,
) -> io::Result<()>
where
    R: BufRead,
    W: Write,
    F: FnMut(&str, Value) -> FcpResult<Value>,
{
    let read_limit = config
        .max_request_bytes
        .checked_add(2)
        .filter(|_| config.max_request_bytes > 0)
        .and_then(|limit| u64::try_from(limit).ok())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid JSONL request limit")
        })?;
    let mut frame = Vec::new();

    loop {
        frame.clear();
        // Take bounds the read itself, including a possible CRLF. Checking
        // the length after an ordinary read_line/read_until would be too late.
        let count = (&mut reader)
            .take(read_limit)
            .read_until(b'\n', &mut frame)?;
        if count == 0 {
            return Ok(());
        }
        if frame.last() == Some(&b'\n') {
            frame.pop();
            if frame.last() == Some(&b'\r') {
                frame.pop();
            }
        }
        if frame.len() > config.max_request_bytes {
            let message = format!(
                "JSONL request exceeds {} byte limit; stream closed",
                config.max_request_bytes
            );
            write_response(
                &mut writer,
                &error_response(Some(Value::Null), 1004, message.clone()),
            )?;
            return Err(io::Error::new(io::ErrorKind::InvalidData, message));
        }
        if frame.iter().all(u8::is_ascii_whitespace) {
            continue;
        }

        let request = match parse_request(&frame) {
            Ok(request) => request,
            Err(response) => {
                write_response(&mut writer, &response)?;
                continue;
            }
        };
        let result = dispatch(&request.method, request.params);
        let should_exit = request.method == "shutdown" && result.is_ok();
        let mut response = match result {
            Ok(value) => json!({"jsonrpc": "2.0", "result": value}),
            Err(error) => json!({"jsonrpc": "2.0", "error": error.to_response()}),
        };
        if let Some(id) = request.id {
            response["id"] = id;
        }
        write_response(&mut writer, &response)?;
        if should_exit {
            return Ok(());
        }
    }
}

/// A validated envelope; operation-specific params are intentionally opaque.
struct Request {
    method: String,
    params: Value,
    id: Option<Value>,
}

/// Parse an envelope without echoing invalid payloads or untrusted IDs in errors.
fn parse_request(frame: &[u8]) -> Result<Request, Value> {
    let value: Value = serde_json::from_slice(frame).map_err(|error| {
        error_response(Some(Value::Null), 1001, format!("Invalid JSON: {error}"))
    })?;
    let Value::Object(mut object) = value else {
        return Err(error_response(
            Some(Value::Null),
            1001,
            "FCP request must be an object".into(),
        ));
    };
    let id = object.remove("id");
    if id
        .as_ref()
        .is_some_and(|id| !matches!(id, Value::Null | Value::Number(_) | Value::String(_)))
    {
        return Err(error_response(
            Some(Value::Null),
            1001,
            "FCP request id must be a string, number, or null".into(),
        ));
    }
    if object
        .get("jsonrpc")
        .is_some_and(|version| version.as_str() != Some("2.0"))
    {
        return Err(error_response(id, 1001, "jsonrpc must be 2.0".into()));
    }
    let method = match object.remove("method") {
        Some(Value::String(method)) if !method.is_empty() => method,
        _ => {
            return Err(error_response(
                id,
                1001,
                "FCP request method must be a non-empty string".into(),
            ));
        }
    };
    Ok(Request {
        method,
        params: object.remove("params").unwrap_or_else(|| json!({})),
        id,
    })
}

/// Wrap a protocol error in the same envelope as connector handler errors.
fn error_response(id: Option<Value>, code: u16, message: String) -> Value {
    let error = FcpError::InvalidRequest { code, message };
    let mut response = json!({"jsonrpc": "2.0", "error": error.to_response()});
    if let Some(id) = id {
        response["id"] = id;
    }
    response
}

/// Write and flush a complete response before processing another request.
fn write_response(writer: &mut impl Write, response: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, response).map_err(io::Error::other)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};

    use super::*;

    fn run_ready<T>(future: impl std::future::Future<Output = T>) -> T {
        let mut future = std::pin::pin!(future);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(value) => value,
            std::task::Poll::Pending => panic!("ready test handler unexpectedly yielded"),
        }
    }

    fn responses(bytes: &[u8]) -> Vec<Value> {
        bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).expect("JSON response"))
            .collect()
    }

    #[test]
    fn raw_invoke_preserves_opaque_payloads_and_inner_string_identifiers() {
        let payloads = [
            Value::Null,
            json!(true),
            json!(42),
            json!("provider text"),
            json!([1, {"nested": true}]),
            json!({"ordinary": "operation output"}),
            json!({
                "type": "response",
                "id": "provider-identifier",
                "status": "error",
                "error": {"code": "provider-data"},
                "result": {"opaque": true},
            }),
        ];
        // RequestId deliberately prescribes no string format. Preserve it
        // exactly instead of adding transport-specific trimming or length rules.
        for id in ["operation-42", "", "  opaque/π identifier  "] {
            for payload in &payloads {
                let params = json!({
                    "id": id,
                    "operation": "test.raw",
                    "input": {"original": [1, 2, 3]},
                    "capability_token": "opaque-test-token",
                });
                let expected_params = params.clone();
                let mut calls = 0;
                let value = run_ready(dispatch_raw_invoke(params, |actual| {
                    calls += 1;
                    assert_eq!(actual, expected_params);
                    std::future::ready(Ok(payload.clone()))
                }))
                .unwrap();
                let response: InvokeResponse = serde_json::from_value(value).unwrap();
                assert_eq!(calls, 1);
                assert_eq!(response.r#type, "response");
                assert_eq!(response.id, RequestId::new(id));
                assert_eq!(response.status, crate::InvokeStatus::Ok);
                assert_eq!(response.result.as_ref(), Some(payload));
                assert!(response.error.is_none());
            }
        }
    }

    #[test]
    fn raw_invoke_rejects_missing_or_non_string_id_before_dispatch() {
        for params in [
            Value::Null,
            json!([]),
            json!({}),
            json!({"id": null}),
            json!({"id": 7}),
            json!({"id": true}),
            json!({"id": []}),
            json!({"id": {"private": "must-not-echo"}}),
        ] {
            let mut calls = 0;
            let error = run_ready(dispatch_raw_invoke(params, |_| {
                calls += 1;
                std::future::ready(Ok(Value::Null))
            }))
            .unwrap_err();
            assert_eq!(calls, 0);
            assert!(matches!(error, FcpError::InvalidRequest { code: 1003, .. }));
            assert!(!error.to_string().contains("must-not-echo"));
        }
    }

    #[test]
    fn raw_invoke_preserves_handler_errors_without_retry_or_envelope_conversion() {
        for error in [
            FcpError::ConnectorUnavailable {
                code: 5001,
                message: "event consumer is unavailable".into(),
            },
            FcpError::External {
                service: "test-mutation".into(),
                message: "provider outcome is unknown; reconcile before retry".into(),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
        ] {
            let expected = serde_json::to_value(&error).unwrap();
            let expected_retryable = error.is_retryable();
            let mut calls = 0;
            let actual = run_ready(dispatch_raw_invoke(json!({"id": "operation-7"}), |_| {
                calls += 1;
                std::future::ready(Err(error))
            }))
            .unwrap_err();
            assert_eq!(calls, 1);
            assert_eq!(serde_json::to_value(&actual).unwrap(), expected);
            assert_eq!(actual.is_retryable(), expected_retryable);
        }
    }

    #[test]
    fn jsonl_raw_invoke_keeps_outer_inner_and_provider_identifiers_separate() {
        let input = [
            json!({
                "jsonrpc": "2.0", "id": 91, "method": "invoke",
                "params": {"id": "operation-7", "operation": "test.raw", "input": null}
            }),
            json!({"jsonrpc": "2.0", "id": "health-rpc", "method": "health"}),
        ]
        .map(|request| request.to_string())
        .join("\n");
        let payload = json!({
            "id": "provider-id", "type": "response",
            "status": "error", "result": {"preserve": true},
        });
        let mut output = Vec::new();
        let mut invocation_calls = 0;
        serve_jsonl(
            Cursor::new(input.as_bytes()),
            &mut output,
            JsonlConfig::default(),
            |method, params| match method {
                "invoke" => run_ready(dispatch_raw_invoke(params, |_| {
                    invocation_calls += 1;
                    std::future::ready(Ok(payload.clone()))
                })),
                "health" => Ok(json!({"status": "healthy"})),
                _ => panic!("unexpected test method"),
            },
        )
        .unwrap();
        let replies = responses(&output);
        assert_eq!(invocation_calls, 1);
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[0]["id"], 91);
        let response: InvokeResponse =
            serde_json::from_value(replies[0]["result"].clone()).unwrap();
        assert_eq!(response.id, RequestId::new("operation-7"));
        assert_eq!(response.status, crate::InvokeStatus::Ok);
        assert_eq!(response.result, Some(payload));
        assert_eq!(
            replies[1],
            json!({
                "jsonrpc": "2.0", "id": "health-rpc",
                "result": {"status": "healthy"},
            })
        );
    }

    #[test]
    fn jsonl_raw_invoke_keeps_uncertain_handler_failure_as_an_rpc_error() {
        let input = concat!(
            "{\"method\":\"invoke\",\"id\":\"outer-1\",\"params\":{\"id\":\"inner-1\"}}\n",
            "{\"method\":\"health\",\"id\":\"outer-2\"}\n",
        );
        let failure = FcpError::External {
            service: "test-mutation".into(),
            message: "provider outcome is unknown; do not retry automatically".into(),
            status_code: None,
            retryable: false,
            retry_after: None,
        };
        let expected_error = serde_json::to_value(failure.to_response()).unwrap();
        let mut failure = Some(failure);
        let mut calls = 0;
        let mut output = Vec::new();
        serve_jsonl(
            Cursor::new(input.as_bytes()),
            &mut output,
            JsonlConfig::default(),
            |method, params| {
                if method == "health" {
                    return Ok(json!("healthy"));
                }
                run_ready(dispatch_raw_invoke(params, |_| {
                    calls += 1;
                    std::future::ready(Err(failure.take().expect("handler must run only once")))
                }))
            },
        )
        .unwrap();
        let replies = responses(&output);
        assert_eq!(calls, 1);
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[0]["id"], "outer-1");
        assert_eq!(replies[0]["error"], expected_error);
        assert!(replies[0].get("result").is_none());
        assert_eq!(replies[1]["result"], "healthy");
    }

    #[test]
    fn jsonl_raw_invoke_never_replays_after_failed_response_flush() {
        let first = "{\"method\":\"invoke\",\"id\":1,\"params\":{\"id\":\"operation-1\"}}\n";
        let input = format!(
            "{first}{{\"method\":\"invoke\",\"id\":2,\"params\":{{\"id\":\"operation-2\"}}}}\n"
        );
        let mut reader = Cursor::new(input.as_bytes());
        let mut writer = RecordingWriter {
            fail_flush: true,
            ..RecordingWriter::default()
        };
        let mut calls = 0;
        let error = serve_jsonl(
            &mut reader,
            &mut writer,
            JsonlConfig::default(),
            |_, params| {
                run_ready(dispatch_raw_invoke(params, |_| {
                    calls += 1;
                    std::future::ready(Ok(json!({"effect": "completed"})))
                }))
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(calls, 1);
        assert_eq!(reader.position(), first.len() as u64);
    }

    #[test]
    fn dispatches_params_once_and_preserves_ids() {
        for id in [json!(7), json!("request-7"), Value::Null] {
            let input = json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "invoke",
                "params": {"x": 3}
            });
            let bytes = serde_json::to_vec(&input).unwrap();
            let mut output = Vec::new();
            let mut calls = 0;
            serve_jsonl(
                Cursor::new(bytes),
                &mut output,
                JsonlConfig::default(),
                |method, params| {
                    calls += 1;
                    assert_eq!(method, "invoke");
                    assert_eq!(params, json!({"x": 3}));
                    Ok(json!({"ok": true}))
                },
            )
            .unwrap();
            assert_eq!(calls, 1);
            assert_eq!(
                responses(&output)[0],
                json!({"jsonrpc": "2.0", "id": id, "result": {"ok": true}})
            );
        }
    }

    #[test]
    fn legacy_envelope_keeps_missing_id_and_defaults_params() {
        let mut output = Vec::new();
        serve_jsonl(
            Cursor::new(br#"{"method":"health"}"#),
            &mut output,
            JsonlConfig::default(),
            |_, params| {
                assert_eq!(params, json!({}));
                Ok(json!("healthy"))
            },
        )
        .unwrap();
        assert!(responses(&output)[0].get("id").is_none());
    }

    #[test]
    fn skips_empty_and_whitespace_frames() {
        let mut output = Vec::new();
        let mut calls = 0;
        serve_jsonl(
            Cursor::new(b"\n \t\r\n\n"),
            &mut output,
            JsonlConfig::default(),
            |_, _| {
                calls += 1;
                Ok(Value::Null)
            },
        )
        .unwrap();
        assert_eq!(calls, 0);
        assert!(output.is_empty());
    }

    #[test]
    fn malformed_json_and_utf8_do_not_poison_next_frame() {
        let input = b"{not json\n\xff\n{\"method\":\"health\",\"id\":9}\n";
        let mut output = Vec::new();
        let mut calls = 0;
        serve_jsonl(
            Cursor::new(input),
            &mut output,
            JsonlConfig::default(),
            |_, _| {
                calls += 1;
                Ok(json!("healthy"))
            },
        )
        .unwrap();
        assert_eq!(calls, 1);
        let replies = responses(&output);
        assert_eq!(replies.len(), 3);
        for reply in &replies[..2] {
            assert_eq!(reply["jsonrpc"], "2.0");
            assert_eq!(reply["error"]["code"], "FCP-1001");
            assert!(reply["id"].is_null());
        }
        assert_eq!(replies[2]["id"], 9);
    }

    #[test]
    fn rejects_invalid_envelopes_before_dispatch() {
        for input in [
            json!(null),
            json!([]),
            json!(42),
            json!("shutdown"),
            json!({}),
            json!({"method": ""}),
            json!({"method": 7}),
            json!({"method": "shutdown", "id": []}),
            json!({"method": "shutdown", "id": {"secret": "not-echoed"}}),
            json!({"method": "shutdown", "id": true}),
            json!({"method": "shutdown", "jsonrpc": "1.0"}),
            json!({"method": "shutdown", "jsonrpc": null}),
        ] {
            let mut output = Vec::new();
            serve_jsonl(
                Cursor::new(serde_json::to_vec(&input).unwrap()),
                &mut output,
                JsonlConfig::default(),
                |_, _| panic!("invalid envelope was dispatched"),
            )
            .unwrap();
            let replies = responses(&output);
            assert_eq!(replies.len(), 1);
            assert_eq!(replies[0]["error"]["code"], "FCP-1001");
            assert!(!String::from_utf8(output).unwrap().contains("not-echoed"));
        }
    }

    #[test]
    fn exact_byte_limit_accepts_lf_crlf_and_eof() {
        let request = r#"{"method":"health","id":"é"}"#.as_bytes();
        for terminator in [b"".as_slice(), b"\n".as_slice(), b"\r\n".as_slice()] {
            let mut input = request.to_vec();
            input.extend_from_slice(terminator);
            let mut output = Vec::new();
            let mut calls = 0;
            serve_jsonl(
                Cursor::new(input),
                &mut output,
                JsonlConfig {
                    max_request_bytes: request.len(),
                },
                |_, _| {
                    calls += 1;
                    Ok(Value::Null)
                },
            )
            .unwrap();
            assert_eq!(calls, 1);
            assert_eq!(responses(&output)[0]["id"], "é");
        }
    }

    #[test]
    fn oversized_frame_fails_closed_without_dispatching_its_suffix() {
        let input = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n{\"method\":\"shutdown\"}\n";
        let mut output = Vec::new();
        let error = serve_jsonl(
            Cursor::new(input),
            &mut output,
            JsonlConfig {
                max_request_bytes: 8,
            },
            |_, _| panic!("oversized frame or its suffix was dispatched"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(responses(&output)[0]["error"]["code"], "FCP-1004");
        assert_eq!(responses(&output).len(), 1);
    }

    #[test]
    fn unterminated_infinite_frame_is_bounded() {
        let mut output = Vec::new();
        let reader = BufReader::with_capacity(8, io::repeat(b'x'));
        let error = serve_jsonl(
            reader,
            &mut output,
            JsonlConfig {
                max_request_bytes: 32,
            },
            |_, _| panic!("infinite frame was dispatched"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn zero_and_overflowing_limits_fail_before_reading() {
        for max_request_bytes in [0, usize::MAX] {
            let mut output = Vec::new();
            let error = serve_jsonl(
                Cursor::new(b""),
                &mut output,
                JsonlConfig { max_request_bytes },
                |_, _| panic!("invalid configuration dispatched a request"),
            )
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(output.is_empty());
        }
    }

    #[test]
    fn successful_shutdown_flushes_and_stops_before_next_request() {
        let shutdown = b"{\"method\":\"shutdown\",\"id\":7}\n";
        let mut input = shutdown.to_vec();
        input.extend_from_slice(b"{\"method\":\"invoke\",\"id\":8}\n");
        let mut reader = Cursor::new(input);
        let mut writer = RecordingWriter::default();
        serve_jsonl(
            &mut reader,
            &mut writer,
            JsonlConfig::default(),
            |method, _| {
                assert_eq!(method, "shutdown");
                Ok(json!({"status": "shutdown"}))
            },
        )
        .unwrap();
        assert_eq!(reader.position(), shutdown.len() as u64);
        assert_eq!(writer.flushes, 1);
        assert_eq!(responses(&writer.bytes)[0]["id"], 7);
    }

    #[test]
    fn failed_shutdown_and_handler_errors_keep_stream_running_without_retry() {
        let input = concat!(
            "{\"method\":\"shutdown\",\"id\":1}\n",
            "{\"method\":\"invoke\",\"id\":2}\n",
            "{\"method\":\"health\",\"id\":3}\n",
        );
        let mut output = Vec::new();
        let mut calls = 0;
        serve_jsonl(
            Cursor::new(input.as_bytes()),
            &mut output,
            JsonlConfig::default(),
            |method, _| {
                calls += 1;
                if method == "health" {
                    Ok(json!("healthy"))
                } else {
                    Err(FcpError::InvalidRequest {
                        code: 1002,
                        message: "rejected".into(),
                    })
                }
            },
        )
        .unwrap();
        assert_eq!(calls, 3);
        let replies = responses(&output);
        assert_eq!(replies.len(), 3);
        assert_eq!(replies[0]["error"]["code"], "FCP-1002");
        assert_eq!(replies[1]["id"], 2);
        assert_eq!(replies[2]["result"], "healthy");
    }

    #[test]
    fn failed_flush_does_not_retry_or_dispatch_next_operation() {
        let input = b"{\"method\":\"invoke\"}\n{\"method\":\"invoke\"}\n";
        let mut writer = RecordingWriter {
            fail_flush: true,
            ..RecordingWriter::default()
        };
        let mut calls = 0;
        let result = serve_jsonl(
            Cursor::new(input),
            &mut writer,
            JsonlConfig::default(),
            |_, _| {
                calls += 1;
                Ok(Value::Null)
            },
        );
        assert!(result.is_err());
        assert_eq!(calls, 1);
    }

    #[derive(Default)]
    struct RecordingWriter {
        bytes: Vec<u8>,
        flushes: usize,
        fail_flush: bool,
    }

    impl Write for RecordingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            if self.fail_flush {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed peer"))
            } else {
                Ok(())
            }
        }
    }
}
