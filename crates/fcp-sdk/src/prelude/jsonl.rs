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
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll};

use fcp_async_core::channel::oneshot;
use serde_json::{Value, json};

use crate::{EventAck, EventEnvelope, FcpError, FcpResult, InvokeResponse, RequestId};

/// Maximum serialized native event notification, including its envelope.
pub const MAX_NATIVE_EVENT_BYTES: usize = 256 * 1024;

/// One serialized stdout owner shared by RPC responses and asynchronous events.
///
/// The lock covers the complete frame and its flush, so event bytes can never
/// interleave with a response. A failed write is terminal for the transport;
/// callers must not retry a possibly partially written frame.
#[derive(Clone)]
pub struct JsonlWriter {
    writer: Arc<Mutex<JsonlWriterState>>,
}

struct JsonlWriterState {
    output: Box<dyn Write + Send>,
    failed: bool,
}

impl JsonlWriter {
    /// Create a writer for one native connector session.
    pub fn new(writer: impl Write + Send + 'static) -> Self {
        Self {
            writer: Arc::new(Mutex::new(JsonlWriterState {
                output: Box::new(writer),
                failed: false,
            })),
        }
    }

    /// Serialize and flush one response without interleaving another frame.
    ///
    /// # Errors
    /// Returns an error if serialization, writing, or flushing fails.
    pub fn write_response(&self, response: &Value) -> io::Result<()> {
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| io::Error::other("JSONL writer poisoned"))?;
        if writer.failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "JSONL transport has failed",
            ));
        }
        let result = write_response(&mut writer.output, response);
        writer.failed = result.is_err();
        result
    }

    fn write_event(&self, stream_id: &str, event: &EventEnvelope) -> io::Result<()> {
        let notification = json!({
            "jsonrpc": "2.0",
            "method": "event",
            "params": {"stream_id": stream_id, "event": event}
        });
        let mut frame = BoundedEventFrame(Vec::new());
        serde_json::to_writer(&mut frame, &notification).map_err(io::Error::other)?;
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| io::Error::other("JSONL writer poisoned"))?;
        if writer.failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "JSONL transport has failed",
            ));
        }
        let result = (|| {
            writer.output.write_all(&frame.0)?;
            writer.output.write_all(b"\n")?;
            writer.output.flush()
        })();
        writer.failed = result.is_err();
        result
    }
}

struct BoundedEventFrame(Vec<u8>);

impl Write for BoundedEventFrame {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > (MAX_NATIVE_EVENT_BYTES - 1).saturating_sub(self.0.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native event exceeds frame limit",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NativeEventIdentity {
    topic: String,
    seq: u64,
    cursor: String,
}

struct PendingNativeEvent {
    identity: NativeEventIdentity,
    acknowledged: oneshot::Sender<()>,
}

struct NativeSubscription {
    stream_id: String,
    topic: String,
    pending: Option<PendingNativeEvent>,
    last_acknowledged: Option<NativeEventIdentity>,
}

/// A bounded, acknowledged native event stream with one event in flight.
///
/// The connector must authorize `open` and bind each event to the negotiated
/// zone. This transport never grants authority. A host acknowledgement must
/// mean the downstream consumer's acknowledgement was durably recorded, not
/// merely that the notification was read from stdout. Only the returned
/// delivery future permits the provider checkpoint to advance.
///
/// A window greater than one is accepted, but the producer conservatively
/// uses one credit. A full window returns an explicit retryable error; it
/// never drops the unacknowledged event or silently increases credit.
#[derive(Clone)]
pub struct JsonlEventStream {
    state: Arc<Mutex<Option<NativeSubscription>>>,
    writer: JsonlWriter,
}

impl JsonlEventStream {
    /// Create a closed stream sharing the session's stdout writer.
    #[must_use]
    pub fn new(writer: JsonlWriter) -> Self {
        Self {
            state: Arc::new(Mutex::new(None)),
            writer,
        }
    }

    /// Open one already-authorized exact topic.
    ///
    /// # Errors
    /// Rejects invalid identifiers, windows outside `1..=64`, and replacing a
    /// live stream. Repeating an identical open is idempotent.
    pub fn open(&self, stream_id: &str, topic: &str, window: u32) -> FcpResult<()> {
        if stream_id.is_empty()
            || stream_id.len() > 128
            || !stream_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || !crate::streaming::topic_name_is_valid(topic)
            || !(1..=64).contains(&window)
        {
            return Err(native_stream_invalid(
                "invalid stream identifier, topic, or window",
            ));
        }
        let mut state = self.lock_state()?;
        if let Some(active) = state.as_ref() {
            if active.stream_id == stream_id && active.topic == topic {
                return Ok(());
            }
            return Err(native_stream_unavailable(
                "a native event stream is already open",
            ));
        }
        *state = Some(NativeSubscription {
            stream_id: stream_id.into(),
            topic: topic.into(),
            pending: None,
            last_acknowledged: None,
        });
        Ok(())
    }

    /// Return whether the currently open stream selects an exact topic.
    #[must_use]
    pub fn accepts(&self, topic: &str) -> bool {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.as_ref().map(|active| active.topic == topic))
            .unwrap_or(false)
    }

    /// Return whether a stream remains open, without exposing its identifier.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.state.lock().is_ok_and(|state| state.is_some())
    }

    /// Emit one event and return its acknowledgement obligation.
    ///
    /// # Errors
    /// Fails before emission for a closed/full stream, wrong topic, invalid
    /// cursor, or missing acknowledgement flag. A write failure closes the
    /// stream, releasing every waiter as a failure rather than an ACK.
    pub fn deliver(&self, event: &EventEnvelope) -> FcpResult<JsonlEventDelivery> {
        if !event.requires_ack || event.cursor.is_empty() || event.cursor.len() > 512 {
            return Err(native_stream_invalid(
                "native event requires a bounded cursor and ACK",
            ));
        }
        let identity = NativeEventIdentity {
            topic: event.topic.clone(),
            seq: event.seq,
            cursor: event.cursor.clone(),
        };
        let (stream_id, acknowledged) = {
            let mut state = self.lock_state()?;
            let active = state
                .as_mut()
                .ok_or_else(|| native_stream_unavailable("native event stream is closed"))?;
            if active.topic != event.topic {
                return Err(native_stream_invalid("event topic is not subscribed"));
            }
            if active.pending.is_some() {
                return Err(native_stream_unavailable(
                    "native event credit is exhausted",
                ));
            }
            let (sender, receiver) = oneshot::channel();
            active.pending = Some(PendingNativeEvent {
                identity: identity.clone(),
                acknowledged: sender,
            });
            (active.stream_id.clone(), receiver)
        };
        let delivery = JsonlEventDelivery {
            stream: self.clone(),
            stream_id: stream_id.clone(),
            identity,
            acknowledged,
        };
        if self.writer.write_event(&stream_id, event).is_err() {
            self.close();
            return Err(native_stream_unavailable(
                "native event transport write failed",
            ));
        }
        Ok(delivery)
    }

    /// Apply one exact host ACK without waiting for an ordinary RPC handler.
    ///
    /// # Errors
    /// A different stream, topic, sequence, or cursor never frees credit.
    /// Repeating the immediately previous ACK is idempotent.
    pub fn acknowledge(&self, params: Value) -> FcpResult<()> {
        let stream_id = params
            .get("stream_id")
            .and_then(Value::as_str)
            .ok_or_else(|| native_stream_invalid("ACK requires stream_id"))?;
        let ack: EventAck = serde_json::from_value(
            params
                .get("ack")
                .cloned()
                .ok_or_else(|| native_stream_invalid("ACK payload is required"))?,
        )
        .map_err(|_| native_stream_invalid("invalid ACK payload"))?;
        if ack.r#type != "ack" || ack.seqs.len() != 1 || ack.cursors.len() != 1 {
            return Err(native_stream_invalid(
                "ACK must identify one sequence and cursor",
            ));
        }
        let identity = NativeEventIdentity {
            topic: ack.topic,
            seq: ack.seqs[0],
            cursor: ack.cursors[0].clone(),
        };
        let sender = {
            let mut state = self.lock_state()?;
            let active = state
                .as_mut()
                .filter(|active| active.stream_id == stream_id)
                .ok_or_else(|| native_stream_invalid("ACK stream is not active"))?;
            if active.pending.as_ref().map(|pending| &pending.identity) != Some(&identity)
                && active.last_acknowledged.as_ref() == Some(&identity)
            {
                return Ok(());
            }
            if active.pending.as_ref().map(|pending| &pending.identity) != Some(&identity) {
                return Err(native_stream_invalid(
                    "ACK does not match the pending event",
                ));
            }
            let pending = active.pending.take().expect("matching pending event");
            active.last_acknowledged = Some(identity);
            pending.acknowledged
        };
        sender
            .send(())
            .map_err(|_| native_stream_unavailable("event producer stopped before ACK"))
    }

    /// Close only the named stream; an old control frame cannot close a new one.
    ///
    /// # Errors
    /// Rejects a missing identifier or a different active stream.
    pub fn close_named(&self, params: &Value) -> FcpResult<()> {
        let stream_id = params
            .get("stream_id")
            .and_then(Value::as_str)
            .ok_or_else(|| native_stream_invalid("stream_close requires stream_id"))?;
        let mut state = self.lock_state()?;
        if let Some(active) = state.as_ref() {
            if active.stream_id != stream_id {
                return Err(native_stream_invalid(
                    "stream_close does not match active stream",
                ));
            }
            *state = None;
        }
        Ok(())
    }

    /// Close the session and fail outstanding acknowledgement obligations.
    pub fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            *state = None;
        }
    }

    fn lock_state(&self) -> FcpResult<std::sync::MutexGuard<'_, Option<NativeSubscription>>> {
        self.state
            .lock()
            .map_err(|_| native_stream_unavailable("native event state poisoned"))
    }
}

/// Completion proof for a single native event.
///
/// Dropping this future before its matching ACK closes the stream. A timeout
/// or cancellation therefore cannot leave a stale ACK able to advance a
/// subsequent provider cursor. The owner supplies a bounded deadline.
pub struct JsonlEventDelivery {
    stream: JsonlEventStream,
    stream_id: String,
    identity: NativeEventIdentity,
    acknowledged: oneshot::Receiver<()>,
}

impl std::future::Future for JsonlEventDelivery {
    type Output = FcpResult<()>;

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        std::pin::Pin::new(&mut self.acknowledged)
            .poll(cx)
            .map(|result| {
                result
                    .map_err(|_| native_stream_unavailable("native event stream closed before ACK"))
            })
    }
}

impl Drop for JsonlEventDelivery {
    fn drop(&mut self) {
        if let Ok(mut state) = self.stream.state.lock()
            && state.as_ref().is_some_and(|active| {
                active.stream_id == self.stream_id
                    && active.pending.as_ref().map(|pending| &pending.identity)
                        == Some(&self.identity)
            })
        {
            *state = None;
        }
    }
}

fn native_stream_invalid(message: &str) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}

fn native_stream_unavailable(message: &str) -> FcpError {
    FcpError::ConnectorUnavailable {
        code: 5001,
        message: message.into(),
    }
}

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

/// Serve native RPCs and acknowledgement controls on independent paths.
///
/// A bounded reader thread handles no-ID `ack` and `stream_close` controls
/// immediately, including while an invoke handler waits for an event's
/// downstream acknowledgement. Ordinary requests use one queued slot; excess
/// requests are rejected explicitly instead of blocking ACK input. Responses
/// and notifications share the same complete-frame stdout lock.
///
/// A successful shutdown is flushed before returning. The reader may remain
/// blocked on process stdin until the executable exits; it owns no connector
/// state, and EOF or a read failure closes outstanding event obligations.
///
/// # Errors
/// Returns framing, reader, writer, or dispatcher transport failures. Handler
/// errors are returned as ordinary FCP error responses and are never retried.
pub fn serve_jsonl_events<R, F>(
    reader: R,
    events: JsonlEventStream,
    config: JsonlConfig,
    mut dispatch: F,
) -> io::Result<()>
where
    R: BufRead + Send + 'static,
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
    let (requests, incoming) = mpsc::sync_channel::<Request>(1);
    let reader_events = events.clone();
    let reader_error = Arc::new(Mutex::new(None));
    let reader_error_slot = Arc::clone(&reader_error);
    std::thread::Builder::new()
        .name("fcp-jsonl-input".into())
        .spawn(move || {
            let result =
                read_native_requests(reader, &reader_events, &requests, config, read_limit);
            reader_events.close();
            if let Err(error) = result
                && let Ok(mut slot) = reader_error_slot.lock()
            {
                *slot = Some(error);
            }
        })?;

    let result = (|| {
        for request in incoming {
            let result = dispatch(&request.method, request.params);
            let should_exit = request.method == "shutdown" && result.is_ok();
            let mut response = match result {
                Ok(value) => json!({"jsonrpc": "2.0", "result": value}),
                Err(error) => json!({"jsonrpc": "2.0", "error": error.to_response()}),
            };
            if let Some(id) = request.id {
                response["id"] = id;
            }
            events.writer.write_response(&response)?;
            if should_exit {
                return Ok(());
            }
        }
        reader_error
            .lock()
            .map_err(|_| io::Error::other("JSONL reader error state poisoned"))?
            .take()
            .map_or(Ok(()), Err)
    })();
    events.close();
    result
}

fn read_native_requests(
    mut reader: impl BufRead,
    events: &JsonlEventStream,
    requests: &mpsc::SyncSender<Request>,
    config: JsonlConfig,
    read_limit: u64,
) -> io::Result<()> {
    let mut frame = Vec::new();
    loop {
        frame.clear();
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
            events.writer.write_response(&error_response(
                Some(Value::Null),
                1004,
                "JSONL request exceeds frame limit; stream closed".into(),
            ))?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "oversized JSONL request",
            ));
        }
        if frame.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let request = match parse_request(&frame) {
            Ok(request) => request,
            Err(response) => {
                events.writer.write_response(&response)?;
                continue;
            }
        };
        if matches!(request.method.as_str(), "ack" | "stream_close") {
            if request.id.is_some() {
                events.writer.write_response(&error_response(
                    request.id,
                    1003,
                    "native event controls must omit the RPC id".into(),
                ))?;
                continue;
            }
            let result = if request.method == "ack" {
                events.acknowledge(request.params)
            } else {
                events.close_named(&request.params)
            };
            if result.is_err() {
                // Never echo control payloads or turn a notification into an
                // unsolicited RPC response. Invalid controls grant no credit.
                tracing::warn!("Rejected native event control notification");
            }
            continue;
        }
        match requests.try_send(request) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(request)) => {
                let mut response = json!({
                    "jsonrpc": "2.0",
                    "error": native_stream_unavailable("native RPC queue is full").to_response()
                });
                if let Some(id) = request.id {
                    response["id"] = id;
                }
                events.writer.write_response(&response)?;
            }
            Err(mpsc::TrySendError::Disconnected(_)) => return Ok(()),
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

    #[derive(Clone, Default)]
    struct NativeCapture(Arc<Mutex<Vec<u8>>>);

    impl Write for NativeCapture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn native_test_event(seq: u64) -> EventEnvelope {
        let data = crate::EventData::new(
            crate::ConnectorId::from_static("fcp.test"),
            crate::InstanceId::new(),
            crate::ZoneId::work(),
            crate::Principal {
                kind: "fixture".into(),
                id: "user".into(),
                trust: crate::TrustLevel::Untrusted,
                display: None,
            },
            json!({"text": "native event"}),
        );
        EventEnvelope::new("test.events", data)
            .with_seq(seq)
            .with_cursor_seq(seq)
            .requiring_ack()
    }

    fn native_ack(stream_id: &str, seq: u64) -> Value {
        json!({
            "stream_id": stream_id,
            "ack": EventAck::new("test.events", vec![seq]).with_cursors(vec![seq.to_string()])
        })
    }

    fn pending_delivery(delivery: &mut JsonlEventDelivery) -> bool {
        use std::future::Future;
        let mut cx = Context::from_waker(std::task::Waker::noop());
        std::pin::Pin::new(delivery).poll(&mut cx).is_pending()
    }

    #[test]
    fn native_credit_is_released_only_by_exact_consumer_ack() {
        let capture = NativeCapture::default();
        let stream = JsonlEventStream::new(JsonlWriter::new(capture.clone()));
        stream.open("stream-1", "test.events", 64).unwrap();
        let mut delivery = stream.deliver(&native_test_event(7)).unwrap();
        assert!(pending_delivery(&mut delivery));
        assert!(stream.deliver(&native_test_event(8)).is_err());
        for params in [
            native_ack("other-stream", 7),
            native_ack("stream-1", 8),
            json!({"stream_id": "stream-1", "ack": {"type": "ack", "topic": "other.topic", "seqs": [7], "cursors": ["7"]}}),
            json!({"stream_id": "stream-1", "ack": {"type": "ack", "topic": "test.events", "seqs": [7], "cursors": ["other-cursor"]}}),
            json!({"stream_id": "stream-1", "ack": {"type": "ack", "topic": "test.events", "seqs": [7], "cursors": []}}),
        ] {
            assert!(stream.acknowledge(params).is_err());
            assert!(pending_delivery(&mut delivery));
        }
        stream.acknowledge(native_ack("stream-1", 7)).unwrap();
        run_ready(delivery).unwrap();
        stream.acknowledge(native_ack("stream-1", 7)).unwrap();
        let mut next = stream.deliver(&native_test_event(8)).unwrap();
        stream.acknowledge(native_ack("stream-1", 7)).unwrap();
        assert!(
            pending_delivery(&mut next),
            "duplicate ACK cannot add credit"
        );
        stream.acknowledge(native_ack("stream-1", 8)).unwrap();
        run_ready(next).unwrap();
        let frames = capture.0.lock().unwrap();
        let values: Vec<Value> = frames
            .split(|byte| *byte == b'\n')
            .filter(|frame| !frame.is_empty())
            .map(|frame| serde_json::from_slice(frame).unwrap())
            .collect();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0]["method"], "event");
        assert_eq!(values[0]["params"]["stream_id"], "stream-1");
        assert_eq!(values[0]["params"]["event"]["cursor"], "7");
        assert!(values[0].get("id").is_none());
    }

    #[test]
    fn native_retransmitted_event_accepts_matching_ack_without_adding_credit() {
        let stream = JsonlEventStream::new(JsonlWriter::new(io::sink()));
        stream.open("stream-1", "test.events", 1).unwrap();
        for _ in 0..2 {
            let delivery = stream.deliver(&native_test_event(7)).unwrap();
            stream.acknowledge(native_ack("stream-1", 7)).unwrap();
            run_ready(delivery).unwrap();
        }
        assert!(stream.is_open());
    }

    #[test]
    fn native_cancelled_delivery_closes_credit_and_rejects_late_ack() {
        let stream = JsonlEventStream::new(JsonlWriter::new(io::sink()));
        stream.open("stream-1", "test.events", 1).unwrap();
        let delivery = stream.deliver(&native_test_event(7)).unwrap();
        drop(delivery);
        assert!(!stream.is_open());
        assert!(stream.acknowledge(native_ack("stream-1", 7)).is_err());
        stream.open("stream-2", "test.events", 1).unwrap();
        let mut next = stream.deliver(&native_test_event(7)).unwrap();
        assert!(stream.acknowledge(native_ack("stream-1", 7)).is_err());
        assert!(
            stream
                .close_named(&json!({"stream_id": "stream-1"}))
                .is_err()
        );
        assert!(pending_delivery(&mut next));
        stream
            .close_named(&json!({"stream_id": "stream-2"}))
            .unwrap();
        assert!(run_ready(next).is_err());
    }

    #[test]
    fn native_open_and_event_validation_fail_before_output() {
        let capture = NativeCapture::default();
        let stream = JsonlEventStream::new(JsonlWriter::new(capture.clone()));
        for (id, topic, window) in [
            ("", "test.events", 1),
            ("a/b", "test.events", 1),
            ("stream-1", "*", 1),
            ("stream-1", "test.events", 0),
            ("stream-1", "test.events", 65),
        ] {
            assert!(stream.open(id, topic, window).is_err());
        }
        stream.open("stream-1", "test.events", 1).unwrap();
        assert!(stream.open("stream-2", "test.events", 1).is_err());
        for event in [
            EventEnvelope {
                topic: "other.events".into(),
                ..native_test_event(7)
            },
            EventEnvelope {
                requires_ack: false,
                ..native_test_event(7)
            },
            EventEnvelope {
                cursor: String::new(),
                ..native_test_event(7)
            },
            EventEnvelope {
                cursor: "x".repeat(513),
                ..native_test_event(7)
            },
        ] {
            assert!(stream.deliver(&event).is_err());
        }
        assert!(capture.0.lock().unwrap().is_empty());
    }

    #[test]
    fn native_oversized_event_never_writes_a_partial_frame() {
        let capture = NativeCapture::default();
        let stream = JsonlEventStream::new(JsonlWriter::new(capture.clone()));
        stream.open("stream-1", "test.events", 1).unwrap();
        let mut event = native_test_event(7);
        event.data.payload = json!({"large": "x".repeat(MAX_NATIVE_EVENT_BYTES)});
        assert!(stream.deliver(&event).is_err());
        assert!(capture.0.lock().unwrap().is_empty());
        assert!(!stream.is_open());
    }

    #[test]
    fn native_write_failure_never_completes_acknowledgement() {
        struct BrokenWriter;
        impl Write for BrokenWriter {
            fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "fixture"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let stream = JsonlEventStream::new(JsonlWriter::new(BrokenWriter));
        stream.open("stream-1", "test.events", 1).unwrap();
        assert!(stream.deliver(&native_test_event(7)).is_err());
        assert!(!stream.is_open());
        assert!(stream.acknowledge(native_ack("stream-1", 7)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn native_ack_input_progresses_while_invoke_waits_for_delivery() {
        use std::os::unix::net::UnixStream;
        use std::time::{Duration, Instant};

        let (mut input, reader) = UnixStream::pair().unwrap();
        let capture = NativeCapture::default();
        let stream = JsonlEventStream::new(JsonlWriter::new(capture.clone()));
        stream.open("stream-1", "test.events", 1).unwrap();
        let producer = stream.clone();
        let (emitted, emitted_rx) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            serve_jsonl_events(
                BufReader::new(reader),
                stream,
                JsonlConfig::default(),
                |method, _| {
                    if method == "invoke" {
                        let mut delivery = producer.deliver(&native_test_event(7))?;
                        emitted.send(()).unwrap();
                        let deadline = Instant::now() + Duration::from_secs(3);
                        loop {
                            use std::future::Future;
                            let mut cx = Context::from_waker(std::task::Waker::noop());
                            match std::pin::Pin::new(&mut delivery).poll(&mut cx) {
                                Poll::Ready(result) => {
                                    result?;
                                    break;
                                }
                                Poll::Pending => {
                                    assert!(
                                        Instant::now() < deadline,
                                        "ACK reader must not deadlock behind invoke"
                                    );
                                    std::thread::sleep(Duration::from_millis(1));
                                }
                            }
                        }
                        Ok(json!({"consumer_acknowledged": true}))
                    } else {
                        assert_eq!(method, "shutdown");
                        Ok(json!({"status": "shutdown"}))
                    }
                },
            )
        });
        writeln!(
            input,
            "{}",
            json!({"jsonrpc": "2.0", "id": 1, "method": "invoke"})
        )
        .unwrap();
        emitted_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        writeln!(
            input,
            "{}",
            json!({"jsonrpc": "2.0", "method": "ack", "params": native_ack("stream-1", 7)})
        )
        .unwrap();
        writeln!(
            input,
            "{}",
            json!({"jsonrpc": "2.0", "id": 2, "method": "shutdown"})
        )
        .unwrap();
        worker.join().unwrap().unwrap();
        let frames = capture.0.lock().unwrap();
        let responses: Vec<Value> = frames
            .split(|byte| *byte == b'\n')
            .filter(|frame| !frame.is_empty())
            .map(|frame| serde_json::from_slice(frame).unwrap())
            .collect();
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0]["method"], "event");
        assert_eq!(responses[1]["id"], 1);
        assert_eq!(responses[1]["result"]["consumer_acknowledged"], true);
        assert_eq!(responses[2]["id"], 2);
    }

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
