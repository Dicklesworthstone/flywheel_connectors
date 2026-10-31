//! Bounded, concurrent stdio MCP transport with owned call cancellation.
//!
//! This module intentionally depends only on the standard library and serde:
//! the real protocol and concurrency behavior can be exercised independently
//! of connector runtimes.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, mpsc};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const PARSE_ERROR: i32 = -32_700;
pub const INVALID_REQUEST: i32 = -32_600;
pub const METHOD_NOT_FOUND: i32 = -32_601;
pub const INVALID_PARAMS: i32 = -32_602;
pub const INTERNAL_ERROR: i32 = -32_603;
pub const SERVER_BUSY: i32 = -32_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Value, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(error),
        }
    }

    pub const fn id(&self) -> &Value {
        &self.id
    }
    pub const fn result(&self) -> Option<&Value> {
        self.result.as_ref()
    }
    pub const fn is_error(&self) -> bool {
        self.error.is_some()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    pub fn parse_error(detail: impl Into<String>) -> Self {
        Self::new(PARSE_ERROR, detail)
    }
    pub fn invalid_request(detail: impl Into<String>) -> Self {
        Self::new(INVALID_REQUEST, detail)
    }
    pub fn method_not_found(method: &str) -> Self {
        Self::new(METHOD_NOT_FOUND, format!("Method not found: {method}"))
    }
    pub fn invalid_params(detail: impl Into<String>) -> Self {
        Self::new(INVALID_PARAMS, detail)
    }
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(INTERNAL_ERROR, detail)
    }
    pub const fn code(&self) -> i32 {
        self.code
    }
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

pub(super) fn parse_jsonrpc_request(raw: &str) -> Result<JsonRpcRequest, JsonRpcResponse> {
    let value = serde_json::from_str(raw).map_err(|error| {
        JsonRpcResponse::error(
            Value::Null,
            JsonRpcError::parse_error(format!("Failed to parse request: {error}")),
        )
    })?;
    parse_jsonrpc_value(value)
}

fn parse_jsonrpc_value(value: Value) -> Result<JsonRpcRequest, JsonRpcResponse> {
    let id = value
        .get("id")
        .filter(|id| id.is_null() || id.is_string() || id.is_number())
        .cloned()
        .unwrap_or(Value::Null);
    let Some(object) = value.as_object() else {
        return Err(JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_request("JSON-RPC request must be an object."),
        ));
    };
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_request("`jsonrpc` must be the string \"2.0\"."),
        ));
    }
    if object
        .get("id")
        .is_some_and(|id| !(id.is_null() || id.is_string() || id.is_number()))
    {
        return Err(JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_request("`id` must be null, a string, or a number."),
        ));
    }
    if object
        .get("method")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_request(
                "JSON-RPC request is missing a non-empty string `method`.",
            ),
        ));
    }
    if object
        .get("params")
        .is_some_and(|params| !params.is_object() && !params.is_array())
    {
        return Err(JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_request("`params` must be an object or array if present."),
        ));
    }
    serde_json::from_value(value).map_err(|error| {
        JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_request(format!("Invalid JSON-RPC request object: {error}")),
        )
    })
}

/// One accepted tool call's cancellation signal.
///
/// Clones always refer to the same call. Reusing an MCP request ID after a call
/// drains creates a new signal; a retained context cannot cancel the new call.
#[derive(Clone, Default)]
pub struct McpCallContext {
    state: Arc<CancellationState>,
}

#[derive(Default)]
struct CancellationState {
    cancelled: Mutex<bool>,
    changed: Condvar,
}

impl McpCallContext {
    pub fn is_cancelled(&self) -> bool {
        *lock(&self.state.cancelled)
    }

    /// Wait for cancellation or the supplied timeout without polling.
    pub fn wait_for_cancellation(&self, timeout: Duration) -> bool {
        let cancelled = lock(&self.state.cancelled);
        let (cancelled, _) = self
            .state
            .changed
            .wait_timeout_while(cancelled, timeout, |cancelled| !*cancelled)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *cancelled
    }

    pub(crate) fn cancel(&self) {
        *lock(&self.state.cancelled) = true;
        self.state.changed.notify_all();
    }

    fn same_call(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }
}

/// Bounds include queued and executing calls. Frame limits exclude LF/CRLF.
#[derive(Clone, Copy, Debug)]
pub struct TransportLimits {
    pub max_in_flight: usize,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_id_bytes: usize,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            max_in_flight: 8,
            // 16 MiB binary uploads need about 22.4 MiB of base64 plus metadata.
            max_request_bytes: 32 * 1024 * 1024,
            max_response_bytes: 32 * 1024 * 1024,
            max_id_bytes: 256,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum RequestKey {
    String(String),
    Number(String),
}

impl RequestKey {
    fn parse(id: &Value, max_bytes: usize) -> Option<Self> {
        match id {
            Value::String(value) if value.len() <= max_bytes => Some(Self::String(value.clone())),
            Value::Number(value) => {
                let text = value.to_string();
                (text.len() <= max_bytes).then_some(Self::Number(text))
            }
            _ => None,
        }
    }
}

struct AcceptedCall<J> {
    key: RequestKey,
    id: Value,
    context: McpCallContext,
    job: J,
}

struct Output<W> {
    writer: W,
    failure: Option<io::Error>,
}

struct Shared<W> {
    active: Mutex<BTreeMap<RequestKey, McpCallContext>>,
    output: Mutex<Output<W>>,
    output_failed: AtomicBool,
    limits: TransportLimits,
}

impl<W: Write> Shared<W> {
    fn cancel_all(&self) {
        for context in lock(&self.active).values() {
            context.cancel();
        }
    }

    fn failed(&self) -> bool {
        self.output_failed.load(Ordering::Acquire)
    }

    fn fail(&self, error: io::Error) {
        self.output_failed.store(true, Ordering::Release);
        self.cancel_all();
        let mut output = lock(&self.output);
        if output.failure.is_none() {
            output.failure = Some(error);
        }
    }

    fn cancel(&self, key: &RequestKey) {
        if let Some(context) = lock(&self.active).get(key) {
            context.cancel();
        }
    }

    fn complete(&self, key: &RequestKey, context: &McpCallContext) -> bool {
        let mut active = lock(&self.active);
        if !active
            .get(key)
            .is_some_and(|registered| registered.same_call(context))
        {
            return false;
        }
        active.remove(key);
        !context.is_cancelled()
    }

    fn emit(&self, mut response: JsonRpcResponse, call: Option<(&RequestKey, &McpCallContext)>) {
        response.jsonrpc = "2.0".into();
        let bytes = match bounded_response(&response, self.limits.max_response_bytes) {
            Ok(bytes) => bytes,
            Err(_) => {
                // Effects may already have occurred. Never imply this is a safe
                // automatic retry, and never release a truncated success.
                let error = JsonRpcResponse::error(
                    response.id.clone(),
                    JsonRpcError::internal("Response exceeds the MCP transport byte limit.")
                        .with_data(json!({
                            "kind": "response_too_large", "outcome": "unknown",
                            "retryable": false, "limit_bytes": self.limits.max_response_bytes,
                        })),
                );
                match bounded_response(&error, self.limits.max_response_bytes) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        if let Some((key, context)) = call {
                            self.complete(key, context);
                        }
                        self.fail(error);
                        return;
                    }
                }
            }
        };
        // Serialize a complete frame under one lock. Claim completion while
        // holding this lock so a cancellation that wins the registry race
        // suppresses the response; cancellation after that commit is ignored.
        let mut output = lock(&self.output);
        if let Some((key, context)) = call
            && !self.complete(key, context)
        {
            return;
        }
        if self.failed() {
            return;
        }
        let result = output
            .writer
            .write_all(&bytes)
            .and_then(|()| output.writer.write_all(b"\n"))
            .and_then(|()| output.writer.flush());
        if let Err(error) = result {
            output.failure = Some(error);
            self.output_failed.store(true, Ordering::Release);
            drop(output);
            self.cancel_all();
        }
    }
}

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct BoundedBuffer {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let required = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|required| *required <= self.limit)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "response byte limit exceeded")
            })?;
        if required > self.bytes.capacity() {
            let capacity = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .min(self.limit)
                .max(required);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(io::Error::other)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_response(response: &JsonRpcResponse, limit: usize) -> io::Result<Vec<u8>> {
    let mut output = BoundedBuffer {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut output, response).map_err(io::Error::other)?;
    Ok(output.bytes)
}

/// Serve MCP requests using a fixed scoped worker pool.
///
/// The reader remains responsive to metadata and cancellation while tools run.
/// No call is detached: EOF, input errors, and output errors cancel active work;
/// all queued/executing callbacks drain before this function returns. Callbacks
/// must observe their context and bound their external I/O. Portable blocking
/// stdin itself cannot be interrupted, so a write failure observed by a worker
/// is returned once the reader next unblocks.
/// Worker output backpressure does not block intake of cancellation or EOF.
/// The reader can still block while writing its own metadata or error response;
/// peers must consume stdout, and shutdown joins outstanding output writes.
///
/// Preparation and metadata routing run on the reader. They must not execute
/// provider work. Only accepted tools reach the concurrent executor.
pub(super) fn run_blocking<R, W, J, Route, Prepare, Execute>(
    mut reader: R,
    writer: W,
    limits: TransportLimits,
    route: Route,
    prepare: Prepare,
    execute: Execute,
) -> io::Result<()>
where
    R: BufRead,
    W: Write + Send,
    J: Send,
    Route: Fn(&JsonRpcRequest) -> JsonRpcResponse,
    Prepare: Fn(&JsonRpcRequest) -> Result<J, JsonRpcResponse>,
    Execute: Fn(J, McpCallContext) -> JsonRpcResponse + Sync,
{
    if limits.max_in_flight == 0
        || limits.max_in_flight > 64
        || limits.max_request_bytes == 0
        || limits.max_response_bytes == 0
        || limits.max_id_bytes == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid MCP transport limits",
        ));
    }
    let read_limit = limits
        .max_request_bytes
        .checked_add(2)
        .and_then(|limit| u64::try_from(limit).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid MCP request limit"))?;
    let shared = Shared {
        active: Mutex::new(BTreeMap::new()),
        output: Mutex::new(Output {
            writer,
            failure: None,
        }),
        output_failed: AtomicBool::new(false),
        limits,
    };
    let (sender, receiver) = mpsc::sync_channel::<AcceptedCall<J>>(limits.max_in_flight);
    let receiver = Mutex::new(receiver);
    let read_result = thread::scope(|scope| {
        for _ in 0..limits.max_in_flight {
            let shared = &shared;
            let receiver = &receiver;
            let execute = &execute;
            scope.spawn(move || {
                loop {
                    let received = lock(receiver).recv();
                    let call = match received {
                        Ok(call) => call,
                        Err(_) => break,
                    };
                    if call.context.is_cancelled() || shared.failed() {
                        call.context.cancel();
                        shared.complete(&call.key, &call.context);
                        continue;
                    }
                    let mut response = match catch_unwind(AssertUnwindSafe(|| {
                        execute(call.job, call.context.clone())
                    })) {
                        Ok(response) => response,
                        Err(_) => JsonRpcResponse::error(
                            call.id.clone(),
                            JsonRpcError::internal("Tool handler panicked; outcome is unknown.")
                                .with_data(json!({"outcome":"unknown", "retryable":false})),
                        ),
                    };
                    response.id = call.id;
                    shared.emit(response, Some((&call.key, &call.context)));
                }
            });
        }
        let result = read_requests(&mut reader, read_limit, &sender, &shared, &route, &prepare);
        shared.cancel_all();
        drop(sender);
        result
    });
    let output_failure = lock(&shared.output).failure.take();
    if let Some(error) = output_failure {
        return Err(error);
    }
    read_result
}

fn read_requests<R, W, J, Route, Prepare>(
    reader: &mut R,
    read_limit: u64,
    sender: &mpsc::SyncSender<AcceptedCall<J>>,
    shared: &Shared<W>,
    route: &Route,
    prepare: &Prepare,
) -> io::Result<()>
where
    R: BufRead,
    W: Write,
    Route: Fn(&JsonRpcRequest) -> JsonRpcResponse,
    Prepare: Fn(&JsonRpcRequest) -> Result<J, JsonRpcResponse>,
{
    let mut frame = Vec::new();
    loop {
        if shared.failed() {
            return Ok(());
        }
        frame.clear();
        let count = (&mut *reader)
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
        if frame.len() > shared.limits.max_request_bytes {
            shared.emit(JsonRpcResponse::error(Value::Null,
                JsonRpcError::invalid_request("MCP request exceeds the transport byte limit; stream closed.")
                    .with_data(json!({"kind":"request_too_large","limit_bytes":shared.limits.max_request_bytes}))), None);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MCP request byte limit exceeded",
            ));
        }
        if frame.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let value: Value = match serde_json::from_slice(&frame) {
            Ok(value) => value,
            Err(error) => {
                shared.emit(
                    JsonRpcResponse::error(
                        Value::Null,
                        JsonRpcError::parse_error(format!("Failed to parse request: {error}")),
                    ),
                    None,
                );
                continue;
            }
        };
        // Malformed cancellation notifications are ignored without a response.
        // Only idless notifications can request cancellation.
        if value.get("method").and_then(Value::as_str) == Some("notifications/cancelled")
            && value.get("id").is_none()
        {
            let params = value.get("params").and_then(Value::as_object);
            if value.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
                && params.is_some_and(|params| params.get("reason").is_none_or(Value::is_string))
                && let Some(key) = value
                    .get("params")
                    .and_then(|params| params.get("requestId"))
                    .and_then(|id| RequestKey::parse(id, shared.limits.max_id_bytes))
            {
                shared.cancel(&key);
            }
            continue;
        }
        // MCP request IDs are strings or numbers, unlike generic JSON-RPC's
        // discouraged null ID. Bound before echoing any attacker-chosen ID.
        if let Some(id) = value.get("id")
            && RequestKey::parse(id, shared.limits.max_id_bytes).is_none()
        {
            shared.emit(
                JsonRpcResponse::error(
                    Value::Null,
                    JsonRpcError::invalid_request("MCP id must be a bounded string or number."),
                ),
                None,
            );
            continue;
        }
        let request = match parse_jsonrpc_value(value) {
            Ok(request) => request,
            Err(response) => {
                shared.emit(response, None);
                continue;
            }
        };
        let Some(id) = request.id.clone() else {
            continue;
        };
        let key = RequestKey::parse(&id, shared.limits.max_id_bytes)
            .expect("request ID was validated before parsing");
        let duplicate = lock(&shared.active).contains_key(&key);
        if duplicate {
            shared.emit(
                JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_request("Request ID is already active.")
                        .with_data(json!({"kind":"duplicate_request_id","admitted":false})),
                ),
                None,
            );
            continue;
        }
        if request.method != "tools/call" {
            shared.emit(route(&request), None);
            continue;
        }
        let job = match prepare(&request) {
            Ok(job) => job,
            Err(response) => {
                shared.emit(response, None);
                continue;
            }
        };
        let context = McpCallContext::default();
        {
            let mut active = lock(&shared.active);
            if active.len() >= shared.limits.max_in_flight {
                drop(active);
                shared.emit(
                    JsonRpcResponse::error(
                        id,
                        JsonRpcError::new(SERVER_BUSY, "MCP tool capacity is full.").with_data(
                            json!({"kind":"server_busy","admitted":false,"retryable":true}),
                        ),
                    ),
                    None,
                );
                continue;
            }
            active.insert(key.clone(), context.clone());
        }
        let call = AcceptedCall {
            key: key.clone(),
            id: id.clone(),
            context: context.clone(),
            job,
        };
        if sender.try_send(call).is_err() {
            shared.complete(&key, &context);
            shared.emit(
                JsonRpcResponse::error(
                    id,
                    JsonRpcError::internal("MCP tool executor is unavailable.")
                        .with_data(json!({"admitted":false})),
                ),
                None,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    struct ChannelReader {
        input: mpsc::Receiver<io::Result<Vec<u8>>>,
        current: Vec<u8>,
        offset: usize,
    }

    impl Read for ChannelReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let available = self.fill_buf()?;
            let count = available.len().min(output.len());
            output[..count].copy_from_slice(&available[..count]);
            self.consume(count);
            Ok(count)
        }
    }

    impl BufRead for ChannelReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            while self.offset == self.current.len() {
                self.current = match self.input.recv() {
                    Ok(chunk) => chunk?,
                    Err(_) => return Ok(&[]),
                };
                self.offset = 0;
            }
            Ok(&self.current[self.offset..])
        }

        fn consume(&mut self, amount: usize) {
            self.offset += amount;
        }
    }

    struct FrameWriter {
        output: mpsc::Sender<Vec<u8>>,
        current: Vec<u8>,
    }

    impl Write for FrameWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            for &byte in bytes {
                if byte == b'\n' {
                    self.output
                        .send(std::mem::take(&mut self.current))
                        .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
                } else {
                    self.current.push(byte);
                }
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct Client {
        input: Option<mpsc::Sender<io::Result<Vec<u8>>>>,
        output: mpsc::Receiver<Vec<u8>>,
        server: Option<thread::JoinHandle<io::Result<()>>>,
    }

    impl Client {
        fn start<F>(limits: TransportLimits, execute: F) -> Self
        where
            F: Fn(JsonRpcRequest, McpCallContext) -> JsonRpcResponse + Send + Sync + 'static,
        {
            let (input, incoming) = mpsc::channel();
            let (outgoing, output) = mpsc::channel();
            let server = thread::spawn(move || {
                run_blocking(
                    ChannelReader {
                        input: incoming,
                        current: Vec::new(),
                        offset: 0,
                    },
                    FrameWriter {
                        output: outgoing,
                        current: Vec::new(),
                    },
                    limits,
                    |request| {
                        let id = request.id.clone().unwrap_or(Value::Null);
                        match request.method.as_str() {
                            "ping" | "initialize" => JsonRpcResponse::success(id, json!({})),
                            _ => JsonRpcResponse::error(
                                id,
                                JsonRpcError::method_not_found(&request.method),
                            ),
                        }
                    },
                    |request| Ok(request.clone()),
                    execute,
                )
            });
            Self {
                input: Some(input),
                output,
                server: Some(server),
            }
        }

        fn raw(&self, bytes: impl Into<Vec<u8>>) {
            self.input.as_ref().unwrap().send(Ok(bytes.into())).unwrap();
        }

        fn send(&self, value: Value) {
            let mut bytes = serde_json::to_vec(&value).unwrap();
            bytes.push(b'\n');
            self.raw(bytes);
        }

        fn call(&self, id: Value) {
            self.send(
                json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"test"}}),
            );
        }

        fn ping(&self, id: Value) {
            self.send(json!({"jsonrpc":"2.0","id":id,"method":"ping"}));
        }

        fn cancel(&self, id: Value) {
            self.send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":id}}));
        }

        fn response(&self) -> JsonRpcResponse {
            let frame = self.output.recv_timeout(TEST_TIMEOUT).unwrap();
            serde_json::from_slice(&frame).unwrap()
        }

        fn finish(mut self) -> (io::Result<()>, Vec<JsonRpcResponse>) {
            self.input.take();
            let result = self.server.take().unwrap().join().unwrap();
            let remaining = self
                .output
                .try_iter()
                .map(|frame| serde_json::from_slice(&frame).unwrap())
                .collect();
            (result, remaining)
        }
    }

    impl Drop for Client {
        fn drop(&mut self) {
            self.input.take();
            if let Some(server) = self.server.take() {
                // Keep tests owned even when an assertion fails. All blocking
                // callbacks below also have finite timeouts.
                let _ = server.join();
            }
        }
    }

    fn limits(max_in_flight: usize) -> TransportLimits {
        TransportLimits {
            max_in_flight,
            max_request_bytes: 4096,
            max_response_bytes: 4096,
            max_id_bytes: 32,
        }
    }

    fn success(request: &JsonRpcRequest) -> JsonRpcResponse {
        JsonRpcResponse::success(request.id.clone().unwrap(), json!({"done":true}))
    }

    #[test]
    fn slow_call_does_not_block_ping_or_another_tool() {
        let (started, running) = mpsc::channel();
        let client = Client::start(limits(2), move |request, context| {
            if request.id == Some(json!("slow")) {
                started.send(context.clone()).unwrap();
                context.wait_for_cancellation(TEST_TIMEOUT);
            }
            success(&request)
        });
        client.call(json!("slow"));
        let slow = running.recv_timeout(TEST_TIMEOUT).unwrap();
        client.ping(json!("ping"));
        client.call(json!("fast"));
        let mut ids = vec![client.response().id, client.response().id];
        ids.sort_by_key(Value::to_string);
        assert_eq!(ids, vec![json!("fast"), json!("ping")]);
        assert!(!slow.is_cancelled());
        client.cancel(json!("slow"));
        client.ping(json!("after-cancel"));
        assert_eq!(client.response().id, json!("after-cancel"));
        assert!(slow.is_cancelled());
        let (result, remaining) = client.finish();
        result.unwrap();
        assert!(remaining.is_empty(), "cancelled tool emitted a response");
    }

    #[test]
    fn saturation_and_duplicate_ids_do_not_block_cancellation() {
        let (started, running) = mpsc::channel();
        let (cancelled, cancellation_seen) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let released = Mutex::new(released);
        let executions = Arc::new(AtomicUsize::new(0));
        let observed_executions = Arc::clone(&executions);
        let client = Client::start(limits(1), move |request, context| {
            observed_executions.fetch_add(1, Ordering::SeqCst);
            started.send(()).unwrap();
            context.wait_for_cancellation(TEST_TIMEOUT);
            cancelled.send(()).unwrap();
            lock(&released).recv_timeout(TEST_TIMEOUT).unwrap();
            success(&request)
        });
        client.call(json!(1));
        running.recv_timeout(TEST_TIMEOUT).unwrap();
        client.call(json!(2));
        let busy = client.response();
        assert_eq!(busy.id, json!(2));
        let error = busy.error.unwrap();
        assert_eq!(error.code, SERVER_BUSY);
        assert_eq!(error.data.unwrap()["admitted"], false);
        client.call(json!(1));
        let duplicate = client.response();
        assert_eq!(
            duplicate.error.unwrap().data.unwrap()["kind"],
            "duplicate_request_id"
        );
        client.cancel(json!(1));
        cancellation_seen.recv_timeout(TEST_TIMEOUT).unwrap();
        // The callback is still draining. Its old ID and its admission slot
        // remain reserved, even though the cancellation has been observed.
        client.call(json!(1));
        assert_eq!(client.response().error.unwrap().code, INVALID_REQUEST);
        client.call(json!(3));
        assert_eq!(client.response().error.unwrap().code, SERVER_BUSY);
        client.ping(json!(4));
        assert_eq!(client.response().id, json!(4));
        release.send(()).unwrap();
        let (result, remaining) = client.finish();
        result.unwrap();
        assert!(remaining.is_empty());
        assert_eq!(executions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn numeric_and_string_ids_have_distinct_cancellation_targets() {
        let (started, running) = mpsc::channel();
        let client = Client::start(limits(2), move |request, context| {
            started
                .send((request.id.clone().unwrap(), context.clone()))
                .unwrap();
            context.wait_for_cancellation(TEST_TIMEOUT);
            success(&request)
        });
        client.call(json!(7));
        client.call(json!("7"));
        let first = running.recv_timeout(TEST_TIMEOUT).unwrap();
        let second = running.recv_timeout(TEST_TIMEOUT).unwrap();
        let (number, string) = if first.0.is_number() {
            (first.1, second.1)
        } else {
            (second.1, first.1)
        };
        client.cancel(json!(7));
        client.ping(json!(8));
        assert_eq!(client.response().id, json!(8));
        assert!(number.is_cancelled());
        assert!(!string.is_cancelled());
        let (result, remaining) = client.finish();
        result.unwrap();
        assert!(string.is_cancelled(), "EOF must cancel the remaining call");
        assert!(remaining.is_empty());
    }

    #[test]
    fn reused_completed_id_gets_a_fresh_context_and_late_old_context_is_harmless() {
        let (started, running) = mpsc::channel();
        let generations = AtomicUsize::new(0);
        let client = Client::start(limits(1), move |request, context| {
            let generation = generations.fetch_add(1, Ordering::SeqCst);
            started.send(context.clone()).unwrap();
            if generation > 0 {
                context.wait_for_cancellation(TEST_TIMEOUT);
            }
            success(&request)
        });
        client.call(json!("reused"));
        let old = running.recv_timeout(TEST_TIMEOUT).unwrap();
        assert_eq!(client.response().id, json!("reused"));
        client.cancel(json!("reused")); // Already completed: ignored.
        client.call(json!("reused"));
        let new = running.recv_timeout(TEST_TIMEOUT).unwrap();
        old.cancel();
        assert!(!new.is_cancelled());
        client.ping(json!("barrier"));
        assert_eq!(client.response().id, json!("barrier"));
        assert!(!new.is_cancelled());
        client.cancel(json!("reused"));
        let (result, remaining) = client.finish();
        result.unwrap();
        assert!(new.is_cancelled());
        assert!(remaining.is_empty());
    }

    #[test]
    fn malformed_and_unknown_cancellation_notifications_are_ignored() {
        let (started, running) = mpsc::channel();
        let client = Client::start(limits(1), move |request, context| {
            started.send(context.clone()).unwrap();
            context.wait_for_cancellation(TEST_TIMEOUT);
            success(&request)
        });
        client.call(json!(10));
        let context = running.recv_timeout(TEST_TIMEOUT).unwrap();
        for notification in [
            json!({"jsonrpc":"2.0","method":"notifications/cancelled"}),
            json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":null}}),
            json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":10,"reason":false}}),
            json!({"jsonrpc":"1.0","method":"notifications/cancelled","params":{"requestId":10}}),
            json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"10"}}),
            json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":999}}),
        ] {
            client.send(notification);
        }
        client.send(json!({"jsonrpc":"2.0","id":11,"method":"notifications/cancelled","params":{"requestId":10}}));
        assert_eq!(client.response().error.unwrap().code, METHOD_NOT_FOUND);
        client.send(json!({"jsonrpc":"2.0","id":12,"method":"initialize","params":{}}));
        assert_eq!(client.response().id, json!(12));
        client.cancel(json!(12)); // Initialize is never an active tool call.
        client.ping(json!(13));
        assert_eq!(client.response().id, json!(13));
        assert!(!context.is_cancelled());
        client.cancel(json!(10));
        let (result, remaining) = client.finish();
        result.unwrap();
        assert!(remaining.is_empty());
    }

    #[test]
    fn idless_tools_and_invalid_ids_never_execute_or_echo_unbounded_ids() {
        let executions = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&executions);
        let client = Client::start(limits(1), move |request, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            success(&request)
        });
        client.send(json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"test"}}));
        for id in [
            Value::Null,
            json!(false),
            json!([]),
            json!({}),
            json!("x".repeat(33)),
        ] {
            client.call(id);
            let response = client.response();
            assert_eq!(response.id, Value::Null);
            assert_eq!(response.error.unwrap().code, INVALID_REQUEST);
        }
        client.ping(json!("alive"));
        assert_eq!(client.response().id, json!("alive"));
        let (result, remaining) = client.finish();
        result.unwrap();
        assert!(remaining.is_empty());
        assert_eq!(executions.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn eof_cancels_and_joins_running_callbacks_without_emitting_their_results() {
        let (started, running) = mpsc::channel();
        let drained = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&drained);
        let client = Client::start(limits(2), move |request, context| {
            started.send(context.clone()).unwrap();
            if context.wait_for_cancellation(TEST_TIMEOUT) {
                observed.fetch_add(1, Ordering::SeqCst);
            }
            success(&request)
        });
        client.call(json!(1));
        client.call(json!(2));
        let first = running.recv_timeout(TEST_TIMEOUT).unwrap();
        let second = running.recv_timeout(TEST_TIMEOUT).unwrap();
        let (result, remaining) = client.finish();
        result.unwrap();
        assert!(first.is_cancelled() && second.is_cancelled());
        assert_eq!(drained.load(Ordering::SeqCst), 2);
        assert!(remaining.is_empty());
    }

    #[test]
    fn input_error_cancels_and_joins_running_callbacks() {
        let (started, running) = mpsc::channel();
        let client = Client::start(limits(1), move |request, context| {
            started.send(context.clone()).unwrap();
            context.wait_for_cancellation(TEST_TIMEOUT);
            success(&request)
        });
        client.call(json!(1));
        let context = running.recv_timeout(TEST_TIMEOUT).unwrap();
        client
            .input
            .as_ref()
            .unwrap()
            .send(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
            .unwrap();
        let (result, remaining) = client.finish();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
        assert!(context.is_cancelled());
        assert!(remaining.is_empty());
    }

    #[test]
    fn invalid_json_is_recoverable_and_exact_lf_or_crlf_frame_limit_is_accepted() {
        let mut bounds = limits(1);
        bounds.max_request_bytes = 96;
        let client = Client::start(bounds, |request, _| success(&request));
        client.raw(b"{bad\n".to_vec());
        assert_eq!(client.response().error.unwrap().code, PARSE_ERROR);
        for ending in [b"\n".as_slice(), b"\r\n".as_slice()] {
            let mut frame =
                serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"ping"})).unwrap();
            frame.resize(bounds.max_request_bytes, b' ');
            frame.extend_from_slice(ending);
            client.raw(frame);
            assert_eq!(client.response().id, json!(1));
        }
        let (result, remaining) = client.finish();
        result.unwrap();
        assert!(remaining.is_empty());
    }

    #[test]
    fn oversized_input_closes_stream_and_cancels_owned_calls() {
        let mut bounds = limits(1);
        bounds.max_request_bytes = 128;
        let (started, running) = mpsc::channel();
        let client = Client::start(bounds, move |request, context| {
            started.send(context.clone()).unwrap();
            context.wait_for_cancellation(TEST_TIMEOUT);
            success(&request)
        });
        client.call(json!(1));
        let context = running.recv_timeout(TEST_TIMEOUT).unwrap();
        client.raw(vec![b'x'; bounds.max_request_bytes + 3]);
        let response = client.response();
        assert_eq!(response.id, Value::Null);
        assert_eq!(
            response.error.unwrap().data.unwrap()["kind"],
            "request_too_large"
        );
        let (result, remaining) = client.finish();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(context.is_cancelled());
        assert!(remaining.is_empty());
    }

    #[test]
    fn oversized_response_is_bounded_and_never_presented_as_retryable_success() {
        let mut bounds = limits(1);
        bounds.max_response_bytes = 512;
        let client = Client::start(bounds, |request, _| {
            JsonRpcResponse::success(request.id.unwrap(), json!({"payload":"x".repeat(4096)}))
        });
        client.call(json!(1));
        let frame = client.output.recv_timeout(TEST_TIMEOUT).unwrap();
        assert!(frame.len() <= bounds.max_response_bytes);
        let response: JsonRpcResponse = serde_json::from_slice(&frame).unwrap();
        assert!(response.result.is_none());
        assert_eq!(response.id, json!(1));
        let error = response.error.unwrap();
        assert_eq!(error.code, INTERNAL_ERROR);
        let data = error.data.unwrap();
        assert_eq!(data["kind"], "response_too_large");
        assert_eq!(data["outcome"], "unknown");
        assert_eq!(data["retryable"], false);
        client.ping(json!(2));
        assert_eq!(client.response().id, json!(2));
        client.finish().0.unwrap();
    }

    #[test]
    fn concurrent_results_are_whole_frames_with_the_accepted_request_id() {
        let executions = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&executions);
        let client = Client::start(limits(8), move |request, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            JsonRpcResponse::success(
                json!("wrong-handler-id"),
                json!({"echo":request.id.unwrap(),"payload":"x".repeat(1024)}),
            )
        });
        for id in 0..8 {
            client.call(json!(id));
        }
        let mut ids = Vec::new();
        for _ in 0..8 {
            let response = client.response();
            let result = response.result.unwrap();
            assert_eq!(response.id, result["echo"]);
            assert_eq!(result["payload"].as_str().unwrap().len(), 1024);
            ids.push(response.id.as_u64().unwrap());
        }
        ids.sort_unstable();
        assert_eq!(ids, (0..8).collect::<Vec<_>>());
        assert_eq!(executions.load(Ordering::SeqCst), 8);
        let (result, remaining) = client.finish();
        result.unwrap();
        assert!(remaining.is_empty());
    }

    #[test]
    fn handler_unwind_reports_unknown_outcome_and_worker_remains_available() {
        let client = Client::start(limits(1), |request, _| {
            if request.id == Some(json!(1)) {
                panic!("simulated handler unwind");
            }
            success(&request)
        });
        client.call(json!(1));
        let failed = client.response();
        let error = failed.error.unwrap();
        assert_eq!(error.code, INTERNAL_ERROR);
        assert_eq!(error.data.unwrap()["retryable"], false);
        client.call(json!(2));
        assert_eq!(client.response().id, json!(2));
        client.finish().0.unwrap();
    }

    #[test]
    fn output_failure_cancels_calls_and_is_returned_after_reader_unblocks() {
        struct BrokenWriter;
        impl Write for BrokenWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (input, incoming) = mpsc::channel();
        let (started, running) = mpsc::channel();
        let server = thread::spawn(move || {
            run_blocking(
                ChannelReader {
                    input: incoming,
                    current: Vec::new(),
                    offset: 0,
                },
                BrokenWriter,
                limits(1),
                success,
                |request| Ok(request.clone()),
                |request, context| {
                    started.send(context.clone()).unwrap();
                    context.wait_for_cancellation(TEST_TIMEOUT);
                    success(&request)
                },
            )
        });
        input
            .send(Ok(
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}\n".to_vec(),
            ))
            .unwrap();
        let context = running.recv_timeout(TEST_TIMEOUT).unwrap();
        input
            .send(Ok(
                b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n".to_vec()
            ))
            .unwrap();
        drop(input);
        assert_eq!(
            server.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(context.is_cancelled());
    }

    #[test]
    fn blocked_worker_output_does_not_block_another_calls_cancellation() {
        struct GatedWriter {
            started: mpsc::Sender<()>,
            release: McpCallContext,
            first_write: bool,
        }
        impl Write for GatedWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.first_write {
                    self.first_write = false;
                    self.started.send(()).unwrap();
                    if !self.release.wait_for_cancellation(TEST_TIMEOUT * 2) {
                        return Err(io::Error::from(io::ErrorKind::TimedOut));
                    }
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        struct ReleaseOnDrop(McpCallContext);
        impl Drop for ReleaseOnDrop {
            fn drop(&mut self) {
                self.0.cancel();
            }
        }

        thread::scope(|scope| {
            let (input, incoming) = mpsc::channel();
            let (started, running) = mpsc::channel();
            let (write_started, writing) = mpsc::channel();
            let release = McpCallContext::default();
            let writer = GatedWriter {
                started: write_started,
                release: release.clone(),
                first_write: true,
            };
            // Always unblock the writer before the outer scope joins, even
            // if an earlier assertion fails.
            let _release_on_drop = ReleaseOnDrop(release.clone());
            let server = scope.spawn(move || {
                run_blocking(
                    ChannelReader {
                        input: incoming,
                        current: Vec::new(),
                        offset: 0,
                    },
                    writer,
                    limits(2),
                    success,
                    |request| Ok(request.clone()),
                    |request, context| {
                        if request.id == Some(json!(1)) {
                            started.send(context.clone()).unwrap();
                            context.wait_for_cancellation(TEST_TIMEOUT * 2);
                        }
                        success(&request)
                    },
                )
            });
            input
                .send(Ok(
                    b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}\n".to_vec(),
                ))
                .unwrap();
            let target = running.recv_timeout(TEST_TIMEOUT).unwrap();
            input
                .send(Ok(
                    b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\"}\n".to_vec(),
                ))
                .unwrap();
            writing.recv_timeout(TEST_TIMEOUT).unwrap();
            // The reader may already be waiting inside read_until. An idless
            // notification forces the next loop's failure check while the
            // worker still holds stdout, before cancellation is consumed.
            input
                .send(Ok(
                    b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n".to_vec(),
                ))
                .unwrap();
            input.send(Ok(
                b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1}}\n".to_vec(),
            )).unwrap();

            let cancelled_while_output_blocked = target.wait_for_cancellation(TEST_TIMEOUT);
            release.cancel();
            drop(input);
            server.join().unwrap().unwrap();
            assert!(
                cancelled_while_output_blocked,
                "reader waited on a worker's blocked stdout write before reading cancellation"
            );
        });
    }

    #[test]
    fn default_frame_limits_preserve_binary_upload_envelopes() {
        let defaults = TransportLimits::default();
        assert_eq!(defaults.max_in_flight, 8);
        assert_eq!(defaults.max_request_bytes, 32 * 1024 * 1024);
        assert_eq!(defaults.max_response_bytes, 32 * 1024 * 1024);
        assert_eq!(defaults.max_id_bytes, 256);
        let mut buffer = BoundedBuffer {
            bytes: Vec::new(),
            limit: 64,
        };
        buffer.write_all(&[b'x'; 63]).unwrap();
        assert!(buffer.write_all(&[b'y'; 2]).is_err());
        assert_eq!(buffer.bytes.len(), 63);
        assert!(buffer.bytes.capacity() <= 64);
    }
}
