//! Server-Sent Events (SSE) implementation.
//!
//! Implements SSE parsing and client per the WHATWG HTML Living Standard.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use chrono::{DateTime, Utc};
use fcp_async_core::bytes::Buf as _;
use fcp_async_core::http::body::Body as _;
use fcp_async_core::http::client_io::ClientIo;
use fcp_async_core::http::{ClientIncomingBody, HttpClient, HttpClientBuilder, Method};
use fcp_async_core::time::{self, Sleep, sleep};
use futures_util::stream::{Stream, StreamExt as _};
use pin_project_lite::pin_project;

use crate::{
    FCP_BACKPRESSURE_REASON_HEADER, FCP_BACKPRESSURE_RETRY_AFTER_HEADER, HOST_BACKPRESSURE_STATUS,
    HostBackpressureSignal, StreamError, StreamResult,
};
use crate::{ReconnectConfig, ReconnectHandler};

const ACCEPT_HEADER: &str = "Accept";
const CACHE_CONTROL_HEADER: &str = "Cache-Control";
const LAST_EVENT_ID_HEADER: &str = "Last-Event-ID";
const NO_CACHE_VALUE: &str = "no-cache";
const SSE_MIME_TYPE: &str = "text/event-stream";

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn parse_retry_after(value: &str) -> Option<Duration> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u128>() {
        return Some(Duration::from_secs(
            u64::try_from(seconds).unwrap_or(u64::MAX),
        ));
    }

    let retry_at = DateTime::parse_from_rfc2822(value).ok()?;
    let wait = retry_at
        .with_timezone(&Utc)
        .signed_duration_since(Utc::now());
    if wait <= chrono::Duration::zero() {
        Some(Duration::ZERO)
    } else {
        wait.to_std().ok().or(Some(Duration::from_secs(u64::MAX)))
    }
}

fn max_retry_after(left: Option<Duration>, right: Option<Duration>) -> Option<Duration> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn http_error_from_head(status: u16, reason: String, headers: &[(String, String)]) -> StreamError {
    if status == HOST_BACKPRESSURE_STATUS {
        if let Some(backpressure_reason) = header_value(headers, FCP_BACKPRESSURE_REASON_HEADER) {
            let retry_after = max_retry_after(
                header_value(headers, "retry-after").and_then(parse_retry_after),
                header_value(headers, FCP_BACKPRESSURE_RETRY_AFTER_HEADER)
                    .and_then(parse_retry_after),
            );

            return StreamError::HostBackpressure {
                status,
                message: reason,
                signal: HostBackpressureSignal::new(backpressure_reason, retry_after),
            };
        }
    }

    // RFC 7231 §7.1.3 defines Retry-After for 429 and 503 (and other
    // statuses, but these are the practical reconnect-budget cases for an
    // SSE consumer). The FCP backpressure 503 path above already extracted
    // retry_after via HostBackpressureSignal; this branch handles generic
    // upstream 429/503 where the connector got an HTTP retry hint without
    // the FCP-specific reason header.
    let retry_after = if status == 429 || status == HOST_BACKPRESSURE_STATUS {
        header_value(headers, "retry-after").and_then(parse_retry_after)
    } else {
        None
    };

    StreamError::HttpError {
        status,
        message: reason,
        retry_after,
    }
}

/// Pick the reconnect delay, honouring a server `Retry-After` but never
/// letting it exceed the configured ceiling.
///
/// `Retry-After` is attacker-controlled: `parse_retry_after` maps an oversized
/// integer to `Duration::from_secs(u64::MAX)`, so an unclamped
/// `base.max(retry_after)` let one response header park the stream for ~584
/// billion years — the sleep never resolves, the connector never reconnects,
/// and its timer thread stays alive. `delay_for_attempt` already enforces
/// `max_delay`; the server-supplied value has to be intersected with the same
/// ceiling rather than allowed to override it. (`fcp-graphql`'s
/// `RetryPolicy::decide` already clamps with `.min(max_delay)`.)
fn reconnect_delay_for_error(handler: &ReconnectHandler, err: &StreamError) -> Duration {
    let config = handler.config();
    let base = config.delay_for_attempt(handler.attempts());
    err.retry_after().map_or(base, |retry_after| {
        base.max(retry_after).min(config.max_delay)
    })
}

/// SSE event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// Event type (from "event:" field).
    pub event: Option<String>,
    /// Event data (from "data:" fields, joined with newlines).
    pub data: String,
    /// Event ID (from "id:" field).
    pub id: Option<String>,
    /// Retry interval in milliseconds (from "retry:" field).
    pub retry: Option<u64>,
}

impl SseEvent {
    /// Create a new SSE event with data.
    #[must_use]
    pub fn new(data: impl Into<String>) -> Self {
        Self {
            event: None,
            data: data.into(),
            id: None,
            retry: None,
        }
    }

    /// Set the event type.
    #[must_use]
    pub fn with_event(mut self, event: impl Into<String>) -> Self {
        self.event = Some(event.into());
        self
    }

    /// Set the event ID.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Check if this is a specific event type.
    #[must_use]
    pub fn is_event(&self, event_type: &str) -> bool {
        self.event.as_deref() == Some(event_type)
    }

    /// Parse data as JSON.
    ///
    /// # Errors
    /// Returns a JSON parsing error if the data is not valid JSON.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_str(&self.data)
    }
}

#[cfg(test)]
const DEFAULT_MAX_DATA_BYTES: usize = 10 * 1024 * 1024;
const MAX_SSE_BUFFER_SIZE: usize = 64 * 1024 * 1024;

/// Fixed cost charged against `max_data_bytes` for every retained `data:` line,
/// on top of the line's own payload length.
///
/// A retained line costs a `String` header inside `data_lines` plus the `\n`
/// separator `dispatch_event` inserts when it joins them — neither of which is
/// payload. Accounting for payload bytes ALONE was unsound: `data:` with an
/// empty value pushes a `String` while adding zero to the running total, so a
/// peer streaming `data:\n` forever (and never sending the blank line that
/// dispatches the event) grew `data_lines` without bound while
/// `retained_bytes()` stayed pinned at 0 and the `BufferOverflow` guard never
/// fired. Measured overshoot before this fix: ~96x the configured 1 MiB cap
/// from 16 MiB of wire input. Charging the per-line overhead makes the
/// accounted total an upper bound on the real heap footprint, which is what
/// the guard needs.
const DATA_LINE_OVERHEAD: usize = size_of::<String>() + 1;

const fn clamp_sse_buffer_size(size: usize) -> usize {
    if size > MAX_SSE_BUFFER_SIZE {
        MAX_SSE_BUFFER_SIZE
    } else {
        size
    }
}

const fn retained_buffer_overflow(
    retained_bytes: usize,
    next_chunk_len: usize,
    max_buffer_size: usize,
) -> Option<StreamError> {
    let limit = clamp_sse_buffer_size(max_buffer_size);
    let size = retained_bytes.saturating_add(next_chunk_len);
    if size > limit {
        Some(StreamError::BufferOverflow { size, limit })
    } else {
        None
    }
}

/// SSE parser state.
#[derive(Debug)]
struct SseParser {
    /// Buffer for incomplete data.
    buffer: BytesMut,
    /// First retained byte not yet scanned for a line ending.
    parse_cursor: usize,
    /// Current event being built.
    event_type: Option<String>,
    /// Accumulated data lines.
    data_lines: Vec<String>,
    /// Current event ID.
    event_id: Option<String>,
    /// Current retry interval.
    retry: Option<u64>,
    /// Last event ID (for reconnection).
    last_event_id: Option<String>,
    /// Total retained cost of `data_lines` (`DoS` protection).
    ///
    /// This is NOT just the sum of the payload byte lengths: each retained
    /// line is also charged [`DATA_LINE_OVERHEAD`]. See that constant for
    /// why the payload-only accounting was unsound.
    data_retained_bytes: usize,
    /// Maximum `data:` payload bytes retained for an in-progress event.
    max_data_bytes: usize,
    /// The previous `parse()` call consumed a CR as its final terminator.
    /// Per WHATWG SSE, a CR followed by LF is a single CRLF terminator —
    /// when CR and LF straddle a chunk boundary the leading LF of the
    /// next chunk must be swallowed rather than treated as a new empty
    /// line (which would dispatch a spurious event between the CR and LF).
    pending_cr_swallows_lf: bool,
}

impl SseParser {
    /// Create a new parser.
    #[cfg(test)]
    fn new() -> Self {
        Self::with_max_data_bytes(DEFAULT_MAX_DATA_BYTES)
    }

    /// Create a new parser with a specific retained payload limit.
    fn with_max_data_bytes(max_data_bytes: usize) -> Self {
        Self {
            buffer: BytesMut::new(),
            parse_cursor: 0,
            event_type: None,
            data_lines: Vec::new(),
            event_id: None,
            retry: None,
            last_event_id: None,
            data_retained_bytes: 0,
            max_data_bytes,
            pending_cr_swallows_lf: false,
        }
    }

    /// Parse incoming data and return complete events.
    fn parse(&mut self, data: &Bytes) -> Vec<SseEvent> {
        // If the previous chunk's final terminator was a lone CR, a leading
        // LF in this chunk is the second half of a CRLF, not a new line
        // terminator. Swallow it before appending to the buffer.
        let data_slice: &[u8] = data;
        let effective = if self.pending_cr_swallows_lf {
            self.pending_cr_swallows_lf = false;
            if data_slice.first() == Some(&b'\n') {
                &data_slice[1..]
            } else {
                data_slice
            }
        } else {
            data_slice
        };
        self.buffer.extend_from_slice(effective);
        let mut events = Vec::new();

        // Process complete lines
        while let Some(line_end) = self.find_line_end() {
            let line = self.buffer.split_to(line_end);
            // Skip the line ending. If we consume a CR with no following
            // byte in the buffer, remember it so a CRLF straddling a chunk
            // boundary is collapsed back to a single terminator next time.
            let mut consumed_lone_trailing_cr = false;
            if self.buffer.starts_with(b"\r\n") {
                self.buffer.advance(2);
            } else if self.buffer.starts_with(b"\n") {
                self.buffer.advance(1);
            } else if self.buffer.starts_with(b"\r") {
                let is_trailing = self.buffer.len() == 1;
                self.buffer.advance(1);
                consumed_lone_trailing_cr = is_trailing;
            }
            self.parse_cursor = 0;

            let line_str = String::from_utf8_lossy(&line);

            if line_str.is_empty() {
                // Empty line = dispatch event
                if let Some(event) = self.dispatch_event() {
                    events.push(event);
                }
            } else if line_str.starts_with(':') {
                // Comment, ignore
            } else {
                self.process_field(&line_str);
            }

            if consumed_lone_trailing_cr {
                self.pending_cr_swallows_lf = true;
            }
        }

        events
    }

    /// Find the end of a line in the buffer.
    fn find_line_end(&mut self) -> Option<usize> {
        let start = self.parse_cursor.min(self.buffer.len());
        for (offset, byte) in self.buffer[start..].iter().enumerate() {
            if *byte == b'\n' || *byte == b'\r' {
                return Some(start + offset);
            }
        }
        self.parse_cursor = self.buffer.len();
        None
    }

    /// Process a field line.
    fn process_field(&mut self, line: &str) {
        let (field, value) = line.find(':').map_or((line, ""), |colon_pos| {
            let field = &line[..colon_pos];
            let value = &line[colon_pos + 1..];
            // Skip leading space after colon
            let value = value.strip_prefix(' ').unwrap_or(value);
            (field, value)
        });

        match field {
            "event" => self.event_type = Some(value.to_string()),
            "data" => {
                let line_cost = value.len().saturating_add(DATA_LINE_OVERHEAD);
                if self.data_retained_bytes.saturating_add(line_cost) <= self.max_data_bytes {
                    self.data_lines.push(value.to_string());
                    self.data_retained_bytes += line_cost;
                }
            }
            "id" if !value.contains('\0') => {
                self.event_id = Some(value.to_string());
            }
            "retry" => {
                if let Ok(ms) = value.parse() {
                    self.retry = Some(ms);
                }
            }
            _ => {} // Unknown field, ignore
        }
    }

    /// Dispatch the current event.
    fn dispatch_event(&mut self) -> Option<SseEvent> {
        if self.data_lines.is_empty() {
            // Reset state but don't dispatch
            self.event_type = None;
            return None;
        }

        let data = self.data_lines.join("\n");
        let event = SseEvent {
            event: self.event_type.take(),
            data,
            id: self.event_id.clone(),
            retry: self.retry.take(),
        };

        // Update last event ID
        if event.id.is_some() {
            self.last_event_id.clone_from(&event.id);
        }

        self.data_lines.clear();
        self.data_retained_bytes = 0;

        Some(event)
    }

    /// Get the last event ID for reconnection.
    fn last_event_id(&self) -> Option<&str> {
        self.last_event_id.as_deref()
    }

    /// Bytes currently retained for the in-progress event.
    fn retained_bytes(&self) -> usize {
        self.buffer.len().saturating_add(self.data_retained_bytes)
    }
}

/// Fuzz-only entry points for the SSE parser.
///
/// Exposed for the `fuzz_sse_event_stream` libfuzzer target so it can drive
/// the private `SseParser` on adversarial byte streams (oversized fields,
/// missing terminators, embedded nulls, malformed retry/id fields). The
/// outer module remains `mod sse;` (private); only this `__fuzz` namespace
/// is public, and it is `#[doc(hidden)]` so it does not appear in rustdoc.
///
/// Bead flywheel_connectors-2qsbc.
#[doc(hidden)]
pub mod __fuzz {
    use super::{Bytes, SseEvent, SseParser};

    /// Drive the SSE parser by feeding `chunks` sequentially, returning
    /// every event the parser dispatched across the whole stream.
    ///
    /// `max_data_bytes` caps the retained `data:` payload for an in-progress
    /// event (matches the production `SseConfig::max_buffer_size` cap path).
    #[must_use]
    pub fn parse_chunks(chunks: &[&[u8]], max_data_bytes: usize) -> Vec<SseEvent> {
        let mut parser = SseParser::with_max_data_bytes(max_data_bytes);
        let mut events = Vec::new();
        for chunk in chunks {
            let bytes = Bytes::copy_from_slice(chunk);
            events.extend(parser.parse(&bytes));
        }
        events
    }

    /// Number of bytes the parser is currently retaining (in-progress buffer
    /// plus accumulated `data:` payload).
    ///
    /// The fuzz target asserts this stays bounded by a multiple of
    /// `max_data_bytes` so a regression that loosens the retention cap
    /// surfaces immediately.
    #[must_use]
    pub fn parse_chunks_with_retained(
        chunks: &[&[u8]],
        max_data_bytes: usize,
    ) -> (Vec<SseEvent>, usize) {
        let mut parser = SseParser::with_max_data_bytes(max_data_bytes);
        let mut events = Vec::new();
        for chunk in chunks {
            let bytes = Bytes::copy_from_slice(chunk);
            events.extend(parser.parse(&bytes));
        }
        (events, parser.retained_bytes())
    }
}

/// Benchmark-only entry points for parser microbenchmarks.
#[doc(hidden)]
pub mod __bench {
    use bytes::BytesMut;

    use super::{Bytes, SseEvent, SseParser};

    /// Harness that lets Criterion time a single parse after setup has already
    /// populated a retained incomplete line.
    #[derive(Debug)]
    pub struct SseParserBenchHarness {
        parser: SseParser,
    }

    impl SseParserBenchHarness {
        /// Build a parser whose retained buffer has already been scanned and
        /// contains no line terminator.
        #[must_use]
        pub fn with_retained_long_line(retained_bytes: usize, max_data_bytes: usize) -> Self {
            let mut parser = SseParser::with_max_data_bytes(max_data_bytes);
            parser.buffer = BytesMut::from(vec![b'x'; retained_bytes].as_slice());
            parser.parse_cursor = retained_bytes;
            Self { parser }
        }

        /// Build an empty parser with the supplied retained-payload cap.
        #[must_use]
        pub fn empty(max_data_bytes: usize) -> Self {
            Self {
                parser: SseParser::with_max_data_bytes(max_data_bytes),
            }
        }

        /// Parse one chunk and return complete events.
        pub fn parse_chunk(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
            self.parser.parse(&Bytes::copy_from_slice(chunk))
        }

        /// Bytes currently retained by the parser.
        #[must_use]
        pub fn retained_bytes(&self) -> usize {
            self.parser.retained_bytes()
        }

        /// Cursor position for benchmark sanity checks.
        #[must_use]
        pub const fn parse_cursor(&self) -> usize {
            self.parser.parse_cursor
        }
    }
}

/// SSE client configuration.
#[derive(Clone)]
pub struct SseConfig {
    /// Request timeout.
    pub timeout: Option<Duration>,
    /// Maximum buffer size.
    pub max_buffer_size: usize,
    /// Additional headers.
    pub headers: HashMap<String, String>,
    /// Whether to auto-reconnect.
    pub auto_reconnect: bool,
    /// Maximum reconnection attempts.
    pub max_reconnect_attempts: Option<u32>,
    /// Initial reconnection delay.
    pub reconnect_delay: Duration,
}

impl fmt::Debug for SseConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_headers: HashMap<&str, &str> = self
            .headers
            .keys()
            .map(|key| (key.as_str(), "[REDACTED]"))
            .collect();

        f.debug_struct("SseConfig")
            .field("timeout", &self.timeout)
            .field("max_buffer_size", &self.max_buffer_size)
            .field("headers", &redacted_headers)
            .field("auto_reconnect", &self.auto_reconnect)
            .field("max_reconnect_attempts", &self.max_reconnect_attempts)
            .field("reconnect_delay", &self.reconnect_delay)
            .finish()
    }
}

impl Default for SseConfig {
    fn default() -> Self {
        Self {
            timeout: None,
            max_buffer_size: 1024 * 1024, // 1MB
            headers: HashMap::new(),
            auto_reconnect: true,
            max_reconnect_attempts: Some(10),
            reconnect_delay: Duration::from_secs(1),
        }
    }
}

impl SseConfig {
    /// Create a new SSE configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set request timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set maximum buffer size.
    #[must_use]
    pub const fn with_max_buffer_size(mut self, size: usize) -> Self {
        self.max_buffer_size = clamp_sse_buffer_size(size);
        self
    }

    /// Add a header.
    #[must_use]
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Set auto-reconnect.
    #[must_use]
    pub const fn with_auto_reconnect(mut self, enabled: bool) -> Self {
        self.auto_reconnect = enabled;
        self
    }

    /// Set maximum reconnection attempts.
    #[must_use]
    pub const fn with_max_reconnect_attempts(mut self, attempts: u32) -> Self {
        self.max_reconnect_attempts = Some(attempts);
        self
    }

    /// Set reconnection delay.
    #[must_use]
    pub const fn with_reconnect_delay(mut self, delay: Duration) -> Self {
        self.reconnect_delay = delay;
        self
    }
}

/// SSE client.
#[derive(Clone)]
pub struct SseClient {
    url: String,
    config: SseConfig,
    http_client: Arc<HttpClient>,
}

impl fmt::Debug for SseClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SseClient")
            .field("url", &self.url)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Build the HTTP client used for SSE.
///
/// The transport's `max_body_size` is a cap on the TOTAL response body, and its
/// counter accumulates across the whole response and is never reset — which is
/// meaningless for an intentionally unbounded stream. Leaving it at the
/// transport default (16 MiB) killed every long-lived SSE connection with
/// `BodyTooLarge` once it had delivered that much: about 80 minutes for an
/// endpoint pushing 200 KB/min. Where a supervisor reconnects with
/// `Last-Event-ID` that degraded into a mysterious periodic reconnect rather
/// than visible data loss, which is why it went unnoticed.
///
/// Memory is bounded by `SseConfig::max_buffer_size` instead, which caps what
/// the parser RETAINS for an in-progress event — the correct bound for a stream,
/// and one that is soundly accounted since the retained-bytes fix.
fn sse_http_client() -> HttpClient {
    HttpClientBuilder::new().max_body_size(usize::MAX).build()
}

impl SseClient {
    /// Create a new SSE client.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            config: SseConfig::default(),
            http_client: Arc::new(sse_http_client()),
        }
    }

    /// Create with custom configuration.
    #[must_use]
    pub fn with_config(url: impl Into<String>, config: SseConfig) -> Self {
        Self {
            url: url.into(),
            config,
            http_client: Arc::new(sse_http_client()),
        }
    }

    /// Create with custom HTTP client.
    #[must_use]
    pub fn with_http_client(url: impl Into<String>, http_client: HttpClient) -> Self {
        Self {
            url: url.into(),
            config: SseConfig::default(),
            http_client: Arc::new(http_client),
        }
    }

    /// Connect and return an event stream.
    ///
    /// # Errors
    /// Returns a stream error if the HTTP request fails or returns a non-2xx status.
    pub async fn connect(&self) -> StreamResult<SseStream> {
        self.connect_with_last_id(None).await
    }

    /// Connect with a last event ID for resumption.
    ///
    /// # Errors
    /// Returns a stream error if the HTTP request fails or returns a non-2xx status.
    pub async fn connect_with_last_id(
        &self,
        last_event_id: Option<&str>,
    ) -> StreamResult<SseStream> {
        let mut headers = vec![
            (ACCEPT_HEADER.to_string(), SSE_MIME_TYPE.to_string()),
            (CACHE_CONTROL_HEADER.to_string(), NO_CACHE_VALUE.to_string()),
        ];
        if let Some(id) = last_event_id {
            headers.push((LAST_EVENT_ID_HEADER.to_string(), id.to_string()));
        }

        headers.extend(
            self.config
                .headers
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );

        let cx = fcp_async_core::compatibility_cx();
        let request =
            self.http_client
                .request_streaming(&cx, Method::Get, &self.url, headers, Vec::new());
        let response = if let Some(timeout) = self.config.timeout {
            match time::timeout(timeout, request).await {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => return Err(StreamError::from(error)),
                Err(_) => return Err(StreamError::Timeout(timeout)),
            }
        } else {
            request.await?
        };

        if !(200..300).contains(&response.head.status) {
            let head = response.head;
            return Err(http_error_from_head(
                head.status,
                head.reason,
                &head.headers,
            ));
        }

        Ok(SseStream::new(response.body, self.config.max_buffer_size))
    }

    /// Get the URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Get the configuration.
    #[must_use]
    pub const fn config(&self) -> &SseConfig {
        &self.config
    }

    /// Create a reconnecting SSE event stream.
    ///
    /// This preserves the one-shot [`Self::connect`] API while giving callers
    /// an explicit boundary that honors `SseConfig` reconnect settings,
    /// `Last-Event-ID` resumption, `Retry-After` hints, and host backpressure.
    #[must_use]
    pub fn stream(&self) -> ReconnectingSseStream {
        ReconnectingSseStream::new(self.clone())
    }
}

pin_project! {
    #[derive(Debug)]
    struct SseChunkStream {
        #[pin]
        body: Option<ClientIncomingBody<ClientIo>>,
    }
}

impl SseChunkStream {
    const fn new(body: ClientIncomingBody<ClientIo>) -> Self {
        Self { body: Some(body) }
    }
}

impl Stream for SseChunkStream {
    type Item = StreamResult<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        loop {
            let Some(body) = this.body.as_mut().as_pin_mut() else {
                return Poll::Ready(None);
            };

            match ready!(body.poll_frame(cx)) {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.into_data() {
                        return Poll::Ready(Some(Ok(Bytes::copy_from_slice(data.chunk()))));
                    }
                }
                Some(Err(error)) => {
                    this.body.set(None);
                    return Poll::Ready(Some(Err(StreamError::from(error))));
                }
                None => {
                    this.body.set(None);
                    return Poll::Ready(None);
                }
            }
        }
    }
}

pin_project! {
    /// SSE event stream.
    pub struct SseStream {
        #[pin]
        inner: SseChunkStream,
        parser: SseParser,
        pending_events: Vec<SseEvent>,
        max_buffer_size: usize,
    }
}

impl SseStream {
    /// Create a new SSE stream.
    fn new(body: ClientIncomingBody<ClientIo>, max_buffer_size: usize) -> Self {
        let max_buffer_size = clamp_sse_buffer_size(max_buffer_size);
        Self {
            inner: SseChunkStream::new(body),
            parser: SseParser::with_max_data_bytes(max_buffer_size),
            pending_events: Vec::new(),
            max_buffer_size,
        }
    }

    /// Get the last event ID.
    #[must_use]
    pub fn last_event_id(&self) -> Option<&str> {
        self.parser.last_event_id()
    }
}

impl Stream for SseStream {
    type Item = StreamResult<SseEvent>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // Return pending events first
        if !this.pending_events.is_empty() {
            return Poll::Ready(Some(Ok(this.pending_events.remove(0))));
        }

        // Loop until we produce an event, hit a chunk-level error/EOF, or the
        // inner stream actually parks us with a waker. Returning `Pending`
        // after the inner stream returned `Ready` would strand the task,
        // since `Ready` does not register a waker — a chunk that failed to
        // close an event boundary (common with fragmented TCP segments or
        // large multi-chunk events) would hang the consumer indefinitely.
        loop {
            match this.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    let retained_bytes = this.parser.retained_bytes();
                    if let Some(error) =
                        retained_buffer_overflow(retained_bytes, data.len(), *this.max_buffer_size)
                    {
                        return Poll::Ready(Some(Err(error)));
                    }

                    let events = this.parser.parse(&data);
                    if !events.is_empty() {
                        *this.pending_events = events;
                        return Poll::Ready(Some(Ok(this.pending_events.remove(0))));
                    }
                    // No complete events yet; keep draining the inner stream
                    // until it either yields more data or parks with a waker.
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Some(Err(error))),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

type ConnectFuture = Pin<Box<dyn Future<Output = StreamResult<SseStream>>>>;
type ReceiveFuture =
    Pin<Box<dyn Future<Output = (Box<SseStream>, Option<StreamResult<SseEvent>>)>>>;

/// Reconnecting SSE event stream.
pub struct ReconnectingSseStream {
    client: SseClient,
    handler: ReconnectHandler,
    state: ReconnectState,
    last_event_id: Option<String>,
}

enum ReconnectState {
    /// Initial state or between attempts.
    Idle,
    /// Waiting for backoff delay.
    Waiting(Pin<Box<Sleep>>),
    /// Connection attempt in progress.
    Connecting(ConnectFuture),
    /// Active SSE stream ready to receive.
    Connected(Box<SseStream>),
    /// Event receive in progress.
    Receiving(ReceiveFuture),
    /// The stream is finished and will yield `None` from here on.
    ///
    /// Reaching a terminal outcome MUST move the state machine here before
    /// returning. `Some(Err(_))` is a resumable `Stream` item, so a normal
    /// consumer polls again after one — and leaving a *completed*
    /// `Connecting`/`Receiving` future in `state` meant that next poll
    /// re-polled an `async` block that had already returned `Ready`, which
    /// panics with "`async fn` resumed after completion". This variant also
    /// makes the stream properly fused after `None`.
    Terminated,
}

impl ReconnectingSseStream {
    fn new(client: SseClient) -> Self {
        let config = ReconnectConfig::new()
            .with_max_attempts(if client.config.auto_reconnect {
                client.config.max_reconnect_attempts.unwrap_or(u32::MAX)
            } else {
                0
            })
            .with_initial_delay(client.config.reconnect_delay);

        Self {
            client,
            handler: ReconnectHandler::new(config),
            state: ReconnectState::Idle,
            last_event_id: None,
        }
    }

    fn note_event_received(&mut self, event: &SseEvent) {
        if let Some(id) = &event.id {
            self.last_event_id = Some(id.clone());
        }
        self.handler.reset();
    }
}

impl Stream for ReconnectingSseStream {
    type Item = StreamResult<SseEvent>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match &mut self.state {
                ReconnectState::Idle => {
                    let client = self.client.clone();
                    let last_event_id = self.last_event_id.clone();
                    self.state = ReconnectState::Connecting(Box::pin(async move {
                        client.connect_with_last_id(last_event_id.as_deref()).await
                    }));
                }
                ReconnectState::Waiting(delay) => match delay.as_mut().poll(cx) {
                    Poll::Ready(()) => self.state = ReconnectState::Idle,
                    Poll::Pending => return Poll::Pending,
                },
                ReconnectState::Terminated => return Poll::Ready(None),
                ReconnectState::Connecting(future) => match future.as_mut().poll(cx) {
                    Poll::Ready(Ok(stream)) => {
                        self.state = ReconnectState::Connected(Box::new(stream));
                    }
                    Poll::Ready(Err(err)) => {
                        if err.is_terminal_backpressure() || !self.handler.can_reconnect() {
                            self.state = ReconnectState::Terminated;
                            return Poll::Ready(Some(Err(err)));
                        }
                        let delay = reconnect_delay_for_error(&self.handler, &err);
                        self.handler.record_failure();
                        self.state = ReconnectState::Waiting(Box::pin(sleep(delay)));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                ReconnectState::Connected(_) => {
                    if let ReconnectState::Connected(stream) =
                        std::mem::replace(&mut self.state, ReconnectState::Idle)
                    {
                        self.state = ReconnectState::Receiving(Box::pin(async move {
                            let mut stream = stream;
                            let result = stream.next().await;
                            (stream, result)
                        }));
                    }
                }
                ReconnectState::Receiving(future) => match future.as_mut().poll(cx) {
                    Poll::Ready((stream, Some(Ok(event)))) => {
                        self.note_event_received(&event);
                        self.state = ReconnectState::Connected(stream);
                        return Poll::Ready(Some(Ok(event)));
                    }
                    Poll::Ready((stream, Some(Err(err)))) => {
                        drop(stream);
                        if err.is_terminal_backpressure() || !self.handler.can_reconnect() {
                            self.state = ReconnectState::Terminated;
                            return Poll::Ready(Some(Err(err)));
                        }
                        let delay = reconnect_delay_for_error(&self.handler, &err);
                        self.handler.record_failure();
                        self.state = ReconnectState::Waiting(Box::pin(sleep(delay)));
                    }
                    Poll::Ready((stream, None)) => {
                        drop(stream);
                        if !self.handler.can_reconnect() {
                            self.state = ReconnectState::Terminated;
                            return Poll::Ready(None);
                        }
                        let delay = self
                            .handler
                            .config()
                            .delay_for_attempt(self.handler.attempts());
                        self.handler.record_failure();
                        self.state = ReconnectState::Waiting(Box::pin(sleep(delay)));
                    }
                    Poll::Pending => return Poll::Pending,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    fn read_request_head(stream: &mut TcpStream) -> String {
        let mut request = Vec::new();
        let mut buf = [0_u8; 512];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buf).expect("read request head");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buf[..read]);
        }
        String::from_utf8_lossy(&request).into_owned()
    }

    fn write_sse_response(stream: &mut TcpStream, body: &str) {
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/event-stream\r\n\
             Cache-Control: no-cache\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            body.len(),
        );
        stream
            .write_all(response.as_bytes())
            .expect("write SSE response");
        stream.flush().expect("flush SSE response");
    }

    fn spawn_reconnect_resume_server() -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind SSE listener");
        let address = listener.local_addr().expect("listener address");

        let handle = thread::spawn(move || {
            let (mut first, _) = listener.accept().expect("accept first SSE connect");
            let first_request = read_request_head(&mut first);
            // Header-name matching is case-insensitive per RFC 7230: the
            // underlying HTTP client emits header names lowercased on the wire
            // (e.g. `last-event-id`), so compare against a normalized copy.
            let first_request_lc = first_request.to_ascii_lowercase();
            assert!(!first_request_lc.contains("last-event-id:"));
            write_sse_response(&mut first, "id: one\ndata: first\n\n");

            let (mut second, _) = listener.accept().expect("accept resumed SSE connect");
            let second_request = read_request_head(&mut second);
            let second_request_lc = second_request.to_ascii_lowercase();
            assert!(
                second_request_lc.contains("last-event-id: one\r\n"),
                "second request did not resume with last event id: {second_request:?}",
            );
            write_sse_response(&mut second, "id: two\ndata: second\n\n");
        });

        (format!("http://{address}/events"), handle)
    }

    #[test]
    fn sse_503_budget_backpressure_refuses_retry() {
        let headers = vec![
            (
                FCP_BACKPRESSURE_REASON_HEADER.to_string(),
                crate::FCP_BACKPRESSURE_BUDGET_EXHAUSTED.to_string(),
            ),
            ("Retry-After".to_string(), "3".to_string()),
            (
                FCP_BACKPRESSURE_RETRY_AFTER_HEADER.to_string(),
                "9".to_string(),
            ),
        ];

        let err = http_error_from_head(503, "Service Unavailable".to_string(), &headers);

        assert!(err.is_terminal_backpressure());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(9)));
    }

    #[test]
    fn sse_429_preserves_retry_after_for_reconnect_backoff() {
        let headers = vec![("Retry-After".to_string(), "7".to_string())];

        let err = http_error_from_head(429, "Too Many Requests".to_string(), &headers);

        assert_eq!(err.retry_after(), Some(Duration::from_secs(7)));
    }

    #[test]
    fn sse_generic_503_preserves_retry_after_when_no_fcp_backpressure_header() {
        // A generic upstream returning 503 with Retry-After must not lose
        // the hint just because the FCP backpressure reason header is
        // absent — that fall-through previously discarded the value.
        let headers = vec![("Retry-After".to_string(), "13".to_string())];

        let err = http_error_from_head(503, "Service Unavailable".to_string(), &headers);

        assert_eq!(err.retry_after(), Some(Duration::from_secs(13)));
        assert!(!err.is_terminal_backpressure());
    }

    #[test]
    fn sse_other_status_does_not_set_retry_after() {
        let headers = vec![("Retry-After".to_string(), "5".to_string())];

        let err = http_error_from_head(500, "Internal Server Error".to_string(), &headers);

        // Retry-After on a non-rate-limited 5xx isn't part of the SSE
        // reconnect-budget contract; ignore it.
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn reconnecting_sse_delay_uses_retry_after_when_server_requests_longer_wait() {
        let handler = ReconnectHandler::new(
            ReconnectConfig::new()
                .with_initial_delay(Duration::from_millis(100))
                .with_jitter(false),
        );
        let err = StreamError::HttpError {
            status: 429,
            message: "Too Many Requests".to_string(),
            retry_after: Some(Duration::from_secs(2)),
        };

        assert_eq!(
            reconnect_delay_for_error(&handler, &err),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn reconnecting_sse_delay_keeps_backoff_when_retry_after_is_shorter() {
        let handler = ReconnectHandler::new(
            ReconnectConfig::new()
                .with_initial_delay(Duration::from_secs(3))
                .with_jitter(false),
        );
        let err = StreamError::HttpError {
            status: 429,
            message: "Too Many Requests".to_string(),
            retry_after: Some(Duration::from_secs(1)),
        };

        assert_eq!(
            reconnect_delay_for_error(&handler, &err),
            Duration::from_secs(3)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn reconnecting_sse_stream_resumes_with_last_event_id_after_eof() {
        let (url, server) = spawn_reconnect_resume_server();
        let client = SseClient::with_config(
            url,
            SseConfig::new()
                .with_timeout(Duration::from_secs(5))
                .with_max_reconnect_attempts(2)
                .with_reconnect_delay(Duration::from_millis(1)),
        );
        let mut stream = client.stream();

        let first = time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("first SSE event timed out")
            .expect("first SSE event present")
            .expect("first SSE event ok");
        assert_eq!(first.id.as_deref(), Some("one"));
        assert_eq!(first.data, "first");

        let second = time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("second SSE event timed out")
            .expect("second SSE event present")
            .expect("second SSE event ok");
        assert_eq!(second.id.as_deref(), Some("two"));
        assert_eq!(second.data, "second");

        server.join().expect("SSE resume server thread");
    }

    #[test]
    fn test_parse_simple_event() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data: hello world\n\n");
        let events = parser.parse(&data);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello world");
        assert_eq!(events[0].event, None);
    }

    #[test]
    fn test_parse_typed_event() {
        let mut parser = SseParser::new();
        let data = Bytes::from("event: message\ndata: hello\n\n");
        let events = parser.parse(&data);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, Some("message".to_string()));
        assert_eq!(events[0].data, "hello");
    }

    #[test]
    fn test_parse_multiline_data() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data: line 1\ndata: line 2\ndata: line 3\n\n");
        let events = parser.parse(&data);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "line 1\nline 2\nline 3");
    }

    #[test]
    fn test_parse_event_with_id() {
        let mut parser = SseParser::new();
        let data = Bytes::from("id: 123\ndata: test\n\n");
        let events = parser.parse(&data);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, Some("123".to_string()));
        assert_eq!(parser.last_event_id(), Some("123"));
    }

    #[test]
    fn test_parse_retry() {
        let mut parser = SseParser::new();
        let data = Bytes::from("retry: 5000\ndata: test\n\n");
        let events = parser.parse(&data);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].retry, Some(5000));
    }

    #[test]
    fn test_parse_comment() {
        let mut parser = SseParser::new();
        let data = Bytes::from(": this is a comment\ndata: actual data\n\n");
        let events = parser.parse(&data);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "actual data");
    }

    #[test]
    fn test_parse_multiple_events() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data: event1\n\ndata: event2\n\n");
        let events = parser.parse(&data);

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].data, "event1");
        assert_eq!(events[1].data, "event2");
    }

    #[test]
    fn test_parse_incomplete_event() {
        let mut parser = SseParser::new();

        // First chunk
        let data1 = Bytes::from("data: hello ");
        let events1 = parser.parse(&data1);
        assert!(events1.is_empty());

        // Second chunk
        let data2 = Bytes::from("world\n\n");
        let events2 = parser.parse(&data2);
        assert_eq!(events2.len(), 1);
        assert_eq!(events2[0].data, "hello world");
    }

    #[test]
    fn test_sse_event_json() {
        #[derive(serde::Deserialize)]
        struct Data {
            message: String,
        }

        let event = SseEvent::new(r#"{"message": "hello"}"#);
        let data: Data = event.json().unwrap();
        assert_eq!(data.message, "hello");
    }

    #[test]
    fn test_sse_event_is_event() {
        let event = SseEvent::new("data").with_event("message");
        assert!(event.is_event("message"));
        assert!(!event.is_event("error"));
    }

    // ── New tests ──

    #[test]
    fn test_sse_event_new_fields() {
        let event = SseEvent::new("test data");
        assert_eq!(event.data, "test data");
        assert_eq!(event.event, None);
        assert_eq!(event.id, None);
        assert_eq!(event.retry, None);
    }

    #[test]
    fn test_sse_event_with_id() {
        let event = SseEvent::new("data").with_id("42");
        assert_eq!(event.id, Some("42".to_string()));
    }

    #[test]
    fn test_sse_event_json_failure() {
        let event = SseEvent::new("not json");
        let result: Result<serde_json::Value, _> = event.json();
        assert!(result.is_err());
    }

    #[test]
    fn test_sse_event_is_event_without_type() {
        let event = SseEvent::new("data");
        assert!(!event.is_event("message"));
    }

    #[test]
    fn test_parse_crlf_line_endings() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data: hello\r\n\r\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello");
    }

    #[test]
    fn test_parse_cr_line_endings() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data: hello\r\r");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello");
    }

    #[test]
    fn test_parse_id_with_null_ignored() {
        let mut parser = SseParser::new();
        let data = Bytes::from("id: abc\0def\ndata: test\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        // id containing null should be ignored per spec
        assert_eq!(events[0].id, None);
    }

    #[test]
    fn test_parse_retry_non_numeric_ignored() {
        let mut parser = SseParser::new();
        let data = Bytes::from("retry: abc\ndata: test\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].retry, None);
    }

    #[test]
    fn test_parse_field_without_colon() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data\n\n");
        let events = parser.parse(&data);
        // "data" without colon → field "data", value "" → data_lines has ""
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "");
    }

    #[test]
    fn test_parse_empty_dispatch_no_event() {
        let mut parser = SseParser::new();
        // event type set but no data lines → no event dispatched
        let data = Bytes::from("event: test\n\n");
        let events = parser.parse(&data);
        assert!(events.is_empty());
    }

    #[test]
    fn test_last_event_id_persists() {
        let mut parser = SseParser::new();
        let data = Bytes::from("id: first\ndata: a\n\ndata: b\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, Some("first".to_string()));
        // Second event has no id field, but last_event_id persists
        assert_eq!(parser.last_event_id(), Some("first"));
    }

    #[test]
    fn test_sse_config_default() {
        let config = SseConfig::default();
        assert_eq!(config.timeout, None);
        assert_eq!(config.max_buffer_size, 1024 * 1024);
        assert!(config.headers.is_empty());
        assert!(config.auto_reconnect);
        assert_eq!(config.max_reconnect_attempts, Some(10));
        assert_eq!(config.reconnect_delay, Duration::from_secs(1));
    }

    #[test]
    fn test_sse_config_builder() {
        let config = SseConfig::new()
            .with_timeout(Duration::from_secs(30))
            .with_max_buffer_size(2048)
            .with_header("Authorization", "Bearer token")
            .with_auto_reconnect(false)
            .with_max_reconnect_attempts(5)
            .with_reconnect_delay(Duration::from_millis(500));

        assert_eq!(config.timeout, Some(Duration::from_secs(30)));
        assert_eq!(config.max_buffer_size, 2048);
        assert_eq!(
            config.headers.get("Authorization"),
            Some(&"Bearer token".to_string())
        );
        assert!(!config.auto_reconnect);
        assert_eq!(config.max_reconnect_attempts, Some(5));
        assert_eq!(config.reconnect_delay, Duration::from_millis(500));
    }

    #[test]
    fn test_sse_client_accessors() {
        let client = SseClient::new("https://example.com/events");
        assert_eq!(client.url(), "https://example.com/events");
        assert_eq!(client.config().max_buffer_size, 1024 * 1024);
    }

    #[test]
    fn test_sse_client_with_config() {
        let config = SseConfig::new().with_max_buffer_size(4096);
        let client = SseClient::with_config("https://example.com/events", config);
        assert_eq!(client.url(), "https://example.com/events");
        assert_eq!(client.config().max_buffer_size, 4096);
    }

    // ── SseEvent trait impls ──

    #[test]
    fn test_sse_event_clone() {
        let event = SseEvent::new("data").with_event("msg").with_id("1");
        let cloned = event.clone();
        assert_eq!(event, cloned);
    }

    #[test]
    fn test_sse_event_partial_eq() {
        let a = SseEvent::new("data").with_event("msg");
        let b = SseEvent::new("data").with_event("msg");
        let c = SseEvent::new("other");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_sse_event_debug() {
        let event = SseEvent::new("test");
        let debug = format!("{event:?}");
        assert!(debug.contains("SseEvent"));
        assert!(debug.contains("test"));
    }

    #[test]
    fn test_sse_event_chained_builder() {
        let event = SseEvent::new("payload").with_event("update").with_id("42");
        assert_eq!(event.data, "payload");
        assert_eq!(event.event, Some("update".to_string()));
        assert_eq!(event.id, Some("42".to_string()));
        assert_eq!(event.retry, None);
    }

    // ── SseParser edge cases ──

    #[test]
    fn test_parse_unknown_field_ignored() {
        let mut parser = SseParser::new();
        let data = Bytes::from("unknown: value\ndata: hello\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello");
    }

    #[test]
    fn test_parse_data_with_colon_in_value() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data: key:value:extra\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "key:value:extra");
    }

    #[test]
    fn test_parse_data_no_space_after_colon() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data:no_space\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "no_space");
    }

    #[test]
    fn test_parse_empty_data_field() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data:\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "");
    }

    #[test]
    fn test_parse_only_comments() {
        let mut parser = SseParser::new();
        let data = Bytes::from(": comment 1\n: comment 2\n\n");
        let events = parser.parse(&data);
        assert!(events.is_empty());
    }

    #[test]
    fn test_parse_event_type_reset_after_dispatch() {
        let mut parser = SseParser::new();
        let data = Bytes::from("event: first\ndata: a\n\ndata: b\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event, Some("first".to_string()));
        // Event type resets after dispatch
        assert_eq!(events[1].event, None);
    }

    #[test]
    fn test_parse_multiple_id_updates() {
        let mut parser = SseParser::new();
        let data = Bytes::from("id: 1\ndata: a\n\nid: 2\ndata: b\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, Some("1".to_string()));
        assert_eq!(events[1].id, Some("2".to_string()));
        assert_eq!(parser.last_event_id(), Some("2"));
    }

    #[test]
    fn test_parse_retry_overrides() {
        let mut parser = SseParser::new();
        let data = Bytes::from("retry: 1000\nretry: 2000\ndata: test\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        // Last retry value wins
        assert_eq!(events[0].retry, Some(2000));
    }

    #[test]
    fn test_parse_incremental_three_chunks() {
        let mut parser = SseParser::new();
        assert!(parser.parse(&Bytes::from("da")).is_empty());
        assert!(parser.parse(&Bytes::from("ta: hel")).is_empty());
        let events = parser.parse(&Bytes::from("lo\n\n"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello");
    }

    #[test]
    fn test_parse_cursor_advances_over_retained_incomplete_line() {
        let mut parser = SseParser::new();

        assert!(parser.parse(&Bytes::from("data: retained")).is_empty());
        assert_eq!(parser.parse_cursor, parser.buffer.len());

        assert!(parser.parse(&Bytes::from(" still incomplete")).is_empty());
        assert_eq!(parser.parse_cursor, parser.buffer.len());

        let events = parser.parse(&Bytes::from("\n\n"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "retained still incomplete");
        assert_eq!(parser.parse_cursor, 0);
        assert_eq!(parser.retained_bytes(), 0);
    }

    #[test]
    fn test_parse_mixed_line_endings() {
        let mut parser = SseParser::new();
        // Mix of \n, \r\n, and \r
        let data = Bytes::from("data: a\ndata: b\r\n\r\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "a\nb");
    }

    /// WHATWG SSE: CRLF is a single line terminator even when the CR and
    /// LF arrive in separate network chunks. A naive parser that consumes
    /// the CR before seeing the LF would re-interpret the trailing LF as
    /// an empty-line dispatch trigger, producing a spurious event split.
    #[test]
    fn test_parse_crlf_split_across_chunks_is_single_terminator() {
        let mut parser = SseParser::new();
        let first = parser.parse(&Bytes::from("data: hello\r"));
        let second = parser.parse(&Bytes::from("\ndata: foo\n\n"));
        let events: Vec<_> = first.into_iter().chain(second).collect();
        assert_eq!(
            events.len(),
            1,
            "split CRLF must not dispatch an event between the CR and LF"
        );
        assert_eq!(events[0].data, "hello\nfoo");
    }

    /// Same hazard with a one-byte LF chunk landing immediately after the
    /// CR chunk and no further data lines before the blank-line dispatch.
    #[test]
    fn test_parse_crlf_split_across_chunks_dispatches_once() {
        let mut parser = SseParser::new();
        let first = parser.parse(&Bytes::from("data: hello\r"));
        let second = parser.parse(&Bytes::from("\n\n"));
        let events: Vec<_> = first.into_iter().chain(second).collect();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello");
    }

    /// When a chunk-ending CR is followed by a non-LF byte in the next
    /// chunk, the spec says the CR was a standalone terminator. The LF-
    /// swallow only triggers on a leading LF, not on arbitrary bytes.
    #[test]
    fn test_parse_trailing_cr_followed_by_non_lf_keeps_separate_terminators() {
        let mut parser = SseParser::new();
        let first = parser.parse(&Bytes::from("data: a\r"));
        let second = parser.parse(&Bytes::from("data: b\n\n"));
        let events: Vec<_> = first.into_iter().chain(second).collect();
        // The CR ends the "data: a" line; the "\n\n" closes the event with
        // data lines ["a", "b"].
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "a\nb");
    }

    #[test]
    fn test_parse_empty_id_field() {
        let mut parser = SseParser::new();
        // Set ID first, then empty ID resets per spec
        let data = Bytes::from("id: old\ndata: a\n\nid:\ndata: b\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, Some("old".to_string()));
        // Empty id field sets event_id to empty string
        assert_eq!(events[1].id, Some(String::new()));
    }

    #[test]
    fn test_parse_comment_between_fields() {
        let mut parser = SseParser::new();
        let data = Bytes::from("event: msg\n: comment\ndata: hello\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, Some("msg".to_string()));
        assert_eq!(events[0].data, "hello");
    }

    // ── SseConfig trait impls ──

    #[test]
    fn test_sse_config_clone() {
        let config = SseConfig::new()
            .with_timeout(Duration::from_secs(5))
            .with_header("X-Key", "val");
        let moved = config;
        assert_eq!(moved.timeout, Some(Duration::from_secs(5)));
        assert_eq!(moved.headers.get("X-Key"), Some(&"val".to_string()));
    }

    #[test]
    fn test_sse_config_debug() {
        let config = SseConfig::new();
        let debug = format!("{config:?}");
        assert!(debug.contains("SseConfig"));
    }

    #[test]
    fn test_sse_config_debug_redacts_header_values() {
        let config = SseConfig::new()
            .with_header("Authorization", "Bearer abc123")
            .with_header("Cookie", "session=secret");
        let debug = format!("{config:?}");
        assert!(debug.contains("Authorization"));
        assert!(debug.contains("Cookie"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("Bearer abc123"));
        assert!(!debug.contains("session=secret"));
    }

    #[test]
    fn test_sse_config_new_equals_default() {
        let new = SseConfig::new();
        let default = SseConfig::default();
        assert_eq!(new.timeout, default.timeout);
        assert_eq!(new.max_buffer_size, default.max_buffer_size);
        assert_eq!(new.auto_reconnect, default.auto_reconnect);
        assert_eq!(new.max_reconnect_attempts, default.max_reconnect_attempts);
        assert_eq!(new.reconnect_delay, default.reconnect_delay);
    }

    #[test]
    fn test_sse_config_multiple_headers() {
        let config = SseConfig::new()
            .with_header("Authorization", "Bearer abc")
            .with_header("X-Custom", "value");
        assert_eq!(config.headers.len(), 2);
        assert_eq!(
            config.headers.get("Authorization"),
            Some(&"Bearer abc".to_string())
        );
        assert_eq!(config.headers.get("X-Custom"), Some(&"value".to_string()));
    }

    // ── SseClient tests ──

    #[test]
    fn test_sse_client_with_http_client() {
        let http_client = HttpClient::new();
        let client = SseClient::with_http_client("https://example.com/events", http_client);
        assert_eq!(client.url(), "https://example.com/events");
    }

    #[test]
    fn test_sse_client_debug() {
        let client = SseClient::new("https://example.com/sse");
        let debug = format!("{client:?}");
        assert!(debug.contains("SseClient"));
    }

    #[test]
    fn test_sse_client_debug_redacts_header_values() {
        let client = SseClient::with_config(
            "https://example.com/sse",
            SseConfig::new().with_header("Authorization", "Bearer hidden"),
        );
        let debug = format!("{client:?}");
        assert!(debug.contains("Authorization"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("Bearer hidden"));
    }

    #[test]
    fn test_sse_client_clone() {
        let client = SseClient::new("https://example.com/sse");
        let moved = client;
        assert_eq!(moved.url(), "https://example.com/sse");
    }

    // ── SseEvent JSON edge cases ──

    #[test]
    fn test_sse_event_json_array() {
        let event = SseEvent::new("[1, 2, 3]");
        let result: Vec<i32> = event.json().unwrap();
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn test_sse_event_json_empty_object() {
        let event = SseEvent::new("{}");
        let result: serde_json::Value = event.json().unwrap();
        assert!(result.is_object());
        assert!(result.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_sse_event_is_event_empty_string() {
        let event = SseEvent::new("data").with_event("");
        assert!(event.is_event(""));
        assert!(!event.is_event("message"));
    }

    // ── SseEvent: unicode content ───────────────────────────────────────

    #[test]
    fn test_sse_event_unicode_data() {
        let event = SseEvent::new("\u{1F600}\u{1F4A9}\u{2764}\u{FE0F}");
        assert_eq!(event.data, "\u{1F600}\u{1F4A9}\u{2764}\u{FE0F}");
    }

    #[test]
    fn test_sse_event_unicode_event_type() {
        let event = SseEvent::new("data").with_event("\u{00C9}v\u{00E9}nement");
        assert!(event.is_event("\u{00C9}v\u{00E9}nement"));
    }

    #[test]
    fn test_sse_event_unicode_id() {
        let event = SseEvent::new("data").with_id("\u{00FC}ber-42");
        assert_eq!(event.id, Some("\u{00FC}ber-42".to_string()));
    }

    // ── SseEvent: large data ────────────────────────────────────────────

    #[test]
    fn test_sse_event_large_data() {
        let big = "x".repeat(100_000);
        let event = SseEvent::new(big);
        assert_eq!(event.data.len(), 100_000);
    }

    #[test]
    fn test_sse_event_empty_data() {
        let event = SseEvent::new("");
        assert_eq!(event.data, "");
    }

    // ── SseEvent: json edge cases ───────────────────────────────────────

    #[test]
    fn test_sse_event_json_nested_object() {
        let event = SseEvent::new(r#"{"a":{"b":{"c":1}}}"#);
        let val: serde_json::Value = event.json().unwrap();
        assert_eq!(val["a"]["b"]["c"], 1);
    }

    #[test]
    fn test_sse_event_json_number() {
        let event = SseEvent::new("42");
        let val: i64 = event.json().unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn test_sse_event_json_string() {
        let event = SseEvent::new(r#""hello""#);
        let val: String = event.json().unwrap();
        assert_eq!(val, "hello");
    }

    #[test]
    fn test_sse_event_json_bool() {
        let event = SseEvent::new("false");
        let val: bool = event.json().unwrap();
        assert!(!val);
    }

    #[test]
    fn test_sse_event_json_null() {
        let event = SseEvent::new("null");
        let val: serde_json::Value = event.json().unwrap();
        assert!(val.is_null());
    }

    // ── SseParser: data overflow protection ─────────────────────────────

    #[test]
    fn test_parse_data_exceeds_10mb_ignored() {
        use std::fmt::Write;
        let mut parser = SseParser::new();
        // Push enough data lines to exceed the 10MB limit
        let big_line = "a".repeat(1_000_000);
        let mut input = String::new();
        for _ in 0..11 {
            let _ = writeln!(input, "data: {big_line}");
        }
        input.push('\n');
        let events = parser.parse(&Bytes::from(input));
        // Event dispatches, but not all data lines were accepted
        assert_eq!(events.len(), 1);
        assert!(events[0].data.len() <= 10 * 1024 * 1024);
    }

    #[test]
    fn test_parse_data_honors_custom_retained_limit() {
        use std::fmt::Write;

        let mut parser = SseParser::with_max_data_bytes(12 * 1024 * 1024);
        let big_line = "a".repeat(11 * 1024 * 1024);
        let mut input = String::new();
        let _ = writeln!(input, "data: {big_line}");
        input.push('\n');

        let events = parser.parse(&Bytes::from(input));

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data.len(), big_line.len());
    }

    #[test]
    fn test_retained_bytes_counts_payload_and_raw_buffer() {
        let mut parser = SseParser::new();

        let events = parser.parse(&Bytes::from("data: hello\n"));
        assert!(events.is_empty());
        assert_eq!(parser.retained_bytes(), "hello".len() + DATA_LINE_OVERHEAD);

        let events = parser.parse(&Bytes::from("data: world"));
        assert!(events.is_empty());
        assert_eq!(
            parser.retained_bytes(),
            "hello".len() + DATA_LINE_OVERHEAD + "data: world".len()
        );

        let events = parser.parse(&Bytes::from("\n\n"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello\nworld");
        assert_eq!(parser.retained_bytes(), 0);
    }

    /// A peer that streams `data:` lines with empty values, and never sends
    /// the blank line that would dispatch the event, must still be bounded by
    /// `max_data_bytes`. Payload-only accounting charged such a line zero, so
    /// `data_lines` grew without limit while `retained_bytes()` stayed pinned
    /// at 0 and the `BufferOverflow` guard never fired.
    #[test]
    fn test_empty_data_lines_are_bounded_by_the_retained_limit() {
        const MAX_DATA_BYTES: usize = 4096;
        let mut parser = SseParser::with_max_data_bytes(MAX_DATA_BYTES);

        // Far more empty `data:` lines than the cap could ever admit.
        let flood = "data:\n".repeat(100_000);
        let events = parser.parse(&Bytes::from(flood));

        assert!(events.is_empty(), "no blank line, so nothing dispatches");
        assert!(
            parser.retained_bytes() <= MAX_DATA_BYTES,
            "retained accounting must stay within the cap, got {}",
            parser.retained_bytes()
        );
        assert!(
            parser.data_lines.len() <= MAX_DATA_BYTES / DATA_LINE_OVERHEAD,
            "retained line count must be bounded, got {}",
            parser.data_lines.len()
        );
    }

    /// The `\n` separators `dispatch_event` inserts are part of the retained
    /// footprint, so a dispatched payload cannot exceed the configured cap.
    #[test]
    fn test_dispatched_data_stays_within_retained_limit() {
        const MAX_DATA_BYTES: usize = 4096;
        let mut parser = SseParser::with_max_data_bytes(MAX_DATA_BYTES);

        let mut input = "data: a\n".repeat(5000);
        input.push('\n');
        let events = parser.parse(&Bytes::from(input));

        assert_eq!(events.len(), 1);
        assert!(
            events[0].data.len() <= MAX_DATA_BYTES,
            "dispatched payload must respect the cap, got {}",
            events[0].data.len()
        );
    }

    // ── SseParser: multiple sequential parses ───────────────────────────

    #[test]
    fn test_parse_multiple_independent_events() {
        let mut parser = SseParser::new();
        for i in 0..5 {
            let data = Bytes::from(format!("data: event{i}\n\n"));
            let events = parser.parse(&data);
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].data, format!("event{i}"));
        }
    }

    #[test]
    fn test_parse_interleaved_events_and_comments() {
        let mut parser = SseParser::new();
        let data = Bytes::from(": heartbeat\ndata: a\n\n: another heartbeat\ndata: b\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].data, "a");
        assert_eq!(events[1].data, "b");
    }

    #[test]
    fn test_parse_event_with_all_fields() {
        let mut parser = SseParser::new();
        let data = Bytes::from("event: update\nid: 99\nretry: 3000\ndata: payload\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, Some("update".to_string()));
        assert_eq!(events[0].id, Some("99".to_string()));
        assert_eq!(events[0].retry, Some(3000));
        assert_eq!(events[0].data, "payload");
    }

    // ── SseParser: field edge cases ─────────────────────────────────────

    #[test]
    fn test_parse_retry_zero() {
        let mut parser = SseParser::new();
        let data = Bytes::from("retry: 0\ndata: test\n\n");
        let events = parser.parse(&data);
        assert_eq!(events[0].retry, Some(0));
    }

    #[test]
    fn test_parse_retry_large_value() {
        let mut parser = SseParser::new();
        let data = Bytes::from("retry: 999999999\ndata: test\n\n");
        let events = parser.parse(&data);
        assert_eq!(events[0].retry, Some(999_999_999));
    }

    #[test]
    fn test_parse_data_with_spaces() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data:  leading space\n\n");
        let events = parser.parse(&data);
        // Per spec, one leading space is stripped after colon
        assert_eq!(events[0].data, " leading space");
    }

    #[test]
    fn test_parse_multiple_empty_lines() {
        let mut parser = SseParser::new();
        // Two empty lines after data field = dispatch + empty dispatch (no event)
        let data = Bytes::from("data: hello\n\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
    }

    // ── SseConfig: builder edge cases ───────────────────────────────────

    #[test]
    fn test_sse_config_zero_buffer() {
        let config = SseConfig::new().with_max_buffer_size(0);
        assert_eq!(config.max_buffer_size, 0);
    }

    #[test]
    fn test_sse_config_large_buffer() {
        let config = SseConfig::new().with_max_buffer_size(usize::MAX);
        assert_eq!(config.max_buffer_size, MAX_SSE_BUFFER_SIZE);
    }

    #[test]
    fn test_retained_buffer_overflow_clamps_unbounded_config() {
        let stream_err =
            retained_buffer_overflow(MAX_SSE_BUFFER_SIZE, 1, usize::MAX).expect("overflow");
        assert!(matches!(
            stream_err,
            StreamError::BufferOverflow { size, limit }
                if size == MAX_SSE_BUFFER_SIZE + 1 && limit == MAX_SSE_BUFFER_SIZE
        ));
    }

    #[test]
    fn test_sse_config_zero_reconnect_delay() {
        let config = SseConfig::new().with_reconnect_delay(Duration::ZERO);
        assert_eq!(config.reconnect_delay, Duration::ZERO);
    }

    #[test]
    fn test_sse_config_header_overwrite() {
        let config = SseConfig::new()
            .with_header("Key", "val1")
            .with_header("Key", "val2");
        assert_eq!(config.headers.get("Key"), Some(&"val2".to_string()));
        assert_eq!(config.headers.len(), 1);
    }

    #[test]
    fn test_sse_config_auto_reconnect_toggle() {
        let config = SseConfig::new()
            .with_auto_reconnect(true)
            .with_auto_reconnect(false)
            .with_auto_reconnect(true);
        assert!(config.auto_reconnect);
    }

    #[test]
    fn test_sse_config_max_reconnect_zero() {
        let config = SseConfig::new().with_max_reconnect_attempts(0);
        assert_eq!(config.max_reconnect_attempts, Some(0));
    }

    // ── SseParser: incremental multi-field parsing ──────────────────────

    #[test]
    fn test_parse_incremental_event_type_then_data() {
        let mut parser = SseParser::new();
        assert!(parser.parse(&Bytes::from("event: up")).is_empty());
        assert!(parser.parse(&Bytes::from("date\n")).is_empty());
        let events = parser.parse(&Bytes::from("data: payload\n\n"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, Some("update".to_string()));
        assert_eq!(events[0].data, "payload");
    }

    #[test]
    fn test_parse_incremental_id_across_chunks() {
        let mut parser = SseParser::new();
        assert!(parser.parse(&Bytes::from("id: abc")).is_empty());
        assert!(parser.parse(&Bytes::from("123\n")).is_empty());
        let events = parser.parse(&Bytes::from("data: test\n\n"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, Some("abc123".to_string()));
    }

    // ── SseParser: retry field edge cases ───────────────────────────────

    #[test]
    fn test_parse_retry_negative_ignored() {
        let mut parser = SseParser::new();
        let data = Bytes::from("retry: -100\ndata: test\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        // Negative values can't parse as u64, so retry is None
        assert_eq!(events[0].retry, None);
    }

    #[test]
    fn test_parse_retry_float_ignored() {
        let mut parser = SseParser::new();
        let data = Bytes::from("retry: 1.5\ndata: test\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].retry, None);
    }

    #[test]
    fn test_parse_retry_empty_ignored() {
        let mut parser = SseParser::new();
        let data = Bytes::from("retry:\ndata: test\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].retry, None);
    }

    // ── SseParser: last_event_id updates ────────────────────────────────

    #[test]
    fn test_last_event_id_not_updated_without_id_field() {
        let mut parser = SseParser::new();
        // First event sets ID
        parser.parse(&Bytes::from("id: first\ndata: a\n\n"));
        assert_eq!(parser.last_event_id(), Some("first"));

        // Second event has no ID; last_event_id stays
        parser.parse(&Bytes::from("data: b\n\n"));
        assert_eq!(parser.last_event_id(), Some("first"));
    }

    #[test]
    fn test_last_event_id_updated_to_empty() {
        let mut parser = SseParser::new();
        parser.parse(&Bytes::from("id: abc\ndata: a\n\n"));
        assert_eq!(parser.last_event_id(), Some("abc"));

        // Empty id: field sets event_id to empty string
        parser.parse(&Bytes::from("id:\ndata: b\n\n"));
        assert_eq!(parser.last_event_id(), Some(""));
    }

    // ── SseParser: data_bytes_len reset after dispatch ──────────────────

    #[test]
    fn test_parse_data_bytes_reset_after_dispatch() {
        let mut parser = SseParser::new();
        // First event with some data
        let events = parser.parse(&Bytes::from("data: hello world\n\n"));
        assert_eq!(events.len(), 1);

        // Second event should accept data fine (counter was reset)
        let events = parser.parse(&Bytes::from("data: another message\n\n"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "another message");
    }

    // ── SseEvent: PartialEq edge cases ──────────────────────────────────

    #[test]
    fn test_sse_event_ne_different_id() {
        let a = SseEvent::new("data").with_id("1");
        let b = SseEvent::new("data").with_id("2");
        assert_ne!(a, b);
    }

    #[test]
    fn test_sse_event_ne_different_event_type() {
        let a = SseEvent::new("data").with_event("msg");
        let b = SseEvent::new("data").with_event("err");
        assert_ne!(a, b);
    }

    #[test]
    fn test_sse_event_eq_both_with_retry() {
        let mut a = SseEvent::new("data");
        a.retry = Some(1000);
        let mut b = SseEvent::new("data");
        b.retry = Some(1000);
        assert_eq!(a, b);
    }

    #[test]
    fn test_sse_event_ne_different_retry() {
        let mut a = SseEvent::new("data");
        a.retry = Some(1000);
        let mut b = SseEvent::new("data");
        b.retry = Some(2000);
        assert_ne!(a, b);
    }

    // ── SseClient: URL handling ─────────────────────────────────────────

    #[test]
    fn test_sse_client_url_with_query_params() {
        let client = SseClient::new("https://example.com/events?cursor=abc&channel=test");
        assert_eq!(
            client.url(),
            "https://example.com/events?cursor=abc&channel=test"
        );
    }

    #[test]
    fn test_sse_client_url_with_fragment() {
        let client = SseClient::new("https://example.com/events#section");
        assert_eq!(client.url(), "https://example.com/events#section");
    }

    // ── SseParser: unicode in data fields ──

    #[test]
    fn test_parse_unicode_data() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data: \u{1F600} hello \u{4E16}\u{754C}\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert!(events[0].data.contains('\u{1F600}'));
        assert!(events[0].data.contains('\u{4E16}'));
    }

    #[test]
    fn test_parse_unicode_event_type() {
        let mut parser = SseParser::new();
        let data = Bytes::from("event: \u{00E9}v\u{00E9}nement\ndata: payload\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, Some("\u{00E9}v\u{00E9}nement".to_string()));
    }

    #[test]
    fn test_parse_unicode_id() {
        let mut parser = SseParser::new();
        let data = Bytes::from("id: \u{00FC}ber-42\ndata: test\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, Some("\u{00FC}ber-42".to_string()));
    }

    // ── SseParser: complex multi-event scenarios ──

    #[test]
    fn test_parse_ten_events_sequentially() {
        use std::fmt::Write;
        let mut parser = SseParser::new();
        let mut input = String::new();
        for i in 0..10 {
            let _ = write!(input, "data: event-{i}\n\n");
        }
        let events = parser.parse(&Bytes::from(input));
        assert_eq!(events.len(), 10);
        for (i, evt) in events.iter().enumerate() {
            assert_eq!(evt.data, format!("event-{i}"));
        }
    }

    #[test]
    fn test_parse_event_with_multiple_data_lines_and_id() {
        let mut parser = SseParser::new();
        let data = Bytes::from("id: 77\nevent: batch\ndata: line1\ndata: line2\ndata: line3\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "line1\nline2\nline3");
        assert_eq!(events[0].id, Some("77".to_string()));
        assert_eq!(events[0].event, Some("batch".to_string()));
    }

    #[test]
    fn test_parse_alternating_comments_and_events() {
        let mut parser = SseParser::new();
        let data = Bytes::from(": ping\ndata: a\n\n: ping\ndata: b\n\n: ping\ndata: c\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].data, "a");
        assert_eq!(events[1].data, "b");
        assert_eq!(events[2].data, "c");
    }

    // ── SseEvent: builder with all fields ──

    #[test]
    fn test_sse_event_full_construction() {
        let mut event = SseEvent::new("payload").with_event("update").with_id("123");
        event.retry = Some(5000);
        assert_eq!(event.data, "payload");
        assert_eq!(event.event, Some("update".to_string()));
        assert_eq!(event.id, Some("123".to_string()));
        assert_eq!(event.retry, Some(5000));
    }

    #[test]
    fn test_sse_event_clone_independence() {
        let original = SseEvent::new("data").with_event("msg").with_id("1");
        let cloned = original.clone();
        // Verify they are equal but independent
        assert_eq!(original, cloned);
        assert_eq!(original.data, cloned.data);
        assert_eq!(original.event, cloned.event);
        assert_eq!(original.id, cloned.id);
    }

    // ── SseConfig: clone preserves all fields ──

    #[test]
    fn test_sse_config_clone_all_fields() {
        let config = SseConfig::new()
            .with_timeout(Duration::from_secs(30))
            .with_max_buffer_size(4096)
            .with_header("Auth", "Bearer tok")
            .with_auto_reconnect(false)
            .with_max_reconnect_attempts(3)
            .with_reconnect_delay(Duration::from_millis(500));
        let cloned = config.clone();
        assert_eq!(config.timeout, cloned.timeout);
        assert_eq!(config.max_buffer_size, cloned.max_buffer_size);
        assert_eq!(config.auto_reconnect, cloned.auto_reconnect);
        assert_eq!(config.max_reconnect_attempts, cloned.max_reconnect_attempts);
        assert_eq!(config.reconnect_delay, cloned.reconnect_delay);
        assert_eq!(config.headers.get("Auth"), cloned.headers.get("Auth"));
    }

    // ── SseParser: empty buffer initially ──

    #[test]
    fn test_parser_initial_state_empty() {
        let parser = SseParser::new();
        assert!(parser.last_event_id().is_none());
    }

    #[test]
    fn test_parser_parse_empty_bytes() {
        let mut parser = SseParser::new();
        let events = parser.parse(&Bytes::new());
        assert!(events.is_empty());
    }

    // ── SseParser: data field with only whitespace ──

    #[test]
    fn test_parse_data_only_spaces() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data:    \n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        // One leading space stripped, rest preserved
        assert_eq!(events[0].data, "   ");
    }

    // ── SseEvent: JSON with unicode keys ──

    #[test]
    fn test_sse_event_json_unicode_key() {
        let event = SseEvent::new(r#"{"\u00e9":"accent"}"#);
        let val: serde_json::Value = event.json().unwrap();
        assert!(val.is_object());
    }

    // ── SseClient: empty URL ──

    #[test]
    fn test_sse_client_empty_url() {
        let client = SseClient::new("");
        assert_eq!(client.url(), "");
    }

    // ── SseConfig: timeout override ──

    #[test]
    fn test_sse_config_timeout_override() {
        let config = SseConfig::new()
            .with_timeout(Duration::from_secs(10))
            .with_timeout(Duration::from_secs(30));
        assert_eq!(config.timeout, Some(Duration::from_secs(30)));
    }
}
