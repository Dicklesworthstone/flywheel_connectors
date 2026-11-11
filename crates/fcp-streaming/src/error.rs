//! Streaming error types.

use std::time::Duration;

use fcp_async_core::http::{HttpClientError, HttpError};

/// HTTP status used by the host when connector budgets are exhausted.
pub const HOST_BACKPRESSURE_STATUS: u16 = 503;
/// Header carrying host backpressure reason for connector clients.
pub const FCP_BACKPRESSURE_REASON_HEADER: &str = "X-FCP-Backpressure-Reason";
/// Header carrying the host-computed retry floor in whole seconds.
pub const FCP_BACKPRESSURE_RETRY_AFTER_HEADER: &str = "X-FCP-Backpressure-Retry-After";
/// Canonical host backpressure reason for exhausted zone budgets.
pub const FCP_BACKPRESSURE_BUDGET_EXHAUSTED: &str = "budget-exhausted";

/// Host-supplied backpressure signal for connector retry loops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostBackpressureSignal {
    /// Machine-readable reason supplied by the host.
    pub reason: String,
    /// Optional retry floor supplied by `Retry-After` or FCP backpressure headers.
    pub retry_after: Option<Duration>,
}

impl HostBackpressureSignal {
    /// Create a host backpressure signal.
    #[must_use]
    pub fn new(reason: impl Into<String>, retry_after: Option<Duration>) -> Self {
        Self {
            reason: reason.into(),
            retry_after,
        }
    }

    /// Return whether connector retry loops should back off.
    #[must_use]
    pub const fn should_back_off(&self) -> bool {
        true
    }

    /// Return the host-supplied retry floor.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    /// Return true for canonical budget-exhaustion backpressure.
    #[must_use]
    pub fn is_budget_exhausted(&self) -> bool {
        self.reason
            .trim()
            .eq_ignore_ascii_case(FCP_BACKPRESSURE_BUDGET_EXHAUSTED)
    }
}

/// Streaming errors.
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    /// Connection failed.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Connection closed unexpectedly.
    #[error("Connection closed: {reason}")]
    ConnectionClosed {
        /// Close reason.
        reason: String,
        /// Close code (for WebSocket).
        code: Option<u16>,
    },

    /// HTTP error.
    #[error("HTTP error: {status} - {message}")]
    HttpError {
        /// HTTP status code.
        status: u16,
        /// Error message.
        message: String,
        /// Optional `Retry-After` guidance from the upstream server.
        retry_after: Option<Duration>,
    },

    /// Host refused work due to connector backpressure.
    #[error("Host backpressure: {status} - {message}: {signal:?}")]
    HostBackpressure {
        /// HTTP status code.
        status: u16,
        /// Error message.
        message: String,
        /// Host-supplied backpressure signal.
        signal: HostBackpressureSignal,
    },

    /// Parse error.
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Timeout.
    #[error("Timeout after {0:?}")]
    Timeout(Duration),

    /// Reconnection limit exceeded.
    #[error("Reconnection limit exceeded after {attempts} attempts")]
    ReconnectLimitExceeded {
        /// Number of reconnection attempts.
        attempts: u32,
    },

    /// A server minimum cannot fit the local reconnect wait policy.
    #[error("Required reconnect delay {required:?} exceeds local maximum {max:?}")]
    ReconnectDelayExceeded {
        /// Minimum delay required by the server.
        required: Duration,
        /// Maximum wait permitted by the local policy.
        max: Duration,
    },

    /// Buffer overflow.
    #[error("Buffer overflow: {size} bytes exceeds limit of {limit}")]
    BufferOverflow {
        /// Current size.
        size: usize,
        /// Maximum allowed size.
        limit: usize,
    },

    /// Invalid state.
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// WebSocket error.
    #[error("WebSocket error: {0}")]
    WebSocketError(String),

    /// SSE error.
    #[error("SSE error: {0}")]
    SseError(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// HTTP client error.
    #[error("HTTP client error: {0}")]
    HttpClientError(#[from] HttpClientError),

    /// HTTP protocol/body error.
    #[error("HTTP protocol error: {0}")]
    HttpProtocolError(#[from] HttpError),
}

/// Result type for streaming operations.
pub type StreamResult<T> = Result<T, StreamError>;

impl StreamError {
    /// Return any upstream `Retry-After` hint carried by this error.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::HttpError { retry_after, .. } => *retry_after,
            Self::HostBackpressure { signal, .. } => signal.retry_after(),
            Self::ReconnectDelayExceeded { required, .. } => Some(*required),
            _ => None,
        }
    }

    /// Return true when retrying would hammer a host that has exhausted budget.
    #[must_use]
    pub fn is_terminal_backpressure(&self) -> bool {
        matches!(
            self,
            Self::HostBackpressure {
                status: HOST_BACKPRESSURE_STATUS,
                signal,
                ..
            } if signal.is_budget_exhausted()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_failed_display() {
        let e = StreamError::ConnectionFailed("refused".into());
        assert_eq!(e.to_string(), "Connection failed: refused");
    }

    #[test]
    fn connection_closed_display() {
        let e = StreamError::ConnectionClosed {
            reason: "gone".into(),
            code: Some(1001),
        };
        assert_eq!(e.to_string(), "Connection closed: gone");
    }

    #[test]
    fn connection_closed_without_code() {
        let e = StreamError::ConnectionClosed {
            reason: "eof".into(),
            code: None,
        };
        assert_eq!(e.to_string(), "Connection closed: eof");
    }

    #[test]
    fn http_error_display() {
        let e = StreamError::HttpError {
            status: 404,
            message: "Not Found".into(),
            retry_after: None,
        };
        assert_eq!(e.to_string(), "HTTP error: 404 - Not Found");
    }

    #[test]
    fn host_backpressure_budget_exhaustion_is_terminal() {
        let e = StreamError::HostBackpressure {
            status: 503,
            message: "Service Unavailable".into(),
            signal: HostBackpressureSignal::new(
                FCP_BACKPRESSURE_BUDGET_EXHAUSTED,
                Some(Duration::from_secs(30)),
            ),
        };

        assert!(e.is_terminal_backpressure());
        assert_eq!(e.retry_after(), Some(Duration::from_secs(30)));
        assert!(e.to_string().contains(FCP_BACKPRESSURE_BUDGET_EXHAUSTED));
    }

    #[test]
    fn parse_error_display() {
        let e = StreamError::ParseError("bad json".into());
        assert_eq!(e.to_string(), "Parse error: bad json");
    }

    #[test]
    fn timeout_display() {
        let e = StreamError::Timeout(Duration::from_secs(5));
        assert_eq!(e.to_string(), "Timeout after 5s");
    }

    #[test]
    fn reconnect_limit_exceeded_display() {
        let e = StreamError::ReconnectLimitExceeded { attempts: 10 };
        assert_eq!(
            e.to_string(),
            "Reconnection limit exceeded after 10 attempts"
        );
    }

    #[test]
    fn buffer_overflow_display() {
        let e = StreamError::BufferOverflow {
            size: 2048,
            limit: 1024,
        };
        assert_eq!(
            e.to_string(),
            "Buffer overflow: 2048 bytes exceeds limit of 1024"
        );
    }

    #[test]
    fn invalid_state_display() {
        let e = StreamError::InvalidState("closed".into());
        assert_eq!(e.to_string(), "Invalid state: closed");
    }

    #[test]
    fn websocket_error_display() {
        let e = StreamError::WebSocketError("protocol error".into());
        assert_eq!(e.to_string(), "WebSocket error: protocol error");
    }

    #[test]
    fn sse_error_display() {
        let e = StreamError::SseError("invalid event".into());
        assert_eq!(e.to_string(), "SSE error: invalid event");
    }

    #[test]
    fn io_error_from() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken");
        let stream_err: StreamError = io_err.into();
        assert!(matches!(stream_err, StreamError::IoError(_)));
        assert!(stream_err.to_string().contains("broken"));
    }

    // ── std::error::Error trait tests ──

    #[test]
    fn connection_failed_is_std_error() {
        let e: Box<dyn std::error::Error> =
            Box::new(StreamError::ConnectionFailed("refused".into()));
        assert!(e.to_string().contains("refused"));
    }

    #[test]
    fn io_error_source_is_inner() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let stream_err = StreamError::IoError(io_err);
        let source = std::error::Error::source(&stream_err);
        assert!(source.is_some(), "IoError variant should expose source");
    }

    #[test]
    fn connection_failed_source_is_none() {
        let e = StreamError::ConnectionFailed("no source".into());
        let source = std::error::Error::source(&e);
        assert!(source.is_none());
    }

    // ── Debug tests ──

    #[test]
    fn connection_failed_debug() {
        let e = StreamError::ConnectionFailed("refused".into());
        let debug = format!("{e:?}");
        assert!(debug.contains("ConnectionFailed"));
    }

    #[test]
    fn connection_closed_debug() {
        let e = StreamError::ConnectionClosed {
            reason: "gone".into(),
            code: Some(1001),
        };
        let debug = format!("{e:?}");
        assert!(debug.contains("ConnectionClosed"));
        assert!(debug.contains("1001"));
    }

    #[test]
    fn http_error_debug() {
        let e = StreamError::HttpError {
            status: 503,
            message: "Service Unavailable".into(),
            retry_after: None,
        };
        let debug = format!("{e:?}");
        assert!(debug.contains("503"));
    }

    #[test]
    fn timeout_debug() {
        let e = StreamError::Timeout(Duration::from_millis(2500));
        let debug = format!("{e:?}");
        assert!(debug.contains("Timeout"));
    }

    #[test]
    fn buffer_overflow_debug() {
        let e = StreamError::BufferOverflow {
            size: 4096,
            limit: 2048,
        };
        let debug = format!("{e:?}");
        assert!(debug.contains("4096"));
        assert!(debug.contains("2048"));
    }

    #[test]
    fn reconnect_limit_debug() {
        let e = StreamError::ReconnectLimitExceeded { attempts: 5 };
        let debug = format!("{e:?}");
        assert!(debug.contains('5'));
    }

    #[test]
    fn websocket_error_debug() {
        let e = StreamError::WebSocketError("protocol".into());
        let debug = format!("{e:?}");
        assert!(debug.contains("WebSocketError"));
    }

    #[test]
    fn sse_error_debug() {
        let e = StreamError::SseError("invalid".into());
        let debug = format!("{e:?}");
        assert!(debug.contains("SseError"));
    }

    #[test]
    fn io_error_debug() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        let e = StreamError::IoError(io_err);
        let debug = format!("{e:?}");
        assert!(debug.contains("IoError"));
    }

    // ── Display boundary tests ──

    #[test]
    fn connection_closed_empty_reason() {
        let e = StreamError::ConnectionClosed {
            reason: String::new(),
            code: None,
        };
        assert_eq!(e.to_string(), "Connection closed: ");
    }

    #[test]
    fn http_error_boundary_status() {
        let e = StreamError::HttpError {
            status: 0,
            message: "zero".into(),
            retry_after: None,
        };
        assert_eq!(e.to_string(), "HTTP error: 0 - zero");
    }

    #[test]
    fn timeout_zero_duration() {
        let e = StreamError::Timeout(Duration::ZERO);
        let display = e.to_string();
        assert!(display.contains('0'));
    }

    #[test]
    fn buffer_overflow_equal_size_and_limit() {
        let e = StreamError::BufferOverflow {
            size: 1024,
            limit: 1024,
        };
        assert!(e.to_string().contains("1024"));
    }

    #[test]
    fn reconnect_zero_attempts() {
        let e = StreamError::ReconnectLimitExceeded { attempts: 0 };
        assert!(e.to_string().contains("0 attempts"));
    }

    #[test]
    fn parse_error_empty_message() {
        let e = StreamError::ParseError(String::new());
        assert_eq!(e.to_string(), "Parse error: ");
    }

    #[test]
    fn invalid_state_empty_message() {
        let e = StreamError::InvalidState(String::new());
        assert_eq!(e.to_string(), "Invalid state: ");
    }

    // ── Send + Sync trait bounds ──

    #[test]
    fn stream_error_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<StreamError>();
    }

    #[test]
    fn stream_error_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<StreamError>();
    }

    // ── Unicode content in error messages ──

    #[test]
    fn connection_failed_unicode() {
        let e = StreamError::ConnectionFailed("verbindung fehlgeschlagen \u{1F4A5}".into());
        let display = e.to_string();
        assert!(display.contains('\u{1F4A5}'));
    }

    #[test]
    fn parse_error_unicode() {
        let e = StreamError::ParseError("\u{00E9}\u{00E8}\u{00EA}".into());
        assert!(e.to_string().contains('\u{00E9}'));
    }

    #[test]
    fn connection_closed_unicode_reason() {
        let e = StreamError::ConnectionClosed {
            reason: "\u{1F44B} goodbye".into(),
            code: Some(1000),
        };
        assert!(e.to_string().contains('\u{1F44B}'));
    }

    #[test]
    fn http_error_unicode_message() {
        let e = StreamError::HttpError {
            status: 500,
            message: "\u{26A0} internal".into(),
            retry_after: None,
        };
        assert!(e.to_string().contains('\u{26A0}'));
    }

    #[test]
    fn invalid_state_unicode() {
        let e = StreamError::InvalidState("\u{2620} danger".into());
        assert!(e.to_string().contains('\u{2620}'));
    }

    #[test]
    fn websocket_error_unicode() {
        let e = StreamError::WebSocketError("\u{1F310} network".into());
        assert!(e.to_string().contains('\u{1F310}'));
    }

    #[test]
    fn sse_error_unicode() {
        let e = StreamError::SseError("\u{1F4E1} stream".into());
        assert!(e.to_string().contains('\u{1F4E1}'));
    }

    // ── Large content ──

    #[test]
    fn connection_failed_long_message() {
        let long_msg = "x".repeat(10_000);
        let e = StreamError::ConnectionFailed(long_msg.clone());
        assert_eq!(e.to_string(), format!("Connection failed: {long_msg}"));
    }

    #[test]
    fn parse_error_long_message() {
        let long_msg = "y".repeat(5_000);
        let e = StreamError::ParseError(long_msg.clone());
        assert_eq!(e.to_string(), format!("Parse error: {long_msg}"));
    }

    // ── Boundary values ──

    #[test]
    fn http_error_max_status() {
        let e = StreamError::HttpError {
            status: u16::MAX,
            message: "max".into(),
            retry_after: None,
        };
        assert!(e.to_string().contains("65535"));
    }

    #[test]
    fn buffer_overflow_zero_values() {
        let e = StreamError::BufferOverflow { size: 0, limit: 0 };
        assert_eq!(e.to_string(), "Buffer overflow: 0 bytes exceeds limit of 0");
    }

    #[test]
    fn buffer_overflow_max_values() {
        let e = StreamError::BufferOverflow {
            size: usize::MAX,
            limit: usize::MAX,
        };
        let display = e.to_string();
        assert!(display.contains(&usize::MAX.to_string()));
    }

    #[test]
    fn reconnect_limit_max_attempts() {
        let e = StreamError::ReconnectLimitExceeded { attempts: u32::MAX };
        assert!(e.to_string().contains(&u32::MAX.to_string()));
    }

    #[test]
    fn timeout_max_duration() {
        let e = StreamError::Timeout(Duration::from_secs(u64::MAX / 2));
        let display = e.to_string();
        assert!(display.contains("Timeout"));
    }

    #[test]
    fn connection_closed_max_code() {
        let e = StreamError::ConnectionClosed {
            reason: "max".into(),
            code: Some(u16::MAX),
        };
        let debug = format!("{e:?}");
        assert!(debug.contains("65535"));
    }

    // ── io error variants ──

    #[test]
    fn io_error_different_kinds() {
        let kinds = [
            std::io::ErrorKind::ConnectionRefused,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::AddrInUse,
        ];
        for kind in kinds {
            let io_err = std::io::Error::new(kind, "test");
            let stream_err: StreamError = io_err.into();
            assert!(matches!(stream_err, StreamError::IoError(_)));
        }
    }

    // ── StreamResult type alias ──

    #[test]
    fn stream_result_type_alias_works() {
        // Verify StreamResult is a proper Result alias
        let ok_val: StreamResult<i32> = std::result::Result::Ok(42);
        let err_val: StreamResult<i32> =
            std::result::Result::Err(StreamError::ParseError("bad".into()));
        assert!(ok_val.is_ok());
        assert!(err_val.is_err());
    }

    // ── Timeout with sub-millisecond precision ──

    #[test]
    fn timeout_display_nanos() {
        let e = StreamError::Timeout(Duration::from_nanos(123));
        let display = e.to_string();
        assert!(display.contains("Timeout"));
        assert!(display.contains("123ns"));
    }

    #[test]
    fn timeout_display_millis() {
        let e = StreamError::Timeout(Duration::from_millis(750));
        let display = e.to_string();
        assert!(display.contains("750ms"));
    }

    // ── Display with escape-like characters ──

    #[test]
    fn connection_failed_with_tabs_and_crlf() {
        let e = StreamError::ConnectionFailed("a\t\r\nb".into());
        let display = e.to_string();
        assert!(display.contains("a\t\r\nb"));
    }

    #[test]
    fn http_error_with_html_in_message() {
        let e = StreamError::HttpError {
            status: 500,
            message: "<h1>Internal Server Error</h1>".into(),
            retry_after: None,
        };
        let display = e.to_string();
        assert!(display.contains("<h1>"));
    }

    #[test]
    fn parse_error_with_json_content() {
        let e = StreamError::ParseError(r#"{"error": "unexpected token"}"#.into());
        let display = e.to_string();
        assert!(display.contains("unexpected token"));
    }

    // ── Multiple From conversions ──

    #[test]
    fn io_error_from_interrupted() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Interrupted, "interrupted");
        let stream_err: StreamError = io_err.into();
        assert!(matches!(stream_err, StreamError::IoError(_)));
        assert!(stream_err.to_string().contains("interrupted"));
    }

    // ── StreamResult with complex types ──

    #[test]
    fn stream_result_with_tuple_type() {
        // Verify StreamResult works with tuple types
        let result: StreamResult<(String, u64)> = Ok(("data".into(), 42));
        assert!(result.is_ok());
        let err: StreamResult<(String, u64)> = Err(StreamError::ParseError("fail".into()));
        assert!(err.is_err());
    }

    #[test]
    fn stream_result_err_preserves_variant() {
        let result: StreamResult<()> = Err(StreamError::BufferOverflow {
            size: 999,
            limit: 100,
        });
        match result {
            Err(StreamError::BufferOverflow { size, limit }) => {
                assert_eq!(size, 999);
                assert_eq!(limit, 100);
            }
            _ => panic!("expected BufferOverflow"),
        }
    }

    // ── Debug output contains all variant fields ──

    #[test]
    fn connection_closed_debug_contains_reason_and_code() {
        let e = StreamError::ConnectionClosed {
            reason: "server shutdown".into(),
            code: Some(4500),
        };
        let debug = format!("{e:?}");
        assert!(debug.contains("server shutdown"));
        assert!(debug.contains("4500"));
    }

    #[test]
    fn http_error_debug_contains_status_and_message() {
        let e = StreamError::HttpError {
            status: 429,
            message: "Too Many Requests".into(),
            retry_after: Some(Duration::from_secs(7)),
        };
        let debug = format!("{e:?}");
        assert!(debug.contains("429"));
        assert!(debug.contains("Too Many Requests"));
    }

    // ── Error source chain for non-source variants ──

    #[test]
    fn connection_closed_source_is_none() {
        let e = StreamError::ConnectionClosed {
            reason: "done".into(),
            code: Some(1000),
        };
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn parse_error_source_is_none() {
        let e = StreamError::ParseError("fail".into());
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn invalid_state_source_is_none() {
        let e = StreamError::InvalidState("bad state".into());
        assert!(std::error::Error::source(&e).is_none());
    }

    // ── Display consistency across constructions ──

    #[test]
    fn connection_failed_display_matches_format() {
        let msg = "host unreachable";
        let e = StreamError::ConnectionFailed(msg.to_string());
        assert_eq!(e.to_string(), format!("Connection failed: {msg}"));
    }

    #[test]
    fn buffer_overflow_display_matches_format() {
        let e = StreamError::BufferOverflow {
            size: 12345,
            limit: 10000,
        };
        assert_eq!(
            e.to_string(),
            "Buffer overflow: 12345 bytes exceeds limit of 10000"
        );
    }

    // ── StreamError: From conversions ───────────────────────────────────

    #[test]
    fn io_error_from_connection_aborted() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "aborted");
        let stream_err: StreamError = io_err.into();
        assert!(matches!(stream_err, StreamError::IoError(_)));
        assert!(stream_err.to_string().contains("aborted"));
    }

    #[test]
    fn io_error_preserves_error_kind_in_source() {
        let io_err = std::io::Error::new(std::io::ErrorKind::WouldBlock, "would block");
        let stream_err = StreamError::IoError(io_err);
        let source = std::error::Error::source(&stream_err);
        assert!(source.is_some());
        let inner = source.unwrap().downcast_ref::<std::io::Error>().unwrap();
        assert_eq!(inner.kind(), std::io::ErrorKind::WouldBlock);
    }

    // ── StreamError: Display with special characters ────────────────────

    #[test]
    fn connection_failed_with_newlines() {
        let e = StreamError::ConnectionFailed("line1\nline2".into());
        let display = e.to_string();
        assert!(display.contains("line1\nline2"));
    }

    #[test]
    fn http_error_empty_message() {
        let e = StreamError::HttpError {
            status: 500,
            message: String::new(),
            retry_after: None,
        };
        assert_eq!(e.to_string(), "HTTP error: 500 - ");
    }

    #[test]
    fn websocket_error_empty_message() {
        let e = StreamError::WebSocketError(String::new());
        assert_eq!(e.to_string(), "WebSocket error: ");
    }

    #[test]
    fn sse_error_empty_message() {
        let e = StreamError::SseError(String::new());
        assert_eq!(e.to_string(), "SSE error: ");
    }

    // ── StreamError: Debug contains variant-specific data ───────────────

    #[test]
    fn parse_error_debug_contains_message() {
        let e = StreamError::ParseError("unexpected token".into());
        let debug = format!("{e:?}");
        assert!(debug.contains("ParseError"));
        assert!(debug.contains("unexpected token"));
    }

    #[test]
    fn invalid_state_debug_contains_state() {
        let e = StreamError::InvalidState("half-closed".into());
        let debug = format!("{e:?}");
        assert!(debug.contains("InvalidState"));
        assert!(debug.contains("half-closed"));
    }

    // ── StreamError: source chain ───────────────────────────────────────

    #[test]
    fn timeout_source_is_none() {
        let e = StreamError::Timeout(Duration::from_secs(5));
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn http_error_source_is_none() {
        let e = StreamError::HttpError {
            status: 503,
            message: "unavailable".into(),
            retry_after: None,
        };
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn http_error_retry_after_accessor() {
        let e = StreamError::HttpError {
            status: 429,
            message: "Too Many Requests".into(),
            retry_after: Some(Duration::from_secs(9)),
        };
        assert_eq!(e.retry_after(), Some(Duration::from_secs(9)));
    }

    #[test]
    fn buffer_overflow_source_is_none() {
        let e = StreamError::BufferOverflow {
            size: 100,
            limit: 50,
        };
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn reconnect_limit_source_is_none() {
        let e = StreamError::ReconnectLimitExceeded { attempts: 3 };
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn websocket_error_source_is_none() {
        let e = StreamError::WebSocketError("err".into());
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn sse_error_source_is_none() {
        let e = StreamError::SseError("err".into());
        assert!(std::error::Error::source(&e).is_none());
    }
}
