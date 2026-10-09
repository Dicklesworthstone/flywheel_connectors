//! Error types for the GraphQL client.

use std::time::Duration;

use fcp_async_core::http::{HttpClientError, StatusCode};
use fcp_prelude::FcpError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// HTTP error information captured from the transport layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpErrorInfo {
    /// Error message.
    pub message: String,
    /// HTTP status code (if available).
    pub status_code: Option<u16>,
    /// Whether the error was a timeout.
    pub is_timeout: bool,
    /// Whether the error was a connection failure.
    pub is_connect: bool,
    /// Whether the error was a request error.
    pub is_request: bool,
}

impl HttpErrorInfo {
    /// Construct a timeout-shaped HTTP error.
    #[must_use]
    pub fn timeout(timeout: Duration) -> Self {
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        Self {
            message: format!("request deadline exceeded after {timeout_ms}ms"),
            status_code: Some(StatusCode::REQUEST_TIMEOUT.as_u16()),
            is_timeout: true,
            is_connect: false,
            is_request: false,
        }
    }

    /// Construct a cancelled request error.
    #[must_use]
    pub fn cancelled() -> Self {
        Self {
            message: "request cancelled".into(),
            status_code: None,
            is_timeout: false,
            is_connect: false,
            is_request: false,
        }
    }
}

impl From<HttpClientError> for HttpErrorInfo {
    fn from(err: HttpClientError) -> Self {
        match err {
            HttpClientError::InvalidUrl(url) => Self {
                message: format!("invalid URL: {url}"),
                status_code: None,
                is_timeout: false,
                is_connect: false,
                is_request: false,
            },
            HttpClientError::DnsError(error) => Self {
                message: format!("DNS resolution failed: {error}"),
                status_code: None,
                is_timeout: error.kind() == std::io::ErrorKind::TimedOut,
                is_connect: true,
                is_request: false,
            },
            HttpClientError::ConnectError(error) => Self {
                message: format!("connection failed: {error}"),
                status_code: None,
                is_timeout: error.kind() == std::io::ErrorKind::TimedOut,
                is_connect: true,
                is_request: false,
            },
            HttpClientError::TlsError(error) => Self {
                message: format!("TLS error: {error}"),
                status_code: None,
                is_timeout: false,
                is_connect: true,
                is_request: false,
            },
            HttpClientError::HttpError(error) => Self {
                message: format!("HTTP error: {error}"),
                status_code: None,
                is_timeout: false,
                is_connect: false,
                is_request: false,
            },
            HttpClientError::TooManyRedirects { count, max } => Self {
                message: format!("too many redirects ({count} of max {max})"),
                status_code: None,
                is_timeout: false,
                is_connect: false,
                is_request: false,
            },
            HttpClientError::Io(error) => Self {
                message: format!("I/O error: {error}"),
                status_code: None,
                is_timeout: error.kind() == std::io::ErrorKind::TimedOut,
                is_connect: false,
                is_request: false,
            },
            HttpClientError::ConnectTunnelRefused { status, reason } => Self {
                message: format!("HTTP CONNECT tunnel rejected with status {status} ({reason})"),
                status_code: Some(status),
                is_timeout: false,
                is_connect: true,
                is_request: false,
            },
            HttpClientError::InvalidConnectInput(message) => Self {
                message: format!("invalid CONNECT input: {message}"),
                status_code: None,
                is_timeout: false,
                is_connect: false,
                is_request: false,
            },
            HttpClientError::ProxyError(message) => Self {
                message: format!("proxy error: {message}"),
                status_code: None,
                is_timeout: false,
                is_connect: true,
                is_request: false,
            },
            HttpClientError::PoolExhausted { host, port } => Self {
                message: format!("connection pool exhausted for {host}:{port}"),
                status_code: None,
                is_timeout: false,
                is_connect: false,
                is_request: true,
            },
            // Expiration is not a response and may occur after a mutation was sent.
            HttpClientError::DeadlineExceeded => Self {
                message: "request deadline exceeded".to_owned(),
                status_code: None,
                is_timeout: true,
                is_connect: false,
                is_request: false,
            },
            HttpClientError::Cancelled => Self {
                message: "request cancelled".to_string(),
                status_code: None,
                is_timeout: false,
                is_connect: false,
                is_request: true,
            },
        }
    }
}

/// GraphQL error location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphqlErrorLocation {
    /// Line number in the query (1-based).
    pub line: u32,
    /// Column number in the query (1-based).
    pub column: u32,
}

/// GraphQL path segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GraphqlPathSegment {
    /// Field name.
    Key(String),
    /// Array index.
    Index(i64),
}

/// GraphQL error (per GraphQL spec).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
pub struct GraphqlError {
    /// Human-readable error message.
    pub message: String,
    /// Location(s) within the query.
    #[serde(default)]
    pub locations: Vec<GraphqlErrorLocation>,
    /// Path within the response where the error occurred.
    #[serde(default)]
    pub path: Vec<GraphqlPathSegment>,
    /// Extensions metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// Query resource limit violation detected before request dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GraphqlLimitExceeded {
    /// Query text exceeded the configured byte limit.
    #[error("query is {actual_bytes} bytes, exceeding limit {max_bytes}")]
    QueryTooLarge {
        /// Actual query size in bytes.
        actual_bytes: usize,
        /// Maximum allowed query size in bytes.
        max_bytes: usize,
    },

    /// Selection-set nesting exceeded the configured depth limit.
    #[error("query depth {actual_depth} exceeds limit {max_depth}")]
    DepthExceeded {
        /// Deepest observed selection depth.
        actual_depth: usize,
        /// Maximum allowed selection depth.
        max_depth: usize,
    },

    /// Alias count exceeded the configured limit.
    #[error("query alias count {actual_aliases} exceeds limit {max_aliases}")]
    AliasLimitExceeded {
        /// Actual alias count.
        actual_aliases: usize,
        /// Maximum allowed alias count.
        max_aliases: usize,
    },

    /// Root field count exceeded the configured limit.
    #[error("query root field count {actual_root_fields} exceeds limit {max_root_fields}")]
    RootFieldLimitExceeded {
        /// Actual root field count.
        actual_root_fields: usize,
        /// Maximum allowed root field count.
        max_root_fields: usize,
    },

    /// Schema introspection field was rejected by policy.
    #[error("GraphQL introspection field `{field_name}` is disabled by policy")]
    IntrospectionDisabled {
        /// Rejected introspection field name.
        field_name: String,
    },
}

/// Error type for GraphQL client operations.
#[derive(Debug, Clone, Error)]
pub enum GraphqlClientError {
    /// HTTP/network error.
    #[error("HTTP error: {0:?}")]
    Http(HttpErrorInfo),

    /// HTTP response status error.
    #[error("HTTP status {status} with body: {body}")]
    HttpStatus {
        /// HTTP status code.
        status: StatusCode,
        /// Response body (truncated if needed).
        body: String,
        /// Retry-After duration when supplied.
        retry_after: Option<Duration>,
    },

    /// JSON parsing error.
    #[error("JSON error: {0}")]
    Json(String),

    /// GraphQL-level errors returned by the server.
    #[error("GraphQL errors: {errors:?}")]
    GraphqlErrors {
        /// GraphQL error list.
        errors: Vec<GraphqlError>,
    },

    /// GraphQL protocol violation.
    #[error("GraphQL protocol error: {message}")]
    Protocol {
        /// Details.
        message: String,
    },

    /// Schema validation error.
    #[error("Schema validation failed: {message}")]
    SchemaValidation {
        /// Summary message.
        message: String,
        /// Individual validation errors.
        errors: Vec<String>,
    },

    /// Query resource limit violation.
    #[error("GraphQL query limit exceeded: {0}")]
    LimitExceeded(#[from] GraphqlLimitExceeded),

    /// Retry policy exhausted.
    #[error("Retry policy exhausted after {attempts} attempts")]
    RetriesExhausted {
        /// Attempt count.
        attempts: usize,
    },

    /// Subscription terminated by the client because the result buffer
    /// filled and a server `next` frame had nowhere to land (br-xnroh
    /// follow-up to VioletPine's br-0q8eh fail-closed work). Surfaces
    /// as the LAST item the consumer stream yields, before stream end.
    /// Callers/automation observing only stream end (without
    /// inspecting the last item) would previously have mistaken this
    /// for a clean server-initiated `complete` and silently dropped
    /// post-buffer events; the terminal Err makes the overflow
    /// distinguishable fail-closed.
    #[error(
        "GraphQL subscription aborted: result buffer overflow (capacity {capacity}) — \
         consumer was not draining fast enough; events after this point were dropped"
    )]
    SubscriptionBufferOverflow {
        /// The fixed buffer capacity that was exceeded. Operators
        /// sizing the consumer-side throughput floor want this number.
        capacity: usize,
    },
}

impl From<HttpClientError> for GraphqlClientError {
    fn from(err: HttpClientError) -> Self {
        Self::Http(HttpErrorInfo::from(err))
    }
}

impl From<serde_json::Error> for GraphqlClientError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err.to_string())
    }
}

impl GraphqlClientError {
    /// Returns `true` if the error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(info) => info.is_timeout || info.is_connect || info.is_request,
            Self::HttpStatus { status, .. } => {
                status.is_server_error() || *status == StatusCode::TOO_MANY_REQUESTS
            }
            _ => false,
        }
    }

    /// Convert the error to an FCP error for a named service.
    #[must_use]
    pub fn to_fcp_error(&self, service: &str) -> FcpError {
        match self {
            Self::Http(info) => FcpError::External {
                service: service.into(),
                message: info.message.clone(),
                status_code: info.status_code,
                retryable: info.is_timeout || info.is_connect,
                retry_after: None,
            },
            Self::HttpStatus {
                status,
                body,
                retry_after,
            } => {
                if *status == StatusCode::TOO_MANY_REQUESTS {
                    if let Some(duration) = retry_after {
                        let retry_after_ms =
                            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
                        return FcpError::RateLimited {
                            retry_after_ms,
                            violation: None,
                        };
                    }
                    return FcpError::RateLimited {
                        retry_after_ms: 1000,
                        violation: None,
                    };
                }
                if *status == StatusCode::UNAUTHORIZED || *status == StatusCode::FORBIDDEN {
                    return FcpError::Unauthorized {
                        code: 2001,
                        message: format!("{service} unauthorized: {body}"),
                    };
                }
                FcpError::External {
                    service: service.into(),
                    message: body.clone(),
                    status_code: Some(status.as_u16()),
                    retryable: status.is_server_error(),
                    retry_after: *retry_after,
                }
            }
            Self::Json(message) => FcpError::MalformedFrame {
                code: 2004,
                message: format!("JSON parsing error: {message}"),
            },
            Self::GraphqlErrors { errors } => {
                let message = errors
                    .first()
                    .map_or_else(|| "GraphQL error".to_string(), |err| err.message.clone());
                FcpError::External {
                    service: service.into(),
                    message,
                    status_code: None,
                    retryable: false,
                    retry_after: None,
                }
            }
            Self::Protocol { message } => FcpError::InvalidRequest {
                code: 1002,
                message: message.clone(),
            },
            Self::SchemaValidation { message, .. } => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::LimitExceeded(limit) => FcpError::InvalidRequest {
                code: 1004,
                message: limit.to_string(),
            },
            Self::RetriesExhausted { attempts } => FcpError::External {
                service: service.into(),
                message: format!("Retry policy exhausted after {attempts} attempts"),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
            Self::SubscriptionBufferOverflow { capacity } => FcpError::External {
                service: service.into(),
                message: format!(
                    "GraphQL subscription aborted: result buffer overflow (capacity {capacity})"
                ),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_http_deadline_preserves_timeout_without_connect_or_status_claims() {
        let info = HttpErrorInfo::from(HttpClientError::DeadlineExceeded);
        assert!(info.is_timeout);
        assert!(!info.is_connect);
        assert!(!info.is_request);
        assert_eq!(info.status_code, None);
        let bytes = serde_json::to_vec(&info).unwrap();
        assert_eq!(serde_json::from_slice::<HttpErrorInfo>(&bytes).unwrap(), info);
    }

    #[test]
    fn native_http_deadline_converts_through_the_public_error_surface() {
        let error = GraphqlClientError::from(HttpClientError::DeadlineExceeded);
        let GraphqlClientError::Http(info) = &error else {
            panic!("native deadline must remain a transport error");
        };
        assert!(info.is_timeout);
        assert!(!info.is_connect);
        assert!(matches!(
            error.to_fcp_error("test"),
            FcpError::External { status_code: None, retry_after: None, .. }
        ));
    }

    // ---- HttpErrorInfo ----

    #[test]
    fn http_error_info_serde_roundtrip() {
        let info = HttpErrorInfo {
            message: "connection refused".into(),
            status_code: Some(502),
            is_timeout: false,
            is_connect: true,
            is_request: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: HttpErrorInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, back);
    }

    #[test]
    fn http_error_info_none_status() {
        let info = HttpErrorInfo {
            message: "DNS resolution failed".into(),
            status_code: None,
            is_timeout: false,
            is_connect: true,
            is_request: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"status_code\":null"));
        let back: HttpErrorInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status_code, None);
    }

    // ---- GraphqlErrorLocation ----

    #[test]
    fn error_location_serde_roundtrip() {
        let loc = GraphqlErrorLocation {
            line: 3,
            column: 12,
        };
        let json = serde_json::to_string(&loc).unwrap();
        let back: GraphqlErrorLocation = serde_json::from_str(&json).unwrap();
        assert_eq!(loc, back);
    }

    // ---- GraphqlPathSegment ----

    #[test]
    fn path_segment_key_serde() {
        let seg = GraphqlPathSegment::Key("user".into());
        let json = serde_json::to_string(&seg).unwrap();
        assert_eq!(json, "\"user\"");
        let back: GraphqlPathSegment = serde_json::from_str(&json).unwrap();
        assert_eq!(seg, back);
    }

    #[test]
    fn path_segment_index_serde() {
        let seg = GraphqlPathSegment::Index(5);
        let json = serde_json::to_string(&seg).unwrap();
        assert_eq!(json, "5");
        let back: GraphqlPathSegment = serde_json::from_str(&json).unwrap();
        assert_eq!(seg, back);
    }

    // ---- GraphqlError ----

    #[test]
    fn graphql_error_serde_roundtrip() {
        let err = GraphqlError {
            message: "Not found".into(),
            locations: vec![GraphqlErrorLocation { line: 1, column: 5 }],
            path: vec![
                GraphqlPathSegment::Key("user".into()),
                GraphqlPathSegment::Index(0),
            ],
            extensions: Some(serde_json::json!({"code": "NOT_FOUND"})),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: GraphqlError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn graphql_error_minimal_serde() {
        let json = r#"{"message":"oops"}"#;
        let err: GraphqlError = serde_json::from_str(json).unwrap();
        assert_eq!(err.message, "oops");
        assert!(err.locations.is_empty());
        assert!(err.path.is_empty());
        assert!(err.extensions.is_none());
    }

    // ---- GraphqlClientError Display ----

    #[test]
    fn display_http_error() {
        let err = GraphqlClientError::Http(HttpErrorInfo {
            message: "timeout".into(),
            status_code: None,
            is_timeout: true,
            is_connect: false,
            is_request: false,
        });
        assert!(err.to_string().contains("HTTP error"));
    }

    #[test]
    fn display_http_status_error() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::BAD_GATEWAY,
            body: "upstream error".into(),
            retry_after: None,
        };
        let s = err.to_string();
        assert!(s.contains("502"));
        assert!(s.contains("upstream error"));
    }

    #[test]
    fn display_json_error() {
        let err = GraphqlClientError::Json("unexpected token".into());
        assert!(err.to_string().contains("JSON error"));
    }

    #[test]
    fn display_graphql_errors() {
        let err = GraphqlClientError::GraphqlErrors {
            errors: vec![GraphqlError {
                message: "syntax error".into(),
                locations: vec![],
                path: vec![],
                extensions: None,
            }],
        };
        assert!(err.to_string().contains("GraphQL errors"));
    }

    #[test]
    fn display_protocol_error() {
        let err = GraphqlClientError::Protocol {
            message: "invalid frame".into(),
        };
        assert!(err.to_string().contains("protocol error"));
    }

    #[test]
    fn display_schema_validation_error() {
        let err = GraphqlClientError::SchemaValidation {
            message: "type mismatch".into(),
            errors: vec!["field x is wrong".into()],
        };
        assert!(err.to_string().contains("Schema validation"));
    }

    #[test]
    fn display_retries_exhausted() {
        let err = GraphqlClientError::RetriesExhausted { attempts: 5 };
        assert!(err.to_string().contains("5 attempts"));
    }

    // ---- is_retryable ----

    #[test]
    fn is_retryable_http_timeout() {
        let err = GraphqlClientError::Http(HttpErrorInfo {
            message: "timed out".into(),
            status_code: None,
            is_timeout: true,
            is_connect: false,
            is_request: false,
        });
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_http_connect() {
        let err = GraphqlClientError::Http(HttpErrorInfo {
            message: "connection refused".into(),
            status_code: None,
            is_timeout: false,
            is_connect: true,
            is_request: false,
        });
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_http_request() {
        let err = GraphqlClientError::Http(HttpErrorInfo {
            message: "request error".into(),
            status_code: None,
            is_timeout: false,
            is_connect: false,
            is_request: true,
        });
        assert!(err.is_retryable());
    }

    #[test]
    fn not_retryable_http_non_transient() {
        let err = GraphqlClientError::Http(HttpErrorInfo {
            message: "decode error".into(),
            status_code: None,
            is_timeout: false,
            is_connect: false,
            is_request: false,
        });
        assert!(!err.is_retryable());
    }

    #[test]
    fn is_retryable_500() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: String::new(),
            retry_after: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_503() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: String::new(),
            retry_after: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_429() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::TOO_MANY_REQUESTS,
            body: String::new(),
            retry_after: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn not_retryable_400() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::BAD_REQUEST,
            body: "bad input".into(),
            retry_after: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_json_error() {
        let err = GraphqlClientError::Json("unexpected".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_graphql_errors() {
        let err = GraphqlClientError::GraphqlErrors { errors: vec![] };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_protocol() {
        let err = GraphqlClientError::Protocol {
            message: "bad".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_schema_validation() {
        let err = GraphqlClientError::SchemaValidation {
            message: "invalid".into(),
            errors: vec![],
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_retries_exhausted() {
        let err = GraphqlClientError::RetriesExhausted { attempts: 3 };
        assert!(!err.is_retryable());
    }

    // ---- to_fcp_error ----

    #[test]
    fn to_fcp_http_error() {
        let err = GraphqlClientError::Http(HttpErrorInfo {
            message: "connection refused".into(),
            status_code: Some(502),
            is_timeout: false,
            is_connect: true,
            is_request: false,
        });
        let fcp = err.to_fcp_error("github");
        match fcp {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "github");
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_429_with_retry_after() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::TOO_MANY_REQUESTS,
            body: "slow down".into(),
            retry_after: Some(Duration::from_secs(30)),
        };
        let fcp = err.to_fcp_error("api");
        match fcp {
            FcpError::RateLimited { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, 30_000);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_429_without_retry_after() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::TOO_MANY_REQUESTS,
            body: String::new(),
            retry_after: None,
        };
        let fcp = err.to_fcp_error("api");
        match fcp {
            FcpError::RateLimited { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, 1000);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_401_unauthorized() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::UNAUTHORIZED,
            body: "bad token".into(),
            retry_after: None,
        };
        let fcp = err.to_fcp_error("github");
        match fcp {
            FcpError::Unauthorized { message, .. } => {
                assert!(message.contains("github unauthorized"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_403_forbidden() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::FORBIDDEN,
            body: "no access".into(),
            retry_after: None,
        };
        let fcp = err.to_fcp_error("gitlab");
        match fcp {
            FcpError::Unauthorized { message, .. } => {
                assert!(message.contains("gitlab unauthorized"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_500_server_error() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: "crash".into(),
            retry_after: None,
        };
        let fcp = err.to_fcp_error("svc");
        match fcp {
            FcpError::External {
                service,
                retryable,
                status_code,
                ..
            } => {
                assert_eq!(service, "svc");
                assert!(retryable);
                assert_eq!(status_code, Some(500));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_json_error() {
        let err = GraphqlClientError::Json("bad json".into());
        let fcp = err.to_fcp_error("api");
        match fcp {
            FcpError::MalformedFrame { message, .. } => {
                assert!(message.contains("JSON parsing"));
            }
            other => panic!("expected MalformedFrame, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_graphql_errors() {
        let err = GraphqlClientError::GraphqlErrors {
            errors: vec![GraphqlError {
                message: "field not found".into(),
                locations: vec![],
                path: vec![],
                extensions: None,
            }],
        };
        let fcp = err.to_fcp_error("github");
        match fcp {
            FcpError::External {
                message, retryable, ..
            } => {
                assert!(message.contains("field not found"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_graphql_errors_empty() {
        let err = GraphqlClientError::GraphqlErrors { errors: vec![] };
        let fcp = err.to_fcp_error("api");
        match fcp {
            FcpError::External { message, .. } => {
                assert_eq!(message, "GraphQL error");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_protocol_error() {
        let err = GraphqlClientError::Protocol {
            message: "bad frame".into(),
        };
        let fcp = err.to_fcp_error("api");
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1002);
                assert_eq!(message, "bad frame");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_schema_validation() {
        let err = GraphqlClientError::SchemaValidation {
            message: "type mismatch".into(),
            errors: vec!["field x".into()],
        };
        let fcp = err.to_fcp_error("api");
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert_eq!(message, "type mismatch");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_retries_exhausted() {
        let err = GraphqlClientError::RetriesExhausted { attempts: 5 };
        let fcp = err.to_fcp_error("svc");
        match fcp {
            FcpError::External {
                message, retryable, ..
            } => {
                assert!(message.contains("5 attempts"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ---- From impls ----

    #[test]
    fn from_serde_json_error() {
        let err: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let gql_err: GraphqlClientError = err.unwrap_err().into();
        match gql_err {
            GraphqlClientError::Json(msg) => {
                assert!(!msg.is_empty());
            }
            other => panic!("expected Json, got {other:?}"),
        }
    }

    // ---- HttpErrorInfo constructors ----

    #[test]
    fn http_error_info_timeout_constructor() {
        let info = HttpErrorInfo::timeout(Duration::from_secs(5));
        assert!(info.is_timeout);
        assert!(!info.is_connect);
        assert!(!info.is_request);
        assert_eq!(info.status_code, Some(408));
        assert!(info.message.contains("5000"));
    }

    #[test]
    fn http_error_info_timeout_large_duration() {
        let info = HttpErrorInfo::timeout(Duration::from_secs(300));
        assert!(info.message.contains("300000"));
        assert!(info.is_timeout);
    }

    #[test]
    fn http_error_info_cancelled_constructor() {
        let info = HttpErrorInfo::cancelled();
        assert!(!info.is_timeout);
        assert!(!info.is_connect);
        assert!(!info.is_request);
        assert!(info.status_code.is_none());
        assert_eq!(info.message, "request cancelled");
    }

    #[test]
    fn http_error_info_from_pool_exhausted() {
        let info = HttpErrorInfo::from(HttpClientError::PoolExhausted {
            host: "graphql.internal".into(),
            port: 443,
        });
        assert_eq!(
            info.message,
            "connection pool exhausted for graphql.internal:443"
        );
        assert!(info.status_code.is_none());
        assert!(!info.is_timeout);
        assert!(!info.is_connect);
        assert!(info.is_request);
    }

    // ---- HttpErrorInfo Clone/Debug ----

    #[test]
    fn http_error_info_clone() {
        let info = HttpErrorInfo {
            message: "test".into(),
            status_code: Some(500),
            is_timeout: true,
            is_connect: false,
            is_request: false,
        };
        let cloned = info.clone();
        assert_eq!(info, cloned);
        assert_eq!(info.message, "test");
    }

    #[test]
    fn http_error_info_debug() {
        let info = HttpErrorInfo::cancelled();
        let dbg = format!("{info:?}");
        assert!(dbg.contains("HttpErrorInfo"));
        assert!(dbg.contains("cancelled"));
    }

    // ---- GraphqlErrorLocation Clone/Debug ----

    #[test]
    fn error_location_clone() {
        let loc = GraphqlErrorLocation {
            line: 5,
            column: 10,
        };
        let cloned = loc.clone();
        assert_eq!(loc, cloned);
        assert_eq!(loc.line, 5);
    }

    #[test]
    fn error_location_debug() {
        let loc = GraphqlErrorLocation { line: 1, column: 1 };
        let dbg = format!("{loc:?}");
        assert!(dbg.contains("GraphqlErrorLocation"));
    }

    #[test]
    fn error_location_inequality() {
        let a = GraphqlErrorLocation { line: 1, column: 1 };
        let b = GraphqlErrorLocation { line: 2, column: 1 };
        assert_ne!(a, b);
    }

    // ---- GraphqlPathSegment additional tests ----

    #[test]
    fn path_segment_key_clone() {
        let seg = GraphqlPathSegment::Key("field".into());
        let cloned = seg.clone();
        assert_eq!(seg, cloned);
        // Use original after clone
        assert_eq!(seg, GraphqlPathSegment::Key("field".into()));
    }

    #[test]
    fn path_segment_index_clone() {
        let seg = GraphqlPathSegment::Index(42);
        let cloned = seg.clone();
        assert_eq!(seg, cloned);
        assert_eq!(seg, GraphqlPathSegment::Index(42));
    }

    #[test]
    fn path_segment_debug() {
        let key = GraphqlPathSegment::Key("name".into());
        let idx = GraphqlPathSegment::Index(3);
        assert!(format!("{key:?}").contains("name"));
        assert!(format!("{idx:?}").contains('3'));
    }

    #[test]
    fn path_segment_negative_index() {
        let seg = GraphqlPathSegment::Index(-1);
        let json = serde_json::to_string(&seg).unwrap();
        assert_eq!(json, "-1");
        let back: GraphqlPathSegment = serde_json::from_str(&json).unwrap();
        assert_eq!(seg, back);
    }

    #[test]
    fn path_segment_empty_key() {
        let seg = GraphqlPathSegment::Key(String::new());
        let json = serde_json::to_string(&seg).unwrap();
        assert_eq!(json, r#""""#);
        let back: GraphqlPathSegment = serde_json::from_str(&json).unwrap();
        assert_eq!(seg, back);
    }

    #[test]
    fn path_segment_unicode_key() {
        let seg = GraphqlPathSegment::Key("utilisateur".into());
        let json = serde_json::to_string(&seg).unwrap();
        let back: GraphqlPathSegment = serde_json::from_str(&json).unwrap();
        assert_eq!(seg, back);
    }

    // ---- GraphqlError additional tests ----

    #[test]
    fn graphql_error_clone() {
        let err = GraphqlError {
            message: "err".into(),
            locations: vec![GraphqlErrorLocation { line: 1, column: 2 }],
            path: vec![GraphqlPathSegment::Key("a".into())],
            extensions: Some(serde_json::json!({"x": 1})),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
        assert_eq!(err.message, "err");
    }

    #[test]
    fn graphql_error_debug() {
        let err = GraphqlError {
            message: "debug test".into(),
            locations: vec![],
            path: vec![],
            extensions: None,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("debug test"));
    }

    #[test]
    fn graphql_error_with_null_extensions() {
        let json = r#"{"message":"err","extensions":null}"#;
        let err: GraphqlError = serde_json::from_str(json).unwrap();
        assert!(err.extensions.is_none());
    }

    #[test]
    fn graphql_error_multiple_locations() {
        let err = GraphqlError {
            message: "multi".into(),
            locations: vec![
                GraphqlErrorLocation { line: 1, column: 5 },
                GraphqlErrorLocation {
                    line: 3,
                    column: 10,
                },
            ],
            path: vec![],
            extensions: None,
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: GraphqlError = serde_json::from_str(&json).unwrap();
        assert_eq!(back.locations.len(), 2);
        assert_eq!(back.locations[1].line, 3);
    }

    #[test]
    fn graphql_error_complex_path() {
        let err = GraphqlError {
            message: "deep".into(),
            locations: vec![],
            path: vec![
                GraphqlPathSegment::Key("users".into()),
                GraphqlPathSegment::Index(0),
                GraphqlPathSegment::Key("posts".into()),
                GraphqlPathSegment::Index(5),
            ],
            extensions: None,
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: GraphqlError = serde_json::from_str(&json).unwrap();
        assert_eq!(back.path.len(), 4);
    }

    // ---- GraphqlClientError Clone/Debug ----

    #[test]
    fn client_error_clone_http() {
        let err = GraphqlClientError::Http(HttpErrorInfo {
            message: "fail".into(),
            status_code: Some(503),
            is_timeout: false,
            is_connect: true,
            is_request: false,
        });
        let cloned = err.clone();
        assert!(cloned.to_string().contains("HTTP error"));
        assert!(err.to_string().contains("HTTP error"));
    }

    #[test]
    fn client_error_clone_json() {
        let err = GraphqlClientError::Json("parse".into());
        let cloned = err.clone();
        assert!(cloned.to_string().contains("JSON"));
        assert!(err.to_string().contains("JSON"));
    }

    #[test]
    fn client_error_debug_all_variants() {
        let variants: Vec<GraphqlClientError> = vec![
            GraphqlClientError::Http(HttpErrorInfo::cancelled()),
            GraphqlClientError::HttpStatus {
                status: StatusCode::BAD_REQUEST,
                body: "bad".into(),
                retry_after: None,
            },
            GraphqlClientError::Json("err".into()),
            GraphqlClientError::GraphqlErrors { errors: vec![] },
            GraphqlClientError::Protocol {
                message: "proto".into(),
            },
            GraphqlClientError::SchemaValidation {
                message: "schema".into(),
                errors: vec![],
            },
            GraphqlClientError::RetriesExhausted { attempts: 1 },
        ];
        for v in &variants {
            let dbg = format!("{v:?}");
            assert!(!dbg.is_empty());
        }
    }

    // ---- to_fcp_error edge cases ----

    #[test]
    fn to_fcp_http_timeout_retryable() {
        let err = GraphqlClientError::Http(HttpErrorInfo {
            message: "timed out".into(),
            status_code: None,
            is_timeout: true,
            is_connect: false,
            is_request: false,
        });
        let fcp = err.to_fcp_error("svc");
        match fcp {
            FcpError::External { retryable, .. } => assert!(retryable),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_http_not_retryable_when_no_flags() {
        let err = GraphqlClientError::Http(HttpErrorInfo {
            message: "other".into(),
            status_code: None,
            is_timeout: false,
            is_connect: false,
            is_request: false,
        });
        let fcp = err.to_fcp_error("svc");
        match fcp {
            FcpError::External { retryable, .. } => assert!(!retryable),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_404_not_found() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::NOT_FOUND,
            body: "not found".into(),
            retry_after: None,
        };
        let fcp = err.to_fcp_error("api");
        match fcp {
            FcpError::External {
                retryable,
                status_code,
                ..
            } => {
                assert!(!retryable);
                assert_eq!(status_code, Some(404));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_502_server_error() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::BAD_GATEWAY,
            body: "bad gw".into(),
            retry_after: None,
        };
        let fcp = err.to_fcp_error("api");
        match fcp {
            FcpError::External { retryable, .. } => assert!(retryable),
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ---- HttpErrorInfo::timeout edge cases ----

    #[test]
    fn http_error_info_timeout_zero_duration() {
        let info = HttpErrorInfo::timeout(Duration::from_secs(0));
        assert!(info.is_timeout);
        assert!(info.message.contains('0'));
        assert_eq!(info.status_code, Some(408));
    }

    #[test]
    fn http_error_info_timeout_sub_millisecond() {
        let info = HttpErrorInfo::timeout(Duration::from_micros(500));
        assert!(info.is_timeout);
        // 500 microseconds rounds to 0ms
        assert!(info.message.contains('0'));
    }

    #[test]
    fn http_error_info_timeout_one_ms() {
        let info = HttpErrorInfo::timeout(Duration::from_millis(1));
        assert!(info.message.contains("1ms"));
    }

    // ---- HttpErrorInfo serde edge cases ----

    #[test]
    fn http_error_info_all_flags_true() {
        let info = HttpErrorInfo {
            message: "everything bad".into(),
            status_code: Some(503),
            is_timeout: true,
            is_connect: true,
            is_request: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: HttpErrorInfo = serde_json::from_str(&json).unwrap();
        assert!(back.is_timeout);
        assert!(back.is_connect);
        assert!(back.is_request);
        assert_eq!(info, back);
    }

    #[test]
    fn http_error_info_all_flags_false() {
        let info = HttpErrorInfo {
            message: "decode error".into(),
            status_code: None,
            is_timeout: false,
            is_connect: false,
            is_request: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: HttpErrorInfo = serde_json::from_str(&json).unwrap();
        assert!(!back.is_timeout);
        assert!(!back.is_connect);
        assert!(!back.is_request);
        assert_eq!(info, back);
    }

    #[test]
    fn http_error_info_empty_message() {
        let info = HttpErrorInfo {
            message: String::new(),
            status_code: None,
            is_timeout: false,
            is_connect: false,
            is_request: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: HttpErrorInfo = serde_json::from_str(&json).unwrap();
        assert!(back.message.is_empty());
    }

    #[test]
    fn http_error_info_max_status_code() {
        let info = HttpErrorInfo {
            message: "max status".into(),
            status_code: Some(599),
            is_timeout: false,
            is_connect: false,
            is_request: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: HttpErrorInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status_code, Some(599));
    }

    // ---- GraphqlErrorLocation edge cases ----

    #[test]
    fn error_location_zero_values() {
        let loc = GraphqlErrorLocation { line: 0, column: 0 };
        let json = serde_json::to_string(&loc).unwrap();
        let back: GraphqlErrorLocation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.line, 0);
        assert_eq!(back.column, 0);
    }

    #[test]
    fn error_location_large_values() {
        let loc = GraphqlErrorLocation {
            line: u32::MAX,
            column: u32::MAX,
        };
        let json = serde_json::to_string(&loc).unwrap();
        let back: GraphqlErrorLocation = serde_json::from_str(&json).unwrap();
        assert_eq!(loc, back);
    }

    // ---- GraphqlPathSegment edge cases ----

    #[test]
    fn path_segment_zero_index() {
        let seg = GraphqlPathSegment::Index(0);
        let json = serde_json::to_string(&seg).unwrap();
        assert_eq!(json, "0");
        let back: GraphqlPathSegment = serde_json::from_str(&json).unwrap();
        assert_eq!(seg, back);
    }

    #[test]
    fn path_segment_large_positive_index() {
        let seg = GraphqlPathSegment::Index(i64::MAX);
        let json = serde_json::to_string(&seg).unwrap();
        let back: GraphqlPathSegment = serde_json::from_str(&json).unwrap();
        assert_eq!(seg, back);
    }

    #[test]
    fn path_segment_key_with_special_chars() {
        let seg = GraphqlPathSegment::Key("field.with.dots".into());
        let json = serde_json::to_string(&seg).unwrap();
        let back: GraphqlPathSegment = serde_json::from_str(&json).unwrap();
        assert_eq!(seg, back);
    }

    #[test]
    fn path_segment_key_with_spaces() {
        let seg = GraphqlPathSegment::Key("field name".into());
        let json = serde_json::to_string(&seg).unwrap();
        let back: GraphqlPathSegment = serde_json::from_str(&json).unwrap();
        assert_eq!(seg, back);
    }

    // ---- GraphqlError serde edge cases ----

    #[test]
    fn graphql_error_empty_locations_and_path() {
        let err = GraphqlError {
            message: "err".into(),
            locations: vec![],
            path: vec![],
            extensions: None,
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: GraphqlError = serde_json::from_str(&json).unwrap();
        assert!(back.locations.is_empty());
        assert!(back.path.is_empty());
    }

    #[test]
    fn graphql_error_extensions_complex_object() {
        let ext = serde_json::json!({
            "code": "UNAUTHENTICATED",
            "retryable": false,
            "details": {"reason": "token expired", "scope": ["read", "write"]}
        });
        let err = GraphqlError {
            message: "auth error".into(),
            locations: vec![],
            path: vec![],
            extensions: Some(ext),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: GraphqlError = serde_json::from_str(&json).unwrap();
        assert_eq!(back.extensions.unwrap()["code"], "UNAUTHENTICATED");
    }

    #[test]
    fn graphql_error_with_empty_message() {
        let err = GraphqlError {
            message: String::new(),
            locations: vec![],
            path: vec![],
            extensions: None,
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: GraphqlError = serde_json::from_str(&json).unwrap();
        assert!(back.message.is_empty());
    }

    // ---- is_retryable combinations ----

    #[test]
    fn is_retryable_http_all_flags_true() {
        let err = GraphqlClientError::Http(HttpErrorInfo {
            message: "multi-fail".into(),
            status_code: Some(500),
            is_timeout: true,
            is_connect: true,
            is_request: true,
        });
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_504_gateway_timeout() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::GATEWAY_TIMEOUT,
            body: String::new(),
            retry_after: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn not_retryable_404_not_found() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::NOT_FOUND,
            body: String::new(),
            retry_after: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_422_unprocessable() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            body: "bad input".into(),
            retry_after: None,
        };
        assert!(!err.is_retryable());
    }

    // ---- to_fcp_error additional edge cases ----

    #[test]
    fn to_fcp_429_very_large_retry_after() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::TOO_MANY_REQUESTS,
            body: String::new(),
            retry_after: Some(Duration::from_secs(86400)),
        };
        let fcp = err.to_fcp_error("api");
        match fcp {
            FcpError::RateLimited { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, 86_400_000);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_retries_exhausted_one_attempt() {
        let err = GraphqlClientError::RetriesExhausted { attempts: 1 };
        let fcp = err.to_fcp_error("svc");
        match fcp {
            FcpError::External { message, .. } => {
                assert!(message.contains("1 attempts"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_graphql_errors_uses_first_message() {
        let err = GraphqlClientError::GraphqlErrors {
            errors: vec![
                GraphqlError {
                    message: "first error".into(),
                    locations: vec![],
                    path: vec![],
                    extensions: None,
                },
                GraphqlError {
                    message: "second error".into(),
                    locations: vec![],
                    path: vec![],
                    extensions: None,
                },
            ],
        };
        let fcp = err.to_fcp_error("api");
        match fcp {
            FcpError::External { message, .. } => {
                assert_eq!(message, "first error");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_http_error_preserves_status_code() {
        let err = GraphqlClientError::Http(HttpErrorInfo {
            message: "fail".into(),
            status_code: Some(502),
            is_timeout: false,
            is_connect: false,
            is_request: false,
        });
        let fcp = err.to_fcp_error("svc");
        match fcp {
            FcpError::External { status_code, .. } => {
                assert_eq!(status_code, Some(502));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_http_status_has_retry_after() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: "crash".into(),
            retry_after: Some(Duration::from_secs(5)),
        };
        let fcp = err.to_fcp_error("svc");
        match fcp {
            FcpError::External { retry_after, .. } => {
                assert_eq!(retry_after, Some(Duration::from_secs(5)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_schema_validation_preserves_code() {
        let err = GraphqlClientError::SchemaValidation {
            message: "bad".into(),
            errors: vec!["err1".into(), "err2".into()],
        };
        let fcp = err.to_fcp_error("svc");
        match fcp {
            FcpError::InvalidRequest { code, .. } => {
                assert_eq!(code, 1003);
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    // ---- GraphqlClientError Display content ----

    #[test]
    fn display_http_status_with_retry_after() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::TOO_MANY_REQUESTS,
            body: "slow down".into(),
            retry_after: Some(Duration::from_secs(30)),
        };
        let s = err.to_string();
        assert!(s.contains("429"));
        assert!(s.contains("slow down"));
    }

    #[test]
    fn display_retries_exhausted_large_attempts() {
        let err = GraphqlClientError::RetriesExhausted { attempts: 999 };
        assert!(err.to_string().contains("999 attempts"));
    }

    #[test]
    fn display_schema_validation_full() {
        let err = GraphqlClientError::SchemaValidation {
            message: "type mismatch in field x".into(),
            errors: vec!["field x wrong".into(), "field y missing".into()],
        };
        let s = err.to_string();
        assert!(s.contains("type mismatch in field x"));
    }

    // ---- HttpErrorInfo unicode and edge cases ----

    #[test]
    fn http_error_info_unicode_message() {
        let info = HttpErrorInfo {
            message: "Verbindung fehlgeschlagen: Zeitlimit".into(),
            status_code: Some(504),
            is_timeout: true,
            is_connect: false,
            is_request: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: HttpErrorInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, back);
        assert!(back.message.contains("Zeitlimit"));
    }

    #[test]
    fn http_error_info_status_code_boundary_100() {
        let info = HttpErrorInfo {
            message: "info status".into(),
            status_code: Some(100),
            is_timeout: false,
            is_connect: false,
            is_request: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: HttpErrorInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status_code, Some(100));
    }

    #[test]
    fn http_error_info_status_code_u16_max() {
        let info = HttpErrorInfo {
            message: "max".into(),
            status_code: Some(u16::MAX),
            is_timeout: false,
            is_connect: false,
            is_request: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: HttpErrorInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status_code, Some(u16::MAX));
    }

    #[test]
    fn http_error_info_inequality_by_timeout_flag() {
        let a = HttpErrorInfo {
            message: "err".into(),
            status_code: None,
            is_timeout: true,
            is_connect: false,
            is_request: false,
        };
        let b = HttpErrorInfo {
            message: "err".into(),
            status_code: None,
            is_timeout: false,
            is_connect: false,
            is_request: false,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn http_error_info_inequality_by_message() {
        let a = HttpErrorInfo {
            message: "alpha".into(),
            status_code: None,
            is_timeout: false,
            is_connect: false,
            is_request: false,
        };
        let b = HttpErrorInfo {
            message: "beta".into(),
            status_code: None,
            is_timeout: false,
            is_connect: false,
            is_request: false,
        };
        assert_ne!(a, b);
    }

    // ---- GraphqlErrorLocation edge cases ----

    #[test]
    fn error_location_equality_both_same() {
        let a = GraphqlErrorLocation { line: 7, column: 3 };
        let b = GraphqlErrorLocation { line: 7, column: 3 };
        assert_eq!(a, b);
    }

    #[test]
    fn error_location_inequality_by_column() {
        let a = GraphqlErrorLocation { line: 1, column: 1 };
        let b = GraphqlErrorLocation { line: 1, column: 2 };
        assert_ne!(a, b);
    }

    // ---- GraphqlPathSegment inequality ----

    #[test]
    fn path_segment_key_vs_index_inequality() {
        let key = GraphqlPathSegment::Key("0".into());
        let idx = GraphqlPathSegment::Index(0);
        assert_ne!(key, idx);
    }

    #[test]
    fn path_segment_different_keys_inequality() {
        let a = GraphqlPathSegment::Key("alpha".into());
        let b = GraphqlPathSegment::Key("beta".into());
        assert_ne!(a, b);
    }

    #[test]
    fn path_segment_different_indices_inequality() {
        let a = GraphqlPathSegment::Index(1);
        let b = GraphqlPathSegment::Index(2);
        assert_ne!(a, b);
    }

    // ---- GraphqlClientError implements std::error::Error ----

    #[test]
    fn client_error_implements_error_trait() {
        fn assert_error<E: std::error::Error>(_e: &E) {}
        assert_error(&GraphqlClientError::Json("test".into()));
        assert_error(&GraphqlClientError::Protocol {
            message: "test".into(),
        });
        assert_error(&GraphqlClientError::RetriesExhausted { attempts: 1 });
    }

    // ---- GraphqlError inequality tests ----

    #[test]
    fn graphql_error_inequality_by_message() {
        let a = GraphqlError {
            message: "alpha".into(),
            locations: vec![],
            path: vec![],
            extensions: None,
        };
        let b = GraphqlError {
            message: "beta".into(),
            locations: vec![],
            path: vec![],
            extensions: None,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn graphql_error_inequality_by_locations() {
        let a = GraphqlError {
            message: "err".into(),
            locations: vec![GraphqlErrorLocation { line: 1, column: 1 }],
            path: vec![],
            extensions: None,
        };
        let b = GraphqlError {
            message: "err".into(),
            locations: vec![],
            path: vec![],
            extensions: None,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn graphql_error_inequality_by_path() {
        let a = GraphqlError {
            message: "err".into(),
            locations: vec![],
            path: vec![GraphqlPathSegment::Key("x".into())],
            extensions: None,
        };
        let b = GraphqlError {
            message: "err".into(),
            locations: vec![],
            path: vec![],
            extensions: None,
        };
        assert_ne!(a, b);
    }

    // ---- GraphqlClientError clone all variants ----

    #[test]
    fn client_error_clone_http_status() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::TOO_MANY_REQUESTS,
            body: "rate limited".into(),
            retry_after: Some(Duration::from_secs(10)),
        };
        let cloned = err.clone();
        assert!(cloned.to_string().contains("429"));
        assert!(err.to_string().contains("429"));
    }

    #[test]
    fn client_error_clone_graphql_errors() {
        let err = GraphqlClientError::GraphqlErrors {
            errors: vec![GraphqlError {
                message: "test".into(),
                locations: vec![],
                path: vec![],
                extensions: None,
            }],
        };
        let cloned = err.clone();
        assert!(cloned.to_string().contains("GraphQL errors"));
        assert!(err.to_string().contains("GraphQL errors"));
    }

    #[test]
    fn client_error_clone_protocol() {
        let err = GraphqlClientError::Protocol {
            message: "proto fail".into(),
        };
        let cloned = err.clone();
        assert!(cloned.to_string().contains("protocol error"));
        assert!(err.to_string().contains("protocol error"));
    }

    #[test]
    fn client_error_clone_schema_validation() {
        let err = GraphqlClientError::SchemaValidation {
            message: "invalid".into(),
            errors: vec!["e1".into(), "e2".into()],
        };
        let cloned = err.clone();
        assert!(cloned.to_string().contains("Schema validation"));
        assert!(err.to_string().contains("Schema validation"));
    }

    #[test]
    fn client_error_clone_retries_exhausted() {
        let err = GraphqlClientError::RetriesExhausted { attempts: 7 };
        let cloned = err.clone();
        assert!(cloned.to_string().contains("7 attempts"));
        assert!(err.to_string().contains("7 attempts"));
    }

    // ---- to_fcp_error: http error with request flag (not included in fcp retryable) ----

    #[test]
    fn to_fcp_http_request_error_not_retryable_in_fcp() {
        // Note: is_request is retryable for retry policy (is_retryable()),
        // but to_fcp_error only considers is_timeout || is_connect for retryable.
        let err = GraphqlClientError::Http(HttpErrorInfo {
            message: "request failed".into(),
            status_code: None,
            is_timeout: false,
            is_connect: false,
            is_request: true,
        });
        let fcp = err.to_fcp_error("svc");
        match fcp {
            FcpError::External { retryable, .. } => assert!(!retryable),
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ---- HttpErrorInfo::timeout with very large Duration ----

    #[test]
    fn http_error_info_timeout_very_large_duration() {
        // A duration larger than what u64 millis can hold via u128
        let info = HttpErrorInfo::timeout(Duration::from_secs(u64::MAX));
        assert!(info.is_timeout);
        assert_eq!(info.status_code, Some(408));
    }

    // ---- GraphqlError serde with all fields populated ----

    #[test]
    fn graphql_error_full_roundtrip_all_fields() {
        let err = GraphqlError {
            message: "full error".into(),
            locations: vec![
                GraphqlErrorLocation { line: 1, column: 1 },
                GraphqlErrorLocation {
                    line: 5,
                    column: 20,
                },
            ],
            path: vec![
                GraphqlPathSegment::Key("root".into()),
                GraphqlPathSegment::Index(0),
                GraphqlPathSegment::Key("child".into()),
            ],
            extensions: Some(serde_json::json!({
                "code": "ERR_001",
                "timestamp": "2026-03-08T00:00:00Z",
                "metadata": {"nested": true}
            })),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: GraphqlError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
        assert_eq!(back.locations.len(), 2);
        assert_eq!(back.path.len(), 3);
        assert_eq!(back.extensions.unwrap()["code"], "ERR_001");
    }

    // ---- is_retryable: HttpStatus 502 ----

    #[test]
    fn is_retryable_502_bad_gateway() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::BAD_GATEWAY,
            body: String::new(),
            retry_after: None,
        };
        assert!(err.is_retryable());
    }

    // ---- to_fcp_error: 503 server error ----

    #[test]
    fn to_fcp_503_service_unavailable() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: "maintenance".into(),
            retry_after: None,
        };
        let fcp = err.to_fcp_error("api");
        match fcp {
            FcpError::External {
                retryable,
                status_code,
                ..
            } => {
                assert!(retryable);
                assert_eq!(status_code, Some(503));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ---- GraphqlPathSegment: key with newlines ----

    #[test]
    fn path_segment_key_with_newlines() {
        let seg = GraphqlPathSegment::Key("line1\nline2".into());
        let json = serde_json::to_string(&seg).unwrap();
        let back: GraphqlPathSegment = serde_json::from_str(&json).unwrap();
        assert_eq!(seg, back);
    }

    // ---- HttpErrorInfo: message with special JSON characters ----

    #[test]
    fn http_error_info_message_with_json_special_chars() {
        let info = HttpErrorInfo {
            message: r#"error: "quoted" and \backslash"#.into(),
            status_code: None,
            is_timeout: false,
            is_connect: false,
            is_request: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: HttpErrorInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, back);
    }
}
