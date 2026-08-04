//! MCP Bridge-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use thiserror::Error;

/// Result alias for MCP Bridge operations.
pub type McpBridgeResult<T> = Result<T, McpBridgeError>;

/// MCP Bridge-specific errors.
#[derive(Error, Debug)]
pub enum McpBridgeError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// MCP server returned a JSON-RPC error
    #[error("MCP server error ({code}): {message}")]
    McpError { code: i64, message: String },

    /// Rate limited (429)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failed (401)
    #[error("Authentication failed: invalid API key")]
    Unauthorized,

    /// Forbidden (403)
    #[error("Forbidden: insufficient permissions")]
    Forbidden,

    /// Resource not found (404)
    #[error("Not found: {resource}")]
    NotFound { resource: String },

    /// HTTP error from MCP server
    #[error("MCP server HTTP error ({status_code}): {message}")]
    Api { status_code: u16, message: String },
}

impl McpBridgeError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, 500..=599 | 429),
            _ => false,
        }
    }

    /// Whether replaying the request that produced this error cannot duplicate
    /// a side effect (br-kxd3e).
    ///
    /// Distinct from `is_retryable`: a rate-limited request was refused
    /// WITHOUT being performed, so it stays safe to replay; a 5xx means the
    /// service received the request and may already have applied it.
    #[must_use]
    pub fn replay_is_safe(&self) -> bool {
        match self {
            Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => *status_code == 429,
            Self::Http(e) => !fcp_sdk::migration::transport_error_reached_service(e),
            _ => false,
        }
    }

    #[must_use]
    pub fn is_session_expired(&self) -> bool {
        match self {
            Self::NotFound { resource }
            | Self::Api {
                message: resource, ..
            }
            | Self::McpError {
                message: resource, ..
            } => {
                let lower = resource.to_ascii_lowercase();
                lower.contains("session expired")
                    || lower.contains("invalid session")
                    || lower.contains("unknown session")
                    || lower.contains("session not found")
            }
            _ => false,
        }
    }

    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "mcp-bridge".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::McpError { code, message } => FcpError::External {
                service: "mcp-bridge".into(),
                message: format!("MCP JSON-RPC error ({code}): {message}"),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
            Self::Api {
                status_code,
                message,
            } => FcpError::External {
                service: "mcp-bridge".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "mcp-bridge".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "mcp-bridge".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "mcp-bridge".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "mcp-bridge".into(),
                message: format!("Not found: {resource}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
        }
    }
}

impl ConnectorErrorMapping for McpBridgeError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                status_code: 408,
                message: format!("deadline exceeded after {timeout_ms}ms"),
            },
            AsyncError::Cancelled => Self::Api {
                status_code: 0,
                message: "request cancelled".into(),
            },
            other => Self::Api {
                status_code: 0,
                message: other.to_string(),
            },
        }
    }

    fn to_fcp_error(&self) -> FcpError {
        Self::to_fcp_error(self)
    }

    fn is_retryable(&self) -> bool {
        Self::is_retryable(self)
    }

    fn retry_after(&self) -> Option<Duration> {
        Self::retry_after(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limited_is_retryable() {
        assert!(
            McpBridgeError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            McpBridgeError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            McpBridgeError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            McpBridgeError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!McpBridgeError::Unauthorized.is_retryable());
    }

    #[test]
    fn session_expired_detected_from_not_found() {
        assert!(
            McpBridgeError::NotFound {
                resource: "session expired".into()
            }
            .is_session_expired()
        );
    }

    #[test]
    fn session_expired_detected_from_mcp_error() {
        assert!(
            McpBridgeError::McpError {
                code: -32001,
                message: "Invalid session id".into()
            }
            .is_session_expired()
        );
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!McpBridgeError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(
            !McpBridgeError::NotFound {
                resource: "tool".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !McpBridgeError::Api {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn mcp_error_not_retryable() {
        assert!(
            !McpBridgeError::McpError {
                code: -32600,
                message: "Invalid Request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = McpBridgeError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(McpBridgeError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(McpBridgeError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            McpBridgeError::Api {
                status_code: 500,
                message: "err".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_none_for_not_found() {
        assert_eq!(
            McpBridgeError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_none_for_mcp_error() {
        assert_eq!(
            McpBridgeError::McpError {
                code: -32600,
                message: "err".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn unauthorized_to_fcp_error() {
        match McpBridgeError::Unauthorized.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "mcp-bridge");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match McpBridgeError::Forbidden.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "mcp-bridge");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (McpBridgeError::NotFound {
            resource: "tool:my_tool".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                status_code,
                message,
                retryable,
                ..
            } => {
                assert_eq!(status_code, Some(404));
                assert!(message.contains("tool:my_tool"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (McpBridgeError::RateLimited {
            retry_after_ms: 60_000,
        })
        .to_fcp_error()
        {
            FcpError::External {
                status_code,
                retryable,
                retry_after,
                ..
            } => {
                assert_eq!(status_code, Some(429));
                assert!(retryable);
                assert_eq!(retry_after, Some(Duration::from_secs(60)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_to_fcp_error() {
        match (McpBridgeError::Api {
            status_code: 503,
            message: "unavailable".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                service,
                status_code,
                retryable,
                message,
                ..
            } => {
                assert_eq!(service, "mcp-bridge");
                assert_eq!(status_code, Some(503));
                assert!(retryable);
                assert_eq!(message, "unavailable");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn mcp_error_to_fcp_error() {
        match (McpBridgeError::McpError {
            code: -32601,
            message: "Method not found".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "mcp-bridge");
                assert!(message.contains("-32601"));
                assert!(message.contains("Method not found"));
                assert!(status_code.is_none());
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn json_error_to_fcp_internal() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        match McpBridgeError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (McpBridgeError::Api {
            status_code: 400,
            message: "bad".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(status_code, Some(400));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn error_display_unauthorized() {
        assert_eq!(
            McpBridgeError::Unauthorized.to_string(),
            "Authentication failed: invalid API key"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            McpBridgeError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            McpBridgeError::NotFound {
                resource: "tool".into()
            }
            .to_string(),
            "Not found: tool"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            McpBridgeError::RateLimited {
                retry_after_ms: 2000
            }
            .to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            McpBridgeError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "MCP server HTTP error (500): Internal"
        );
    }

    #[test]
    fn error_display_mcp_error() {
        assert_eq!(
            McpBridgeError::McpError {
                code: -32600,
                message: "Invalid Request".into()
            }
            .to_string(),
            "MCP server error (-32600): Invalid Request"
        );
    }

    #[test]
    fn api_502_is_retryable() {
        assert!(
            McpBridgeError::Api {
                status_code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_504_is_retryable() {
        assert!(
            McpBridgeError::Api {
                status_code: 504,
                message: "timeout".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn rate_limited_retry_after_zero() {
        let err = McpBridgeError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn not_found_to_fcp_error_service() {
        match (McpBridgeError::NotFound {
            resource: "res".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { service, .. } => assert_eq!(service, "mcp-bridge"),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error_service() {
        match (McpBridgeError::RateLimited {
            retry_after_ms: 1000,
        })
        .to_fcp_error()
        {
            FcpError::External { service, .. } => assert_eq!(service, "mcp-bridge"),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_422_not_retryable() {
        assert!(
            !McpBridgeError::Api {
                status_code: 422,
                message: "unprocessable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn error_debug_format_unauthorized() {
        let dbg = format!("{:?}", McpBridgeError::Unauthorized);
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn error_debug_format_forbidden() {
        let dbg = format!("{:?}", McpBridgeError::Forbidden);
        assert!(dbg.contains("Forbidden"));
    }

    #[test]
    fn error_debug_format_not_found() {
        let dbg = format!(
            "{:?}",
            McpBridgeError::NotFound {
                resource: "tool".into()
            }
        );
        assert!(dbg.contains("NotFound"));
        assert!(dbg.contains("tool"));
    }

    #[test]
    fn error_debug_format_rate_limited() {
        let dbg = format!(
            "{:?}",
            McpBridgeError::RateLimited {
                retry_after_ms: 250
            }
        );
        assert!(dbg.contains("RateLimited"));
    }

    #[test]
    fn error_debug_format_api() {
        let dbg = format!(
            "{:?}",
            McpBridgeError::Api {
                status_code: 418,
                message: "teapot".into()
            }
        );
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("418"));
    }

    #[test]
    fn error_debug_format_mcp_error() {
        let dbg = format!(
            "{:?}",
            McpBridgeError::McpError {
                code: -32601,
                message: "not found".into()
            }
        );
        assert!(dbg.contains("McpError"));
        assert!(dbg.contains("-32601"));
    }

    #[test]
    fn api_599_is_retryable() {
        assert!(
            McpBridgeError::Api {
                status_code: 599,
                message: "custom".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn rate_limited_large_retry_after() {
        let err = McpBridgeError::RateLimited {
            retry_after_ms: 3_600_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn json_error_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        assert!(!McpBridgeError::Json(bad.unwrap_err()).is_retryable());
    }

    #[test]
    fn retry_after_none_for_json_error() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert_eq!(McpBridgeError::Json(bad.unwrap_err()).retry_after(), None);
    }

    #[test]
    fn unauthorized_fcp_retry_after_is_none() {
        match McpBridgeError::Unauthorized.to_fcp_error() {
            FcpError::External { retry_after, .. } => assert!(retry_after.is_none()),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_fcp_retry_after_is_none() {
        match McpBridgeError::Forbidden.to_fcp_error() {
            FcpError::External { retry_after, .. } => assert!(retry_after.is_none()),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_fcp_retry_after_is_none() {
        match (McpBridgeError::Api {
            status_code: 502,
            message: "gw".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { retry_after, .. } => assert!(retry_after.is_none()),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn mcp_error_fcp_retry_after_is_none() {
        match (McpBridgeError::McpError {
            code: -32600,
            message: "err".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { retry_after, .. } => assert!(retry_after.is_none()),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_409_not_retryable() {
        assert!(
            !McpBridgeError::Api {
                status_code: 409,
                message: "conflict".into()
            }
            .is_retryable()
        );
    }
}
