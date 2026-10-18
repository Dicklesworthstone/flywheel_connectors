//! Hacker News connector error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use fcp_sdk::migration::classify_http_status;
use thiserror::Error;

/// Hacker News connector errors.
#[derive(Error, Debug)]
pub enum HackerNewsError {
    /// HTTP transport error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// HN API returned an error status.
    #[error("HN API error ({status}): {message}")]
    Api { status: u16, message: String },

    /// Rate limited.
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Item not found (null response from HN API).
    #[error("Item not found: {0}")]
    NotFound(String),

    /// Async operation error (timeout, cancellation).
    #[error("Async error: {0}")]
    Async(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),
}

impl HackerNewsError {
    /// Whether this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } | Self::Async(_) => true,
            Self::Api { status, .. } => classify_http_status(*status, None).is_retryable(),
            Self::Json(_) | Self::NotFound(_) | Self::Config(_) => false,
        }
    }

    /// Suggested retry-after delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    /// Convert to FCP error taxonomy.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "hackernews".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api { status, message } => FcpError::External {
                service: "hackernews".into(),
                message: format!("API error {status}: {message}"),
                status_code: Some(*status),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::NotFound(msg) => FcpError::InvalidRequest {
                code: 1006,
                message: format!("Not found: {msg}"),
            },
            Self::Async(msg) => FcpError::Internal {
                message: format!("Async error: {msg}"),
            },
            Self::Config(msg) => FcpError::InvalidRequest {
                code: 1001,
                message: format!("Configuration error: {msg}"),
            },
        }
    }
}

impl ConnectorErrorMapping for HackerNewsError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => {
                Self::Async(format!("operation timed out after {timeout_ms}ms"))
            }
            AsyncError::Cancelled => Self::Async("operation cancelled".into()),
            other => Self::Async(format!("async error: {other}")),
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

pub type HackerNewsResult<T> = Result<T, HackerNewsError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_error_is_retryable() {
        let err = HackerNewsError::Http(
            reqwest::Client::new()
                .get("://invalid")
                .build()
                .unwrap_err(),
        );
        assert!(err.is_retryable());
    }

    #[test]
    fn rate_limited_is_retryable() {
        let err = HackerNewsError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn not_found_not_retryable() {
        let err = HackerNewsError::NotFound("item 999".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_error_503_is_retryable() {
        let err = HackerNewsError::Api {
            status: 503,
            message: "Service unavailable".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_error_404_not_retryable() {
        let err = HackerNewsError::Api {
            status: 404,
            message: "Not found".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_error_maps_to_fcp() {
        let err = HackerNewsError::Api {
            status: 500,
            message: "Internal server error".into(),
        };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::External { .. }));
    }

    #[test]
    fn rate_limited_maps_to_fcp() {
        let err = HackerNewsError::RateLimited {
            retry_after_ms: 3000,
        };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::RateLimited { .. }));
    }

    #[test]
    fn not_found_maps_to_invalid_request() {
        let err = HackerNewsError::NotFound("item 42".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn config_error_not_retryable() {
        let err = HackerNewsError::Config("bad config".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn from_async_timeout() {
        let err = HackerNewsError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(matches!(err, HackerNewsError::Async(_)));
        assert!(err.is_retryable());
    }

    #[test]
    fn from_async_cancelled() {
        let err = HackerNewsError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, HackerNewsError::Async(_)));
    }

    #[test]
    fn from_async_channel_closed() {
        let err = HackerNewsError::from_async_error(AsyncError::ChannelClosed);
        assert!(matches!(err, HackerNewsError::Async(_)));
    }

    #[test]
    fn error_display_format() {
        let err = HackerNewsError::Api {
            status: 500,
            message: "Server error".into(),
        };
        let display = format!("{err}");
        assert!(display.contains("HN API error"));
        assert!(display.contains("500"));
    }

    #[test]
    fn json_error_maps_to_internal() {
        let err = HackerNewsError::Json(
            serde_json::from_str::<serde_json::Value>("{{bad json").unwrap_err(),
        );
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::Internal { .. }));
    }
}
