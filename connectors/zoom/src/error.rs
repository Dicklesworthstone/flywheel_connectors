//! Zoom connector error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use fcp_sdk::migration::classify_http_status;
use thiserror::Error;

/// Zoom connector errors.
#[derive(Error, Debug)]
pub enum ZoomError {
    /// HTTP transport error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Zoom API returned an error response.
    #[error("Zoom API error ({code}): {message}")]
    Api { code: u32, message: String },

    /// Rate limited by Zoom API.
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failure.
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Invalid input from caller.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Async operation error (timeout, cancellation).
    #[error("Async error: {0}")]
    Async(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),
}

impl ZoomError {
    /// Whether this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } | Self::Async(_) => true,
            Self::Api { code, .. } => {
                // Treat as HTTP status codes for retryability
                u16::try_from(*code)
                    .is_ok_and(|status| classify_http_status(status, None).is_retryable())
            }
            Self::Json(_) | Self::Unauthorized(_) | Self::InvalidInput(_) | Self::Config(_) => {
                false
            }
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
                service: "zoom".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api { code, message } => FcpError::External {
                service: "zoom".into(),
                message: format!("API error {code}: {message}"),
                status_code: u16::try_from(*code).ok(),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Unauthorized(msg) => FcpError::Unauthorized {
                code: 2001,
                message: msg.clone(),
            },
            Self::InvalidInput(msg) => FcpError::InvalidRequest {
                code: 1005,
                message: msg.clone(),
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

impl ConnectorErrorMapping for ZoomError {
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

pub type ZoomResult<T> = Result<T, ZoomError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_error_is_retryable() {
        let err = ZoomError::Http(
            reqwest::Client::new()
                .get("://invalid")
                .build()
                .unwrap_err(),
        );
        assert!(err.is_retryable());
    }

    #[test]
    fn rate_limited_is_retryable() {
        let err = ZoomError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn unauthorized_not_retryable() {
        let err = ZoomError::Unauthorized("bad token".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_error_maps_to_fcp() {
        let err = ZoomError::Api {
            code: 3001,
            message: "Meeting not found".into(),
        };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::External { .. }));
    }

    #[test]
    fn invalid_input_maps_to_invalid_request() {
        let err = ZoomError::InvalidInput("empty meeting_id".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn from_async_timeout() {
        let err = ZoomError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(matches!(err, ZoomError::Async(_)));
        assert!(err.is_retryable());
    }

    #[test]
    fn from_async_cancelled() {
        let err = ZoomError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, ZoomError::Async(_)));
    }

    #[test]
    fn from_async_channel_closed() {
        let err = ZoomError::from_async_error(AsyncError::ChannelClosed);
        assert!(matches!(err, ZoomError::Async(_)));
    }

    #[test]
    fn rate_limited_maps_to_fcp() {
        let err = ZoomError::RateLimited {
            retry_after_ms: 3000,
        };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::RateLimited { .. }));
    }

    #[test]
    fn config_error_not_retryable() {
        let err = ZoomError::Config("missing account_id".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn json_error_not_retryable() {
        let err = ZoomError::Json(serde_json::from_str::<String>("invalid").unwrap_err());
        assert!(!err.is_retryable());
    }

    #[test]
    fn error_display_format() {
        let err = ZoomError::Api {
            code: 3001,
            message: "Meeting not found".into(),
        };
        let display = format!("{err}");
        assert!(display.contains("Zoom API error"));
        assert!(display.contains("3001"));
    }

    #[test]
    fn api_503_is_retryable() {
        let err = ZoomError::Api {
            code: 503,
            message: "Service unavailable".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_404_not_retryable() {
        let err = ZoomError::Api {
            code: 404,
            message: "Not found".into(),
        };
        assert!(!err.is_retryable());
    }
}
