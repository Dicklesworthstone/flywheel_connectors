//! `CircleCI` connector error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use fcp_sdk::migration::classify_http_status;
use thiserror::Error;

/// `CircleCI` connector errors.
#[derive(Error, Debug)]
pub enum Error {
    /// HTTP transport error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `CircleCI` API returned an error response.
    #[error("CircleCI API error ({status}): {message}")]
    Api { status: u16, message: String },

    /// Rate limited by `CircleCI` API.
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failure.
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Async operation error (timeout, cancellation).
    #[error("Async error: {0}")]
    Async(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Invalid input.
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl Error {
    /// Whether this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } | Self::Async(_) => true,
            Self::Api { status, .. } => classify_http_status(*status, None).is_retryable(),
            Self::Json(_) | Self::Unauthorized(_) | Self::Config(_) | Self::InvalidInput(_) => {
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
                service: "circleci".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api { status, message } => FcpError::External {
                service: "circleci".into(),
                message: format!("API error {status}: {message}"),
                status_code: Some(*status),
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
            Self::Async(msg) => FcpError::Internal {
                message: format!("Async error: {msg}"),
            },
            Self::Config(msg) => FcpError::InvalidRequest {
                code: 1001,
                message: format!("Configuration error: {msg}"),
            },
            Self::InvalidInput(msg) => FcpError::InvalidRequest {
                code: 1005,
                message: msg.clone(),
            },
        }
    }
}

impl ConnectorErrorMapping for Error {
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

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_error_is_retryable() {
        let err = Error::Http(
            reqwest::Client::new()
                .get("://invalid")
                .build()
                .unwrap_err(),
        );
        assert!(err.is_retryable());
    }

    #[test]
    fn rate_limited_is_retryable() {
        let err = Error::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn unauthorized_not_retryable() {
        let err = Error::Unauthorized("bad token".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_error_429_retryable() {
        let err = Error::Api {
            status: 429,
            message: "Too Many Requests".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_error_500_retryable() {
        let err = Error::Api {
            status: 500,
            message: "Internal Server Error".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_error_404_not_retryable() {
        let err = Error::Api {
            status: 404,
            message: "Not Found".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_error_maps_to_fcp_external() {
        let err = Error::Api {
            status: 500,
            message: "Server error".into(),
        };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::External { .. }));
    }

    #[test]
    fn rate_limited_maps_to_fcp() {
        let err = Error::RateLimited {
            retry_after_ms: 3000,
        };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::RateLimited { .. }));
    }

    #[test]
    fn config_error_not_retryable() {
        let err = Error::Config("missing token".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn invalid_input_maps_to_invalid_request() {
        let err = Error::InvalidInput("bad field".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn from_async_timeout() {
        let err = Error::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(matches!(err, Error::Async(_)));
        assert!(err.is_retryable());
    }

    #[test]
    fn from_async_cancelled() {
        let err = Error::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, Error::Async(_)));
    }

    #[test]
    fn from_async_channel_closed() {
        let err = Error::from_async_error(AsyncError::ChannelClosed);
        assert!(matches!(err, Error::Async(_)));
    }

    #[test]
    fn error_display_format() {
        let err = Error::Api {
            status: 403,
            message: "Forbidden".into(),
        };
        let display = format!("{err}");
        assert!(display.contains("CircleCI API error"));
        assert!(display.contains("403"));
    }

    #[test]
    fn json_error_not_retryable() {
        let json_err = serde_json::from_str::<String>("invalid").unwrap_err();
        let err = Error::Json(json_err);
        assert!(!err.is_retryable());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::Internal { .. }));
    }
}
