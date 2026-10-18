//! Calendly connector error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use fcp_sdk::migration::classify_http_status;
use thiserror::Error;

/// Calendly connector errors.
#[derive(Error, Debug)]
pub enum CalendlyError {
    /// HTTP transport error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Calendly API returned an error response.
    #[error("Calendly API error ({status}): {message}")]
    Api {
        status: u16,
        message: String,
        title: Option<String>,
    },

    /// Rate limited by Calendly API.
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failure.
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Resource not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// Async operation error (timeout, cancellation).
    #[error("Async error: {0}")]
    Async(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Invalid input (path traversal, etc.).
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl CalendlyError {
    /// Whether this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } | Self::Async(_) => true,
            Self::Api { status, .. } => classify_http_status(*status, None).is_retryable(),
            Self::Json(_)
            | Self::Unauthorized(_)
            | Self::NotFound(_)
            | Self::Config(_)
            | Self::InvalidInput(_) => false,
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
                service: "calendly".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api {
                status, message, ..
            } => FcpError::External {
                service: "calendly".into(),
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
            Self::InvalidInput(msg) => FcpError::InvalidRequest {
                code: 1005,
                message: format!("Invalid input: {msg}"),
            },
        }
    }
}

impl ConnectorErrorMapping for CalendlyError {
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

pub type CalendlyResult<T> = Result<T, CalendlyError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_error_is_retryable() {
        let err = CalendlyError::Http(
            reqwest::Client::new()
                .get("://invalid")
                .build()
                .unwrap_err(),
        );
        assert!(err.is_retryable());
    }

    #[test]
    fn rate_limited_is_retryable() {
        let err = CalendlyError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn unauthorized_not_retryable() {
        let err = CalendlyError::Unauthorized("bad token".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        let err = CalendlyError::NotFound("event not found".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_error_5xx_retryable() {
        let err = CalendlyError::Api {
            status: 503,
            message: "Service unavailable".into(),
            title: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_error_4xx_not_retryable() {
        let err = CalendlyError::Api {
            status: 400,
            message: "Bad request".into(),
            title: Some("Validation Error".into()),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_error_maps_to_fcp_external() {
        let err = CalendlyError::Api {
            status: 500,
            message: "Internal error".into(),
            title: None,
        };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::External { .. }));
    }

    #[test]
    fn rate_limited_maps_to_fcp() {
        let err = CalendlyError::RateLimited {
            retry_after_ms: 3000,
        };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::RateLimited { .. }));
    }

    #[test]
    fn unauthorized_maps_to_fcp() {
        let err = CalendlyError::Unauthorized("invalid token".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::Unauthorized { .. }));
    }

    #[test]
    fn config_error_not_retryable() {
        let err = CalendlyError::Config("missing token".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn from_async_timeout() {
        let err = CalendlyError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(matches!(err, CalendlyError::Async(_)));
        assert!(err.is_retryable());
    }

    #[test]
    fn from_async_cancelled() {
        let err = CalendlyError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, CalendlyError::Async(_)));
    }

    #[test]
    fn from_async_channel_closed() {
        let err = CalendlyError::from_async_error(AsyncError::ChannelClosed);
        assert!(matches!(err, CalendlyError::Async(_)));
    }

    #[test]
    fn invalid_input_maps_to_invalid_request() {
        let err = CalendlyError::InvalidInput("path traversal".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn error_display_format() {
        let err = CalendlyError::Api {
            status: 404,
            message: "Resource not found".into(),
            title: Some("Not Found".into()),
        };
        let display = format!("{err}");
        assert!(display.contains("Calendly API error"));
        assert!(display.contains("404"));
    }

    #[test]
    fn json_error_maps_to_internal() {
        let json_err: serde_json::Error = serde_json::from_str::<String>("invalid").unwrap_err();
        let err = CalendlyError::Json(json_err);
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::Internal { .. }));
    }

    #[test]
    fn not_found_maps_to_invalid_request() {
        let err = CalendlyError::NotFound("no such event".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::InvalidRequest { .. }));
    }
}
