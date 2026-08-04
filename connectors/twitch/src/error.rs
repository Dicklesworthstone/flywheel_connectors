//! Twitch connector error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use fcp_sdk::migration::classify_http_status;
use thiserror::Error;

/// Twitch connector errors.
#[derive(Error, Debug)]
pub enum TwitchError {
    /// HTTP transport error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Twitch API returned an error response.
    #[error("Twitch API error ({status}): {message}")]
    Api { status: u16, message: String },

    /// Rate limited by Twitch API.
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failure.
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// OAuth token acquisition failure.
    #[error("Token error: {0}")]
    TokenError(String),

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

impl TwitchError {
    /// Whether this error is retryable.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } | Self::Async(_) => true,
            Self::Api { status, .. } => classify_http_status(*status, None).is_retryable(),
            Self::Json(_)
            | Self::Unauthorized(_)
            | Self::TokenError(_)
            | Self::Config(_)
            | Self::InvalidInput(_) => false,
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
            Self::Api { status, .. } => *status == 429,
            Self::Http(e) => !fcp_sdk::migration::transport_error_reached_service(e),
            _ => false,
        }
    }

    /// Suggested retry-after delay.
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    /// Convert to FCP error taxonomy.
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "twitch".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api { status, message } => FcpError::External {
                service: "twitch".into(),
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
            Self::TokenError(msg) => FcpError::Unauthorized {
                code: 2002,
                message: format!("Token error: {msg}"),
            },
            Self::Async(msg) => FcpError::Internal {
                message: format!("Async error: {msg}"),
            },
            Self::Config(msg) => FcpError::InvalidRequest {
                code: 1001,
                message: format!("Configuration error: {msg}"),
            },
            Self::InvalidInput(msg) => FcpError::InvalidRequest {
                code: 1008,
                message: format!("Invalid input: {msg}"),
            },
        }
    }
}

impl ConnectorErrorMapping for TwitchError {
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

pub type TwitchResult<T> = Result<T, TwitchError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_error_is_retryable() {
        let err = TwitchError::Http(
            reqwest::Client::new()
                .get("://invalid")
                .build()
                .unwrap_err(),
        );
        assert!(err.is_retryable());
    }

    #[test]
    fn rate_limited_is_retryable() {
        let err = TwitchError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn unauthorized_not_retryable() {
        let err = TwitchError::Unauthorized("bad token".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_error_503_retryable() {
        let err = TwitchError::Api {
            status: 503,
            message: "Service unavailable".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_error_400_not_retryable() {
        let err = TwitchError::Api {
            status: 400,
            message: "Bad request".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_error_maps_to_external() {
        let err = TwitchError::Api {
            status: 500,
            message: "Server error".into(),
        };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::External { .. }));
    }

    #[test]
    fn rate_limited_maps_to_fcp() {
        let err = TwitchError::RateLimited {
            retry_after_ms: 3000,
        };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::RateLimited { .. }));
    }

    #[test]
    fn token_error_maps_to_unauthorized() {
        let err = TwitchError::TokenError("invalid grant".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::Unauthorized { .. }));
    }

    #[test]
    fn config_error_not_retryable() {
        let err = TwitchError::Config("missing client_id".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn from_async_timeout() {
        let err = TwitchError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(matches!(err, TwitchError::Async(_)));
        assert!(err.is_retryable());
    }

    #[test]
    fn from_async_cancelled() {
        let err = TwitchError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, TwitchError::Async(_)));
    }

    #[test]
    fn from_async_channel_closed() {
        let err = TwitchError::from_async_error(AsyncError::ChannelClosed);
        assert!(matches!(err, TwitchError::Async(_)));
    }

    #[test]
    fn invalid_input_maps_to_invalid_request() {
        let err = TwitchError::InvalidInput("bad id".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(
            fcp_err,
            FcpError::InvalidRequest { code: 1008, .. }
        ));
    }

    #[test]
    fn error_display_format() {
        let err = TwitchError::Api {
            status: 404,
            message: "Not Found".into(),
        };
        let display = format!("{err}");
        assert!(display.contains("Twitch API error"));
        assert!(display.contains("404"));
    }
}
