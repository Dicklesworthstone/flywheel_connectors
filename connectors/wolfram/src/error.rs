//! Wolfram Alpha error types and FCP error mapping.

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_prelude::log_redaction::redact_url;
use fcp_sdk::ConnectorErrorMapping;
use thiserror::Error;

/// Wolfram Alpha connector error.
#[derive(Error, Debug)]
pub enum WolframError {
    // Wolfram passes `appid` (the API key) as a query param, and
    // `reqwest::Error`'s `Display` appends the full request URL with the query
    // string unredacted. Interpolating the reqwest error into Display (`{0}`)
    // would leak the key; the redaction-safe detail is built in `to_fcp_error`.
    /// HTTP transport error.
    #[error("HTTP transport error")]
    Http(#[from] reqwest::Error),

    /// API returned an error status code.
    #[error("API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited by Wolfram Alpha.
    #[error("Rate limited")]
    RateLimited { retry_after_ms: u64 },

    /// Invalid input to the API.
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },

    /// Serialization/deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Internal connector error.
    #[error("Internal error: {message}")]
    Internal { message: String },
}

impl ConnectorErrorMapping for WolframError {
    fn from_async_error(error: AsyncError) -> Self
    where
        Self: Sized,
    {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                status_code: 408,
                message: format!("Request timed out after {timeout_ms}ms"),
            },
            AsyncError::Cancelled => Self::Api {
                status_code: 0,
                message: "Request cancelled".into(),
            },
            AsyncError::ChannelClosed => Self::Internal {
                message: "Channel closed unexpectedly".into(),
            },
            other => Self::Internal {
                message: other.to_string(),
            },
        }
    }

    fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => {
                if e.is_timeout() {
                    FcpError::UpstreamTimeout {
                        service: "wolfram_alpha".into(),
                    }
                } else {
                    // `{e}` would append the request URL, whose query string
                    // carries `appid=<API_KEY>`. Surface a redaction-safe URL
                    // (query dropped) instead of the raw reqwest error string.
                    let redacted = e
                        .url()
                        .map_or_else(|| "unknown".to_string(), |u| redact_url(u.as_str()));
                    if e.is_connect() {
                        FcpError::External {
                            service: "wolfram_alpha".into(),
                            message: format!("connection failed for url ({redacted})"),
                            status_code: None,
                            retryable: true,
                            retry_after: Some(std::time::Duration::from_secs(5)),
                        }
                    } else {
                        FcpError::Internal {
                            message: format!("HTTP transport error for url ({redacted})"),
                        }
                    }
                }
            }
            Self::Api {
                status_code,
                message,
            } => match *status_code {
                401 | 403 => FcpError::Unauthorized {
                    code: *status_code,
                    message: message.clone(),
                },
                404 => FcpError::ResourceNotFound {
                    resource: message.clone(),
                },
                429 => FcpError::RateLimited {
                    retry_after_ms: 60_000,
                    violation: None,
                },
                500..=599 => FcpError::External {
                    service: "wolfram_alpha".into(),
                    message: message.clone(),
                    status_code: Some(*status_code),
                    retryable: true,
                    retry_after: Some(std::time::Duration::from_secs(5)),
                },
                _ => FcpError::Internal {
                    message: format!("API error ({status_code}): {message}"),
                },
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::InvalidInput { message } => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::Serialization(msg) => FcpError::Internal {
                message: format!("Serialization error: {msg}"),
            },
            Self::Internal { message } => FcpError::Internal {
                message: message.clone(),
            },
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            Self::Http(e) => e.is_timeout() || e.is_connect(),
            Self::Api { status_code, .. } => matches!(*status_code, 429 | 500..=599 | 408),
            Self::RateLimited { .. } => true,
            Self::InvalidInput { .. } | Self::Serialization(_) | Self::Internal { .. } => false,
        }
    }

    fn retry_after(&self) -> Option<std::time::Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => {
                Some(std::time::Duration::from_millis(*retry_after_ms))
            }
            Self::Api {
                status_code: 429, ..
            } => Some(std::time::Duration::from_mins(1)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_timeout_is_retryable() {
        let err = WolframError::Api {
            status_code: 408,
            message: "timeout".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn rate_limited_is_retryable() {
        let err = WolframError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(std::time::Duration::from_secs(5)));
    }

    #[test]
    fn server_error_is_retryable() {
        let err = WolframError::Api {
            status_code: 503,
            message: "Service unavailable".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn client_error_is_not_retryable() {
        let err = WolframError::Api {
            status_code: 400,
            message: "Bad request".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn invalid_input_is_not_retryable() {
        let err = WolframError::InvalidInput {
            message: "empty query".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn auth_error_maps_to_unauthorized() {
        let err = WolframError::Api {
            status_code: 401,
            message: "Invalid AppID".into(),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { .. } => {}
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn not_found_maps_correctly() {
        let err = WolframError::Api {
            status_code: 404,
            message: "Not found".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { .. } => {}
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_maps_correctly() {
        let err = WolframError::RateLimited {
            retry_after_ms: 10_000,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, 10_000);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn async_timeout_maps_to_api_error() {
        let err = WolframError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        match err {
            WolframError::Api { status_code, .. } => assert_eq!(status_code, 408),
            other => panic!("expected Api, got {other:?}"),
        }
    }

    #[test]
    fn async_cancelled_maps_to_api_error() {
        let err = WolframError::from_async_error(AsyncError::Cancelled);
        match err {
            WolframError::Api { status_code, .. } => assert_eq!(status_code, 0),
            other => panic!("expected Api, got {other:?}"),
        }
    }

    #[test]
    fn async_channel_closed_maps_to_internal() {
        let err = WolframError::from_async_error(AsyncError::ChannelClosed);
        match err {
            WolframError::Internal { .. } => {}
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn display_formats() {
        let err = WolframError::InvalidInput {
            message: "test".into(),
        };
        assert!(err.to_string().contains("test"));
    }
}
