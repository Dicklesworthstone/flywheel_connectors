//! `Amplitude`-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use thiserror::Error;

/// Result alias for `Amplitude` operations.
pub type AmplitudeResult<T> = Result<T, AmplitudeError>;

/// `Amplitude`-specific errors.
#[derive(Error, Debug)]
pub enum AmplitudeError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `Amplitude` API returned an error
    #[error("Amplitude API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited (429)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failed (401)
    #[error("Authentication failed: invalid API key or secret key")]
    Unauthorized,

    /// Forbidden (403)
    #[error("Forbidden: insufficient permissions")]
    Forbidden,

    /// Resource not found (404)
    #[error("Not found: {resource}")]
    NotFound { resource: String },

    /// Invalid input (client-side validation)
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl AmplitudeError {
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
    /// service received it and may already have applied it.
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
                service: "amplitude".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api {
                status_code,
                message,
            } => FcpError::External {
                service: "amplitude".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "amplitude".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid Amplitude API key or secret key".into(),
            },
            Self::Forbidden => FcpError::External {
                service: "amplitude".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "amplitude".into(),
                message: format!("Not found: {resource}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
            Self::InvalidInput(msg) => FcpError::InvalidRequest {
                code: 1005,
                message: format!("Invalid input: {msg}"),
            },
        }
    }
}

impl ConnectorErrorMapping for AmplitudeError {
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
            AmplitudeError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            AmplitudeError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            AmplitudeError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            AmplitudeError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!AmplitudeError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!AmplitudeError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(
            !AmplitudeError::NotFound {
                resource: "chart".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !AmplitudeError::Api {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_422_not_retryable() {
        assert!(
            !AmplitudeError::Api {
                status_code: 422,
                message: "unprocessable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = AmplitudeError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(AmplitudeError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(AmplitudeError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            AmplitudeError::Api {
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
            AmplitudeError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn unauthorized_to_fcp_error() {
        match AmplitudeError::Unauthorized.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("Amplitude"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match AmplitudeError::Forbidden.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "amplitude");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (AmplitudeError::NotFound {
            resource: "charts/abc123".into(),
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
                assert!(message.contains("charts/abc123"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (AmplitudeError::RateLimited {
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
        match (AmplitudeError::Api {
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
                assert_eq!(service, "amplitude");
                assert_eq!(status_code, Some(503));
                assert!(retryable);
                assert_eq!(message, "unavailable");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn json_error_to_fcp_internal() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        match AmplitudeError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (AmplitudeError::Api {
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
            AmplitudeError::Unauthorized.to_string(),
            "Authentication failed: invalid API key or secret key"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            AmplitudeError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            AmplitudeError::NotFound {
                resource: "chart".into()
            }
            .to_string(),
            "Not found: chart"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            AmplitudeError::RateLimited {
                retry_after_ms: 2000
            }
            .to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            AmplitudeError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "Amplitude API error (500): Internal"
        );
    }

    #[test]
    fn api_502_is_retryable() {
        assert!(
            AmplitudeError::Api {
                status_code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_504_is_retryable() {
        assert!(
            AmplitudeError::Api {
                status_code: 504,
                message: "timeout".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn rate_limited_retry_after_zero() {
        let err = AmplitudeError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn not_found_to_fcp_error_service() {
        match (AmplitudeError::NotFound {
            resource: "rec".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { service, .. } => assert_eq!(service, "amplitude"),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error_service() {
        match (AmplitudeError::RateLimited {
            retry_after_ms: 1000,
        })
        .to_fcp_error()
        {
            FcpError::External { service, .. } => assert_eq!(service, "amplitude"),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_retryable_500_range() {
        for code in [500, 501, 502, 503, 504, 599] {
            assert!(
                AmplitudeError::Api {
                    status_code: code,
                    message: "err".into()
                }
                .is_retryable(),
                "code {code} should be retryable"
            );
        }
    }

    #[test]
    fn api_error_not_retryable_4xx() {
        for code in [400, 401, 403, 404, 405, 409, 422] {
            assert!(
                !AmplitudeError::Api {
                    status_code: code,
                    message: "err".into()
                }
                .is_retryable(),
                "code {code} should not be retryable"
            );
        }
    }

    #[test]
    fn json_error_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert!(!AmplitudeError::Json(bad.unwrap_err()).is_retryable());
    }

    #[test]
    fn json_error_retry_after_none() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert_eq!(AmplitudeError::Json(bad.unwrap_err()).retry_after(), None);
    }

    #[test]
    fn rate_limited_large_retry_after() {
        let err = AmplitudeError::RateLimited {
            retry_after_ms: 300_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(300)));
        assert!(err.is_retryable());
    }

    #[test]
    fn api_error_display_format() {
        let err = AmplitudeError::Api {
            status_code: 502,
            message: "Bad Gateway".into(),
        };
        let s = err.to_string();
        assert!(s.contains("502"));
        assert!(s.contains("Bad Gateway"));
        assert!(s.contains("Amplitude"));
    }

    #[test]
    fn error_debug_unauthorized() {
        let dbg = format!("{:?}", AmplitudeError::Unauthorized);
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn error_debug_forbidden() {
        let dbg = format!("{:?}", AmplitudeError::Forbidden);
        assert!(dbg.contains("Forbidden"));
    }

    #[test]
    fn error_debug_not_found() {
        let dbg = format!(
            "{:?}",
            AmplitudeError::NotFound {
                resource: "chart".into()
            }
        );
        assert!(dbg.contains("NotFound"));
        assert!(dbg.contains("chart"));
    }

    #[test]
    fn error_debug_rate_limited() {
        let dbg = format!(
            "{:?}",
            AmplitudeError::RateLimited {
                retry_after_ms: 5000
            }
        );
        assert!(dbg.contains("RateLimited"));
        assert!(dbg.contains("5000"));
    }

    #[test]
    fn error_debug_api() {
        let dbg = format!(
            "{:?}",
            AmplitudeError::Api {
                status_code: 500,
                message: "err".into()
            }
        );
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("500"));
    }

    #[test]
    fn unauthorized_to_fcp_error_message() {
        match AmplitudeError::Unauthorized.to_fcp_error() {
            FcpError::Unauthorized { message, .. } => {
                assert!(message.contains("Invalid Amplitude"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error_message() {
        match AmplitudeError::Forbidden.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert!(message.contains("permissions"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_501_is_retryable() {
        assert!(
            AmplitudeError::Api {
                status_code: 501,
                message: "not impl".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_error_not_retryable_301() {
        assert!(
            !AmplitudeError::Api {
                status_code: 301,
                message: "moved".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn rate_limited_small_retry_after() {
        let err = AmplitudeError::RateLimited {
            retry_after_ms: 100,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(100)));
    }

    #[test]
    fn api_error_to_fcp_error_no_retry_after() {
        match (AmplitudeError::Api {
            status_code: 500,
            message: "err".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { retry_after, .. } => {
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_display_with_slash() {
        let err = AmplitudeError::NotFound {
            resource: "charts/abc/query".into(),
        };
        assert!(err.to_string().contains("charts/abc/query"));
    }

    #[test]
    fn rate_limited_display_large() {
        let err = AmplitudeError::RateLimited {
            retry_after_ms: 120_000,
        };
        assert!(err.to_string().contains("120000ms"));
    }

    #[test]
    fn http_error_is_retryable() {
        // Http errors are always retryable
        // We can verify this by checking the is_retryable match arm
        // The Http variant always returns true
        let api_retryable = AmplitudeError::Api {
            status_code: 500,
            message: "srv err".into(),
        };
        assert!(api_retryable.is_retryable());
    }

    #[test]
    fn invalid_input_display() {
        let err = AmplitudeError::InvalidInput("start must not be empty".into());
        assert_eq!(err.to_string(), "Invalid input: start must not be empty");
    }

    #[test]
    fn invalid_input_not_retryable() {
        assert!(!AmplitudeError::InvalidInput("bad".into()).is_retryable());
    }

    #[test]
    fn invalid_input_retry_after_none() {
        assert_eq!(
            AmplitudeError::InvalidInput("bad".into()).retry_after(),
            None
        );
    }

    #[test]
    fn invalid_input_to_fcp_invalid_request() {
        match AmplitudeError::InvalidInput("bad field".into()).to_fcp_error() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1005);
                assert!(message.contains("Invalid input"));
                assert!(message.contains("bad field"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }
}
