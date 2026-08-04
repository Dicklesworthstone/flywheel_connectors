//! `Box`-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use thiserror::Error;

/// Result alias for `Box` operations.
pub type BoxResult<T> = Result<T, BoxError>;

/// `Box`-specific errors.
#[derive(Error, Debug)]
pub enum BoxError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `Box` API returned an error
    #[error("Box API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited (429)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failed (401)
    #[error("Authentication failed: invalid or expired access token")]
    Unauthorized,

    /// Forbidden (403)
    #[error("Forbidden: insufficient permissions")]
    Forbidden,

    /// Resource not found (404)
    #[error("Not found: {resource}")]
    NotFound { resource: String },

    /// Conflict (409)
    #[error("Conflict: {message}")]
    Conflict { message: String },

    /// Invalid input (missing field, path traversal, etc.).
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl BoxError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, 500..=599 | 429),
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
                service: "box".into(),
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
                service: "box".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "box".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "box".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "box".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "box".into(),
                message: format!("Not found: {resource}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
            Self::Conflict { message } => FcpError::External {
                service: "box".into(),
                message: format!("Conflict: {message}"),
                status_code: Some(409),
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

impl ConnectorErrorMapping for BoxError {
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
            BoxError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            BoxError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            BoxError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_502_is_retryable() {
        assert!(
            BoxError::Api {
                status_code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            BoxError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!BoxError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!BoxError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(
            !BoxError::NotFound {
                resource: "file".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn conflict_not_retryable() {
        assert!(
            !BoxError::Conflict {
                message: "item_name_in_use".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !BoxError::Api {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_404_not_retryable() {
        assert!(
            !BoxError::Api {
                status_code: 404,
                message: "not found".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = BoxError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(BoxError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(BoxError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            BoxError::Api {
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
            BoxError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_none_for_conflict() {
        assert_eq!(
            BoxError::Conflict {
                message: "dup".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn unauthorized_to_fcp_error() {
        assert!(matches!(
            BoxError::Unauthorized.to_fcp_error(),
            FcpError::External {
                service,
                status_code: Some(401),
                retryable: false,
                ..
            } if service == "box"
        ));
    }

    #[test]
    fn forbidden_to_fcp_error() {
        assert!(matches!(
            BoxError::Forbidden.to_fcp_error(),
            FcpError::External {
                service,
                status_code: Some(403),
                retryable: false,
                ..
            } if service == "box"
        ));
    }

    #[test]
    fn not_found_to_fcp_error() {
        assert!(matches!(
            (BoxError::NotFound {
            resource: "file_abc".into(),
        })
            .to_fcp_error(),
            FcpError::External {
                status_code: Some(404),
                message,
                retryable: false,
                ..
            } if message.contains("file_abc")
        ));
    }

    #[test]
    fn conflict_to_fcp_error() {
        assert!(matches!(
            (BoxError::Conflict {
            message: "item_name_in_use".into(),
        })
            .to_fcp_error(),
            FcpError::External {
                status_code: Some(409),
                message,
                retryable: false,
                ..
            } if message.contains("item_name_in_use")
        ));
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        assert!(matches!(
            (BoxError::RateLimited {
            retry_after_ms: 60_000,
        })
            .to_fcp_error(),
            FcpError::External {
                status_code: Some(429),
                retryable: true,
                retry_after: Some(retry_after),
                ..
            } if retry_after == Duration::from_secs(60)
        ));
    }

    #[test]
    fn api_error_to_fcp_error() {
        assert!(matches!(
            (BoxError::Api {
            status_code: 503,
            message: "unavailable".into(),
        })
            .to_fcp_error(),
            FcpError::External {
                service,
                status_code: Some(503),
                retryable: true,
                message,
                ..
            } if service == "box" && message == "unavailable"
        ));
    }

    #[test]
    fn json_error_to_fcp_internal() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        assert!(matches!(
            BoxError::Json(bad.unwrap_err()).to_fcp_error(),
            FcpError::Internal { message } if message.starts_with("JSON error:")
        ));
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        assert!(matches!(
            (BoxError::Api {
                status_code: 400,
                message: "bad".into(),
            })
            .to_fcp_error(),
            FcpError::External {
                status_code: Some(400),
                retryable: false,
                ..
            }
        ));
    }

    #[test]
    fn error_display_unauthorized() {
        assert_eq!(
            BoxError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired access token"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            BoxError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            BoxError::NotFound {
                resource: "file".into()
            }
            .to_string(),
            "Not found: file"
        );
    }

    #[test]
    fn error_display_conflict() {
        assert_eq!(
            BoxError::Conflict {
                message: "item_name_in_use".into()
            }
            .to_string(),
            "Conflict: item_name_in_use"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            BoxError::RateLimited {
                retry_after_ms: 2000
            }
            .to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            BoxError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "Box API error (500): Internal"
        );
    }

    #[test]
    fn api_error_retryable_599() {
        assert!(
            BoxError::Api {
                status_code: 599,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_error_not_retryable_499() {
        assert!(
            !BoxError::Api {
                status_code: 499,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn rate_limited_retry_after_small() {
        let err = BoxError::RateLimited {
            retry_after_ms: 100,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(100)));
    }

    #[test]
    fn rate_limited_retry_after_zero() {
        let err = BoxError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn json_error_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        assert!(!BoxError::Json(bad.unwrap_err()).is_retryable());
    }

    #[test]
    fn json_error_retry_after_none() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        assert_eq!(BoxError::Json(bad.unwrap_err()).retry_after(), None);
    }

    #[test]
    fn api_501_is_retryable() {
        assert!(
            BoxError::Api {
                status_code: 501,
                message: "not impl".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn error_debug_unauthorized() {
        let err = BoxError::Unauthorized;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn error_debug_conflict() {
        let err = BoxError::Conflict {
            message: "dup".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Conflict"));
    }

    #[test]
    fn error_debug_api_contains_code() {
        let err = BoxError::Api {
            status_code: 503,
            message: "svc".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("503"));
    }

    #[test]
    fn unauthorized_fcp_error_no_retry_after() {
        assert!(matches!(
            BoxError::Unauthorized.to_fcp_error(),
            FcpError::External {
                retry_after: None,
                ..
            }
        ));
    }

    #[test]
    fn conflict_fcp_error_no_retry_after() {
        assert!(matches!(
            (BoxError::Conflict {
                message: "dup".into(),
            })
            .to_fcp_error(),
            FcpError::External {
                retry_after: None,
                ..
            }
        ));
    }

    #[test]
    fn rate_limited_large_value() {
        let err = BoxError::RateLimited {
            retry_after_ms: 3_600_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
        assert!(err.is_retryable());
    }

    #[test]
    fn conflict_fcp_error_service() {
        assert!(matches!(
            (BoxError::Conflict {
            message: "x".into(),
        })
            .to_fcp_error(),
            FcpError::External { service, .. } if service == "box"
        ));
    }
}
