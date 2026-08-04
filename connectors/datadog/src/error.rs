//! Datadog-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use thiserror::Error;

/// Result alias for Datadog operations.
pub type DatadogResult<T> = Result<T, DatadogError>;

/// Datadog-specific errors.
#[derive(Error, Debug)]
pub enum DatadogError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Datadog API returned an error
    #[error("Datadog API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

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

    /// Invalid input (missing field, path traversal, etc.).
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl DatadogError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::RateLimited { .. } => true,
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

    /// Get the suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "datadog".into(),
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
                service: "datadog".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Authentication failed: invalid API key".into(),
            },
            Self::Forbidden => FcpError::External {
                service: "datadog".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::ResourceNotFound {
                resource: resource.clone(),
            },
            Self::InvalidInput(msg) => FcpError::InvalidRequest {
                code: 1005,
                message: format!("Invalid input: {msg}"),
            },
        }
    }
}

impl ConnectorErrorMapping for DatadogError {
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

    // -- is_retryable --

    #[test]
    fn rate_limited_is_retryable() {
        let err = DatadogError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_500_is_retryable() {
        let err = DatadogError::Api {
            status_code: 500,
            message: "Internal Server Error".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_503_is_retryable() {
        let err = DatadogError::Api {
            status_code: 503,
            message: "Service Unavailable".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_429_is_retryable() {
        let err = DatadogError::Api {
            status_code: 429,
            message: "Too Many Requests".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!DatadogError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!DatadogError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        let err = DatadogError::NotFound {
            resource: "monitor".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_400_not_retryable() {
        let err = DatadogError::Api {
            status_code: 400,
            message: "Bad Request".into(),
        };
        assert!(!err.is_retryable());
    }

    // -- retry_after --

    #[test]
    fn retry_after_for_rate_limited() {
        let err = DatadogError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(DatadogError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(DatadogError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            DatadogError::Api {
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
            DatadogError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    // -- to_fcp_error --

    #[test]
    fn unauthorized_to_fcp_error() {
        let fcp = DatadogError::Unauthorized.to_fcp_error();
        match &fcp {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(*code, 2001);
                assert!(message.contains("Authentication failed"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        let fcp = DatadogError::Forbidden.to_fcp_error();
        match &fcp {
            FcpError::External {
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(*status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        let fcp = DatadogError::NotFound {
            resource: "monitor-123".into(),
        }
        .to_fcp_error();
        match &fcp {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "monitor-123");
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        let fcp = DatadogError::RateLimited {
            retry_after_ms: 60_000,
        }
        .to_fcp_error();
        match &fcp {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(*retry_after_ms, 60_000);
                assert!(violation.is_none());
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn api_error_to_fcp_error() {
        let fcp = DatadogError::Api {
            status_code: 502,
            message: "Bad Gateway".into(),
        }
        .to_fcp_error();
        match &fcp {
            FcpError::External {
                message,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(message, "Bad Gateway");
                assert_eq!(*status_code, Some(502));
                assert!(*retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn json_error_to_fcp_internal() {
        let bad_json: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        let err = DatadogError::Json(bad_json.unwrap_err());
        let fcp = err.to_fcp_error();
        match &fcp {
            FcpError::Internal { message } => {
                assert!(message.starts_with("JSON error:"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (DatadogError::Api {
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

    // -- Display --

    #[test]
    fn error_display_unauthorized() {
        assert_eq!(
            DatadogError::Unauthorized.to_string(),
            "Authentication failed: invalid API key"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            DatadogError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            DatadogError::NotFound {
                resource: "monitor".into()
            }
            .to_string(),
            "Not found: monitor"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            DatadogError::RateLimited {
                retry_after_ms: 1000
            }
            .to_string(),
            "Rate limited, retry after 1000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            DatadogError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "Datadog API error (500): Internal"
        );
    }

    // ── Additional retryable / boundary cases ─────────────────────

    #[test]
    fn api_599_is_retryable() {
        let err = DatadogError::Api {
            status_code: 599,
            message: "edge".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_499_not_retryable() {
        let err = DatadogError::Api {
            status_code: 499,
            message: "not server".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn json_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let err = DatadogError::Json(bad.unwrap_err());
        assert!(!err.is_retryable());
    }

    #[test]
    fn retry_after_none_for_json() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let err = DatadogError::Json(bad.unwrap_err());
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn rate_limited_zero_ms() {
        let err = DatadogError::RateLimited { retry_after_ms: 0 };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn rate_limited_large_ms() {
        let err = DatadogError::RateLimited {
            retry_after_ms: 3_600_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
    }

    // ── Display with empty / special strings ──────────────────────

    #[test]
    fn error_display_not_found_empty_resource() {
        let err = DatadogError::NotFound {
            resource: String::new(),
        };
        assert_eq!(err.to_string(), "Not found: ");
    }

    #[test]
    fn error_display_api_empty_message() {
        let err = DatadogError::Api {
            status_code: 502,
            message: String::new(),
        };
        assert_eq!(err.to_string(), "Datadog API error (502): ");
    }

    // ── to_fcp_error service field ────────────────────────────────

    #[test]
    fn external_fcp_errors_have_datadog_service() {
        let errors: Vec<DatadogError> = vec![
            DatadogError::Forbidden,
            DatadogError::Api {
                status_code: 500,
                message: "err".into(),
            },
        ];
        for err in &errors {
            let fcp = err.to_fcp_error();
            if let FcpError::External { service, .. } = fcp {
                assert_eq!(service, "datadog");
            }
        }
    }

    #[test]
    fn rate_limited_fcp_error_retry_after_matches() {
        let err = DatadogError::RateLimited {
            retry_after_ms: 45_000,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, 45_000);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    // ── Debug format ──────────────────────────────────────────────

    #[test]
    fn error_debug_format() {
        let err = DatadogError::Api {
            status_code: 503,
            message: "retry".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("503"));
    }

    #[test]
    fn error_debug_unauthorized() {
        let dbg = format!("{:?}", DatadogError::Unauthorized);
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn error_debug_rate_limited() {
        let dbg = format!(
            "{:?}",
            DatadogError::RateLimited {
                retry_after_ms: 100
            }
        );
        assert!(dbg.contains("RateLimited"));
        assert!(dbg.contains("100"));
    }

    // ── Additional boundary / fcp_error tests ────────────────────

    #[test]
    fn api_501_is_retryable() {
        let err = DatadogError::Api {
            status_code: 501,
            message: "Not Implemented".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_502_is_retryable() {
        let err = DatadogError::Api {
            status_code: 502,
            message: "Bad Gateway".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_200_not_retryable() {
        let err = DatadogError::Api {
            status_code: 200,
            message: "ok".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_403_not_retryable() {
        let err = DatadogError::Api {
            status_code: 403,
            message: "Forbidden".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_404_not_retryable() {
        let err = DatadogError::Api {
            status_code: 404,
            message: "nope".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_found_fcp_error_is_resource_not_found() {
        let fcp = DatadogError::NotFound {
            resource: "dashboard-x".into(),
        }
        .to_fcp_error();
        match fcp {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "dashboard-x");
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_fcp_error_service_is_datadog() {
        match DatadogError::Forbidden.to_fcp_error() {
            FcpError::External { service, .. } => assert_eq!(service, "datadog"),
            other => panic!("expected External for Forbidden, got {other:?}"),
        }
    }
}
