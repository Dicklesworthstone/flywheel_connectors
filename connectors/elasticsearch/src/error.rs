//! Elasticsearch-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use thiserror::Error;

/// Result alias for Elasticsearch operations.
pub type ElasticsearchResult<T> = Result<T, ElasticsearchError>;

/// Elasticsearch-specific errors.
#[derive(Error, Debug)]
pub enum ElasticsearchError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Elasticsearch API returned an error
    #[error("Elasticsearch API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited (429)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failed (401)
    #[error("Authentication failed: invalid or expired API key")]
    Unauthorized,

    /// Forbidden (403)
    #[error("Forbidden: insufficient permissions")]
    Forbidden,

    /// Resource not found (404)
    #[error("Not found: {resource}")]
    NotFound { resource: String },

    /// Invalid input (path traversal, empty segment, etc.)
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl ElasticsearchError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, 500..=599 | 429),
            Self::InvalidInput(_) => false,
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
                service: "elasticsearch".into(),
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
                service: "elasticsearch".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::External {
                service: "elasticsearch".into(),
                message: format!("Rate limited, retry after {retry_after_ms}ms"),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Unauthorized => FcpError::External {
                service: "elasticsearch".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "elasticsearch".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "elasticsearch".into(),
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

impl ConnectorErrorMapping for ElasticsearchError {
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

    // ── is_retryable ─────────────────────────────────────────────────

    #[test]
    fn rate_limited_is_retryable() {
        let err = ElasticsearchError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_500_is_retryable() {
        let err = ElasticsearchError::Api {
            status_code: 500,
            message: "Internal Server Error".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_503_is_retryable() {
        let err = ElasticsearchError::Api {
            status_code: 503,
            message: "Service Unavailable".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_429_is_retryable() {
        let err = ElasticsearchError::Api {
            status_code: 429,
            message: "Too Many Requests".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!ElasticsearchError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!ElasticsearchError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        let err = ElasticsearchError::NotFound {
            resource: "index".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_400_not_retryable() {
        let err = ElasticsearchError::Api {
            status_code: 400,
            message: "Bad Request".into(),
        };
        assert!(!err.is_retryable());
    }

    // ── retry_after ──────────────────────────────────────────────────

    #[test]
    fn retry_after_for_rate_limited() {
        let err = ElasticsearchError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(ElasticsearchError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(ElasticsearchError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            ElasticsearchError::Api {
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
            ElasticsearchError::NotFound {
                resource: "idx".into()
            }
            .retry_after(),
            None
        );
    }

    // ── to_fcp_error ─────────────────────────────────────────────────

    #[test]
    fn unauthorized_to_fcp_error() {
        let fcp = ElasticsearchError::Unauthorized.to_fcp_error();
        match &fcp {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "elasticsearch");
                assert_eq!(*status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        let fcp = ElasticsearchError::Forbidden.to_fcp_error();
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
        let fcp = ElasticsearchError::NotFound {
            resource: "my-index".into(),
        }
        .to_fcp_error();
        match &fcp {
            FcpError::External {
                message,
                status_code,
                retryable,
                ..
            } => {
                assert!(message.contains("my-index"));
                assert_eq!(*status_code, Some(404));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        let fcp = ElasticsearchError::RateLimited {
            retry_after_ms: 60_000,
        }
        .to_fcp_error();
        match &fcp {
            FcpError::External {
                status_code,
                retryable,
                retry_after,
                ..
            } => {
                assert_eq!(*status_code, Some(429));
                assert!(retryable);
                assert_eq!(*retry_after, Some(Duration::from_secs(60)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_to_fcp_error() {
        let fcp = ElasticsearchError::Api {
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
        let err = ElasticsearchError::Json(bad_json.unwrap_err());
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
        match (ElasticsearchError::Api {
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

    // ── Display ──────────────────────────────────────────────────────

    #[test]
    fn error_display_unauthorized() {
        assert_eq!(
            ElasticsearchError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired API key"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            ElasticsearchError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            ElasticsearchError::NotFound {
                resource: "my-index".into()
            }
            .to_string(),
            "Not found: my-index"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            ElasticsearchError::RateLimited {
                retry_after_ms: 1000
            }
            .to_string(),
            "Rate limited, retry after 1000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            ElasticsearchError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "Elasticsearch API error (500): Internal"
        );
    }

    // ── Additional Display tests ────────────────────────────────────

    #[test]
    fn error_display_api_empty_message() {
        let err = ElasticsearchError::Api {
            status_code: 422,
            message: String::new(),
        };
        assert_eq!(err.to_string(), "Elasticsearch API error (422): ");
    }

    #[test]
    fn error_display_not_found_empty_resource() {
        let err = ElasticsearchError::NotFound {
            resource: String::new(),
        };
        assert_eq!(err.to_string(), "Not found: ");
    }

    #[test]
    fn error_display_rate_limited_zero_ms() {
        let err = ElasticsearchError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.to_string(), "Rate limited, retry after 0ms");
    }

    #[test]
    fn error_display_rate_limited_large_value() {
        let err = ElasticsearchError::RateLimited {
            retry_after_ms: 3_600_000,
        };
        assert_eq!(err.to_string(), "Rate limited, retry after 3600000ms");
    }

    // ── Additional is_retryable tests ───────────────────────────────

    #[test]
    fn api_502_is_retryable() {
        assert!(
            ElasticsearchError::Api {
                status_code: 502,
                message: "Bad Gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_504_is_retryable() {
        assert!(
            ElasticsearchError::Api {
                status_code: 504,
                message: "Gateway Timeout".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_599_is_retryable() {
        assert!(
            ElasticsearchError::Api {
                status_code: 599,
                message: "custom".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_409_not_retryable() {
        assert!(
            !ElasticsearchError::Api {
                status_code: 409,
                message: "conflict".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_422_not_retryable() {
        assert!(
            !ElasticsearchError::Api {
                status_code: 422,
                message: "unprocessable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn json_error_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert!(!ElasticsearchError::Json(bad.unwrap_err()).is_retryable());
    }

    // ── Additional retry_after tests ────────────────────────────────

    #[test]
    fn retry_after_zero_ms() {
        let err = ElasticsearchError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn retry_after_1ms() {
        let err = ElasticsearchError::RateLimited { retry_after_ms: 1 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(1)));
    }

    #[test]
    fn retry_after_none_for_json_error() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert_eq!(
            ElasticsearchError::Json(bad.unwrap_err()).retry_after(),
            None
        );
    }

    // ── Additional to_fcp_error tests ───────────────────────────────

    #[test]
    fn api_error_504_to_fcp_retryable() {
        match (ElasticsearchError::Api {
            status_code: 504,
            message: "timeout".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                status_code,
                retryable,
                retry_after,
                ..
            } => {
                assert_eq!(status_code, Some(504));
                assert!(retryable);
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_zero_to_fcp_error() {
        match (ElasticsearchError::RateLimited { retry_after_ms: 0 }).to_fcp_error() {
            FcpError::External {
                retry_after,
                retryable,
                ..
            } => {
                assert!(retryable);
                assert_eq!(retry_after, Some(Duration::from_millis(0)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error_service_name() {
        match (ElasticsearchError::NotFound {
            resource: "idx".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { service, .. } => {
                assert_eq!(service, "elasticsearch");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn unauthorized_fcp_error_message() {
        match ElasticsearchError::Unauthorized.to_fcp_error() {
            FcpError::External {
                message,
                retry_after,
                ..
            } => {
                assert_eq!(message, "Authentication failed");
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_fcp_error_message() {
        match ElasticsearchError::Forbidden.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert_eq!(message, "Insufficient permissions");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ── Debug trait ─────────────────────────────────────────────────

    #[test]
    fn error_debug_unauthorized() {
        let dbg = format!("{:?}", ElasticsearchError::Unauthorized);
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn error_debug_forbidden() {
        let dbg = format!("{:?}", ElasticsearchError::Forbidden);
        assert!(dbg.contains("Forbidden"));
    }

    #[test]
    fn error_debug_rate_limited() {
        let dbg = format!(
            "{:?}",
            ElasticsearchError::RateLimited {
                retry_after_ms: 5000
            }
        );
        assert!(dbg.contains("RateLimited"));
        assert!(dbg.contains("5000"));
    }

    #[test]
    fn error_debug_not_found() {
        let dbg = format!(
            "{:?}",
            ElasticsearchError::NotFound {
                resource: "my-idx".into()
            }
        );
        assert!(dbg.contains("NotFound"));
        assert!(dbg.contains("my-idx"));
    }

    #[test]
    fn error_debug_api() {
        let dbg = format!(
            "{:?}",
            ElasticsearchError::Api {
                status_code: 418,
                message: "teapot".into()
            }
        );
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("418"));
        assert!(dbg.contains("teapot"));
    }

    #[test]
    fn error_debug_json() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let dbg = format!("{:?}", ElasticsearchError::Json(bad.unwrap_err()));
        assert!(dbg.contains("Json"));
    }

    #[test]
    fn api_600_not_retryable() {
        assert!(
            !ElasticsearchError::Api {
                status_code: 600,
                message: "custom".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn rate_limited_fcp_error_service() {
        match (ElasticsearchError::RateLimited {
            retry_after_ms: 1000,
        })
        .to_fcp_error()
        {
            FcpError::External {
                service, message, ..
            } => {
                assert_eq!(service, "elasticsearch");
                assert!(message.contains("1000"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }
}
