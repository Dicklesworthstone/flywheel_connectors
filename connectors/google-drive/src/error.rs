//! Google Drive-specific error types.

use std::time::Duration;

use fcp_prelude::FcpError;
use thiserror::Error;

/// Google Drive-specific errors.
#[derive(Error, Debug)]
pub enum DriveError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Google Drive API returned an error
    #[error("Drive API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    /// Invalid or expired token
    #[error("Invalid or expired Google Drive credentials")]
    Unauthorized,

    /// File not found
    #[error("File not found: {file_id}")]
    FileNotFound { file_id: String },

    /// Insufficient permissions
    #[error("Insufficient Drive permissions: {message}")]
    Forbidden { message: String },

    /// Storage quota exceeded
    #[error("Drive storage quota exceeded")]
    QuotaExceeded,
}

impl DriveError {
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
    /// Distinct from [`Self::is_retryable`]: a rate limit was refused WITHOUT
    /// creating anything, so replaying is safe; a 5xx means Drive received the
    /// request and may already have created the file or folder.
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
            Self::RateLimited { retry_after_secs } => Some(Duration::from_secs(*retry_after_secs)),
            _ => None,
        }
    }

    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "google_drive".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api {
                status_code: 401 | 403,
                message,
            } => FcpError::Unauthorized {
                code: 2001,
                message: format!("Drive auth failed: {message}"),
            },
            Self::Api {
                status_code: 404,
                message,
            } => FcpError::ResourceNotFound {
                resource: message.clone(),
            },
            Self::Api {
                status_code: 429, ..
            } => FcpError::RateLimited {
                retry_after_ms: 60_000,
                violation: None,
            },
            Self::Api {
                status_code,
                message,
            } => FcpError::External {
                service: "google_drive".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_secs } => FcpError::RateLimited {
                retry_after_ms: retry_after_secs * 1000,
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid or expired Google Drive credentials".into(),
            },
            Self::FileNotFound { file_id } => FcpError::ResourceNotFound {
                resource: format!("file:{file_id}"),
            },
            Self::Forbidden { message } => FcpError::Unauthorized {
                code: 2001,
                message: format!("Drive permission denied: {message}"),
            },
            Self::QuotaExceeded => FcpError::RateLimited {
                retry_after_ms: 0,
                violation: None,
            },
        }
    }
}

impl fcp_sdk::ConnectorErrorMapping for DriveError {
    fn from_async_error(error: fcp_async_core::AsyncError) -> Self {
        use fcp_async_core::AsyncError;
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

/// Result type for Drive operations.
pub type DriveResult<T> = Result<T, DriveError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!DriveError::Unauthorized.is_retryable());
    }

    #[test]
    fn rate_limited_is_retryable() {
        assert!(
            DriveError::RateLimited {
                retry_after_secs: 5
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            DriveError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !DriveError::Api {
                status_code: 400,
                message: "bad".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = DriveError::RateLimited {
            retry_after_secs: 30,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(DriveError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn to_fcp_error_unauthorized() {
        match DriveError::Unauthorized.to_fcp_error() {
            FcpError::Unauthorized { code, .. } => assert_eq!(code, 2001),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_file_not_found() {
        let err = DriveError::FileNotFound {
            file_id: "abc".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => assert_eq!(resource, "file:abc"),
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_429() {
        let err = DriveError::Api {
            status_code: 429,
            message: "rate limited".into(),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::RateLimited { .. }));
    }

    #[test]
    fn to_fcp_error_quota_exceeded() {
        match DriveError::QuotaExceeded.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 0),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        match DriveError::Json(json_err).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // ── ConnectorErrorMapping ────────────────────────────────────────

    #[test]
    fn connector_error_mapping_timeout() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::ConnectorErrorMapping;
        let err = DriveError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(matches!(
            err,
            DriveError::Api {
                status_code: 408,
                ..
            }
        ));
        assert!(err.to_string().contains("5000"));
    }

    #[test]
    fn connector_error_mapping_cancelled() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::ConnectorErrorMapping;
        let err = DriveError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, DriveError::Api { status_code: 0, .. }));
    }

    #[test]
    fn connector_error_mapping_to_fcp_delegates() {
        use fcp_sdk::ConnectorErrorMapping;
        let err = DriveError::Unauthorized;
        let fcp = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp, FcpError::Unauthorized { .. }));
    }

    #[test]
    fn connector_error_mapping_is_retryable_delegates() {
        use fcp_sdk::ConnectorErrorMapping;
        let err = DriveError::RateLimited {
            retry_after_secs: 10,
        };
        assert!(ConnectorErrorMapping::is_retryable(&err));
    }

    #[test]
    fn connector_error_mapping_retry_after_delegates() {
        use fcp_sdk::ConnectorErrorMapping;
        let err = DriveError::RateLimited {
            retry_after_secs: 60,
        };
        assert_eq!(
            ConnectorErrorMapping::retry_after(&err),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn display_all_variants() {
        let _ = DriveError::Unauthorized.to_string();
        let _ = DriveError::RateLimited {
            retry_after_secs: 5,
        }
        .to_string();
        let _ = DriveError::FileNotFound {
            file_id: "x".into(),
        }
        .to_string();
        let _ = DriveError::Forbidden {
            message: "no".into(),
        }
        .to_string();
        let _ = DriveError::QuotaExceeded.to_string();
        let _ = DriveError::Api {
            status_code: 500,
            message: "err".into(),
        }
        .to_string();
    }
}
