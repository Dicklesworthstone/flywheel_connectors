//! Google Sheets-specific error types.

use std::time::Duration;

use fcp_prelude::FcpError;
use thiserror::Error;

/// Google Sheets-specific errors.
#[derive(Error, Debug)]
pub enum SheetsError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Google Sheets API returned an error
    #[error("Sheets API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// A temporary provider failure carrying a minimum wait for a safe retry.
    #[error("Sheets API error ({status_code}): {message}")]
    TransientApi {
        status_code: u16,
        message: String,
        retry_after_ms: u64,
    },

    /// The write may have taken effect even though its result was unavailable.
    #[error("Sheets write outcome unknown. Check the affected range before retrying. {message}")]
    WriteOutcomeUnknown {
        status_code: Option<u16>,
        message: String,
    },

    /// Response exceeded the bounded decoded-body budget.
    #[error("Sheets response exceeds {limit} bytes; request a smaller range")]
    ResponseTooLarge { limit: usize },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Invalid or expired token
    #[error("Invalid or expired Google Sheets credentials")]
    Unauthorized,

    /// Spreadsheet not found
    #[error("Spreadsheet not found: {spreadsheet_id}")]
    SpreadsheetNotFound { spreadsheet_id: String },

    /// Insufficient permissions
    #[error("Insufficient Sheets permissions: {message}")]
    Forbidden { message: String },

    /// Invalid range specification
    #[error("Invalid range: {range}")]
    InvalidRange { range: String },
}

impl SheetsError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } | Self::TransientApi { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, 500..=599 | 429),
            _ => false,
        }
    }

    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } | Self::TransientApi { retry_after_ms, .. } => {
                Some(Duration::from_millis(*retry_after_ms))
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "google_sheets".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::WriteOutcomeUnknown { status_code, .. } => FcpError::External {
                service: "google_sheets".into(),
                message: self.to_string(),
                status_code: *status_code,
                retryable: false,
                retry_after: None,
            },
            Self::ResponseTooLarge { .. } => FcpError::External {
                service: "google_sheets".into(),
                message: self.to_string(),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api {
                status_code: 401 | 403,
                message,
            } => FcpError::Unauthorized {
                code: 2001,
                message: format!("Sheets auth failed: {message}"),
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
            }
            | Self::TransientApi {
                status_code,
                message,
                ..
            } => FcpError::External {
                service: "google_sheets".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid or expired Google Sheets credentials".into(),
            },
            Self::SpreadsheetNotFound { spreadsheet_id } => FcpError::ResourceNotFound {
                resource: format!("spreadsheet:{spreadsheet_id}"),
            },
            Self::Forbidden { message } => FcpError::Unauthorized {
                code: 2001,
                message: format!("Sheets permission denied: {message}"),
            },
            Self::InvalidRange { range } => FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid range: {range}"),
            },
        }
    }
}

impl fcp_sdk::ConnectorErrorMapping for SheetsError {
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

/// Result type for Sheets operations.
pub type SheetsResult<T> = Result<T, SheetsError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!SheetsError::Unauthorized.is_retryable());
    }

    #[test]
    fn rate_limited_is_retryable() {
        assert!(
            SheetsError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            SheetsError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !SheetsError::Api {
                status_code: 400,
                message: "bad".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = SheetsError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(SheetsError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn to_fcp_error_unauthorized() {
        match SheetsError::Unauthorized.to_fcp_error() {
            FcpError::Unauthorized { code, .. } => assert_eq!(code, 2001),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_spreadsheet_not_found() {
        let err = SheetsError::SpreadsheetNotFound {
            spreadsheet_id: "abc".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "spreadsheet:abc");
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_429() {
        let err = SheetsError::Api {
            status_code: 429,
            message: "rate limited".into(),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::RateLimited { .. }));
    }

    #[test]
    fn to_fcp_error_invalid_range() {
        let err = SheetsError::InvalidRange {
            range: "Sheet1!ZZ:ZZ".into(),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::InvalidRequest { .. }
        ));
    }

    #[test]
    fn to_fcp_error_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        match SheetsError::Json(json_err).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_401() {
        let err = SheetsError::Api {
            status_code: 401,
            message: "bad token".into(),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn to_fcp_error_api_403() {
        let err = SheetsError::Api {
            status_code: 403,
            message: "forbidden".into(),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn to_fcp_error_api_500() {
        let err = SheetsError::Api {
            status_code: 500,
            message: "internal".into(),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "google_sheets");
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn display_all_variants() {
        let _ = SheetsError::Unauthorized.to_string();
        let _ = SheetsError::RateLimited {
            retry_after_ms: 5000,
        }
        .to_string();
        let _ = SheetsError::SpreadsheetNotFound {
            spreadsheet_id: "x".into(),
        }
        .to_string();
        let _ = SheetsError::Forbidden {
            message: "no".into(),
        }
        .to_string();
        let _ = SheetsError::InvalidRange {
            range: "bad".into(),
        }
        .to_string();
        let _ = SheetsError::Api {
            status_code: 500,
            message: "err".into(),
        }
        .to_string();
    }

    // ── ConnectorErrorMapping ────────────────────────────────────────

    #[test]
    fn connector_error_mapping_timeout() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::ConnectorErrorMapping;
        let err = SheetsError::from_async_error(AsyncError::Timeout { timeout_ms: 3000 });
        assert!(matches!(
            err,
            SheetsError::Api {
                status_code: 408,
                ..
            }
        ));
    }

    #[test]
    fn connector_error_mapping_cancelled() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::ConnectorErrorMapping;
        let err = SheetsError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, SheetsError::Api { status_code: 0, .. }));
    }

    #[test]
    fn connector_error_mapping_to_fcp_delegates() {
        use fcp_sdk::ConnectorErrorMapping;
        let err = SheetsError::Unauthorized;
        let fcp = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp, FcpError::Unauthorized { .. }));
    }

    #[test]
    fn connector_error_mapping_is_retryable_delegates() {
        use fcp_sdk::ConnectorErrorMapping;
        let err = SheetsError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(ConnectorErrorMapping::is_retryable(&err));
    }

    #[test]
    fn connector_error_mapping_retry_after_delegates() {
        use fcp_sdk::ConnectorErrorMapping;
        let err = SheetsError::RateLimited {
            retry_after_ms: 60_000,
        };
        assert_eq!(
            ConnectorErrorMapping::retry_after(&err),
            Some(Duration::from_secs(60))
        );
    }
}
