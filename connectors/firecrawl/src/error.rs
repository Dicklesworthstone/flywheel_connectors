use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;

pub type FirecrawlResult<T> = Result<T, FirecrawlError>;

#[derive(Debug, thiserror::Error)]
pub enum FirecrawlError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Firecrawl API error {status}: {message}")]
    Api { status: u16, message: String },

    #[error("Rate limited (retry after {retry_after_ms}ms)")]
    RateLimited { retry_after_ms: u64 },

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Async error: {0}")]
    Async(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// A billable POST may have executed. Never invite a second job or charge.
    #[error("firecrawl.outcome_unknown: the request may have executed; automatic replay refused")]
    OutcomeUnknown { status: Option<u16> },

    /// A bounded read could not produce a usable provider response.
    #[error("invalid Firecrawl response: {0}")]
    InvalidResponse(&'static str),
}

impl FirecrawlError {
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(error) => error.is_timeout() || error.is_connect(),
            Self::RateLimited { .. } => true,
            Self::Api { status, .. } => matches!(status, 500 | 502 | 503 | 504 | 520..=524),
            Self::Json(_)
            | Self::Unauthorized(_)
            | Self::NotFound(_)
            | Self::Async(_)
            | Self::Config(_)
            | Self::InvalidInput(_)
            | Self::OutcomeUnknown { .. }
            | Self::InvalidResponse(_) => false,
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
            Self::Http(error) => FcpError::External {
                service: "firecrawl".into(),
                message: error.to_string(),
                status_code: error.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON parse error: {error}"),
            },
            Self::Api { status, message } => FcpError::External {
                service: "firecrawl".into(),
                message: format!("Firecrawl API error {status}: {message}"),
                status_code: Some(*status),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Unauthorized(message) => FcpError::Unauthorized {
                code: 2001,
                message: message.clone(),
            },
            Self::NotFound(resource) => FcpError::ResourceNotFound {
                resource: resource.clone(),
            },
            Self::Async(message) => FcpError::Internal {
                message: format!("Async error: {message}"),
            },
            Self::Config(message) => FcpError::InvalidRequest {
                code: 1001,
                message: format!("Configuration error: {message}"),
            },
            Self::InvalidInput(message) => FcpError::InvalidRequest {
                code: 1005,
                message: message.clone(),
            },
            Self::OutcomeUnknown { status } => FcpError::External {
                service: "firecrawl".into(),
                message: self.to_string(),
                status_code: *status,
                retryable: false,
                retry_after: None,
            },
            Self::InvalidResponse(_) => FcpError::External {
                service: "firecrawl".into(),
                message: self.to_string(),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
        }
    }
}

impl ConnectorErrorMapping for FirecrawlError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => {
                Self::Async(format!("request deadline exceeded after {timeout_ms}ms"))
            }
            AsyncError::Cancelled => Self::Async("operation cancelled".into()),
            other => Self::Async(other.to_string()),
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
    fn unknown_post_outcomes_are_terminal_in_both_error_contracts() {
        for status in [None, Some(200), Some(408), Some(503)] {
            let error = FirecrawlError::OutcomeUnknown { status };
            assert!(!error.is_retryable());
            assert!(!ConnectorErrorMapping::is_retryable(&error));
            assert!(error.retry_after().is_none());
            let FcpError::External { status_code, retryable, retry_after, message, .. } =
                error.to_fcp_error()
            else {
                panic!("unknown outcomes must remain external provider failures");
            };
            assert_eq!(status_code, status);
            assert!(!retryable);
            assert!(retry_after.is_none());
            assert!(message.contains("firecrawl.outcome_unknown"));
        }
    }

    #[test]
    fn response_limit_errors_do_not_become_retryable_provider_errors() {
        let error = FirecrawlError::InvalidResponse("response exceeds byte limit");
        assert!(!error.is_retryable());
        assert!(matches!(error.to_fcp_error(), FcpError::External { retryable: false, .. }));
    }

    #[test]
    fn rate_limited_is_retryable() {
        let err = FirecrawlError::RateLimited {
            retry_after_ms: 5_000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn unauthorized_is_not_retryable() {
        let err = FirecrawlError::Unauthorized("bad token".into());
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn not_found_maps_to_resource_not_found() {
        let err = FirecrawlError::NotFound("crawl job abc".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::ResourceNotFound { resource } => assert_eq!(resource, "crawl job abc"),
            other => panic!("Expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn api_error_retryable_for_server_errors() {
        let retryable = FirecrawlError::Api {
            status: 500,
            message: "Internal".into(),
        };
        assert!(retryable.is_retryable());

        let terminal = FirecrawlError::Api {
            status: 400,
            message: "Bad request".into(),
        };
        assert!(!terminal.is_retryable());
    }

    #[test]
    fn config_error_maps_to_invalid_request() {
        let err = FirecrawlError::Config("missing api_key".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1001);
                assert!(message.contains("missing api_key"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_maps_to_fcp_rate_limited() {
        let err = FirecrawlError::RateLimited {
            retry_after_ms: 3_000,
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 3_000);
                assert!(violation.is_none());
            }
            other => panic!("Expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn async_error_mapping_preserves_timeout() {
        let err = FirecrawlError::from_async_error(AsyncError::Timeout { timeout_ms: 1_500 });
        assert_eq!(
            err.to_string(),
            "Async error: request deadline exceeded after 1500ms"
        );
    }

    #[test]
    fn invalid_input_maps_to_invalid_request() {
        let err = FirecrawlError::InvalidInput("url is required".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1005);
                assert_eq!(message, "url is required");
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }
}
