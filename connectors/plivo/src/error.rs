//! Plivo-specific error mapping.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;

/// Plivo API error.
#[derive(Debug, thiserror::Error)]
pub enum PlivoError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Plivo API error: {message}")]
    Api {
        message: String,
        status_code: Option<u16>,
        retry_after: Option<Duration>,
    },

    #[error("rate limited")]
    RateLimited { retry_after_ms: u64 },

    #[error("unauthorized")]
    Unauthorized,

    #[error("not found: {resource}")]
    NotFound { resource: String },

    #[error("invalid input: {0}")]
    InvalidInput(String),
}

pub type PlivoResult<T> = Result<T, PlivoError>;

impl PlivoError {
    /// Whether retrying can make progress.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => {
                matches!(status_code, Some(408 | 425 | 429 | 500..=599))
            }
            Self::Json(_) | Self::Unauthorized | Self::NotFound { .. } | Self::InvalidInput(_) => {
                false
            }
        }
    }

    /// Retry delay suggested by Plivo or the connector policy.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            Self::Api { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    /// Convert into FCP's shared error taxonomy.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(error) => FcpError::External {
                service: "plivo".into(),
                message: error.to_string(),
                status_code: error.status().map(|status| status.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON error: {error}"),
            },
            Self::Api {
                message,
                status_code,
                ..
            } => match status_code {
                Some(401 | 403) => FcpError::Unauthorized {
                    code: 2001,
                    message: message.clone(),
                },
                Some(429) => FcpError::RateLimited {
                    retry_after_ms: self
                        .retry_after()
                        .map_or(60_000, duration_millis_saturating),
                    violation: None,
                },
                _ => FcpError::External {
                    service: "plivo".into(),
                    message: message.clone(),
                    status_code: *status_code,
                    retryable: self.is_retryable(),
                    retry_after: self.retry_after(),
                },
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Plivo API authentication failed".into(),
            },
            Self::NotFound { resource } => FcpError::ResourceNotFound {
                resource: resource.clone(),
            },
            Self::InvalidInput(message) => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
        }
    }
}

fn duration_millis_saturating(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

impl ConnectorErrorMapping for PlivoError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                message: format!("deadline exceeded after {timeout_ms}ms"),
                status_code: Some(408),
                retry_after: None,
            },
            AsyncError::Cancelled => Self::Api {
                message: "request cancelled".into(),
                status_code: None,
                retry_after: None,
            },
            other => Self::Api {
                message: other.to_string(),
                status_code: None,
                retry_after: None,
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
    fn maps_rate_limit_to_fcp_rate_limited() {
        let error = PlivoError::RateLimited {
            retry_after_ms: 1_500,
        };
        assert!(matches!(error.to_fcp_error(), FcpError::RateLimited { .. }));
    }

    #[test]
    fn server_errors_remain_retryable_external_errors() {
        let error = PlivoError::Api {
            message: "temporary outage".into(),
            status_code: Some(503),
            retry_after: None,
        };
        assert!(error.is_retryable());
        assert!(matches!(error.to_fcp_error(), FcpError::External { .. }));
    }
}
