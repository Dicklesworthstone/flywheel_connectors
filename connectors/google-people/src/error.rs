//! Google People-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use thiserror::Error;

/// Google People-specific errors.
#[derive(Error, Debug)]
pub enum GooglePeopleError {
    /// HTTP request failed.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Google People API returned an error.
    #[error("People API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited.
    #[error("Rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    /// Invalid or expired token.
    #[error("Invalid or expired Google People credentials")]
    Unauthorized,

    /// Requested resource was not found.
    #[error("People resource not found: {resource}")]
    NotFound { resource: String },

    /// Permission denied.
    #[error("People permission denied: {message}")]
    Forbidden { message: String },

    /// Concurrency or etag conflict.
    #[error("People conflict: {message}")]
    Conflict { message: String },

    /// Local input validation failure.
    #[error("Invalid People request: {message}")]
    InvalidInput { message: String },
}

impl GooglePeopleError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, 429 | 500..=599),
            _ => false,
        }
    }

    /// Whether replaying the request that produced this error cannot duplicate
    /// a side effect (br-kxd3e).
    ///
    /// Distinct from [`Self::is_retryable`]: a rate limit was refused WITHOUT
    /// creating anything, so replaying is safe; a 5xx means Google received
    /// the request and may already have created the contact.
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
            Self::Http(error) => FcpError::External {
                service: "google_people".into(),
                message: error.to_string(),
                status_code: error.status().map(|status| status.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON error: {error}"),
            },
            Self::Api {
                status_code: 401 | 403,
                message,
            }
            | Self::Forbidden { message } => FcpError::Unauthorized {
                code: 2001,
                message: format!("People auth failed: {message}"),
            },
            Self::Api {
                status_code: 404,
                message,
            }
            | Self::NotFound { resource: message } => FcpError::ResourceNotFound {
                resource: message.clone(),
            },
            Self::Api {
                status_code: 409,
                message,
            }
            | Self::Conflict { message } => FcpError::Conflict {
                message: message.clone(),
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
                service: "google_people".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::RateLimited { retry_after_secs } => FcpError::RateLimited {
                retry_after_ms: retry_after_secs * 1000,
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid or expired Google People credentials".into(),
            },
            Self::InvalidInput { message } => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
        }
    }
}

impl ConnectorErrorMapping for GooglePeopleError {
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

/// Result type for People operations.
pub type PeopleResult<T> = Result<T, GooglePeopleError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_input_maps_to_invalid_request() {
        let error = GooglePeopleError::InvalidInput {
            message: "bad field mask".into(),
        };
        assert!(matches!(
            error.to_fcp_error(),
            FcpError::InvalidRequest { code: 1003, .. }
        ));
    }

    #[test]
    fn conflict_maps_to_conflict() {
        let error = GooglePeopleError::Conflict {
            message: "etag mismatch".into(),
        };
        assert!(matches!(error.to_fcp_error(), FcpError::Conflict { .. }));
    }
}
