//! Google Workspace Events-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use thiserror::Error;

/// Google Workspace Events-specific errors.
#[derive(Error, Debug)]
pub enum WorkspaceEventsError {
    /// HTTP request failed.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Google Workspace Events or Pub/Sub API returned an error.
    #[error("Workspace Events API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited.
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Invalid or expired credentials.
    #[error("Invalid or expired Google Workspace Events credentials")]
    Unauthorized,

    /// A Workspace Events subscription was not found.
    #[error("Workspace Events subscription not found: {subscription_name}")]
    SubscriptionNotFound { subscription_name: String },

    /// A Pub/Sub subscription was not found.
    #[error("Pub/Sub subscription not found: {subscription_name}")]
    PubsubSubscriptionNotFound { subscription_name: String },

    /// Event payload could not be decoded.
    #[error("Invalid Pub/Sub event payload: {message}")]
    InvalidEventPayload { message: String },

    /// Caller-supplied input rejected before any request was sent
    /// (e.g. a subscription resource name carrying injection characters).
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },
}

impl WorkspaceEventsError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, 429 | 500..=599),
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
                service: "google_workspace_events".into(),
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
                message: format!("Workspace Events auth failed: {message}"),
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
                service: "google_workspace_events".into(),
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
                message: "Invalid or expired Google Workspace Events credentials".into(),
            },
            Self::SubscriptionNotFound { subscription_name } => FcpError::ResourceNotFound {
                resource: format!("workspace_subscription:{subscription_name}"),
            },
            Self::PubsubSubscriptionNotFound { subscription_name } => FcpError::ResourceNotFound {
                resource: format!("pubsub_subscription:{subscription_name}"),
            },
            Self::InvalidEventPayload { message } => FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid event payload: {message}"),
            },
            Self::InvalidInput { message } => FcpError::InvalidRequest {
                code: 1004,
                message: message.clone(),
            },
        }
    }
}

impl ConnectorErrorMapping for WorkspaceEventsError {
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

/// Result type for Workspace Events operations.
pub type WorkspaceEventsResult<T> = Result<T, WorkspaceEventsError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unauthorized_is_not_retryable() {
        assert!(!WorkspaceEventsError::Unauthorized.is_retryable());
    }

    #[test]
    fn rate_limited_is_retryable() {
        assert!(
            WorkspaceEventsError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn subscription_not_found_maps_to_resource_not_found() {
        let err = WorkspaceEventsError::SubscriptionNotFound {
            subscription_name: "subscriptions/123".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "workspace_subscription:subscriptions/123");
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }
}
