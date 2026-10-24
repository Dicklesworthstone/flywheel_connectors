use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;

pub type GcpResult<T> = Result<T, GcpError>;

#[derive(Debug, thiserror::Error)]
pub enum GcpError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("GCP API error {code}: {message}")]
    Api { code: u32, message: String },

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

    #[error("Project required: {0}")]
    ProjectRequired(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// The provider's pagination could not be completed. Static reasons keep
    /// opaque cursors and provider payloads out of diagnostics.
    #[error("GCP listing incomplete: {reason}; no partial results were returned")]
    IncompleteListing { reason: &'static str },
}

impl GcpError {
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(error) => error.is_timeout() || error.is_connect(),
            Self::RateLimited { .. } => true,
            Self::Api { code, .. } => matches!(code, 500 | 502 | 503 | 504),
            Self::Json(_)
            | Self::Unauthorized(_)
            | Self::NotFound(_)
            | Self::Async(_)
            | Self::Config(_)
            | Self::ProjectRequired(_)
            | Self::InvalidInput(_)
            | Self::IncompleteListing { .. } => false,
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
                service: "gcp".into(),
                message: error.to_string(),
                status_code: error.status().map(|status| status.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON parse error: {error}"),
            },
            Self::Api { code, message } => FcpError::External {
                service: "gcp".into(),
                message: format!("GCP API error {code}: {message}"),
                status_code: u16::try_from(*code).ok(),
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
            Self::ProjectRequired(message) => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::InvalidInput(message) => FcpError::InvalidRequest {
                code: 1005,
                message: message.clone(),
            },
            Self::IncompleteListing { .. } => FcpError::External {
                service: "gcp".into(),
                message: self.to_string(),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
        }
    }
}

impl ConnectorErrorMapping for GcpError {
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
    fn incomplete_listing_is_not_a_success_or_retryable_host_result() {
        let error = GcpError::IncompleteListing {
            reason: "pagination cursor repeated",
        };
        assert!(!ConnectorErrorMapping::is_retryable(&error));
        assert!(ConnectorErrorMapping::retry_after(&error).is_none());
        assert!(matches!(
            ConnectorErrorMapping::to_fcp_error(&error),
            FcpError::External {
                service,
                message,
                retryable: false,
                retry_after: None,
                status_code: None,
            } if service == "gcp" && message.contains("no partial results")
        ));
    }

    #[test]
    fn rate_limited_is_retryable() {
        let err = GcpError::RateLimited {
            retry_after_ms: 5_000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn unauthorized_is_not_retryable() {
        let err = GcpError::Unauthorized("bad token".into());
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn not_found_maps_to_resource_not_found() {
        let err = GcpError::NotFound("instance my-vm".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::ResourceNotFound { resource } => assert_eq!(resource, "instance my-vm"),
            other => panic!("Expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn api_error_retryable_for_server_errors() {
        let retryable = GcpError::Api {
            code: 500,
            message: "Internal".into(),
        };
        assert!(retryable.is_retryable());

        let terminal = GcpError::Api {
            code: 400,
            message: "Bad request".into(),
        };
        assert!(!terminal.is_retryable());
    }

    #[test]
    fn config_error_maps_to_invalid_request() {
        let err = GcpError::Config("missing access_token".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1001);
                assert!(message.contains("missing access_token"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn project_required_maps_to_invalid_request() {
        let err = GcpError::ProjectRequired("project_id is required".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, .. } => assert_eq!(code, 1003),
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_maps_to_fcp_rate_limited() {
        let err = GcpError::RateLimited {
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
        let err = GcpError::from_async_error(AsyncError::Timeout { timeout_ms: 1_500 });
        assert_eq!(
            err.to_string(),
            "Async error: request deadline exceeded after 1500ms"
        );
    }

    #[test]
    fn async_error_cancelled() {
        let err = GcpError::from_async_error(AsyncError::Cancelled);
        assert_eq!(err.to_string(), "Async error: operation cancelled");
    }

    #[test]
    fn json_error_not_retryable() {
        let raw_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err = GcpError::Json(raw_err);
        assert!(!err.is_retryable());
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Internal { .. }));
    }

    #[test]
    fn invalid_input_maps_to_invalid_request() {
        let err = GcpError::InvalidInput("zone is required".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1005);
                assert!(message.contains("zone is required"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn api_503_is_retryable() {
        let err = GcpError::Api {
            code: 503,
            message: "Service unavailable".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_404_not_retryable() {
        let err = GcpError::Api {
            code: 404,
            message: "Not found".into(),
        };
        assert!(!err.is_retryable());
    }
}
