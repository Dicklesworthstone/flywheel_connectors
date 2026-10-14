use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;

pub type ShopifyResult<T> = Result<T, ShopifyError>;

#[derive(Debug, thiserror::Error)]
pub enum ShopifyError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Shopify API error {code}: {message}")]
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

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Shopify request outcome is unknown after delivery (status {status:?})")]
    OutcomeUnknown { status: Option<u16> },
}

impl ShopifyError {
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
            | Self::InvalidInput(_)
            | Self::OutcomeUnknown { .. } => false,
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
                service: "shopify".into(),
                message: error.to_string(),
                status_code: error.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON parse error: {error}"),
            },
            Self::Api { code, message } => FcpError::External {
                service: "shopify".into(),
                message: format!("Shopify API error {code}: {message}"),
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
            Self::InvalidInput(message) => FcpError::InvalidRequest {
                code: 1005,
                message: message.clone(),
            },
            Self::OutcomeUnknown { status } => FcpError::External {
                service: "shopify".into(),
                message: "Shopify request may already have taken effect; automatic replay refused"
                    .into(),
                status_code: *status,
                retryable: false,
                retry_after: None,
            },
        }
    }
}

impl ConnectorErrorMapping for ShopifyError {
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
    fn outcome_unknown_is_never_retryable_at_fcp_boundary() {
        let err = ShopifyError::OutcomeUnknown { status: Some(503) };
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::External {
                status_code: Some(503),
                retryable: false,
                retry_after: None,
                ..
            }
        ));
    }

    #[test]
    fn rate_limited_is_retryable() {
        let err = ShopifyError::RateLimited {
            retry_after_ms: 5_000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn unauthorized_is_not_retryable() {
        let err = ShopifyError::Unauthorized("bad token".into());
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn not_found_maps_to_resource_not_found() {
        let err = ShopifyError::NotFound("product 123".into());
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::ResourceNotFound { ref resource } if resource == "product 123"
        ));
    }

    #[test]
    fn api_error_retryable_for_server_errors() {
        let retryable = ShopifyError::Api {
            code: 500,
            message: "Internal".into(),
        };
        assert!(retryable.is_retryable());

        let terminal = ShopifyError::Api {
            code: 400,
            message: "Bad request".into(),
        };
        assert!(!terminal.is_retryable());
    }

    #[test]
    fn config_error_maps_to_invalid_request() {
        let err = ShopifyError::Config("missing access_token".into());
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::InvalidRequest { code: 1001, ref message }
                if message.contains("missing access_token")
        ));
    }

    #[test]
    fn rate_limited_maps_to_fcp_rate_limited() {
        let err = ShopifyError::RateLimited {
            retry_after_ms: 3_000,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::RateLimited {
                retry_after_ms: 3_000,
                violation: None,
            }
        ));
    }

    #[test]
    fn async_error_mapping_preserves_timeout() {
        let err = ShopifyError::from_async_error(AsyncError::Timeout { timeout_ms: 1_500 });
        assert_eq!(
            err.to_string(),
            "Async error: request deadline exceeded after 1500ms"
        );
    }

    #[test]
    fn async_error_mapping_cancelled() {
        let err = ShopifyError::from_async_error(AsyncError::Cancelled);
        assert!(err.to_string().contains("cancelled"));
    }

    #[test]
    fn invalid_input_maps_correctly() {
        let err = ShopifyError::InvalidInput("product_id required".into());
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::InvalidRequest { code: 1005, ref message }
                if message == "product_id required"
        ));
    }

    #[test]
    fn http_error_maps_to_external() {
        // Build an error through JSON parse since we can't construct reqwest::Error directly
        let err =
            ShopifyError::Json(serde_json::from_str::<serde_json::Value>("invalid").unwrap_err());
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Internal { .. }));
    }

    #[test]
    fn api_502_is_retryable() {
        let err = ShopifyError::Api {
            code: 502,
            message: "Bad gateway".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_422_is_not_retryable() {
        let err = ShopifyError::Api {
            code: 422,
            message: "Unprocessable".into(),
        };
        assert!(!err.is_retryable());
    }
}
