//! Hugging Face connector error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;

pub type HuggingfaceResult<T> = Result<T, HuggingfaceError>;

#[derive(Debug, thiserror::Error)]
pub enum HuggingfaceError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Hugging Face API error {status}: {message}")]
    Api { status: u16, message: String },

    /// Inference may already have consumed provider compute. Neither a
    /// connector retry nor a new host invoke can safely repeat this request.
    /// Do not retain upstream bodies or transport URLs in this error: they
    /// can contain the input prompt or credentials.
    #[error("inference outcome unknown; the request may already have executed; automatic retry suppressed")]
    InferenceOutcomeUnknown { status: Option<u16> },

    #[error("Rate limited (retry after {retry_after_ms}ms)")]
    RateLimited { retry_after_ms: u64 },

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Model loading: {0}")]
    ModelLoading(String),

    #[error("Async error: {0}")]
    Async(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl HuggingfaceError {
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(error) => error.is_timeout() || error.is_connect(),
            Self::RateLimited { .. } | Self::ModelLoading(_) => true,
            Self::Api { status, .. } => matches!(status, 500 | 502 | 503 | 504),
            Self::Json(_)
            | Self::InferenceOutcomeUnknown { .. }
            | Self::Unauthorized(_)
            | Self::NotFound(_)
            | Self::Async(_)
            | Self::InvalidInput(_) => false,
        }
    }

    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            Self::ModelLoading(_) => Some(Duration::from_secs(10)),
            _ => None,
        }
    }

    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(error) => FcpError::External {
                service: "huggingface".into(),
                message: error.to_string(),
                status_code: error.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON parse error: {error}"),
            },
            Self::Api { status, message } => FcpError::External {
                service: "huggingface".into(),
                message: format!("HF API error {status}: {message}"),
                status_code: Some(*status),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::InferenceOutcomeUnknown { status } => FcpError::External {
                service: "huggingface".into(),
                message: self.to_string(),
                status_code: *status,
                retryable: false,
                retry_after: None,
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
            Self::ModelLoading(message) => FcpError::External {
                service: "huggingface".into(),
                message: message.clone(),
                status_code: Some(503),
                retryable: true,
                retry_after: Some(Duration::from_secs(10)),
            },
            Self::Async(message) => FcpError::Internal {
                message: format!("Async error: {message}"),
            },
            Self::InvalidInput(message) => FcpError::InvalidRequest {
                code: 1005,
                message: message.clone(),
            },
        }
    }
}

impl ConnectorErrorMapping for HuggingfaceError {
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
    fn rate_limited_is_retryable() {
        let err = HuggingfaceError::RateLimited {
            retry_after_ms: 5_000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn unauthorized_is_not_retryable() {
        let err = HuggingfaceError::Unauthorized("bad token".into());
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn not_found_maps_to_resource_not_found() {
        let err = HuggingfaceError::NotFound("model gpt2".into());
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::ResourceNotFound { ref resource } if resource == "model gpt2"
        ));
    }

    #[test]
    fn model_loading_is_retryable() {
        let err = HuggingfaceError::ModelLoading("model is loading".into());
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(10)));
    }

    #[test]
    fn api_error_retryable_for_server_errors() {
        let retryable = HuggingfaceError::Api {
            status: 500,
            message: "Internal".into(),
        };
        assert!(retryable.is_retryable());

        let terminal = HuggingfaceError::Api {
            status: 400,
            message: "Bad request".into(),
        };
        assert!(!terminal.is_retryable());
    }

    #[test]
    fn invalid_input_maps_to_invalid_request() {
        let err = HuggingfaceError::InvalidInput("model_id missing".into());
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::InvalidRequest { code: 1005, ref message } if message.contains("model_id")
        ));
    }

    #[test]
    fn rate_limited_maps_to_fcp_rate_limited() {
        let err = HuggingfaceError::RateLimited {
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
        let err = HuggingfaceError::from_async_error(AsyncError::Timeout { timeout_ms: 1_500 });
        assert_eq!(
            err.to_string(),
            "Async error: request deadline exceeded after 1500ms"
        );
    }

    #[test]
    fn ambiguous_inference_stays_non_retryable_across_the_host_boundary() {
        for status in [None, Some(200), Some(408), Some(500), Some(503)] {
            let err = HuggingfaceError::InferenceOutcomeUnknown { status };
            assert!(!err.is_retryable());
            assert!(err.retry_after().is_none());
            assert!(!ConnectorErrorMapping::is_retryable(&err));
            assert!(matches!(
                ConnectorErrorMapping::to_fcp_error(&err),
                FcpError::External {
                    status_code,
                    retryable: false,
                    retry_after: None,
                    ref message,
                    ..
                } if status_code == status && message.contains("outcome unknown")
            ));
        }
    }
}
