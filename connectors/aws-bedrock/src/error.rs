use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;

use crate::event_stream::EventStreamError;

pub type BedrockResult<T> = Result<T, BedrockError>;

#[derive(Debug, thiserror::Error)]
pub enum BedrockError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("AWS event-stream error: {0}")]
    EventStream(#[from] EventStreamError),

    #[error("Bedrock API error {status}: {kind}: {message}")]
    Api {
        status: u16,
        kind: String,
        message: String,
    },

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
}

impl BedrockError {
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(error) => error.is_timeout() || error.is_connect(),
            Self::RateLimited { .. } => true,
            Self::Api { status, kind, .. } => {
                *status == 408
                    || *status == 424
                    || *status == 429
                    || *status == 529
                    || matches!(*status, 500 | 502 | 503 | 504)
                    || kind == "ModelNotReadyException"
                    || kind == "ThrottlingException"
                    || kind == "ServiceUnavailableException"
                    || kind == "overloaded_error"
                    || kind == "rate_limit_error"
            }
            Self::Json(_)
            | Self::EventStream(_)
            | Self::Unauthorized(_)
            | Self::NotFound(_)
            | Self::Async(_)
            | Self::Config(_)
            | Self::InvalidInput(_) => false,
        }
    }

    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(error) => FcpError::External {
                service: "aws-bedrock".into(),
                message: http_error_message(error),
                status_code: error.status().map(|status| status.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON parse error: {error}"),
            },
            Self::EventStream(error) => FcpError::External {
                service: "aws-bedrock".into(),
                message: format!("AWS event-stream decode error: {error}"),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
            Self::Api {
                status,
                kind,
                message,
            } => FcpError::External {
                service: "aws-bedrock".into(),
                message: format!("{kind}: {message}"),
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
        }
    }
}

fn http_error_message(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        format!("request timeout: {error}")
    } else if error.is_connect() {
        format!("connection error: {error}")
    } else {
        error.to_string()
    }
}

impl ConnectorErrorMapping for BedrockError {
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

pub fn bedrock_error_from_status(status: u16, body: &str) -> BedrockError {
    let parsed = serde_json::from_str::<serde_json::Value>(body).ok();
    let kind = parsed
        .as_ref()
        .and_then(|value| value.get("__type"))
        .or_else(|| parsed.as_ref().and_then(|value| value.get("code")))
        .or_else(|| {
            parsed
                .as_ref()
                .and_then(|value| value.get("error"))
                .and_then(|error| error.get("type"))
        })
        .and_then(serde_json::Value::as_str)
        .map_or_else(
            || format!("HTTP {status}"),
            |value| value.rsplit('#').next().unwrap_or(value).to_string(),
        );
    let message = parsed
        .as_ref()
        .and_then(|value| value.get("message"))
        .or_else(|| parsed.as_ref().and_then(|value| value.get("Message")))
        .or_else(|| {
            parsed
                .as_ref()
                .and_then(|value| value.get("error"))
                .and_then(|error| error.get("message"))
        })
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| body.to_string(), str::to_string);

    match status {
        401 | 403 => BedrockError::Unauthorized(message),
        404 => BedrockError::NotFound(message),
        429 => BedrockError::RateLimited {
            retry_after_ms: 30_000,
        },
        _ => BedrockError::Api {
            status,
            kind,
            message,
        },
    }
}
