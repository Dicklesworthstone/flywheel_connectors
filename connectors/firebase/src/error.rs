//! Error mapping for the Firebase connector.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use serde::Deserialize;

/// Result alias for Firebase operations.
pub type FirebaseResult<T> = Result<T, FirebaseError>;

/// Connector-local error type.
#[derive(Debug, thiserror::Error)]
pub enum FirebaseError {
    /// Invalid connector input.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// Authentication or authorization failure.
    #[error("unauthorized: {message}")]
    Unauthorized { message: String },
    /// Provider-side throttling.
    #[error("rate limited")]
    RateLimited { retry_after_ms: u64 },
    /// Provider API error.
    #[error("firebase api error ({status_code}): {message}")]
    Api {
        status_code: u16,
        message: String,
        retryable: bool,
    },
    /// HTTP transport failure.
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    /// JSON serialization or decoding failure.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// Async runtime failure.
    #[error("async error: {0}")]
    Async(String),
}

impl FirebaseError {
    /// Construct a provider error from an HTTP status and response body.
    #[must_use]
    pub fn from_http_response(status_code: u16, body: &str) -> Self {
        let parsed = serde_json::from_str::<GoogleErrorEnvelope>(body).ok();
        let message = parsed
            .and_then(|envelope| envelope.error)
            .and_then(|error| error.message)
            .filter(|message| !message.trim().is_empty())
            .unwrap_or_else(|| {
                if body.trim().is_empty() {
                    format!("Firebase request failed with status {status_code}")
                } else {
                    body.trim().to_string()
                }
            });

        match status_code {
            401 | 403 => Self::Unauthorized { message },
            429 => Self::RateLimited {
                retry_after_ms: 60_000,
            },
            _ => Self::Api {
                status_code,
                message,
                retryable: matches!(status_code, 429 | 500..=599),
            },
        }
    }

    /// Whether the error should be retried automatically.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::RateLimited { .. } => true,
            Self::Api { retryable, .. } => *retryable,
            Self::Http(_) => true,
            Self::InvalidInput(_) | Self::Unauthorized { .. } | Self::Json(_) => false,
            Self::Async(_) => false,
        }
    }

    /// Whether replaying the request that produced this error cannot duplicate
    /// a side effect (br-kxd3e).
    ///
    /// Distinct from `is_retryable`: a rate-limited request was refused
    /// WITHOUT being performed, so it stays safe to replay; a 5xx means the
    /// service received the request and may already have applied it.
    #[must_use]
    pub fn replay_is_safe(&self) -> bool {
        match self {
            Self::RateLimited { .. } => true,
            // Firestore marks a 429 retryable through this flag as well.
            Self::Api { status_code, .. } => *status_code == 429,
            Self::Http(e) => !fcp_sdk::migration::transport_error_reached_service(e),
            _ => false,
        }
    }

    /// Retry delay hint when available.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    /// Convert into the shared FCP error model.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::InvalidInput(message) => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::Unauthorized { message } => FcpError::Unauthorized {
                code: 2001,
                message: message.clone(),
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Api {
                status_code,
                message,
                retryable,
            } => FcpError::External {
                service: "firebase".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: *retryable,
                retry_after: None,
            },
            Self::Http(error) => FcpError::External {
                service: "firebase".into(),
                message: error.to_string(),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
            Self::Json(error) => FcpError::Internal {
                message: error.to_string(),
            },
            Self::Async(message) => FcpError::Internal {
                message: format!("Async error: {message}"),
            },
        }
    }
}

impl ConnectorErrorMapping for FirebaseError {
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

#[derive(Debug, Deserialize)]
struct GoogleErrorEnvelope {
    #[serde(default)]
    error: Option<GoogleErrorBody>,
}

#[derive(Debug, Deserialize)]
struct GoogleErrorBody {
    #[serde(default)]
    message: Option<String>,
}
