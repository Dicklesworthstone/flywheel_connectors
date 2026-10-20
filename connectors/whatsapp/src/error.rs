//! `WhatsApp` connector error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use fcp_sdk::migration::classify_http_status;
use thiserror::Error;

/// `WhatsApp` connector errors.
#[derive(Error, Debug)]
pub enum WhatsAppError {
    /// HTTP transport error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// `WhatsApp` API returned an error response.
    #[error("WhatsApp API error ({code}): {message}")]
    Api {
        code: u32,
        message: String,
        error_type: String,
        subcode: Option<u32>,
    },

    /// Rate limited by `WhatsApp` API.
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failure.
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Invalid phone number format.
    #[error("Invalid phone number: {0}")]
    InvalidPhoneNumber(String),

    /// Template message rejected by `WhatsApp`.
    #[error("Template rejected: {0}")]
    TemplateRejected(String),

    /// Async operation error (timeout, cancellation).
    #[error("Async error: {0}")]
    Async(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Webhook signature verification failed.
    #[error("Webhook error: {0}")]
    Webhook(String),

    /// Invalid input (path traversal, bad identifier, etc.).
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl WhatsAppError {
    /// Whether this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } | Self::Async(_) => true,
            // Meta API transient codes: 1=unknown, 2=temporary, 4=too many calls, 368=temp block
            Self::Api {
                code, error_type, ..
            } => {
                if matches!(error_type.as_str(), "HttpError" | "HealthCheckError") {
                    return u16::try_from(*code)
                        .is_ok_and(|status| classify_http_status(status, None).is_retryable());
                }
                matches!(*code, 1 | 2 | 4 | 368)
            }
            Self::Json(_)
            | Self::Unauthorized(_)
            | Self::InvalidPhoneNumber(_)
            | Self::TemplateRejected(_)
            | Self::Config(_)
            | Self::Webhook(_)
            | Self::InvalidInput(_) => false,
        }
    }

    /// Suggested retry-after delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    /// Convert to FCP error taxonomy.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "whatsapp".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api { code, message, .. } => FcpError::External {
                service: "whatsapp".into(),
                message: format!("API error {code}: {message}"),
                // status_code is for HTTP status; API-level codes (e.g., 100, 2018001)
                // only fit u16 when they originated from an HTTP status fallback
                status_code: u16::try_from(*code).ok(),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Unauthorized(msg) => FcpError::Unauthorized {
                code: 2001,
                message: msg.clone(),
            },
            Self::InvalidPhoneNumber(msg) => FcpError::InvalidRequest {
                code: 1005,
                message: format!("Invalid phone number: {msg}"),
            },
            Self::TemplateRejected(msg) => FcpError::InvalidRequest {
                code: 1006,
                message: format!("Template rejected: {msg}"),
            },
            Self::Async(msg) => FcpError::Internal {
                message: format!("Async error: {msg}"),
            },
            Self::Config(msg) => FcpError::InvalidRequest {
                code: 1001,
                message: format!("Configuration error: {msg}"),
            },
            Self::Webhook(msg) => FcpError::InvalidRequest {
                code: 1007,
                message: format!("Webhook error: {msg}"),
            },
            Self::InvalidInput(msg) => FcpError::InvalidRequest {
                code: 1008,
                message: format!("Invalid input: {msg}"),
            },
        }
    }
}

impl ConnectorErrorMapping for WhatsAppError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => {
                Self::Async(format!("operation timed out after {timeout_ms}ms"))
            }
            AsyncError::Cancelled => Self::Async("operation cancelled".into()),
            other => Self::Async(format!("async error: {other}")),
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

pub type WhatsAppResult<T> = Result<T, WhatsAppError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_error_is_retryable() {
        let err = WhatsAppError::Http(
            reqwest::Client::new()
                .get("://invalid")
                .build()
                .unwrap_err(),
        );
        assert!(err.is_retryable());
    }

    #[test]
    fn rate_limited_is_retryable() {
        let err = WhatsAppError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn unauthorized_not_retryable() {
        let err = WhatsAppError::Unauthorized("bad token".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_error_maps_to_fcp() {
        let err = WhatsAppError::Api {
            code: 100,
            message: "Invalid parameter".into(),
            error_type: "OAuthException".into(),
            subcode: Some(2_018_001),
        };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::External { .. }));
    }

    #[test]
    fn template_rejected_maps_to_invalid_request() {
        let err = WhatsAppError::TemplateRejected("not approved".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn invalid_phone_maps_to_invalid_request() {
        let err = WhatsAppError::InvalidPhoneNumber("abc".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn from_async_timeout() {
        let err = WhatsAppError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(matches!(err, WhatsAppError::Async(_)));
        assert!(err.is_retryable());
    }

    #[test]
    fn from_async_cancelled() {
        let err = WhatsAppError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, WhatsAppError::Async(_)));
    }

    #[test]
    fn from_async_channel_closed() {
        let err = WhatsAppError::from_async_error(AsyncError::ChannelClosed);
        assert!(matches!(err, WhatsAppError::Async(_)));
    }

    #[test]
    fn rate_limited_maps_to_fcp() {
        let err = WhatsAppError::RateLimited {
            retry_after_ms: 3000,
        };
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::RateLimited { .. }));
    }

    #[test]
    fn config_error_not_retryable() {
        let err = WhatsAppError::Config("missing token".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn webhook_error_not_retryable() {
        let err = WhatsAppError::Webhook("invalid signature".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn webhook_error_maps_to_invalid_request() {
        let err = WhatsAppError::Webhook("bad payload".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn health_check_http_status_can_be_retryable() {
        let err = WhatsAppError::Api {
            code: 503,
            message: "Service unavailable".into(),
            error_type: "HealthCheckError".into(),
            subcode: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn error_display_format() {
        let err = WhatsAppError::Api {
            code: 100,
            message: "Invalid parameter".into(),
            error_type: "OAuthException".into(),
            subcode: None,
        };
        let display = format!("{err}");
        assert!(display.contains("WhatsApp API error"));
        assert!(display.contains("100"));
    }
}
