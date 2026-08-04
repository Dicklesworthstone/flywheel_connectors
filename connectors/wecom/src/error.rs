//! Error types for the `WeCom` connector.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_prelude::log_redaction::redact_url;
use fcp_sdk::ConnectorErrorMapping;

pub type WeComResult<T> = Result<T, WeComError>;

#[derive(Debug, thiserror::Error)]
pub enum WeComError {
    // WeCom puts `corpsecret`/`access_token` in the request query string, and
    // `reqwest::Error`'s `Display` appends the full request URL (query included,
    // unredacted). Interpolating the reqwest error here (`{0}`) would leak the
    // long-lived app secret into any surfaced/logged message, so Display carries
    // no URL; the redaction-safe detail is built in `to_fcp_error`.
    #[error("HTTP transport error")]
    Http(#[from] reqwest::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("WeCom API error {errcode}: {errmsg}")]
    Api { errcode: i64, errmsg: String },

    #[error("Rate limited (retry after {retry_after_ms}ms)")]
    RateLimited { retry_after_ms: u64 },

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Async error: {0}")]
    Async(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Token error: {0}")]
    Token(String),
}

impl WeComError {
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(error) => error.is_timeout() || error.is_connect(),
            Self::RateLimited { .. } | Self::Token(_) => true,
            Self::Api { errcode, .. } => matches!(errcode, 429 | 500 | 502 | 503 | 504),
            Self::Json(_)
            | Self::Unauthorized(_)
            | Self::Async(_)
            | Self::Config(_)
            | Self::InvalidInput(_) => false,
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
            Self::Http(error) => {
                let kind = if error.is_timeout() {
                    "timeout"
                } else if error.is_connect() {
                    "connect"
                } else if error.is_body() || error.is_decode() {
                    "body"
                } else {
                    "transport"
                };
                // `error.to_string()` would append the raw request URL, whose
                // query string carries `corpsecret`/`access_token`. Surface the
                // failure kind plus a redaction-safe URL (query dropped) instead.
                let message = error.url().map_or_else(
                    || format!("HTTP {kind} error"),
                    |url| format!("HTTP {kind} error for url ({})", redact_url(url.as_str())),
                );
                FcpError::External {
                    service: "wecom".into(),
                    message,
                    status_code: error.status().map(|s| s.as_u16()),
                    retryable: self.is_retryable(),
                    retry_after: self.retry_after(),
                }
            }
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON parse error: {error}"),
            },
            Self::Api { errcode, errmsg } => FcpError::External {
                service: "wecom".into(),
                message: format!("WeCom API error {errcode}: {errmsg}"),
                status_code: u16::try_from(*errcode)
                    .ok()
                    .filter(|&c| (100..600).contains(&c)),
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
            Self::Token(message) => FcpError::External {
                service: "wecom".into(),
                message: format!("Token error: {message}"),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
        }
    }
}

impl ConnectorErrorMapping for WeComError {
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
        let err = WeComError::RateLimited {
            retry_after_ms: 5_000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn unauthorized_is_not_retryable() {
        let err = WeComError::Unauthorized("bad token".into());
        assert!(!err.is_retryable());
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn api_error_retryable_for_server_errors() {
        for errcode in [429, 500, 502, 503, 504] {
            let err = WeComError::Api {
                errcode,
                errmsg: "server error".into(),
            };
            assert!(err.is_retryable(), "errcode {errcode} should be retryable");
        }
        let err = WeComError::Api {
            errcode: 400,
            errmsg: "bad request".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn config_error_maps_to_invalid_request() {
        let err = WeComError::Config("missing corp_id".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1001);
                assert!(message.contains("missing corp_id"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn api_error_maps_to_external() {
        let err = WeComError::Api {
            errcode: 40001,
            errmsg: "invalid credential".into(),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "wecom");
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn token_error_is_retryable() {
        let err = WeComError::Token("expired".into());
        assert!(err.is_retryable());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External { retryable, .. } => {
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn async_error_mapping_preserves_timeout() {
        let async_err = AsyncError::Timeout { timeout_ms: 30000 };
        let err = WeComError::from_async_error(async_err);
        match &err {
            WeComError::Async(msg) => {
                assert!(msg.contains("30000"));
                assert!(msg.contains("deadline exceeded"));
            }
            other => panic!("expected Async, got {other:?}"),
        }
    }

    #[test]
    fn json_error_maps_to_internal() {
        let json_err: serde_json::Error = serde_json::from_str::<String>("not json").unwrap_err();
        let err = WeComError::Json(json_err);
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Internal { message } => {
                assert!(message.contains("JSON parse error"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn invalid_input_maps_to_invalid_request() {
        let err = WeComError::InvalidInput("missing content field".into());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1005);
                assert!(message.contains("missing content field"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }
}
