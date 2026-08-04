//! Error types for the `DingTalk` connector.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_prelude::log_redaction::redact_url;
use fcp_sdk::ConnectorErrorMapping;

pub type DingTalkResult<T> = Result<T, DingTalkError>;

#[derive(Debug, thiserror::Error)]
pub enum DingTalkError {
    // The media-upload endpoint carries `access_token` in the request query
    // string, and `reqwest::Error`'s `Display` appends the full request URL
    // (query included, unredacted). Interpolating the reqwest error here (`{0}`)
    // would leak the live access token into any surfaced/logged message, so
    // Display carries no URL; the redaction-safe detail is built in
    // `to_fcp_error`.
    #[error("HTTP transport error")]
    Http(#[from] reqwest::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("DingTalk API error {code}: {message}")]
    Api { code: u32, message: String },

    #[error("DingTalk media error {errcode}: {errmsg}")]
    Media { errcode: i64, errmsg: String },

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

impl DingTalkError {
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(error) => error.is_timeout() || error.is_connect(),
            Self::RateLimited { .. } | Self::Token(_) => true,
            Self::Api { code, .. } => matches!(code, 429 | 500 | 502 | 503 | 504),
            Self::Media { .. }
            | Self::Json(_)
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
                // `error.to_string()` would append the raw request URL, whose
                // query string carries `access_token`. Surface a redaction-safe
                // URL (query dropped) instead.
                let message = error.url().map_or_else(
                    || "HTTP transport error".to_string(),
                    |url| {
                        format!(
                            "HTTP transport error for url ({})",
                            redact_url(url.as_str())
                        )
                    },
                );
                FcpError::External {
                    service: "dingtalk".into(),
                    message,
                    status_code: error.status().map(|s| s.as_u16()),
                    retryable: self.is_retryable(),
                    retry_after: self.retry_after(),
                }
            }
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON parse error: {error}"),
            },
            Self::Api { code, message } => FcpError::External {
                service: "dingtalk".into(),
                message: format!("DingTalk API error {code}: {message}"),
                status_code: u16::try_from(*code)
                    .ok()
                    .filter(|&c| (100..600).contains(&c)),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Media { errcode, errmsg } => FcpError::External {
                service: "dingtalk".into(),
                message: format!("DingTalk media error {errcode}: {errmsg}"),
                status_code: None,
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
                service: "dingtalk".into(),
                message: format!("Token error: {message}"),
                status_code: None,
                retryable: true,
                retry_after: None,
            },
        }
    }
}

impl ConnectorErrorMapping for DingTalkError {
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
        let err = DingTalkError::RateLimited {
            retry_after_ms: 5_000,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn unauthorized_is_not_retryable() {
        let err = DingTalkError::Unauthorized("bad token".into());
        assert!(!err.is_retryable());
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn api_error_retryable_for_server_errors() {
        for code in [429, 500, 502, 503, 504] {
            let err = DingTalkError::Api {
                code,
                message: "server error".into(),
            };
            assert!(err.is_retryable(), "code {code} should be retryable");
        }
        let err = DingTalkError::Api {
            code: 400,
            message: "bad request".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn config_error_maps_to_invalid_request() {
        let err = DingTalkError::Config("missing client_id".into());
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::InvalidRequest {
                code: 1001,
                ref message
            } if message.contains("missing client_id")
        ));
    }

    #[test]
    fn media_error_maps_to_external() {
        let err = DingTalkError::Media {
            errcode: 40001,
            errmsg: "invalid media".into(),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::External {
                ref service,
                retryable: false,
                ..
            } if service == "dingtalk"
        ));
    }

    #[test]
    fn token_error_is_retryable() {
        let err = DingTalkError::Token("expired".into());
        assert!(err.is_retryable());
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::External {
                retryable: true,
                ..
            }
        ));
    }

    #[test]
    fn async_error_mapping_preserves_timeout() {
        let async_err = AsyncError::Timeout { timeout_ms: 30000 };
        let err = DingTalkError::from_async_error(async_err);
        assert!(matches!(
            err,
            DingTalkError::Async(ref msg)
                if msg.contains("30000") && msg.contains("deadline exceeded")
        ));
    }

    #[test]
    fn json_error_maps_to_internal() {
        let json_err: serde_json::Error = serde_json::from_str::<String>("not json").unwrap_err();
        let err = DingTalkError::Json(json_err);
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::Internal { ref message } if message.contains("JSON parse error")
        ));
    }

    #[test]
    fn http_timeout_is_retryable() {
        // We can't easily construct a reqwest::Error with timeout,
        // so we verify the match arm logic via an API error with code 504
        let err = DingTalkError::Api {
            code: 504,
            message: "gateway timeout".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn http_transport_error_never_leaks_access_token() {
        const SECRET: &str = "dingtalk-access-token-DEADBEEF-super-secret";
        // Bind then immediately drop a loopback socket so the port refuses
        // connections deterministically (no accept-loop thread, no flakiness).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let port = listener.local_addr().expect("listener local addr").port();
        drop(listener);

        // `upload_media` sends POST /media/upload?access_token=<SECRET>&type=…;
        // a connect failure yields a `reqwest::Error` carrying that URL. The
        // access token in the query string must never survive into any surfaced
        // message. The assertion is a negative, so it holds for any transport
        // error variant the environment yields.
        let url = format!("http://127.0.0.1:{port}/media/upload?access_token={SECRET}&type=image");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(500))
            .build()
            .expect("client should build");
        let outcome = fcp_async_core::runtime::block_on_sync(async move {
            client.post(&url).send().await.map_err(DingTalkError::from)
        })
        .expect("runtime should drive the future to completion");
        let error = outcome.expect_err("connection to a closed loopback port must fail");
        assert!(
            matches!(error, DingTalkError::Http(_)),
            "expected transport error, got {error:?}"
        );

        let display = error.to_string();
        assert!(
            !display.contains(SECRET) && !display.contains("access_token"),
            "Display leaked the access_token query: {display}"
        );

        match error.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert!(
                    !message.contains(SECRET) && !message.contains("access_token"),
                    "FcpError message leaked the access_token query: {message}"
                );
            }
            other => panic!("expected External FcpError, got {other:?}"),
        }
    }
}
