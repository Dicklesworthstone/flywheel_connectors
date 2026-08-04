//! Error types for the Synology Chat connector.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_prelude::log_redaction::redact_url;
use fcp_sdk::ConnectorErrorMapping;
use fcp_sdk::migration::map_async_to_fcp_error;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SynologyChatError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    // The Synology Chat incoming-webhook URL embeds the posting credential as a
    // `token` query parameter, and `reqwest::Error`'s `Display` appends the full
    // request URL (query included, unredacted). Interpolating the reqwest error
    // here (`{0}`) would leak that webhook token into any surfaced/logged
    // message, so Display carries no URL; the redaction-safe detail is built in
    // `to_fcp_error`.
    #[error("http error")]
    Http(#[from] reqwest::Error),

    #[error("api error: status={status}, message={message}")]
    Api {
        status: u16,
        message: String,
        retry_after_ms: Option<u64>,
    },

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("async error: {0}")]
    Async(AsyncError),
}

pub type SynologyChatResult<T> = Result<T, SynologyChatError>;

impl SynologyChatError {
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        ConnectorErrorMapping::to_fcp_error(self)
    }

    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Config(_) | Self::InvalidInput(_) | Self::Json(_) => false,
            Self::Http(error) => error.is_connect() || error.is_timeout(),
            Self::Api { status, .. } => matches!(status, 429 | 500 | 502 | 503 | 504),
            Self::Async(error) => matches!(error, AsyncError::Timeout { .. }),
        }
    }

    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Api {
                retry_after_ms: Some(retry_after_ms),
                ..
            } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    fn fcp_error_impl(&self) -> FcpError {
        match self {
            Self::Config(message) => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::InvalidInput(message) => FcpError::InvalidRequest {
                code: 1005,
                message: message.clone(),
            },
            Self::Http(error) if error.is_timeout() => FcpError::UpstreamTimeout {
                service: "synology_chat".into(),
            },
            Self::Http(error) => {
                // `error.to_string()` would append the raw request URL, whose
                // query string carries the webhook `token`. Surface a
                // redaction-safe URL (query dropped) instead.
                let message = error.url().map_or_else(
                    || "http error".to_string(),
                    |url| format!("http error for url ({})", redact_url(url.as_str())),
                );
                FcpError::External {
                    service: "synology_chat".into(),
                    message,
                    status_code: error.status().map(|status| status.as_u16()),
                    retryable: self.is_retryable(),
                    retry_after: self.retry_after(),
                }
            }
            Self::Api {
                status: 429,
                retry_after_ms: Some(retry_after_ms),
                ..
            } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Api {
                status,
                message,
                retry_after_ms: _,
            } => FcpError::External {
                service: "synology_chat".into(),
                message: message.clone(),
                status_code: Some(*status),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(error) => FcpError::MalformedFrame {
                code: 1006,
                message: format!("Failed to decode Synology Chat response: {error}"),
            },
            Self::Async(error) => map_async_to_fcp_error(error),
        }
    }
}

impl ConnectorErrorMapping for SynologyChatError {
    fn from_async_error(error: AsyncError) -> Self {
        Self::Async(error)
    }

    fn to_fcp_error(&self) -> FcpError {
        self.fcp_error_impl()
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
    fn api_server_error_is_retryable() {
        let error = SynologyChatError::Api {
            status: 503,
            message: "unavailable".into(),
            retry_after_ms: None,
        };
        assert!(error.is_retryable());
        assert_eq!(error.retry_after(), None);
    }

    #[test]
    fn invalid_input_maps_to_invalid_request() {
        let error = SynologyChatError::InvalidInput("payload must be an object".into());
        match error.to_fcp_error() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1005);
                assert!(message.contains("payload must be an object"));
            }
            other => assert!(matches!(other, FcpError::InvalidRequest { .. })),
        }
    }

    #[test]
    fn api_retry_after_maps_to_rate_limited() {
        let error = SynologyChatError::Api {
            status: 429,
            message: "slow down".into(),
            retry_after_ms: Some(7000),
        };
        match error.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 7000);
                assert!(violation.is_none());
            }
            other => assert!(matches!(other, FcpError::RateLimited { .. })),
        }
    }

    #[test]
    fn timeout_async_error_maps_through_connector_trait() {
        let error = SynologyChatError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(error.is_retryable());
        match error {
            SynologyChatError::Async(AsyncError::Timeout { timeout_ms }) => {
                assert_eq!(timeout_ms, 5000);
            }
            other => assert!(matches!(
                other,
                SynologyChatError::Async(AsyncError::Timeout { .. })
            )),
        }
    }

    #[test]
    fn cancelled_async_error_maps_to_standard_fcp_error() {
        let error = SynologyChatError::from_async_error(AsyncError::Cancelled);
        match error.to_fcp_error() {
            FcpError::External {
                message, retryable, ..
            } => {
                assert!(message.contains("cancelled"));
                assert!(!retryable);
            }
            other => assert!(matches!(other, FcpError::External { .. })),
        }
    }

    #[test]
    fn http_transport_error_never_leaks_webhook_token() {
        const SECRET: &str = "synology-webhook-token-DEADBEEF-secret";
        // Bind then immediately drop a loopback socket so the port refuses
        // connections deterministically (no accept-loop thread, no flakiness).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let port = listener.local_addr().expect("listener local addr").port();
        drop(listener);

        // The incoming-webhook POST targets a URL with `?token=<SECRET>`; a
        // connect failure yields a `reqwest::Error` carrying that URL. The token
        // in the query string must never survive into any surfaced message. The
        // assertion is a negative, so it holds for any transport error variant.
        let url = format!("http://127.0.0.1:{port}/webapi/entry.cgi?token={SECRET}");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(500))
            .build()
            .expect("client should build");
        let outcome = fcp_async_core::runtime::block_on_sync(async move {
            client
                .post(&url)
                .send()
                .await
                .map_err(SynologyChatError::from)
        })
        .expect("runtime should drive the future to completion");
        let error = outcome.expect_err("connection to a closed loopback port must fail");
        assert!(
            matches!(error, SynologyChatError::Http(_)),
            "expected transport error, got {error:?}"
        );

        let display = error.to_string();
        assert!(
            !display.contains(SECRET) && !display.contains("token="),
            "Display leaked the webhook token query: {display}"
        );

        if let FcpError::External { message, .. } = error.to_fcp_error() {
            assert!(
                !message.contains(SECRET) && !message.contains("token="),
                "FcpError message leaked the webhook token query: {message}"
            );
        }
    }
}
