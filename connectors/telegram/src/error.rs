//! Error types for the Telegram connector.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use thiserror::Error;

/// Convenience alias used throughout the connector.
pub type TelegramResult<T> = Result<T, TelegramError>;

/// Telegram API errors.
///
/// `Debug` is hand-written (not derived) so the `Http` variant never prints
/// the raw `reqwest::Error`, whose `url` field would otherwise leak the bot
/// token embedded in every Telegram API path. Both `Display` and `Debug`
/// route the HTTP error through `redact_telegram_bot_token_segments`.
#[derive(Error)]
pub enum TelegramError {    #[error("HTTP error: {}", redacted_http_error(.0))]
    Http(#[from] reqwest::Error),

    #[error("Telegram API error ({code}): {description}")]
    Api { code: i32, description: String },

    #[error("Telegram rate limit: {description} (retry after {retry_after:?})")]
    RateLimited {
        description: String,
        retry_after: Duration,
    },

    #[error("Telegram mutation may already have been applied; automatic retry refused: {source}")]
    UncertainMutation { source: Box<TelegramError> },

    #[error("Invalid chat ID: {0}")]
    InvalidChatId(String),

    #[error("Invalid file path: {0}")]
    InvalidFilePath(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error(
        "Partial Telegram send after {sent_chunks} chunk(s); failed chunk {failed_chunk_index}: {source}"
    )]
    PartialSend {
        sent_chunks: usize,
        failed_chunk_index: usize,
        sent_message_ids: Vec<i64>,
        source: Box<TelegramError>,
    },
}

impl std::fmt::Debug for TelegramError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(error) => f
                .debug_tuple("Http")
                .field(&redacted_http_error(error))
                .finish(),
            Self::Api { code, description } => f
                .debug_struct("Api")
                .field("code", code)
                .field("description", description)
                .finish(),
            Self::RateLimited {
                description,
                retry_after,
            } => f
                .debug_struct("RateLimited")
                .field("description", description)
                .field("retry_after", retry_after)
                .finish(),
            Self::UncertainMutation { source } => f
                .debug_struct("UncertainMutation")
                .field("source", source)
                .finish(),
            Self::InvalidChatId(value) => f.debug_tuple("InvalidChatId").field(value).finish(),
            Self::InvalidFilePath(value) => f.debug_tuple("InvalidFilePath").field(value).finish(),
            Self::InvalidRequest(value) => f.debug_tuple("InvalidRequest").field(value).finish(),
            Self::PartialSend {
                sent_chunks,
                failed_chunk_index,
                sent_message_ids,
                source,
            } => f
                .debug_struct("PartialSend")
                .field("sent_chunks", sent_chunks)
                .field("failed_chunk_index", failed_chunk_index)
                .field("sent_message_ids", sent_message_ids)
                .field("source", source)
                .finish(),
        }
    }
}

impl TelegramError {
    /// Check if this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(error) => error.is_timeout() || error.is_connect(),
            Self::Api { code, .. } => *code == 429 || *code >= 500,
            Self::RateLimited { .. } => true,
            Self::UncertainMutation { .. } => false,
            Self::InvalidChatId(_) => false,
            Self::InvalidFilePath(_) => false,
            Self::InvalidRequest(_) => false,
            Self::PartialSend { .. } => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after, .. } => Some(*retry_after),
            Self::Api { code, .. } if *code == 429 => Some(Duration::from_secs(30)),
            _ => None,
        }
    }

    /// Convert to an FCP-native error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(error) => FcpError::External {
                service: "telegram".into(),
                message: redacted_http_error(error),
                status_code: error.status().map(|status| status.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api { code, description } => {
                if *code == 429 {
                    FcpError::RateLimited {
                        retry_after_ms: 30_000,
                        violation: None,
                    }
                } else if *code == 401 {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: description.clone(),
                    }
                } else if *code == 403 {
                    FcpError::CapabilityDenied {
                        capability: "telegram.api".into(),
                        reason: description.clone(),
                    }
                } else {
                    FcpError::External {
                        service: "telegram".into(),
                        message: description.clone(),
                        status_code: Some(u16::try_from(*code).unwrap_or(0)),
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::RateLimited { retry_after, .. } => FcpError::RateLimited {
                // Round up so conversion never shortens a provider's minimum.
                retry_after_ms: u64::try_from(retry_after.as_nanos().div_ceil(1_000_000))
                    .unwrap_or(u64::MAX),
                violation: None,
            },
            Self::UncertainMutation { source } => FcpError::External {
                service: "telegram".into(),
                message: self.to_string(),
                status_code: match source.as_ref() {
                    Self::Api { code, .. } => u16::try_from(*code).ok(),
                    Self::Http(error) => error.status().map(|status| status.as_u16()),
                    _ => None,
                },
                retryable: false,
                retry_after: None,
            },
            Self::InvalidChatId(message) => FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid chat ID: {message}"),
            },
            Self::InvalidFilePath(message) => FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid file path: {message}"),
            },
            Self::InvalidRequest(message) => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::PartialSend { .. } => FcpError::External {
                service: "telegram".into(),
                message: self.to_string(),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
        }
    }

    pub(crate) fn from_fcp(error: &FcpError) -> Self {
        Self::InvalidRequest(error.to_string())
    }
}

fn redacted_http_error(error: &reqwest::Error) -> String {
    // reqwest's `Display` omits the source chain, which hides the actual
    // failure class (connection refused vs reset vs resource exhaustion).
    // Walk the chain and append each cause; the token redaction below
    // covers the joined text.
    let mut message = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    redact_telegram_bot_token_segments(&message)
}

fn redact_telegram_bot_token_segments(message: &str) -> String {
    let mut redacted = String::with_capacity(message.len());
    let mut cursor = 0;

    while let Some(relative_start) = message[cursor..].find("/bot") {
        let segment_start = cursor + relative_start;
        let credential_start = segment_start + "/bot".len();
        redacted.push_str(&message[cursor..credential_start]);
        redacted.push_str("[REDACTED]");

        let credential_end = message[credential_start..]
            .find(['/', '?', '#', '&', ')', ' ', '\t', '\r', '\n'])
            .map_or(message.len(), |relative_end| {
                credential_start + relative_end
            });
        cursor = credential_end;
    }

    redacted.push_str(&message[cursor..]);
    redacted
}

impl ConnectorErrorMapping for TelegramError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                code: 408,
                description: format!("deadline exceeded after {timeout_ms}ms"),
            },
            AsyncError::Cancelled => Self::Api {
                code: 0,
                description: "request cancelled".into(),
            },
            other => Self::Api {
                code: 0,
                description: other.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    const BOT_TOKEN: &str = "123456:SECRET_secret-SECRET_secret";

    #[test]
    fn rate_limit_delay_survives_error_mapping_without_shortening() {
        for (retry_after, expected_ms) in [
            (Duration::ZERO, 0),
            (Duration::from_secs(95), 95_000),
            (Duration::from_nanos(1), 1),
            (Duration::MAX, u64::MAX),
        ] {
            let error = TelegramError::RateLimited {
                description: "flood control".into(),
                retry_after,
            };
            assert!(error.is_retryable());
            assert_eq!(error.retry_after(), Some(retry_after));
            assert!(matches!(
                error.to_fcp_error(),
                FcpError::RateLimited { retry_after_ms, .. } if retry_after_ms == expected_ms
            ));
        }
    }

    #[test]
    fn uncertain_mutation_is_terminal_through_error_mapping() {
        let error = TelegramError::UncertainMutation {
            source: Box::new(TelegramError::Api {
                code: 503,
                description: "service unavailable".into(),
            }),
        };
        assert!(!error.is_retryable());
        assert_eq!(error.retry_after(), None);
        assert!(matches!(
            error.to_fcp_error(),
            FcpError::External {
                status_code: Some(503),
                retryable: false,
                retry_after: None,
                ..
            }
        ));
    }

    #[test]
    fn partial_send_remains_terminal_with_nested_rate_limit() {
        let error = TelegramError::PartialSend {
            sent_chunks: 1,
            failed_chunk_index: 1,
            sent_message_ids: vec![42],
            source: Box::new(TelegramError::RateLimited {
                description: "flood control".into(),
                retry_after: Duration::from_secs(95),
            }),
        };
        assert!(!error.is_retryable());
        assert_eq!(error.retry_after(), None);
        assert!(matches!(
            error.to_fcp_error(),
            FcpError::External {
                retryable: false,
                retry_after: None,
                ..
            }
        ));
    }

    #[test]
    fn redacts_bot_token_url_segments() {
        let message = format!(
            "error sending request for url (https://api.telegram.org/bot{BOT_TOKEN}/sendMessage)"
        );

        let redacted = redact_telegram_bot_token_segments(&message);

        assert!(!redacted.contains(BOT_TOKEN));
        assert!(redacted.contains("/bot[REDACTED]/sendMessage"));
    }

    #[fcp_async_core::runtime::test]
    async fn http_error_to_fcp_error_redacts_bot_token_url() {
        let url = format!("http://127.0.0.1:1/bot{BOT_TOKEN}/getMe");
        let error = reqwest::Client::builder()
            .timeout(Duration::from_millis(10))
            .build()
            .expect("client should build")
            .get(url)
            .send()
            .await
            .expect_err("closed local port should fail");

        let telegram_error = TelegramError::Http(error);
        let display = telegram_error.to_string();
        assert!(!display.contains(BOT_TOKEN));

        // The derived Debug would print the inner reqwest::Error's `url`
        // field verbatim (token included); the hand-written Debug must redact,
        // both directly and when nested inside another variant.
        let debug = format!("{telegram_error:?}");
        assert!(
            !debug.contains(BOT_TOKEN),
            "Debug leaked bot token: {debug}"
        );
        let uncertain = TelegramError::UncertainMutation {
            source: Box::new(telegram_error),
        };
        assert!(!uncertain.to_string().contains(BOT_TOKEN));
        assert!(!format!("{uncertain:?}").contains(BOT_TOKEN));
        let TelegramError::UncertainMutation { source } = uncertain else {
            unreachable!();
        };
        let telegram_error = *source;
        let nested_debug = format!(
            "{:?}",
            TelegramError::PartialSend {
                sent_chunks: 1,
                failed_chunk_index: 1,
                sent_message_ids: vec![1],
                source: Box::new(TelegramError::InvalidRequest(format!(
                    "wrapping {telegram_error:?}"
                ))),
            }
        );
        assert!(
            !nested_debug.contains(BOT_TOKEN),
            "nested Debug leaked bot token: {nested_debug}"
        );

        let fcp_error = telegram_error.to_fcp_error();
        match fcp_error {
            FcpError::External { message, .. } => {
                assert!(!message.contains(BOT_TOKEN));
                assert!(message.contains("/bot[REDACTED]/getMe") || !message.contains("/bot"));
            }
            other => assert!(
                matches!(other, FcpError::External { .. }),
                "expected External error, got {other:?}"
            ),
        }
    }
}
