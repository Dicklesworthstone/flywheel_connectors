//! Error taxonomy and redaction helpers.

use std::fmt;
use std::time::Duration;

use serde_json::Value;
use thiserror::Error;

/// Transport-level error details.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NetworkError {
    /// HTTP client error.
    #[error("{message}")]
    Http {
        /// Redacted error message.
        message: String,
    },
    /// Request was cancelled.
    #[error("request cancelled: {message}")]
    Cancelled {
        /// Cancellation detail.
        message: String,
    },
    /// The complete operation, including retries or streaming, exhausted its budget.
    #[error("request deadline exceeded after {timeout_ms}ms")]
    DeadlineExceeded {
        /// Effective timeout after narrowing against the caller's context.
        timeout_ms: u64,
    },
    /// A generation stream ended before completion. Replaying may bill twice.
    #[error("stream connection dropped before completion; provider outcome may be unknown")]
    ConnectionDropped,
}

/// Streaming protocol error details.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StreamingError {
    /// Invalid UTF-8 or JSON payload.
    #[error("malformed stream payload: {message}")]
    MalformedPayload {
        /// Redacted detail.
        message: String,
    },
    /// Provider emitted an error SSE event.
    #[error("provider stream error: {message}")]
    ProviderEvent {
        /// Redacted detail.
        message: String,
    },
}

/// OpenAI-compatible error taxonomy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenAiError {
    /// Invalid request.
    InvalidRequest {
        /// Message.
        message: String,
        /// Provider parameter.
        param: Option<String>,
        /// Provider code.
        code: Option<String>,
    },
    /// Authentication failed.
    Authentication {
        /// Message.
        message: String,
    },
    /// Permission denied.
    PermissionDenied {
        /// Message.
        message: String,
    },
    /// Missing resource.
    NotFound {
        /// Message.
        message: String,
        /// Resource.
        resource: Option<String>,
    },
    /// Rate limited.
    RateLimited {
        /// Message.
        message: String,
        /// Retry hint.
        retry_after: Option<Duration>,
    },
    /// Service unavailable.
    ServiceUnavailable {
        /// Message.
        message: String,
        /// Retry hint.
        retry_after: Option<Duration>,
    },
    /// Provider internal error.
    InternalError {
        /// Message.
        message: String,
    },
    /// An effectful request was dispatched, but its outcome cannot be established.
    ///
    /// This error never permits automatic replay. It contains no provider body,
    /// request URL, prompt, completion, or credential material.
    OutcomeUnknown {
        /// Observed HTTP status, when a complete response was received.
        status: Option<u16>,
    },
    /// Transport failure.
    Network(NetworkError),
    /// Streaming failure.
    Streaming(StreamingError),
    /// Non-standard provider response.
    Provider {
        /// Provider name.
        provider: String,
        /// HTTP status.
        status: u16,
        /// Redacted body.
        body: String,
    },
}

impl OpenAiError {
    /// Whether retrying this error can be useful.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. }
                | Self::ServiceUnavailable { .. }
                | Self::InternalError { .. }
                | Self::Network(NetworkError::Http { .. })
        )
    }

    /// Bind a received error to the replay safety of the dispatched operation.
    ///
    /// `status` must be the actual HTTP status, not a status inferred by a
    /// provider error mapper. A generation or embedding POST may already have
    /// incurred cost when a server failure, transport interruption, or malformed
    /// success response arrives. Only an explicit HTTP 429 refusal can retain
    /// a retryable classification for those requests. Ordinary terminal 4xx
    /// rejections retain their useful authentication/validation taxonomy.
    ///
    /// Cancellation and deadlines retain their own terminal taxonomy. Streaming
    /// truncation is independently terminal, including accumulator-only use.
    #[must_use]
    pub fn for_dispatched_request(self, replay_safe: bool, status: Option<u16>) -> Self {
        if replay_safe
            || matches!(
                &self,
                Self::OutcomeUnknown { .. }
                    | Self::Network(
                        NetworkError::Cancelled { .. } | NetworkError::DeadlineExceeded { .. }
                    )
            )
            || status == Some(429)
        {
            return self;
        }
        if status.is_some_and(|status| (400..500).contains(&status) && status != 408)
            && (matches!(
                &self,
                Self::InvalidRequest { .. }
                    | Self::Authentication { .. }
                    | Self::PermissionDenied { .. }
                    | Self::NotFound { .. }
            ) || matches!(&self, Self::Provider { status: mapped, .. } if Some(*mapped) == status))
        {
            return self;
        }
        Self::OutcomeUnknown { status }
    }

    /// Provider retry hint.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after, .. }
            | Self::ServiceUnavailable { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

impl fmt::Display for OpenAiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest {
                message,
                param,
                code,
            } => write!(
                f,
                "invalid request: {}{}{}",
                redact_sensitive_text(message),
                param
                    .as_ref()
                    .map_or_else(String::new, |param| format!(" param={param}")),
                code.as_ref()
                    .map_or_else(String::new, |code| format!(" code={code}"))
            ),
            Self::Authentication { message } => {
                write!(
                    f,
                    "authentication failed: {}",
                    redact_sensitive_text(message)
                )
            }
            Self::PermissionDenied { message } => {
                write!(f, "permission denied: {}", redact_sensitive_text(message))
            }
            Self::NotFound { message, resource } => write!(
                f,
                "not found: {}{}",
                redact_sensitive_text(message),
                resource
                    .as_ref()
                    .map_or_else(String::new, |resource| format!(" resource={resource}"))
            ),
            Self::RateLimited {
                message,
                retry_after,
            } => write!(
                f,
                "rate limited: {}{}",
                redact_sensitive_text(message),
                retry_after
                    .map_or_else(String::new, |duration| format!(" retry_after={duration:?}"))
            ),
            Self::ServiceUnavailable {
                message,
                retry_after,
            } => write!(
                f,
                "service unavailable: {}{}",
                redact_sensitive_text(message),
                retry_after
                    .map_or_else(String::new, |duration| format!(" retry_after={duration:?}"))
            ),
            Self::InternalError { message } => {
                write!(
                    f,
                    "internal provider error: {}",
                    redact_sensitive_text(message)
                )
            }
            Self::OutcomeUnknown { status } => {
                write!(f, "provider outcome is unknown after dispatch")?;
                if let Some(status) = status {
                    write!(f, " (HTTP {status})")?;
                }
                write!(f, "; do not automatically retry")
            }
            Self::Network(error) => write!(f, "network error: {error}"),
            Self::Streaming(error) => write!(f, "streaming error: {error}"),
            Self::Provider {
                provider,
                status,
                body,
            } => write!(
                f,
                "{provider} returned HTTP {status}: {}",
                redact_sensitive_text(body)
            ),
        }
    }
}

impl std::error::Error for OpenAiError {}

/// Truncate a response body at a UTF-8 boundary.
#[must_use]
pub fn truncate_response_body(bytes: &[u8]) -> String {
    const MAX_LEN: usize = 4096;
    let slice = if bytes.len() > MAX_LEN + 4 {
        &bytes[..MAX_LEN + 4]
    } else {
        bytes
    };
    let mut body = String::from_utf8_lossy(slice).to_string();
    if body.len() > MAX_LEN {
        let mut end = MAX_LEN;
        while !body.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        body.truncate(end);
        body.push('…');
    }
    body
}

/// Redact credentials and prompt/completion-shaped payloads from logs/errors.
#[must_use]
pub fn redact_sensitive_text(input: &str) -> String {
    if let Ok(mut value) = serde_json::from_str::<Value>(input) {
        redact_json_value(&mut value);
        return redact_bearer_tokens(&value.to_string());
    }
    redact_bearer_tokens(input)
}

fn redact_json_value(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if is_sensitive_json_key(key) {
                    *child = Value::String("[REDACTED]".to_string());
                } else {
                    redact_json_value(child);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_json_value(item);
            }
        }
        Value::String(text) => {
            *text = redact_bearer_tokens(text);
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn is_sensitive_json_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace('_', "-");
    normalized == "authorization"
        || normalized == "api-key"
        || normalized == "x-api-key"
        || normalized == "prompt"
        || normalized == "completion"
        || normalized == "content"
        || normalized == "reasoning-content"
        || normalized.contains("token")
        || normalized.contains("secret")
        || normalized.contains("credential")
        || normalized.ends_with("-key")
}

fn redact_bearer_tokens(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut index = 0;
    while let Some(relative) = input[index..].to_ascii_lowercase().find("bearer ") {
        let start = index + relative;
        output.push_str(&input[index..start]);
        output.push_str("Bearer [REDACTED]");
        let mut end = start + "bearer ".len();
        while let Some(ch) = input[end..].chars().next() {
            if ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | ')' | ']' | '}') {
                break;
            }
            end += ch.len_utf8();
        }
        index = end;
    }
    output.push_str(&input[index..]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_redacts_json_tokens_and_prompt_text() {
        let err = OpenAiError::Provider {
            provider: "test".to_string(),
            status: 400,
            body: r#"{"error":{"message":"bad","token":"sk-live","prompt":"secret prompt"}}"#
                .to_string(),
        };

        let text = err.to_string();
        assert!(!text.contains("sk-live"));
        assert!(!text.contains("secret prompt"));
        assert!(text.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_bearer_tokens_in_plain_text() {
        let redacted = redact_sensitive_text("Authorization: Bearer sk-test, failed");
        assert_eq!(redacted, "Authorization: Bearer [REDACTED], failed");
    }

    #[test]
    fn redacts_reasoning_content_payloads() {
        let redacted = redact_sensitive_text(
            r#"{"choices":[{"message":{"reasoning_content":"private trace","content":"final"}}]}"#,
        );
        assert!(!redacted.contains("private trace"));
        assert!(!redacted.contains("final"));
        assert!(redacted.contains("[REDACTED]"));
    }

    #[test]
    fn effectful_dispatch_errors_require_an_observed_rate_limit_refusal() {
        for status in [None, Some(200), Some(408), Some(409), Some(500), Some(503)] {
            let error = OpenAiError::RateLimited {
                message: "private provider body".into(),
                retry_after: Some(Duration::ZERO),
            }
            .for_dispatched_request(false, status);
            assert_eq!(error, OpenAiError::OutcomeUnknown { status });
            assert!(!error.is_retryable());
            assert_eq!(error.retry_after(), None);
            assert!(!error.to_string().contains("private provider body"));
        }

        let limited = OpenAiError::RateLimited {
            message: "rate limit refusal".into(),
            retry_after: Some(Duration::from_secs(1)),
        };
        assert_eq!(
            limited.clone().for_dispatched_request(false, Some(429)),
            limited
        );
        let unavailable = OpenAiError::ServiceUnavailable {
            message: "maintenance".into(),
            retry_after: Some(Duration::ZERO),
        };
        assert_eq!(
            unavailable.clone().for_dispatched_request(true, Some(503)),
            unavailable
        );
        let denied = OpenAiError::Authentication {
            message: "unauthorized".into(),
        };
        assert_eq!(
            denied.clone().for_dispatched_request(false, Some(401)),
            denied
        );
    }

    #[test]
    fn a_mapper_cannot_replace_a_terminal_wire_status_with_a_retryable_provider_status() {
        for observed in [400, 404, 409] {
            let error = OpenAiError::Provider {
                provider: "fixture".into(),
                status: 503,
                body: "private provider body".into(),
            }
            .for_dispatched_request(false, Some(observed));
            assert_eq!(
                error,
                OpenAiError::OutcomeUnknown {
                    status: Some(observed)
                }
            );
            assert!(!error.is_retryable());
        }
        let rejected = OpenAiError::Provider {
            provider: "fixture".into(),
            status: 409,
            body: "rejected".into(),
        };
        assert_eq!(
            rejected.clone().for_dispatched_request(false, Some(409)),
            rejected
        );
    }

    #[test]
    fn cancellation_and_incomplete_streams_remain_terminal() {
        for error in [
            OpenAiError::Network(NetworkError::Cancelled {
                message: "cancelled".into(),
            }),
            OpenAiError::Network(NetworkError::DeadlineExceeded { timeout_ms: 10 }),
        ] {
            assert_eq!(error.clone().for_dispatched_request(false, None), error);
            assert!(!error.is_retryable());
        }
        let dropped = OpenAiError::Network(NetworkError::ConnectionDropped);
        assert!(!dropped.is_retryable());
        assert_eq!(dropped.retry_after(), None);
    }

    #[test]
    fn retryable_variants_are_classified() {
        assert!(
            OpenAiError::RateLimited {
                message: "slow".to_string(),
                retry_after: Some(Duration::from_secs(1)),
            }
            .is_retryable()
        );
        assert!(
            !OpenAiError::Authentication {
                message: "bad".to_string(),
            }
            .is_retryable()
        );
    }
}
