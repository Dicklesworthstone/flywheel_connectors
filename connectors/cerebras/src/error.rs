use std::time::Duration;

use fcp_openai_compat::{NetworkError, OpenAiError, StreamingError, redact_sensitive_text};
use fcp_prelude::FcpError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CerebrasError {
    #[error(transparent)]
    OpenAi(#[from] OpenAiError),
}

impl CerebrasError {
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::OpenAi(error) => openai_error_to_fcp(error),
        }
    }
}

pub fn openai_error_to_fcp(error: &OpenAiError) -> FcpError {
    match error {
        OpenAiError::InvalidRequest { message, .. } => FcpError::InvalidRequest {
            code: 1003,
            message: safe_provider_message(message),
        },
        OpenAiError::Authentication { message } => FcpError::Unauthorized {
            code: 2001,
            message: safe_provider_message(message),
        },
        OpenAiError::PermissionDenied { message } => FcpError::CapabilityDenied {
            capability: "cerebras".into(),
            reason: safe_provider_message(message),
        },
        OpenAiError::NotFound { message, resource } => FcpError::ResourceNotFound {
            resource: resource
                .as_deref()
                .map_or_else(|| safe_provider_message(message), safe_provider_message),
        },
        OpenAiError::RateLimited { retry_after, .. } => FcpError::RateLimited {
            retry_after_ms: duration_millis(*retry_after),
            violation: None,
        },
        OpenAiError::OutcomeUnknown { status } => FcpError::External {
            service: "cerebras".into(),
            message: error.to_string(),
            status_code: *status,
            retryable: false,
            retry_after: None,
        },
        OpenAiError::ServiceUnavailable {
            message,
            retry_after,
        } => FcpError::External {
            service: "cerebras".into(),
            message: safe_provider_message(message),
            status_code: Some(503),
            retryable: true,
            retry_after: *retry_after,
        },
        OpenAiError::InternalError { message } => FcpError::External {
            service: "cerebras".into(),
            message: safe_provider_message(message),
            status_code: Some(500),
            retryable: true,
            retry_after: None,
        },
        OpenAiError::Network(NetworkError::Cancelled { .. }) => FcpError::External {
            service: "cerebras".into(),
            message: "Cerebras request cancelled; provider outcome may be unknown".into(),
            status_code: None,
            retryable: false,
            retry_after: None,
        },
        OpenAiError::Network(NetworkError::DeadlineExceeded { timeout_ms }) => FcpError::External {
            service: "cerebras".into(),
            message: format!(
                "request budget exhausted after {timeout_ms}ms; provider outcome may be unknown"
            ),
            status_code: Some(504),
            retryable: false,
            retry_after: None,
        },
        OpenAiError::Network(NetworkError::ConnectionDropped) => FcpError::External {
            service: "cerebras".into(),
            message: "stream incomplete; provider outcome may be unknown".into(),
            status_code: None,
            retryable: false,
            retry_after: None,
        },
        OpenAiError::Network(NetworkError::Http { message }) => FcpError::External {
            service: "cerebras".into(),
            message: safe_provider_message(message),
            status_code: None,
            retryable: true,
            retry_after: None,
        },
        OpenAiError::Streaming(
            StreamingError::MalformedPayload { message }
            | StreamingError::ProviderEvent { message },
        ) => FcpError::External {
            service: "cerebras".into(),
            message: safe_provider_message(message),
            status_code: None,
            retryable: false,
            retry_after: None,
        },
        OpenAiError::Provider {
            status, provider, ..
        } => FcpError::External {
            service: provider.clone(),
            message: format!("Cerebras provider returned HTTP {status}"),
            status_code: Some(*status),
            retryable: *status >= 500,
            retry_after: None,
        },
    }
}

fn safe_provider_message(message: &str) -> String {
    redact_sensitive_text(message)
}

fn duration_millis(duration: Option<Duration>) -> u64 {
    duration.map_or(0, |duration| {
        u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_request_is_not_retryable_and_does_not_expose_cancellation_reason() {
        let error = openai_error_to_fcp(&OpenAiError::Network(NetworkError::Cancelled {
            message: "Bearer private-test-token; sensitive prompt content".into(),
        }));

        assert!(!error.is_retryable());
        assert!(matches!(
            &error,
            FcpError::External {
                service,
                status_code: None,
                retryable: false,
                retry_after: None,
                ..
            } if service == "cerebras"
        ));
        let message = error.to_string();
        assert!(message.contains("provider outcome may be unknown"));
        assert!(!message.contains("private-test-token"));
        assert!(!message.contains("sensitive prompt"));
    }
}

#[cfg(test)]
#[test]
fn interrupted_provider_work_never_authorizes_automatic_replay() {
    for error in [
        OpenAiError::OutcomeUnknown { status: None },
        OpenAiError::OutcomeUnknown { status: Some(503) },
        OpenAiError::Network(NetworkError::ConnectionDropped),
        OpenAiError::Network(NetworkError::DeadlineExceeded { timeout_ms: 10 }),
        OpenAiError::Network(NetworkError::Cancelled {
            message: "private cancellation detail".into(),
        }),
    ] {
        let mapped = openai_error_to_fcp(&error);
        assert!(matches!(
            &mapped,
            FcpError::External {
                retryable: false,
                retry_after: None,
                ..
            }
        ));
        if let OpenAiError::OutcomeUnknown { status } = error {
            assert!(
                matches!(&mapped, FcpError::External { status_code, .. } if *status_code == status)
            );
        }
        assert!(!mapped.to_string().contains("private cancellation detail"));
    }
}
