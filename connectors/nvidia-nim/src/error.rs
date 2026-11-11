use std::time::Duration;

use fcp_openai_compat::{NetworkError, OpenAiError, StreamingError, redact_sensitive_text};
use fcp_prelude::FcpError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NvidiaNimError {
    #[error(transparent)]
    OpenAi(#[from] OpenAiError),
}

impl NvidiaNimError {
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
            capability: "nvidia_nim".into(),
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
        OpenAiError::ServiceUnavailable {
            message,
            retry_after,
        } => FcpError::External {
            service: "nvidia_nim".into(),
            message: safe_provider_message(message),
            status_code: Some(503),
            retryable: true,
            retry_after: *retry_after,
        },
        OpenAiError::InternalError { message } => FcpError::External {
            service: "nvidia_nim".into(),
            message: safe_provider_message(message),
            status_code: Some(500),
            retryable: true,
            retry_after: None,
        },
        OpenAiError::Network(NetworkError::Cancelled { message }) => {
            FcpError::ConnectorUnavailable {
                code: 5000,
                message: format!("NVIDIA NIM request cancelled: {message}"),
            }
        }
        OpenAiError::Network(NetworkError::DeadlineExceeded { timeout_ms }) => FcpError::External {
            service: "nvidia-nim".into(),
            message: format!(
                "request budget exhausted after {timeout_ms}ms; provider outcome may be unknown"
            ),
            status_code: Some(504),
            retryable: false,
            retry_after: None,
        },
        OpenAiError::Network(NetworkError::ConnectionDropped) => FcpError::External {
            service: "nvidia_nim".into(),
            message: "stream connection dropped before completion".into(),
            status_code: None,
            retryable: true,
            retry_after: None,
        },
        OpenAiError::Network(NetworkError::Http { message }) => FcpError::External {
            service: "nvidia_nim".into(),
            message: safe_provider_message(message),
            status_code: None,
            retryable: true,
            retry_after: None,
        },
        OpenAiError::Streaming(
            StreamingError::MalformedPayload { message }
            | StreamingError::ProviderEvent { message },
        ) => FcpError::External {
            service: "nvidia_nim".into(),
            message: safe_provider_message(message),
            status_code: None,
            retryable: false,
            retry_after: None,
        },
        OpenAiError::Provider {
            status, provider, ..
        } => FcpError::External {
            service: provider.clone(),
            message: format!("NVIDIA NIM provider returned HTTP {status}"),
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
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn invalid_auth_permission_and_not_found_errors_are_redacted() {
        let unauthorized = openai_error_to_fcp(&OpenAiError::Authentication {
            message: "bad Bearer secret-token for private prompt".into(),
        });
        assert!(matches!(unauthorized, FcpError::Unauthorized { .. }));
        if let FcpError::Unauthorized { message, .. } = unauthorized {
            assert!(!message.contains("secret-token"));
            assert!(message.contains("Bearer"));
        }

        let denied = openai_error_to_fcp(&OpenAiError::PermissionDenied {
            message: "denied sk-nim-secret".into(),
        });
        assert!(matches!(denied, FcpError::CapabilityDenied { .. }));

        let missing = openai_error_to_fcp(&OpenAiError::NotFound {
            message: "missing model".into(),
            resource: Some("nvidia/unknown".into()),
        });
        assert!(matches!(missing, FcpError::ResourceNotFound { .. }));
    }

    #[test]
    fn rate_limit_and_service_errors_preserve_retry_semantics() {
        let retry_after = Duration::from_millis(1_500);
        let limited = openai_error_to_fcp(&OpenAiError::RateLimited {
            message: "too many requests".into(),
            retry_after: Some(retry_after),
        });
        assert!(matches!(limited, FcpError::RateLimited { .. }));
        if let FcpError::RateLimited { retry_after_ms, .. } = limited {
            assert_eq!(retry_after_ms, 1_500);
        }

        let unavailable = openai_error_to_fcp(&OpenAiError::ServiceUnavailable {
            message: "provider maintenance".into(),
            retry_after: Some(retry_after),
        });
        assert!(matches!(unavailable, FcpError::External { .. }));
        if let FcpError::External {
            service,
            status_code,
            retryable,
            retry_after: mapped_retry_after,
            ..
        } = unavailable
        {
            assert_eq!(service, "nvidia_nim");
            assert_eq!(status_code, Some(503));
            assert!(retryable);
            assert_eq!(mapped_retry_after, Some(retry_after));
        }
    }

    #[test]
    fn network_and_streaming_errors_map_to_retryable_or_terminal_fcp_errors() {
        let cancelled = openai_error_to_fcp(&OpenAiError::Network(NetworkError::Cancelled {
            message: "cancelled by caller".into(),
        }));
        assert!(matches!(cancelled, FcpError::ConnectorUnavailable { .. }));

        let http = openai_error_to_fcp(&OpenAiError::Network(NetworkError::Http {
            message: "connection failed".into(),
        }));
        assert!(matches!(http, FcpError::External { .. }));
        if let FcpError::External {
            retryable,
            status_code,
            ..
        } = http
        {
            assert!(retryable);
            assert_eq!(status_code, None);
        }

        let malformed =
            openai_error_to_fcp(&OpenAiError::Streaming(StreamingError::MalformedPayload {
                message: "bad sse event".into(),
            }));
        assert!(matches!(malformed, FcpError::External { .. }));
        if let FcpError::External { retryable, .. } = malformed {
            assert!(!retryable);
        }
    }

    #[test]
    fn provider_status_errors_do_not_echo_bodies() {
        let mapped = openai_error_to_fcp(&OpenAiError::Provider {
            provider: "nvidia_nim".into(),
            status: 502,
            body: "Bearer secret-token and private prompt".into(),
        });
        assert!(matches!(mapped, FcpError::External { .. }));
        if let FcpError::External {
            message,
            status_code,
            retryable,
            ..
        } = mapped
        {
            assert_eq!(status_code, Some(502));
            assert!(retryable);
            assert_eq!(message, "NVIDIA NIM provider returned HTTP 502");
            assert!(!message.contains("secret-token"));
        }
    }
}
