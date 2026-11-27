//! OpenAI error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use thiserror::Error;

/// Result type for OpenAI operations.
pub type OpenAIResult<T> = Result<T, OpenAIError>;

/// OpenAI-specific errors.
#[derive(Debug, Error)]
pub enum OpenAIError {
    /// HTTP/network error
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON parsing error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid API key
    #[error("Invalid API key")]
    InvalidApiKey,

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited {
        /// Suggested retry delay in milliseconds
        retry_after_ms: u64,
    },

    /// Server overloaded
    #[error("Server overloaded, retry after {retry_after_ms}ms")]
    Overloaded {
        /// Suggested retry delay in milliseconds
        retry_after_ms: u64,
    },

    /// Context length exceeded
    #[error("Context length exceeded: {message}")]
    ContextLengthExceeded {
        /// Error message
        message: String,
    },

    /// Content filter triggered
    #[error("Content filtered: {message}")]
    ContentFiltered {
        /// Error message
        message: String,
    },

    /// API error
    #[error("API error ({error_type}): {message}")]
    Api {
        /// Error type
        error_type: String,
        /// Error message
        message: String,
        /// HTTP status code
        status_code: Option<u16>,
    },

    /// A dispatched mutation may have completed, so replay is not authorized.
    #[error("OpenAI operation outcome is unknown; automatic replay is disabled")]
    OutcomeUnknown {
        /// Observed HTTP status, when the provider returned one.
        status_code: Option<u16>,
    },

    /// Caller-supplied input rejected before any request was sent
    /// (e.g. an id carrying path-traversal characters or a pagination
    /// cursor that would smuggle additional query parameters).
    #[error("Invalid input: {message}")]
    InvalidInput {
        /// Error message
        message: String,
    },
}

impl OpenAIError {
    /// Preserve uncertainty after dispatching a billed request or mutation.
    ///
    /// A transport failure, malformed success body, or server failure does not
    /// prove that the provider rejected the operation. Builder errors remain
    /// local failures, and an observed rate-limit refusal remains retryable.
    pub(crate) fn after_effectful_dispatch(self, status_code: Option<u16>) -> Self {
        if status_code.is_none()
            && matches!(
                &self,
                Self::Http(error) if error.is_builder()
            )
        {
            return self;
        }
        if status_code.is_none() && matches!(&self, Self::InvalidInput { .. }) {
            return self;
        }
        if status_code == Some(429) {
            return self;
        }
        if status_code.is_some_and(|status| (400..500).contains(&status) && status != 408)
            && (matches!(
                &self,
                Self::InvalidApiKey
                    | Self::ContextLengthExceeded { .. }
                    | Self::ContentFiltered { .. }
            ) || matches!(&self, Self::Api { status_code: mapped, .. } if *mapped == status_code))
        {
            return self;
        }
        Self::OutcomeUnknown { status_code }
    }

    /// A read failure after an accepted generation cannot authorize repeating
    /// the earlier billed submission. Preserve definitive terminal job failures.
    pub(crate) fn after_accepted_generation(self) -> Self {
        match self {
            Self::RateLimited { .. } => Self::OutcomeUnknown {
                status_code: Some(429),
            },
            Self::Overloaded { .. } => Self::OutcomeUnknown {
                status_code: Some(503),
            },
            Self::Http(error) => Self::OutcomeUnknown {
                status_code: error.status().map(|status| status.as_u16()),
            },
            Self::Json(_) => Self::OutcomeUnknown { status_code: None },
            other => other,
        }
    }

    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::RateLimited { .. } | Self::Overloaded { .. })
    }

    /// Get retry-after duration if available.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } | Self::Overloaded { retry_after_ms } => {
                Some(Duration::from_millis(*retry_after_ms))
            }
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        ConnectorErrorMapping::to_fcp_error(self)
    }

    fn fcp_error_impl(&self) -> FcpError {
        match self {
            Self::InvalidApiKey => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid OpenAI API key".into(),
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::ContextLengthExceeded { message } => FcpError::InvalidRequest {
                code: 2002,
                message: message.clone(),
            },
            Self::ContentFiltered { message } => FcpError::InvalidRequest {
                code: 2003,
                message: message.clone(),
            },
            Self::Api {
                message,
                status_code,
                ..
            } => FcpError::External {
                service: "openai".into(),
                message: message.clone(),
                status_code: *status_code,
                retryable: false,
                retry_after: None,
            },
            Self::OutcomeUnknown { status_code } => FcpError::External {
                service: "openai".into(),
                message: self.to_string(),
                status_code: *status_code,
                retryable: false,
                retry_after: None,
            },
            Self::Http(e) => FcpError::External {
                service: "openai".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                // Mutation paths contextualize dispatched failures before
                // mapping. Standalone transport errors here can be safe reads.
                retryable: e.is_connect(),
                retry_after: None,
            },
            Self::Json(e) => FcpError::MalformedFrame {
                code: 2004,
                message: format!("JSON parsing error: {e}"),
            },
            Self::InvalidInput { message } => FcpError::InvalidRequest {
                code: 2005,
                message: message.clone(),
            },
            Self::Overloaded { retry_after_ms } => FcpError::External {
                service: "openai".into(),
                message: "Server is overloaded".into(),
                status_code: Some(503),
                retryable: true,
                retry_after: Some(Duration::from_millis(*retry_after_ms)),
            },
        }
    }
}

impl ConnectorErrorMapping for OpenAIError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                error_type: "deadline_timeout".into(),
                message: format!("request context deadline exceeded after {timeout_ms}ms"),
                status_code: Some(408),
            },
            AsyncError::Cancelled => Self::Api {
                error_type: "request_cancelled".into(),
                message: "request context cancelled".into(),
                status_code: None,
            },
            other => Self::Api {
                error_type: "runtime_context".into(),
                message: other.to_string(),
                status_code: None,
            },
        }
    }

    fn to_fcp_error(&self) -> FcpError {
        self.fcp_error_impl()
    }

    fn is_retryable(&self) -> bool {
        // Delegate to inherent method
        matches!(self, Self::RateLimited { .. } | Self::Overloaded { .. })
    }

    fn retry_after(&self) -> Option<Duration> {
        // Delegate to inherent method
        match self {
            Self::RateLimited { retry_after_ms } | Self::Overloaded { retry_after_ms } => {
                Some(Duration::from_millis(*retry_after_ms))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatched_mutations_keep_uncertain_failures_terminal() {
        for (error, status_code) in [
            (
                OpenAIError::Overloaded {
                    retry_after_ms: 60_000,
                },
                Some(503),
            ),
            (
                OpenAIError::Api {
                    error_type: "server_error".into(),
                    message: "provider details".into(),
                    status_code: Some(502),
                },
                Some(502),
            ),
            (
                OpenAIError::Api {
                    error_type: "request_timeout".into(),
                    message: "provider details".into(),
                    status_code: Some(408),
                },
                Some(408),
            ),
            (
                OpenAIError::ContextLengthExceeded {
                    message: "provider details".into(),
                },
                Some(500),
            ),
            (
                OpenAIError::ContentFiltered {
                    message: "provider details".into(),
                },
                Some(500),
            ),
            (
                OpenAIError::Json(serde_json::from_str::<serde_json::Value>("{").unwrap_err()),
                Some(200),
            ),
        ] {
            let error = error.after_effectful_dispatch(status_code);
            assert!(
                matches!(error, OpenAIError::OutcomeUnknown { status_code: observed } if observed == status_code)
            );
            assert!(!error.is_retryable());
            assert!(!ConnectorErrorMapping::is_retryable(&error));
            assert_eq!(error.retry_after(), None);
            assert!(matches!(
                error.to_fcp_error(),
                FcpError::External {
                    retryable: false,
                    retry_after: None,
                    ..
                }
            ));
            assert!(!error.to_string().contains("provider details"));
        }
    }

    #[test]
    fn dispatch_classification_preserves_refusals_and_local_failures() {
        assert!(matches!(
            OpenAIError::RateLimited { retry_after_ms: 7 }.after_effectful_dispatch(Some(429)),
            OpenAIError::RateLimited { retry_after_ms: 7 }
        ));
        assert!(matches!(
            OpenAIError::InvalidApiKey.after_effectful_dispatch(Some(401)),
            OpenAIError::InvalidApiKey
        ));
        assert!(matches!(
            OpenAIError::InvalidInput {
                message: "invalid".into()
            }
            .after_effectful_dispatch(None),
            OpenAIError::InvalidInput { .. }
        ));
        assert!(matches!(
            OpenAIError::Api {
                error_type: "invalid_request_error".into(),
                message: "invalid".into(),
                status_code: Some(400),
            }
            .after_effectful_dispatch(Some(400)),
            OpenAIError::Api {
                status_code: Some(400),
                ..
            }
        ));
        assert!(OpenAIError::Overloaded { retry_after_ms: 7 }.is_retryable());
    }

    #[test]
    fn accepted_generation_does_not_inherit_read_retry_permission() {
        for error in [
            OpenAIError::RateLimited { retry_after_ms: 5 },
            OpenAIError::Overloaded { retry_after_ms: 5 },
        ] {
            let error = error.after_accepted_generation();
            assert!(matches!(error, OpenAIError::OutcomeUnknown { .. }));
            assert!(!error.is_retryable());
            assert!(matches!(
                error.to_fcp_error(),
                FcpError::External {
                    retryable: false,
                    retry_after: None,
                    ..
                }
            ));
        }
        let failed = OpenAIError::Api {
            error_type: "video_failed".into(),
            message: "provider job failed".into(),
            status_code: None,
        }
        .after_accepted_generation();
        assert!(
            matches!(failed, OpenAIError::Api { ref error_type, .. } if error_type == "video_failed")
        );
        assert!(!failed.is_retryable());
    }

    // ---- is_retryable ----

    #[test]
    fn rate_limited_is_retryable() {
        let err = OpenAIError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn overloaded_is_retryable() {
        let err = OpenAIError::Overloaded {
            retry_after_ms: 60_000,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn invalid_api_key_not_retryable() {
        let err = OpenAIError::InvalidApiKey;
        assert!(!err.is_retryable());
    }

    #[test]
    fn context_length_exceeded_not_retryable() {
        let err = OpenAIError::ContextLengthExceeded {
            message: "too long".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn content_filtered_not_retryable() {
        let err = OpenAIError::ContentFiltered {
            message: "blocked".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_error_not_retryable() {
        let err = OpenAIError::Api {
            error_type: "server_error".into(),
            message: "internal".into(),
            status_code: Some(500),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn json_error_not_retryable() {
        let inner = serde_json::from_str::<serde_json::Value>("bad json").unwrap_err();
        let err = OpenAIError::Json(inner);
        assert!(!err.is_retryable());
    }

    // ---- retry_after ----

    #[test]
    fn rate_limited_has_retry_after() {
        let err = OpenAIError::RateLimited {
            retry_after_ms: 5000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn overloaded_has_retry_after() {
        let err = OpenAIError::Overloaded {
            retry_after_ms: 60_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(60)));
    }

    #[test]
    fn non_retryable_errors_have_no_retry_after() {
        assert_eq!(OpenAIError::InvalidApiKey.retry_after(), None);

        let err = OpenAIError::Api {
            error_type: "x".into(),
            message: "y".into(),
            status_code: Some(500),
        };
        assert_eq!(err.retry_after(), None);

        let err = OpenAIError::ContextLengthExceeded {
            message: "too long".into(),
        };
        assert_eq!(err.retry_after(), None);

        let err = OpenAIError::ContentFiltered {
            message: "blocked".into(),
        };
        assert_eq!(err.retry_after(), None);
    }

    // ---- to_fcp_error / fcp_error_impl ----

    #[test]
    fn invalid_api_key_maps_to_unauthorized() {
        let err = OpenAIError::InvalidApiKey;
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("OpenAI"));
            }
            other => panic!("Expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_maps_to_rate_limited() {
        let err = OpenAIError::RateLimited {
            retry_after_ms: 30_000,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 30_000);
                assert!(violation.is_none());
            }
            other => panic!("Expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn context_length_exceeded_maps_to_invalid_request() {
        let err = OpenAIError::ContextLengthExceeded {
            message: "exceeded maximum context length".into(),
        };
        match err.to_fcp_error() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 2002);
                assert!(message.contains("context length"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn content_filtered_maps_to_invalid_request() {
        let err = OpenAIError::ContentFiltered {
            message: "content policy violation".into(),
        };
        match err.to_fcp_error() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 2003);
                assert!(message.contains("content policy"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn api_error_maps_to_external() {
        let err = OpenAIError::Api {
            error_type: "server_error".into(),
            message: "internal server error".into(),
            status_code: Some(500),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "openai");
                assert!(message.contains("internal server error"));
                assert_eq!(status_code, Some(500));
                assert!(!retryable);
            }
            other => panic!("Expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_without_status_code() {
        let err = OpenAIError::Api {
            error_type: "unknown".into(),
            message: "something went wrong".into(),
            status_code: None,
        };
        match err.to_fcp_error() {
            FcpError::External { status_code, .. } => {
                assert!(status_code.is_none());
            }
            other => panic!("Expected External, got {other:?}"),
        }
    }

    #[test]
    fn json_error_maps_to_malformed_frame() {
        let inner = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = OpenAIError::Json(inner);
        match err.to_fcp_error() {
            FcpError::MalformedFrame { code, message } => {
                assert_eq!(code, 2004);
                assert!(message.contains("JSON parsing error"));
            }
            other => panic!("Expected MalformedFrame, got {other:?}"),
        }
    }

    #[test]
    fn overloaded_maps_to_external_retryable() {
        let err = OpenAIError::Overloaded {
            retry_after_ms: 60_000,
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                retry_after,
                ..
            } => {
                assert_eq!(service, "openai");
                assert_eq!(status_code, Some(503));
                assert!(retryable);
                assert_eq!(retry_after, Some(Duration::from_secs(60)));
            }
            other => panic!("Expected External, got {other:?}"),
        }
    }

    // ---- ConnectorErrorMapping::from_async_error ----

    #[test]
    fn from_async_error_timeout() {
        let err = OpenAIError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        match &err {
            OpenAIError::Api {
                error_type,
                message,
                status_code,
            } => {
                assert_eq!(error_type, "deadline_timeout");
                assert!(message.contains("5000ms"));
                assert_eq!(*status_code, Some(408));
            }
            other => panic!("Expected Api, got {other:?}"),
        }
    }

    #[test]
    fn from_async_error_cancelled() {
        let err = OpenAIError::from_async_error(AsyncError::Cancelled);
        match &err {
            OpenAIError::Api {
                error_type,
                status_code,
                ..
            } => {
                assert_eq!(error_type, "request_cancelled");
                assert!(status_code.is_none());
            }
            other => panic!("Expected Api, got {other:?}"),
        }
    }

    #[test]
    fn from_async_error_other() {
        let err = OpenAIError::from_async_error(AsyncError::Runtime {
            message: "something broke".into(),
        });
        match &err {
            OpenAIError::Api {
                error_type,
                status_code,
                ..
            } => {
                assert_eq!(error_type, "runtime_context");
                assert!(status_code.is_none());
            }
            other => panic!("Expected Api, got {other:?}"),
        }
    }

    // ---- ConnectorErrorMapping trait consistency ----

    #[test]
    fn trait_is_retryable_matches_inherent() {
        let retryable = OpenAIError::RateLimited {
            retry_after_ms: 1000,
        };
        assert_eq!(
            retryable.is_retryable(),
            ConnectorErrorMapping::is_retryable(&retryable)
        );

        let not_retryable = OpenAIError::InvalidApiKey;
        assert_eq!(
            not_retryable.is_retryable(),
            ConnectorErrorMapping::is_retryable(&not_retryable)
        );
    }

    #[test]
    fn trait_retry_after_matches_inherent() {
        let err = OpenAIError::Overloaded {
            retry_after_ms: 10_000,
        };
        assert_eq!(err.retry_after(), ConnectorErrorMapping::retry_after(&err));
    }

    // ---- Display ----

    #[test]
    fn error_display_messages() {
        assert_eq!(OpenAIError::InvalidApiKey.to_string(), "Invalid API key");

        let rate_limited = OpenAIError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert!(rate_limited.to_string().contains("30000ms"));

        let overloaded = OpenAIError::Overloaded {
            retry_after_ms: 60_000,
        };
        assert!(overloaded.to_string().contains("60000ms"));

        let ctx = OpenAIError::ContextLengthExceeded {
            message: "too long".into(),
        };
        assert!(ctx.to_string().contains("too long"));

        let filtered = OpenAIError::ContentFiltered {
            message: "policy".into(),
        };
        assert!(filtered.to_string().contains("policy"));

        let api = OpenAIError::Api {
            error_type: "server_error".into(),
            message: "oops".into(),
            status_code: Some(500),
        };
        let display = api.to_string();
        assert!(display.contains("server_error"));
        assert!(display.contains("oops"));
    }
}
