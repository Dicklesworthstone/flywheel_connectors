//! Gmail-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use thiserror::Error;

/// Gmail-specific errors.
#[derive(Error, Debug)]
pub enum GmailError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Gmail API returned an error
    #[error("Gmail API error: {message} (code: {code})")]
    Api { code: u32, message: String },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    /// Invalid or expired token
    #[error("Invalid or expired Gmail credentials")]
    Unauthorized,

    /// Message not found
    #[error("Message not found: {message_id}")]
    MessageNotFound { message_id: String },

    /// Thread not found
    #[error("Thread not found: {thread_id}")]
    ThreadNotFound { thread_id: String },

    /// Label not found
    #[error("Label not found: {label}")]
    LabelNotFound { label: String },
}

impl GmailError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { code, .. } => {
                matches!(code, 429 | 500 | 502 | 503)
            }
            _ => false,
        }
    }

    /// Whether replaying the request that produced this error cannot duplicate
    /// a side effect (br-kxd3e).
    ///
    /// Deliberately NOT the same question as [`Self::is_retryable`]. Gmail
    /// refuses a rate-limited request WITHOUT sending anything, so replaying
    /// it is safe; a 5xx means Gmail received the request and may already have
    /// delivered the mail. Collapsing the two would disable rate-limit backoff
    /// on every send.
    #[must_use]
    pub fn replay_is_safe(&self) -> bool {
        match self {
            Self::RateLimited { .. } => true,
            Self::Api { code, .. } => *code == 429,
            // Only a connect-phase failure proves the request never left us.
            Self::Http(e) => !fcp_sdk::migration::transport_error_reached_service(e),
            _ => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_secs } => Some(Duration::from_secs(*retry_after_secs)),
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "gmail".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api { code, message } => {
                if *code == 401 {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid or insufficient Gmail credentials".into(),
                    }
                } else if *code == 429 {
                    FcpError::RateLimited {
                        retry_after_ms: 60_000,
                        violation: None,
                    }
                } else if *code == 404 {
                    FcpError::ResourceNotFound {
                        resource: message.clone(),
                    }
                } else {
                    FcpError::External {
                        service: "gmail".into(),
                        message: message.clone(),
                        status_code: Some((*code).try_into().unwrap_or(500)),
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::RateLimited { retry_after_secs } => FcpError::RateLimited {
                retry_after_ms: retry_after_secs * 1000,
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid or expired Gmail credentials".into(),
            },
            Self::MessageNotFound { message_id } => FcpError::ResourceNotFound {
                resource: format!("message:{message_id}"),
            },
            Self::ThreadNotFound { thread_id } => FcpError::ResourceNotFound {
                resource: format!("thread:{thread_id}"),
            },
            Self::LabelNotFound { label } => FcpError::ResourceNotFound {
                resource: format!("label:{label}"),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for Gmail operations.
pub type GmailResult<T> = Result<T, GmailError>;

impl ConnectorErrorMapping for GmailError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                code: 408,
                message: format!("deadline exceeded after {timeout_ms}ms"),
            },
            AsyncError::Cancelled => Self::Api {
                code: 0,
                message: "request cancelled".into(),
            },
            other => Self::Api {
                code: 0,
                message: other.to_string(),
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

    // ---- is_retryable ----

    #[test]
    fn rate_limited_is_retryable() {
        let err = GmailError::RateLimited {
            retry_after_secs: 30,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_429_is_retryable() {
        let err = GmailError::Api {
            code: 429,
            message: "throttled".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_500_is_retryable() {
        let err = GmailError::Api {
            code: 500,
            message: "internal error".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_502_is_retryable() {
        let err = GmailError::Api {
            code: 502,
            message: "bad gateway".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_503_is_retryable() {
        let err = GmailError::Api {
            code: 503,
            message: "service unavailable".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_400_not_retryable() {
        let err = GmailError::Api {
            code: 400,
            message: "bad request".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_401_not_retryable() {
        let err = GmailError::Api {
            code: 401,
            message: "unauthorized".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_404_not_retryable() {
        let err = GmailError::Api {
            code: 404,
            message: "not found".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn json_error_not_retryable() {
        let inner = serde_json::from_str::<serde_json::Value>("bad json").unwrap_err();
        let err = GmailError::Json(inner);
        assert!(!err.is_retryable());
    }

    #[test]
    fn unauthorized_not_retryable() {
        let err = GmailError::Unauthorized;
        assert!(!err.is_retryable());
    }

    #[test]
    fn message_not_found_not_retryable() {
        let err = GmailError::MessageNotFound {
            message_id: "msg-1".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn thread_not_found_not_retryable() {
        let err = GmailError::ThreadNotFound {
            thread_id: "thread-1".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn label_not_found_not_retryable() {
        let err = GmailError::LabelNotFound {
            label: "IMPORTANT".into(),
        };
        assert!(!err.is_retryable());
    }

    // ---- retry_after ----

    #[test]
    fn rate_limited_has_retry_after() {
        let err = GmailError::RateLimited {
            retry_after_secs: 5,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn non_rate_limit_errors_have_no_retry_after() {
        let err = GmailError::Unauthorized;
        assert_eq!(err.retry_after(), None);

        let err = GmailError::Api {
            code: 500,
            message: "error".into(),
        };
        assert_eq!(err.retry_after(), None);

        let err = GmailError::MessageNotFound {
            message_id: "m".into(),
        };
        assert_eq!(err.retry_after(), None);
    }

    // ---- to_fcp_error ----

    #[test]
    fn api_401_maps_to_unauthorized() {
        let err = GmailError::Api {
            code: 401,
            message: "bad credentials".into(),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("Gmail credentials"));
            }
            other => panic!("Expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn api_429_maps_to_rate_limited() {
        let err = GmailError::Api {
            code: 429,
            message: "throttled".into(),
        };
        match err.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, 60_000);
            }
            other => panic!("Expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn api_404_maps_to_resource_not_found() {
        let err = GmailError::Api {
            code: 404,
            message: "message not found".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.contains("message not found"));
            }
            other => panic!("Expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn api_500_maps_to_external() {
        let err = GmailError::Api {
            code: 500,
            message: "internal error".into(),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "gmail");
                assert!(retryable);
            }
            other => panic!("Expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_403_maps_to_external() {
        let err = GmailError::Api {
            code: 403,
            message: "forbidden".into(),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                retryable,
                status_code,
                ..
            } => {
                assert_eq!(service, "gmail");
                assert!(!retryable);
                assert_eq!(status_code, Some(403));
            }
            other => panic!("Expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_maps_to_rate_limited() {
        let err = GmailError::RateLimited {
            retry_after_secs: 30,
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
    fn unauthorized_maps_to_unauthorized() {
        let err = GmailError::Unauthorized;
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("expired"));
            }
            other => panic!("Expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn message_not_found_maps_to_resource_not_found() {
        let err = GmailError::MessageNotFound {
            message_id: "msg-123".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.contains("message:msg-123"));
            }
            other => panic!("Expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn thread_not_found_maps_to_resource_not_found() {
        let err = GmailError::ThreadNotFound {
            thread_id: "thread-456".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.contains("thread:thread-456"));
            }
            other => panic!("Expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn label_not_found_maps_to_resource_not_found() {
        let err = GmailError::LabelNotFound {
            label: "IMPORTANT".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.contains("label:IMPORTANT"));
            }
            other => panic!("Expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn json_error_maps_to_internal() {
        let inner = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = GmailError::Json(inner);
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.contains("JSON error"));
            }
            other => panic!("Expected Internal, got {other:?}"),
        }
    }

    // ---- Display ----

    #[test]
    fn error_display_messages() {
        assert_eq!(
            GmailError::Unauthorized.to_string(),
            "Invalid or expired Gmail credentials"
        );
        assert!(
            GmailError::RateLimited {
                retry_after_secs: 10
            }
            .to_string()
            .contains("10s")
        );
        assert!(
            GmailError::Api {
                code: 500,
                message: "oops".into()
            }
            .to_string()
            .contains("oops")
        );
        assert!(
            GmailError::MessageNotFound {
                message_id: "m1".into()
            }
            .to_string()
            .contains("m1")
        );
        assert!(
            GmailError::ThreadNotFound {
                thread_id: "t1".into()
            }
            .to_string()
            .contains("t1")
        );
        assert!(
            GmailError::LabelNotFound {
                label: "INBOX".into()
            }
            .to_string()
            .contains("INBOX")
        );
    }

    // ── Debug format ────────────────────────────────────────────────

    #[test]
    fn debug_all_variants() {
        let variants: Vec<GmailError> = vec![
            GmailError::Api {
                code: 418,
                message: "teapot".into(),
            },
            GmailError::RateLimited {
                retry_after_secs: 60,
            },
            GmailError::Unauthorized,
            GmailError::MessageNotFound {
                message_id: "m-dbg".into(),
            },
            GmailError::ThreadNotFound {
                thread_id: "t-dbg".into(),
            },
            GmailError::LabelNotFound {
                label: "L-dbg".into(),
            },
        ];
        for v in &variants {
            let dbg = format!("{v:?}");
            assert!(!dbg.is_empty());
        }
    }

    #[test]
    fn api_error_debug_contains_code() {
        let err = GmailError::Api {
            code: 503,
            message: "service unavailable".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("503"));
        assert!(dbg.contains("service unavailable"));
    }

    // ── Additional retryable edge cases ─────────────────────────────

    #[test]
    fn api_403_not_retryable() {
        let err = GmailError::Api {
            code: 403,
            message: "forbidden".into(),
        };
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn rate_limited_zero_seconds() {
        let err = GmailError::RateLimited {
            retry_after_secs: 0,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(0)));
        match err.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 0),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    // ── Extended error mapping tests ─────────────────────────────

    #[test]
    fn rate_limited_large_value() {
        let err = GmailError::RateLimited {
            retry_after_secs: 3600,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
        match err.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 3_600_000),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn api_502_retryable_check() {
        assert!(
            GmailError::Api {
                code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_200_not_retryable() {
        assert!(
            !GmailError::Api {
                code: 200,
                message: "ok".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_403_maps_to_external_with_correct_status() {
        match (GmailError::Api {
            code: 403,
            message: "insufficient scope".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "gmail");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_500_fcp_error_service_is_gmail() {
        match (GmailError::Api {
            code: 500,
            message: "err".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { service, .. } => assert_eq!(service, "gmail"),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn message_not_found_fcp_resource_contains_prefix() {
        match (GmailError::MessageNotFound {
            message_id: "abc".into(),
        })
        .to_fcp_error()
        {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.starts_with("message:"));
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn thread_not_found_fcp_resource_contains_prefix() {
        match (GmailError::ThreadNotFound {
            thread_id: "xyz".into(),
        })
        .to_fcp_error()
        {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.starts_with("thread:"));
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn label_not_found_fcp_resource_contains_prefix() {
        match (GmailError::LabelNotFound {
            label: "STARRED".into(),
        })
        .to_fcp_error()
        {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.starts_with("label:"));
                assert!(resource.contains("STARRED"));
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn json_error_display_starts_with_prefix() {
        let inner = serde_json::from_str::<serde_json::Value>("{bad").unwrap_err();
        let err = GmailError::Json(inner);
        assert!(err.to_string().starts_with("JSON error:"));
    }

    #[test]
    fn json_error_not_retryable_no_retry_after() {
        let inner = serde_json::from_str::<serde_json::Value>("{bad").unwrap_err();
        let err = GmailError::Json(inner);
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }
}
