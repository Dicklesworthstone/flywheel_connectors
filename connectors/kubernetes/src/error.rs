//! Kubernetes-specific error types.

use std::time::Duration;

use fcp_prelude::FcpError;
use thiserror::Error;

/// Result alias for Kubernetes operations.
pub type KubernetesResult<T> = Result<T, KubernetesError>;

/// Kubernetes-specific errors.
#[derive(Error, Debug)]
pub enum KubernetesError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Kubernetes API returned an error
    #[error("Kubernetes API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// Rate limited (429)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Authentication failed (401)
    #[error("Authentication failed: invalid or expired token")]
    Unauthorized,

    /// Forbidden (403)
    #[error("Forbidden: insufficient permissions")]
    Forbidden,

    /// Resource not found (404)
    #[error("Not found: {resource}")]
    NotFound { resource: String },

    /// Invalid input (path traversal, empty segment, etc.)
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Connector policy denied the requested action.
    #[error("Policy denied: {0}")]
    PolicyDenied(String),

    /// Exec may have started, but no complete, trustworthy result is available.
    /// Only fixed diagnostic text and byte counts are retained, never command
    /// arguments, bearer headers, provider status messages or partial output.
    #[error(
        "Kubernetes exec outcome unknown: {reason}; captured {stdout_bytes} stdout bytes and {stderr_bytes} stderr bytes; command may have run; do not replay automatically"
    )]
    ExecOutcomeUnknown {
        reason: &'static str,
        stdout_bytes: usize,
        stderr_bytes: usize,
    },
}

impl KubernetesError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, 500..=599 | 429),
            Self::InvalidInput(_) | Self::PolicyDenied(_) => false,
            _ => false,
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
            Self::Http(e) => FcpError::External {
                service: "kubernetes".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api {
                status_code,
                message,
            } => FcpError::External {
                service: "kubernetes".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: None,
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Unauthorized => FcpError::External {
                service: "kubernetes".into(),
                message: "Authentication failed".into(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden => FcpError::External {
                service: "kubernetes".into(),
                message: "Insufficient permissions".into(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::NotFound { resource } => FcpError::External {
                service: "kubernetes".into(),
                message: format!("Not found: {resource}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
            Self::InvalidInput(msg) => FcpError::InvalidRequest {
                code: 1005,
                message: format!("Invalid input: {msg}"),
            },
            Self::PolicyDenied(reason) => FcpError::CapabilityDenied {
                capability: "kubernetes.policy".into(),
                reason: reason.clone(),
            },
            Self::ExecOutcomeUnknown { .. } => FcpError::External {
                service: "kubernetes".into(),
                message: self.to_string(),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
        }
    }
}

impl fcp_sdk::ConnectorErrorMapping for KubernetesError {
    fn from_async_error(error: fcp_async_core::AsyncError) -> Self {
        use fcp_async_core::AsyncError;
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                status_code: 408,
                message: format!("deadline exceeded after {timeout_ms}ms"),
            },
            AsyncError::Cancelled => Self::Api {
                status_code: 0,
                message: "request cancelled".into(),
            },
            other => Self::Api {
                status_code: 0,
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

    #[test]
    fn exec_unknown_outcome_is_terminal_and_preserves_only_safe_counts() {
        let error = KubernetesError::ExecOutcomeUnknown {
            reason: "exec stream was interrupted before terminal status",
            stdout_bytes: 17,
            stderr_bytes: 9,
        };
        assert!(!error.is_retryable());
        assert!(error.retry_after().is_none());
        let FcpError::External { service, message, status_code, retryable, retry_after } = error.to_fcp_error() else {
            panic!("exec uncertainty must remain an external provider failure");
        };
        assert_eq!(service, "kubernetes");
        assert!(message.contains("17 stdout bytes and 9 stderr bytes"));
        assert!(message.contains("do not replay automatically"));
        assert!(!retryable);
        assert!(status_code.is_none());
        assert!(retry_after.is_none());
    }

    #[test]
    fn rate_limited_is_retryable() {
        assert!(
            KubernetesError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            KubernetesError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            KubernetesError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_502_is_retryable() {
        assert!(
            KubernetesError::Api {
                status_code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            KubernetesError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!KubernetesError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!KubernetesError::Forbidden.is_retryable());
    }

    #[test]
    fn not_found_not_retryable() {
        assert!(
            !KubernetesError::NotFound {
                resource: "pod".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !KubernetesError::Api {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_422_not_retryable() {
        assert!(
            !KubernetesError::Api {
                status_code: 422,
                message: "unprocessable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = KubernetesError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(KubernetesError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_forbidden() {
        assert_eq!(KubernetesError::Forbidden.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_api_error() {
        assert_eq!(
            KubernetesError::Api {
                status_code: 500,
                message: "err".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_none_for_not_found() {
        assert_eq!(
            KubernetesError::NotFound {
                resource: "x".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_none_for_json_error() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        assert_eq!(KubernetesError::Json(bad.unwrap_err()).retry_after(), None);
    }

    #[test]
    fn unauthorized_to_fcp_error() {
        match KubernetesError::Unauthorized.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "kubernetes");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match KubernetesError::Forbidden.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "kubernetes");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error() {
        match (KubernetesError::NotFound {
            resource: "pod/nginx".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                status_code,
                message,
                retryable,
                ..
            } => {
                assert_eq!(status_code, Some(404));
                assert!(message.contains("pod/nginx"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (KubernetesError::RateLimited {
            retry_after_ms: 60_000,
        })
        .to_fcp_error()
        {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 60_000);
                assert!(violation.is_none());
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn api_error_to_fcp_error() {
        match (KubernetesError::Api {
            status_code: 503,
            message: "unavailable".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                service,
                status_code,
                retryable,
                message,
                ..
            } => {
                assert_eq!(service, "kubernetes");
                assert_eq!(status_code, Some(503));
                assert!(retryable);
                assert_eq!(message, "unavailable");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn json_error_to_fcp_internal() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        match KubernetesError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn api_error_non_retryable_to_fcp_error() {
        match (KubernetesError::Api {
            status_code: 400,
            message: "bad".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(status_code, Some(400));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn error_display_unauthorized() {
        assert_eq!(
            KubernetesError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired token"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            KubernetesError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_not_found() {
        assert_eq!(
            KubernetesError::NotFound {
                resource: "pod".into()
            }
            .to_string(),
            "Not found: pod"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            KubernetesError::RateLimited {
                retry_after_ms: 2000
            }
            .to_string(),
            "Rate limited, retry after 2000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            KubernetesError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "Kubernetes API error (500): Internal"
        );
    }

    #[test]
    fn error_display_http() {
        let err = reqwest::Client::new().get("://bad").build().unwrap_err();
        let k8s_err = KubernetesError::Http(err);
        let display = k8s_err.to_string();
        assert!(display.starts_with("HTTP error:"));
    }

    #[test]
    fn error_display_json() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        let err = KubernetesError::Json(bad.unwrap_err());
        assert!(err.to_string().starts_with("JSON error:"));
    }

    #[test]
    fn error_debug_contains_variant_name() {
        let err = KubernetesError::Unauthorized;
        assert!(format!("{err:?}").contains("Unauthorized"));
    }

    #[test]
    fn error_debug_api_contains_fields() {
        let err = KubernetesError::Api {
            status_code: 422,
            message: "Unprocessable".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("422"));
        assert!(dbg.contains("Unprocessable"));
    }

    // ── ConnectorErrorMapping ────────────────────────────────────────

    #[test]
    fn connector_error_mapping_timeout() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::ConnectorErrorMapping;
        let err = KubernetesError::from_async_error(AsyncError::Timeout { timeout_ms: 4000 });
        assert!(matches!(
            err,
            KubernetesError::Api {
                status_code: 408,
                ..
            }
        ));
        assert!(err.to_string().contains("4000"));
    }

    #[test]
    fn connector_error_mapping_cancelled() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::ConnectorErrorMapping;
        let err = KubernetesError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, KubernetesError::Api { status_code: 0, .. }));
    }

    #[test]
    fn connector_error_mapping_join_error() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::ConnectorErrorMapping;
        let err = KubernetesError::from_async_error(AsyncError::Join {
            message: "task panicked".into(),
        });
        assert!(matches!(err, KubernetesError::Api { .. }));
    }

    #[test]
    fn connector_error_mapping_to_fcp_delegates() {
        use fcp_sdk::ConnectorErrorMapping;
        let err = KubernetesError::Forbidden;
        let fcp = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(
            fcp,
            FcpError::External {
                status_code: Some(403),
                ..
            }
        ));
    }

    #[test]
    fn connector_error_mapping_is_retryable_delegates() {
        use fcp_sdk::ConnectorErrorMapping;
        let err = KubernetesError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(ConnectorErrorMapping::is_retryable(&err));
    }

    #[test]
    fn connector_error_mapping_retry_after_delegates() {
        use fcp_sdk::ConnectorErrorMapping;
        let err = KubernetesError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(
            ConnectorErrorMapping::retry_after(&err),
            Some(Duration::from_secs(30))
        );
    }

    #[test]
    fn api_504_is_retryable() {
        assert!(
            KubernetesError::Api {
                status_code: 504,
                message: "timeout".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn json_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert!(!KubernetesError::Json(bad.unwrap_err()).is_retryable());
    }

    #[test]
    fn rate_limited_retry_after_zero() {
        let err = KubernetesError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn rate_limited_retry_after_large_value() {
        let err = KubernetesError::RateLimited {
            retry_after_ms: 300_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(300)));
    }

    #[test]
    fn api_error_to_fcp_has_no_retry_after() {
        match (KubernetesError::Api {
            status_code: 500,
            message: "err".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { retry_after, .. } => {
                assert_eq!(retry_after, None);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error_preserves_ms() {
        match (KubernetesError::RateLimited {
            retry_after_ms: 5000,
        })
        .to_fcp_error()
        {
            FcpError::RateLimited { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, 5000);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn not_found_to_fcp_error_has_no_retry_after() {
        match (KubernetesError::NotFound {
            resource: "x".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { retry_after, .. } => {
                assert_eq!(retry_after, None);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn unauthorized_to_fcp_error_has_no_retry_after() {
        match KubernetesError::Unauthorized.to_fcp_error() {
            FcpError::External { retry_after, .. } => {
                assert_eq!(retry_after, None);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error_has_no_retry_after() {
        match KubernetesError::Forbidden.to_fcp_error() {
            FcpError::External { retry_after, .. } => {
                assert_eq!(retry_after, None);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }
}
