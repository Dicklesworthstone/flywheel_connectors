//! Google Chat-specific error types.

use std::time::Duration;

use fcp_prelude::FcpError;
use thiserror::Error;

/// Google Chat-specific errors.
#[derive(Error, Debug)]
pub enum ChatError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Google Chat API returned an error
    #[error("Chat API error ({status_code}): {message}")]
    Api { status_code: u16, message: String },

    /// A provider write may have taken effect even though its receipt was unavailable.
    #[error("Google Chat {operation} outcome unknown. Check the space before retrying.")]
    WriteOutcomeUnknown { operation: &'static str, status_code: Option<u16> },

    /// The connector uploaded media before message creation failed.
    #[error("Google Chat accepted the attachment upload. {message}")]
    IncompleteMediaSend { message: &'static str, status_code: Option<u16> },

    /// A replayable read received a server error with a minimum retry delay.
    #[error("Chat API error ({status_code}): {message}")]
    TransientApi { status_code: u16, message: String, retry_after_ms: u64 },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Invalid or expired token
    #[error("Invalid or expired Google Chat credentials")]
    Unauthorized,

    /// Space not found
    #[error("Space not found: {space_name}")]
    SpaceNotFound { space_name: String },

    /// Insufficient permissions
    #[error("Insufficient Chat permissions: {message}")]
    Forbidden { message: String },
}

impl ChatError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } | Self::TransientApi { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, 500..=599 | 429),
            _ => false,
        }
    }

    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } | Self::TransientApi { retry_after_ms, .. } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    /// Retrying the whole media operation would upload the same bytes again.
    pub(crate) fn after_media_upload(self) -> Self {
        let uncertain = matches!(self, Self::WriteOutcomeUnknown { .. });
        let status_code = match self {
            Self::Http(ref error) => error.status().map(|status| status.as_u16()),
            Self::Api { status_code, .. } if status_code != 0 => Some(status_code),
            Self::WriteOutcomeUnknown { status_code, .. } => status_code,
            Self::RateLimited { .. } => Some(429),
            Self::Unauthorized => Some(401),
            Self::Forbidden { .. } => Some(403),
            Self::SpaceNotFound { .. } => Some(404),
            _ => None,
        };
        // A provider diagnostic may echo the upload token or the message.
        Self::IncompleteMediaSend {
            status_code,
            message: if uncertain {
                "Message delivery is unknown. Check the space before submitting the media again."
            } else {
                "The message was not sent. Restarting this operation would upload the attachment again."
            },
        }
    }

    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "google_chat".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::WriteOutcomeUnknown { status_code, .. } | Self::IncompleteMediaSend { status_code, .. } => FcpError::External {
                service: "google_chat".into(), message: self.to_string(), status_code: *status_code, retryable: false, retry_after: None,
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api {
                status_code: 401 | 403,
                message,
            } => FcpError::Unauthorized {
                code: 2001,
                message: format!("Chat auth failed: {message}"),
            },
            Self::Api {
                status_code: 404,
                message,
            } => FcpError::ResourceNotFound {
                resource: message.clone(),
            },
            Self::Api {
                status_code: 429, ..
            } => FcpError::RateLimited {
                retry_after_ms: 60_000,
                violation: None,
            },
            Self::Api { status_code, message } | Self::TransientApi { status_code, message, .. } => FcpError::External {
                service: "google_chat".into(),
                message: message.clone(),
                status_code: Some(*status_code),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid or expired Google Chat credentials".into(),
            },
            Self::SpaceNotFound { space_name } => FcpError::ResourceNotFound {
                resource: format!("space:{space_name}"),
            },
            Self::Forbidden { message } => FcpError::Unauthorized {
                code: 2001,
                message: format!("Chat permission denied: {message}"),
            },
        }
    }
}

impl fcp_sdk::ConnectorErrorMapping for ChatError {
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

/// Result type for Chat operations.
pub type ChatResult<T> = Result<T, ChatError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!ChatError::Unauthorized.is_retryable());
    }

    #[test]
    fn rate_limited_is_retryable() {
        assert!(
            ChatError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            ChatError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !ChatError::Api {
                status_code: 400,
                message: "bad".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_rate_limited() {
        let err = ChatError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(ChatError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn to_fcp_error_unauthorized() {
        match ChatError::Unauthorized.to_fcp_error() {
            FcpError::Unauthorized { code, .. } => assert_eq!(code, 2001),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_space_not_found() {
        let err = ChatError::SpaceNotFound {
            space_name: "spaces/abc".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "space:spaces/abc");
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_429() {
        let err = ChatError::Api {
            status_code: 429,
            message: "rate limited".into(),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::RateLimited { .. }));
    }

    #[test]
    fn to_fcp_error_forbidden() {
        let err = ChatError::Forbidden {
            message: "no access".into(),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("Chat permission denied"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        match ChatError::Json(json_err).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_401() {
        let err = ChatError::Api {
            status_code: 401,
            message: "bad token".into(),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn to_fcp_error_api_403() {
        let err = ChatError::Api {
            status_code: 403,
            message: "forbidden".into(),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn to_fcp_error_api_500() {
        let err = ChatError::Api {
            status_code: 500,
            message: "internal".into(),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "google_chat");
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_404() {
        let err = ChatError::Api {
            status_code: 404,
            message: "not found".into(),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::ResourceNotFound { .. }
        ));
    }

    #[test]
    fn to_fcp_error_http() {
        // We can't easily construct a reqwest::Error, but we test the other branches
        let err = ChatError::Api {
            status_code: 502,
            message: "bad gateway".into(),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                retryable,
                status_code,
                ..
            } => {
                assert_eq!(service, "google_chat");
                assert!(retryable);
                assert_eq!(status_code, Some(502));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn display_all_variants() {
        let _ = ChatError::Unauthorized.to_string();
        let _ = ChatError::RateLimited {
            retry_after_ms: 5000,
        }
        .to_string();
        let _ = ChatError::SpaceNotFound {
            space_name: "spaces/x".into(),
        }
        .to_string();
        let _ = ChatError::Forbidden {
            message: "no".into(),
        }
        .to_string();
        let _ = ChatError::Api {
            status_code: 500,
            message: "err".into(),
        }
        .to_string();
    }

    // -- ConnectorErrorMapping --

    #[test]
    fn connector_error_mapping_timeout() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::ConnectorErrorMapping;
        let err = ChatError::from_async_error(AsyncError::Timeout { timeout_ms: 3000 });
        assert!(matches!(
            err,
            ChatError::Api {
                status_code: 408,
                ..
            }
        ));
    }

    #[test]
    fn connector_error_mapping_cancelled() {
        use fcp_async_core::AsyncError;
        use fcp_sdk::ConnectorErrorMapping;
        let err = ChatError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, ChatError::Api { status_code: 0, .. }));
    }

    #[test]
    fn connector_error_mapping_to_fcp_delegates() {
        use fcp_sdk::ConnectorErrorMapping;
        let err = ChatError::Unauthorized;
        let fcp = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp, FcpError::Unauthorized { .. }));
    }

    #[test]
    fn connector_error_mapping_is_retryable_delegates() {
        use fcp_sdk::ConnectorErrorMapping;
        let err = ChatError::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(ConnectorErrorMapping::is_retryable(&err));
    }

    #[test]
    fn connector_error_mapping_retry_after_delegates() {
        use fcp_sdk::ConnectorErrorMapping;
        let err = ChatError::RateLimited {
            retry_after_ms: 60_000,
        };
        assert_eq!(
            ConnectorErrorMapping::retry_after(&err),
            Some(Duration::from_secs(60))
        );
    }
}
