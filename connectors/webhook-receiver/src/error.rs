//! Webhook Receiver error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use thiserror::Error;

/// Result alias for Webhook Receiver operations.
pub type WebhookReceiverResult<T> = Result<T, WebhookReceiverError>;

/// Webhook Receiver errors.
#[derive(Error, Debug)]
pub enum WebhookReceiverError {
    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Endpoint not found
    #[error("Endpoint not found: {endpoint_id}")]
    EndpointNotFound { endpoint_id: String },

    /// Duplicate endpoint path
    #[error("Endpoint path already registered: {path}")]
    DuplicatePath { path: String },

    /// Duplicate event delivery for the same endpoint
    #[error("Event already recorded for endpoint {endpoint_id}: {event_id}")]
    DuplicateEvent {
        endpoint_id: String,
        event_id: String,
    },

    /// Retention removed an event that the polling cursor has not passed.
    #[error("Webhook replay gap for endpoint {endpoint_id}; restart polling explicitly")]
    ReplayGap { endpoint_id: String },

    /// Polling cursors cannot cross receiver reset or restart boundaries.
    #[error("Webhook cursor expired with its receiver state; restart polling explicitly")]
    ExpiredCursor,

    /// Invalid input
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },

    /// Request was not authorized
    #[error("Unauthorized: {message}")]
    Unauthorized { message: String },

    /// Request was authenticated but not allowed by policy
    #[error("Forbidden: {message}")]
    Forbidden { message: String },

    /// HTTP method is not supported for webhook ingress
    #[error("Method not allowed: {method}")]
    MethodNotAllowed { method: String },

    /// Request content type is not supported
    #[error("Unsupported media type: {content_type}")]
    UnsupportedMediaType { content_type: String },

    /// Request body exceeded the configured limit
    #[error("Payload too large: {message}")]
    PayloadTooLarge { message: String },

    /// Request body read or request-region deadline timed out
    #[error("Request timeout: {message}")]
    RequestTimeout { message: String },

    /// Store capacity exceeded
    #[error("Store capacity exceeded: {message}")]
    CapacityExceeded { message: String },

    /// Replay protection is full; waiting cannot safely free accepted identities.
    #[error(
        "Webhook replay protection capacity exhausted for endpoint {endpoint_id} (limit {limit}); new deliveries require operator recovery"
    )]
    ReplayCapacityExceeded { endpoint_id: String, limit: usize },

    /// Durable state is unavailable, corrupt, or fenced after an uncertain write.
    /// Messages identify only the failed invariant, never stored values or paths.
    #[error("Webhook durable state unavailable: {message}")]
    Persistence { message: String },

    /// Internal error
    #[error("Internal error: {message}")]
    Internal { message: String },
}

impl WebhookReceiverError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::CapacityExceeded { .. } => true,
            Self::RequestTimeout { .. } => true,
            Self::EndpointNotFound { .. }
            | Self::DuplicatePath { .. }
            | Self::DuplicateEvent { .. }
            | Self::ReplayGap { .. }
            | Self::ExpiredCursor
            | Self::InvalidInput { .. }
            | Self::Unauthorized { .. }
            | Self::Forbidden { .. }
            | Self::MethodNotAllowed { .. }
            | Self::UnsupportedMediaType { .. }
            | Self::PayloadTooLarge { .. }
            | Self::ReplayCapacityExceeded { .. }
            | Self::Persistence { .. }
            | Self::Json(_)
            | Self::Internal { .. } => false,
        }
    }

    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::CapacityExceeded { .. } | Self::RequestTimeout { .. } => {
                Some(Duration::from_secs(5))
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::EndpointNotFound { endpoint_id } => FcpError::External {
                service: "webhook-receiver".into(),
                message: format!("Endpoint not found: {endpoint_id}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
            Self::DuplicatePath { path } => FcpError::External {
                service: "webhook-receiver".into(),
                message: format!("Endpoint path already registered: {path}"),
                status_code: Some(409),
                retryable: false,
                retry_after: None,
            },
            Self::DuplicateEvent {
                endpoint_id,
                event_id,
            } => FcpError::External {
                service: "webhook-receiver".into(),
                message: format!("Event already recorded for endpoint {endpoint_id}: {event_id}"),
                status_code: Some(409),
                retryable: false,
                retry_after: None,
            },
            Self::ReplayGap { .. } => FcpError::External {
                service: "webhook-receiver".into(),
                message: "webhook_replay_gap".into(),
                status_code: Some(410),
                retryable: false,
                retry_after: None,
            },
            Self::ExpiredCursor => FcpError::External {
                service: "webhook-receiver".into(),
                message: "webhook_cursor_expired".into(),
                status_code: Some(410),
                retryable: false,
                retry_after: None,
            },
            Self::InvalidInput { message } => FcpError::External {
                service: "webhook-receiver".into(),
                message: message.clone(),
                status_code: Some(400),
                retryable: false,
                retry_after: None,
            },
            Self::Unauthorized { message } => FcpError::External {
                service: "webhook-receiver".into(),
                message: message.clone(),
                status_code: Some(401),
                retryable: false,
                retry_after: None,
            },
            Self::Forbidden { message } => FcpError::External {
                service: "webhook-receiver".into(),
                message: message.clone(),
                status_code: Some(403),
                retryable: false,
                retry_after: None,
            },
            Self::MethodNotAllowed { method } => FcpError::External {
                service: "webhook-receiver".into(),
                message: format!("Webhook ingress accepts POST requests only, got {method}"),
                status_code: Some(405),
                retryable: false,
                retry_after: None,
            },
            Self::UnsupportedMediaType { content_type } => FcpError::External {
                service: "webhook-receiver".into(),
                message: format!("Unsupported webhook content type: {content_type}"),
                status_code: Some(415),
                retryable: false,
                retry_after: None,
            },
            Self::PayloadTooLarge { message } => FcpError::External {
                service: "webhook-receiver".into(),
                message: message.clone(),
                status_code: Some(413),
                retryable: false,
                retry_after: None,
            },
            Self::RequestTimeout { message } => FcpError::External {
                service: "webhook-receiver".into(),
                message: message.clone(),
                status_code: Some(408),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::CapacityExceeded { message } => FcpError::External {
                service: "webhook-receiver".into(),
                message: message.clone(),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::ReplayCapacityExceeded { .. } => FcpError::External {
                service: "webhook-receiver".into(),
                message: self.to_string(),
                status_code: Some(507),
                retryable: false,
                retry_after: None,
            },
            Self::Internal { message } => FcpError::Internal {
                message: message.clone(),
            },
            Self::Persistence { .. } => FcpError::Internal {
                message: "Webhook durable state is unavailable; restore or reopen the receiver before continuing".into(),
            },
        }
    }
}

impl ConnectorErrorMapping for WebhookReceiverError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Internal {
                message: format!("deadline exceeded after {timeout_ms}ms"),
            },
            AsyncError::Cancelled => Self::Internal {
                message: "request cancelled".into(),
            },
            other => Self::Internal {
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
    fn endpoint_not_found_not_retryable() {
        assert!(
            !WebhookReceiverError::EndpointNotFound {
                endpoint_id: "ep_1".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn duplicate_path_not_retryable() {
        assert!(
            !WebhookReceiverError::DuplicatePath {
                path: "/hooks/test".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn invalid_input_not_retryable() {
        assert!(
            !WebhookReceiverError::InvalidInput {
                message: "bad".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn duplicate_event_not_retryable() {
        assert!(
            !WebhookReceiverError::DuplicateEvent {
                endpoint_id: "ep_1".into(),
                event_id: "evt_1".into(),
            }
            .is_retryable()
        );
    }

    #[test]
    fn capacity_exceeded_is_retryable() {
        assert!(
            WebhookReceiverError::CapacityExceeded {
                message: "full".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn internal_not_retryable() {
        assert!(
            !WebhookReceiverError::Internal {
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn retry_after_for_capacity_exceeded() {
        let err = WebhookReceiverError::CapacityExceeded {
            message: "full".into(),
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn retry_after_none_for_not_found() {
        let err = WebhookReceiverError::EndpointNotFound {
            endpoint_id: "ep_1".into(),
        };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_duplicate_path() {
        let err = WebhookReceiverError::DuplicatePath { path: "/x".into() };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_duplicate_event() {
        let err = WebhookReceiverError::DuplicateEvent {
            endpoint_id: "ep_1".into(),
            event_id: "evt_1".into(),
        };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_invalid_input() {
        let err = WebhookReceiverError::InvalidInput {
            message: "bad".into(),
        };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_internal() {
        let err = WebhookReceiverError::Internal {
            message: "err".into(),
        };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn endpoint_not_found_to_fcp_error() {
        match (WebhookReceiverError::EndpointNotFound {
            endpoint_id: "ep_abc".into(),
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
                assert_eq!(service, "webhook-receiver");
                assert_eq!(status_code, Some(404));
                assert!(!retryable);
                assert!(message.contains("ep_abc"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_path_to_fcp_error() {
        match (WebhookReceiverError::DuplicatePath {
            path: "/hooks/github".into(),
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
                assert_eq!(service, "webhook-receiver");
                assert_eq!(status_code, Some(409));
                assert!(!retryable);
                assert!(message.contains("/hooks/github"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn invalid_input_to_fcp_error() {
        match (WebhookReceiverError::InvalidInput {
            message: "missing field".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                status_code,
                retryable,
                message,
                ..
            } => {
                assert_eq!(status_code, Some(400));
                assert!(!retryable);
                assert_eq!(message, "missing field");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_event_to_fcp_error() {
        match (WebhookReceiverError::DuplicateEvent {
            endpoint_id: "ep_abc".into(),
            event_id: "evt_123".into(),
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
                assert_eq!(service, "webhook-receiver");
                assert_eq!(status_code, Some(409));
                assert!(!retryable);
                assert!(message.contains("ep_abc"));
                assert!(message.contains("evt_123"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn capacity_exceeded_to_fcp_error() {
        match (WebhookReceiverError::CapacityExceeded {
            message: "too many".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                status_code,
                retryable,
                retry_after,
                message,
                ..
            } => {
                assert_eq!(status_code, Some(429));
                assert!(retryable);
                assert_eq!(retry_after, Some(Duration::from_secs(5)));
                assert_eq!(message, "too many");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn replay_capacity_exhaustion_is_nonretryable_and_requires_recovery() {
        let error = WebhookReceiverError::ReplayCapacityExceeded {
            endpoint_id: "ep_full".into(),
            limit: 100_000,
        };
        assert!(!error.is_retryable());
        assert_eq!(error.retry_after(), None);
        assert!(error.to_string().contains("operator recovery"));
        assert!(matches!(
            error.to_fcp_error(),
            FcpError::External {
                status_code: Some(507),
                retryable: false,
                retry_after: None,
                ..
            }
        ));
    }

    #[test]
    fn polling_gaps_and_expired_cursors_have_stable_nonretryable_reasons() {
        for (error, reason) in [
            (
                WebhookReceiverError::ReplayGap {
                    endpoint_id: "ep_private".into(),
                },
                "webhook_replay_gap",
            ),
            (
                WebhookReceiverError::ExpiredCursor,
                "webhook_cursor_expired",
            ),
        ] {
            assert!(!error.is_retryable());
            assert_eq!(error.retry_after(), None);
            match error.to_fcp_error() {
                FcpError::External {
                    service,
                    message,
                    status_code,
                    retryable,
                    retry_after,
                } => {
                    assert_eq!(service, "webhook-receiver");
                    assert_eq!(message, reason);
                    assert_eq!(status_code, Some(410));
                    assert!(!retryable);
                    assert_eq!(retry_after, None);
                }
                other => panic!("expected External, got {other:?}"),
            }
        }
    }

    #[test]
    fn internal_to_fcp_error() {
        match (WebhookReceiverError::Internal {
            message: "boom".into(),
        })
        .to_fcp_error()
        {
            FcpError::Internal { message } => assert_eq!(message, "boom"),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn json_error_to_fcp_internal() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        match WebhookReceiverError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn error_display_endpoint_not_found() {
        assert_eq!(
            WebhookReceiverError::EndpointNotFound {
                endpoint_id: "ep_1".into()
            }
            .to_string(),
            "Endpoint not found: ep_1"
        );
    }

    #[test]
    fn error_display_duplicate_path() {
        assert_eq!(
            WebhookReceiverError::DuplicatePath {
                path: "/hooks/test".into()
            }
            .to_string(),
            "Endpoint path already registered: /hooks/test"
        );
    }

    #[test]
    fn error_display_duplicate_event() {
        assert_eq!(
            WebhookReceiverError::DuplicateEvent {
                endpoint_id: "ep_1".into(),
                event_id: "evt_1".into(),
            }
            .to_string(),
            "Event already recorded for endpoint ep_1: evt_1"
        );
    }

    #[test]
    fn error_display_invalid_input() {
        assert_eq!(
            WebhookReceiverError::InvalidInput {
                message: "bad data".into()
            }
            .to_string(),
            "Invalid input: bad data"
        );
    }

    #[test]
    fn error_display_capacity_exceeded() {
        assert_eq!(
            WebhookReceiverError::CapacityExceeded {
                message: "store full".into()
            }
            .to_string(),
            "Store capacity exceeded: store full"
        );
    }

    #[test]
    fn error_display_internal() {
        assert_eq!(
            WebhookReceiverError::Internal {
                message: "something broke".into()
            }
            .to_string(),
            "Internal error: something broke"
        );
    }

    #[test]
    fn json_error_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        let err = WebhookReceiverError::Json(bad.unwrap_err());
        assert!(!err.is_retryable());
    }

    #[test]
    fn json_error_retry_after_none() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        let err = WebhookReceiverError::Json(bad.unwrap_err());
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn error_debug_endpoint_not_found() {
        let dbg = format!(
            "{:?}",
            WebhookReceiverError::EndpointNotFound {
                endpoint_id: "ep_1".into()
            }
        );
        assert!(dbg.contains("EndpointNotFound"));
        assert!(dbg.contains("ep_1"));
    }

    #[test]
    fn error_debug_duplicate_path() {
        let dbg = format!(
            "{:?}",
            WebhookReceiverError::DuplicatePath {
                path: "/hooks/x".into()
            }
        );
        assert!(dbg.contains("DuplicatePath"));
        assert!(dbg.contains("/hooks/x"));
    }

    #[test]
    fn error_debug_invalid_input() {
        let dbg = format!(
            "{:?}",
            WebhookReceiverError::InvalidInput {
                message: "bad data".into()
            }
        );
        assert!(dbg.contains("InvalidInput"));
        assert!(dbg.contains("bad data"));
    }

    #[test]
    fn error_debug_capacity_exceeded() {
        let dbg = format!(
            "{:?}",
            WebhookReceiverError::CapacityExceeded {
                message: "full".into()
            }
        );
        assert!(dbg.contains("CapacityExceeded"));
        assert!(dbg.contains("full"));
    }

    #[test]
    fn error_debug_internal() {
        let dbg = format!(
            "{:?}",
            WebhookReceiverError::Internal {
                message: "boom".into()
            }
        );
        assert!(dbg.contains("Internal"));
        assert!(dbg.contains("boom"));
    }

    #[test]
    fn error_debug_json() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let err = WebhookReceiverError::Json(bad.unwrap_err());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Json"));
    }

    #[test]
    fn error_display_json() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let err = WebhookReceiverError::Json(bad.unwrap_err());
        let display = err.to_string();
        assert!(display.starts_with("JSON error:"), "got: {display}");
    }

    #[test]
    fn capacity_exceeded_retry_after_is_5_seconds() {
        let err = WebhookReceiverError::CapacityExceeded {
            message: "max endpoints".into(),
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn endpoint_not_found_fcp_error_has_service() {
        match (WebhookReceiverError::EndpointNotFound {
            endpoint_id: "ep_z".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { service, .. } => assert_eq!(service, "webhook-receiver"),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_path_fcp_error_has_409() {
        match (WebhookReceiverError::DuplicatePath { path: "/x".into() }).to_fcp_error() {
            FcpError::External { status_code, .. } => assert_eq!(status_code, Some(409)),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn invalid_input_fcp_error_has_400() {
        match (WebhookReceiverError::InvalidInput {
            message: "test".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { status_code, .. } => assert_eq!(status_code, Some(400)),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn capacity_exceeded_fcp_error_has_retry_after() {
        match (WebhookReceiverError::CapacityExceeded {
            message: "full".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { retry_after, .. } => {
                assert_eq!(retry_after, Some(Duration::from_secs(5)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn internal_fcp_error_preserves_message() {
        match (WebhookReceiverError::Internal {
            message: "critical failure".into(),
        })
        .to_fcp_error()
        {
            FcpError::Internal { message } => assert_eq!(message, "critical failure"),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn json_fcp_error_is_internal() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        match WebhookReceiverError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.contains("JSON error:"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn endpoint_not_found_fcp_error_not_retryable() {
        match (WebhookReceiverError::EndpointNotFound {
            endpoint_id: "ep_x".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { retryable, .. } => assert!(!retryable),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn capacity_exceeded_fcp_error_is_retryable() {
        match (WebhookReceiverError::CapacityExceeded {
            message: "full".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { retryable, .. } => assert!(retryable),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_path_fcp_error_not_retryable() {
        match (WebhookReceiverError::DuplicatePath { path: "/y".into() }).to_fcp_error() {
            FcpError::External { retryable, .. } => assert!(!retryable),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn invalid_input_fcp_error_not_retryable() {
        match (WebhookReceiverError::InvalidInput {
            message: "test".into(),
        })
        .to_fcp_error()
        {
            FcpError::External { retryable, .. } => assert!(!retryable),
            other => panic!("expected External, got {other:?}"),
        }
    }
}
