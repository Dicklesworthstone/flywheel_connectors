//! Slack-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_async_core::http::HttpClientError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use fcp_sdk::migration::http_client_error_reached_service;
use thiserror::Error;

/// Slack-specific errors.
#[derive(Error, Debug)]
pub enum SlackError {
    /// HTTP request failed
    #[error("HTTP error: {message}")]
    Http {
        /// Human-readable error detail.
        message: String,
        /// Optional HTTP-like status associated with the failure.
        status_code: Option<u16>,
        /// Whether the failure was a timeout.
        is_timeout: bool,
        /// Whether it is POSSIBLE that Slack received and acted on the request
        /// before this failure was observed (br-kxd3e).
        ///
        /// `false` only for connection-establishment failures, which prove no
        /// request bytes were written. A non-idempotent POST may only be
        /// replayed when this is `false`; everything else — including a
        /// timeout, which is the TOTAL request deadline and so fires after the
        /// body may have been fully sent — must be treated as "may already
        /// have executed".
        reached_service: bool,
    },

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Slack API returned an error
    #[error("Slack API error: {error} (code: {code:?})")]
    Api {
        error: String,
        code: Option<String>,
        ok: bool,
    },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    /// Invalid or expired token
    #[error("Invalid or expired Slack token")]
    Unauthorized,

    /// Channel not found
    #[error("Channel not found: {channel}")]
    ChannelNotFound { channel: String },

    /// User not found
    #[error("User not found: {user}")]
    UserNotFound { user: String },
}

impl SlackError {
    /// Create an HTTP transport error.
    ///
    /// Conservatively marked as having reached Slack: callers that can prove
    /// otherwise construct the variant directly.
    #[must_use]
    pub fn http(message: impl Into<String>) -> Self {
        Self::Http {
            message: message.into(),
            status_code: None,
            is_timeout: false,
            reached_service: true,
        }
    }

    /// Create a timeout transport error.
    #[must_use]
    pub fn timeout(timeout: Duration) -> Self {
        Self::Http {
            message: format!("request timed out after {}ms", timeout.as_millis()),
            status_code: None,
            is_timeout: true,
            // The timeout wraps the whole request, so it can elapse after the
            // body was fully written and even after Slack acted on it.
            reached_service: true,
        }
    }

    /// Convert an ASUPERSYNC HTTP client error.
    #[must_use]
    pub fn from_http_client_error(error: &HttpClientError) -> Self {
        let status_code = match error {
            HttpClientError::ConnectTunnelRefused { status, .. } => Some(*status),
            _ => None,
        };
        Self::Http {
            message: error.to_string(),
            status_code,
            is_timeout: false,
            reached_service: http_client_error_reached_service(error),
        }
    }

    /// Convert an async-core request failure into a transport error.
    #[must_use]
    pub fn from_async_error(error: AsyncError, timeout: Duration) -> Self {
        match error {
            AsyncError::Timeout { .. } => Self::timeout(timeout),
            AsyncError::Cancelled => Self::http("request cancelled"),
            AsyncError::ProtocolIo { message }
            | AsyncError::Join { message }
            | AsyncError::Runtime { message } => Self::http(message),
            AsyncError::ChannelClosed => Self::http("request channel closed"),
            AsyncError::ChannelFull => Self::http("request channel full"),
        }
    }

    /// Whether replaying the request that produced this error cannot duplicate
    /// a side effect (br-kxd3e).
    ///
    /// This is deliberately NOT "was the error transient". A rate-limit
    /// rejection is safe to replay because the request was refused *without*
    /// being performed; a 5xx or a timeout is not, because Slack received it.
    #[must_use]
    pub const fn replay_is_safe(&self) -> bool {
        match self {
            // Refused before Slack performed the work.
            Self::RateLimited { .. } => true,
            Self::Http {
                reached_service, ..
            } => !*reached_service,
            _ => false,
        }
    }

    /// Check if this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http { .. } | Self::RateLimited { .. } => true,
            Self::Api { error, .. } => {
                // Slack transient errors
                matches!(
                    error.as_str(),
                    "internal_error" | "request_timeout" | "service_unavailable" | "fatal_error"
                )
            }
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
            Self::Http {
                message,
                status_code,
                ..
            } => FcpError::External {
                service: "slack".into(),
                message: message.clone(),
                status_code: *status_code,
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api { error, .. } => {
                if error == "not_authed" || error == "invalid_auth" || error == "token_revoked" {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid or insufficient Slack token".into(),
                    }
                } else if error == "ratelimited" {
                    FcpError::RateLimited {
                        retry_after_ms: 60_000,
                        violation: None,
                    }
                } else if error == "missing_scope"
                    || error == "not_in_channel"
                    || error == "restricted_action"
                    || error == "ekm_access_denied"
                    || error == "access_denied"
                {
                    FcpError::CapabilityDenied {
                        capability: "slack".into(),
                        reason: format!("Slack permission error: {error}"),
                    }
                } else if error == "channel_not_found" {
                    FcpError::ResourceNotFound {
                        resource: "channel".into(),
                    }
                } else if error == "user_not_found" {
                    FcpError::ResourceNotFound {
                        resource: "user".into(),
                    }
                } else {
                    FcpError::External {
                        service: "slack".into(),
                        message: error.clone(),
                        status_code: None,
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::RateLimited { retry_after_secs } => FcpError::RateLimited {
                retry_after_ms: retry_after_secs.saturating_mul(1000),
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid or expired Slack token".into(),
            },
            Self::ChannelNotFound { channel } => FcpError::ResourceNotFound {
                resource: format!("channel:{channel}"),
            },
            Self::UserNotFound { user } => FcpError::ResourceNotFound {
                resource: format!("user:{user}"),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

// ── FCP3 SDK ConnectorErrorMapping trait implementation ──────────────

impl ConnectorErrorMapping for SlackError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Http {
                message: format!("request timed out after {timeout_ms}ms"),
                status_code: None,
                is_timeout: true,
                reached_service: true,
            },
            AsyncError::Cancelled => Self::http("request cancelled"),
            AsyncError::ProtocolIo { message }
            | AsyncError::Join { message }
            | AsyncError::Runtime { message } => Self::http(message),
            AsyncError::ChannelClosed => Self::http("request channel closed"),
            AsyncError::ChannelFull => Self::http("request channel full"),
        }
    }

    fn to_fcp_error(&self) -> FcpError {
        // Delegate to the existing inherent method.
        Self::to_fcp_error(self)
    }

    fn is_retryable(&self) -> bool {
        // Delegate to the existing inherent method.
        Self::is_retryable(self)
    }

    fn retry_after(&self) -> Option<Duration> {
        // Delegate to the existing inherent method.
        Self::retry_after(self)
    }
}

/// Result type for Slack operations.
pub type SlackResult<T> = Result<T, SlackError>;

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_prelude::FcpError;

    #[test]
    fn test_not_authed_maps_to_unauthorized() {
        let err = SlackError::Api {
            error: "not_authed".into(),
            code: None,
            ok: false,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Unauthorized { code: 2001, .. }));
    }

    #[test]
    fn test_invalid_auth_maps_to_unauthorized() {
        let err = SlackError::Api {
            error: "invalid_auth".into(),
            code: None,
            ok: false,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Unauthorized { code: 2001, .. }));
    }

    #[test]
    fn test_token_revoked_maps_to_unauthorized() {
        let err = SlackError::Api {
            error: "token_revoked".into(),
            code: None,
            ok: false,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Unauthorized { code: 2001, .. }));
    }

    #[test]
    fn test_ratelimited_api_maps_to_rate_limited() {
        let err = SlackError::Api {
            error: "ratelimited".into(),
            code: None,
            ok: false,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::RateLimited {
                retry_after_ms: 60_000,
                ..
            }
        ));
    }

    #[test]
    fn test_missing_scope_maps_to_capability_denied() {
        let err = SlackError::Api {
            error: "missing_scope".into(),
            code: None,
            ok: false,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::CapabilityDenied { .. }));
    }

    #[test]
    fn test_permission_errors_map_to_capability_denied() {
        for error_str in &[
            "not_in_channel",
            "restricted_action",
            "ekm_access_denied",
            "access_denied",
        ] {
            let err = SlackError::Api {
                error: (*error_str).into(),
                code: None,
                ok: false,
            };
            let fcp = err.to_fcp_error();
            assert!(
                matches!(fcp, FcpError::CapabilityDenied { .. }),
                "{error_str} should map to CapabilityDenied"
            );
        }
    }

    #[test]
    fn test_channel_not_found_api_maps_to_resource_not_found() {
        let err = SlackError::Api {
            error: "channel_not_found".into(),
            code: None,
            ok: false,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::ResourceNotFound { resource } if resource == "channel"));
    }

    #[test]
    fn test_user_not_found_api_maps_to_resource_not_found() {
        let err = SlackError::Api {
            error: "user_not_found".into(),
            code: None,
            ok: false,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::ResourceNotFound { resource } if resource == "user"));
    }

    #[test]
    fn test_unknown_api_error_maps_to_external() {
        let err = SlackError::Api {
            error: "some_unknown_error".into(),
            code: Some("42".into()),
            ok: false,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::External {
                retryable: false,
                ..
            }
        ));
    }

    #[test]
    fn test_rate_limited_variant_maps_with_correct_ms() {
        let err = SlackError::RateLimited {
            retry_after_secs: 30,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::RateLimited {
                retry_after_ms: 30_000,
                violation: None
            }
        ));
    }

    #[test]
    fn test_unauthorized_variant_maps_to_fcp_unauthorized() {
        let err = SlackError::Unauthorized;
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Unauthorized { code: 2001, .. }));
    }

    #[test]
    fn test_channel_not_found_variant_maps_to_resource_not_found() {
        let err = SlackError::ChannelNotFound {
            channel: "C12345".into(),
        };
        let fcp = err.to_fcp_error();
        assert!(
            matches!(fcp, FcpError::ResourceNotFound { resource } if resource.contains("C12345"))
        );
    }

    #[test]
    fn test_user_not_found_variant_maps_to_resource_not_found() {
        let err = SlackError::UserNotFound {
            user: "U98765".into(),
        };
        let fcp = err.to_fcp_error();
        assert!(
            matches!(fcp, FcpError::ResourceNotFound { resource } if resource.contains("U98765"))
        );
    }

    #[test]
    fn test_json_error_maps_to_internal() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = SlackError::Json(json_err);
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Internal { message } if message.contains("JSON error")));
    }

    #[test]
    fn test_retryable_checks() {
        // Retryable
        assert!(
            SlackError::RateLimited {
                retry_after_secs: 1
            }
            .is_retryable()
        );
        for error_str in &[
            "internal_error",
            "request_timeout",
            "service_unavailable",
            "fatal_error",
        ] {
            assert!(
                SlackError::Api {
                    error: (*error_str).into(),
                    code: None,
                    ok: false,
                }
                .is_retryable(),
                "{error_str} should be retryable"
            );
        }

        // Not retryable
        assert!(!SlackError::Unauthorized.is_retryable());
        assert!(
            !SlackError::ChannelNotFound {
                channel: "x".into()
            }
            .is_retryable()
        );
        assert!(!SlackError::UserNotFound { user: "x".into() }.is_retryable());
        assert!(
            !SlackError::Api {
                error: "not_authed".into(),
                code: None,
                ok: false,
            }
            .is_retryable()
        );
        assert!(
            !SlackError::Api {
                error: "channel_not_found".into(),
                code: None,
                ok: false,
            }
            .is_retryable()
        );
    }

    #[test]
    fn test_retry_after_extraction() {
        assert_eq!(
            SlackError::RateLimited {
                retry_after_secs: 60
            }
            .retry_after()
            .map(|d| d.as_secs()),
            Some(60)
        );
        assert!(SlackError::Unauthorized.retry_after().is_none());
        assert!(
            SlackError::ChannelNotFound {
                channel: "x".into()
            }
            .retry_after()
            .is_none()
        );
        assert!(
            SlackError::Api {
                error: "internal_error".into(),
                code: None,
                ok: false,
            }
            .retry_after()
            .is_none()
        );
    }

    #[test]
    fn test_transient_api_errors_are_retryable_external() {
        for error_str in &["internal_error", "service_unavailable"] {
            let err = SlackError::Api {
                error: (*error_str).into(),
                code: None,
                ok: false,
            };
            assert!(err.is_retryable(), "{error_str} should be retryable");
            let fcp = err.to_fcp_error();
            assert!(
                matches!(
                    fcp,
                    FcpError::External {
                        retryable: true,
                        ..
                    }
                ),
                "{error_str} should map to retryable External"
            );
        }
    }

    // ---- Display messages ----

    #[test]
    fn display_api_with_code_some() {
        let err = SlackError::Api {
            error: "channel_not_found".into(),
            code: Some("404".into()),
            ok: false,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("channel_not_found"),
            "should contain error string"
        );
        assert!(msg.contains("404"), "should contain code value");
    }

    #[test]
    fn display_api_with_code_none() {
        let err = SlackError::Api {
            error: "not_authed".into(),
            code: None,
            ok: false,
        };
        let msg = err.to_string();
        assert!(msg.contains("not_authed"));
        assert!(msg.contains("None"), "code None should appear in display");
    }

    #[test]
    fn display_rate_limited() {
        let err = SlackError::RateLimited {
            retry_after_secs: 45,
        };
        let msg = err.to_string();
        assert!(msg.contains("45"), "should contain retry seconds");
        assert!(msg.contains("Rate limited"));
    }

    #[test]
    fn display_unauthorized() {
        let err = SlackError::Unauthorized;
        let msg = err.to_string();
        assert!(msg.contains("Invalid or expired"));
    }

    #[test]
    fn display_channel_not_found() {
        let err = SlackError::ChannelNotFound {
            channel: "C99999".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("C99999"));
        assert!(msg.contains("Channel not found"));
    }

    #[test]
    fn display_user_not_found() {
        let err = SlackError::UserNotFound {
            user: "UFOO".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("UFOO"));
        assert!(msg.contains("User not found"));
    }

    #[test]
    fn display_json_error() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("{{bad").unwrap_err();
        let err = SlackError::Json(json_err);
        let msg = err.to_string();
        assert!(msg.contains("JSON error"));
    }

    // ---- Debug format ----

    #[test]
    fn debug_api_variant() {
        let err = SlackError::Api {
            error: "test_err".into(),
            code: Some("500".into()),
            ok: false,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("test_err"));
        assert!(dbg.contains("500"));
    }

    #[test]
    fn debug_rate_limited_variant() {
        let err = SlackError::RateLimited {
            retry_after_secs: 10,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RateLimited"));
        assert!(dbg.contains("10"));
    }

    #[test]
    fn debug_unauthorized_variant() {
        let err = SlackError::Unauthorized;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn debug_channel_not_found_variant() {
        let err = SlackError::ChannelNotFound {
            channel: "C_DBG".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ChannelNotFound"));
        assert!(dbg.contains("C_DBG"));
    }

    #[test]
    fn debug_user_not_found_variant() {
        let err = SlackError::UserNotFound {
            user: "U_DBG".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("UserNotFound"));
        assert!(dbg.contains("U_DBG"));
    }

    #[test]
    fn debug_json_variant() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("nope").unwrap_err();
        let err = SlackError::Json(json_err);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Json"));
    }

    // ---- std::error::Error source chain ----

    #[test]
    fn error_source_json_has_source() {
        use std::error::Error;
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("[invalid").unwrap_err();
        let err = SlackError::Json(json_err);
        assert!(
            err.source().is_some(),
            "Json variant should have a source error"
        );
    }

    #[test]
    fn error_source_api_is_none() {
        use std::error::Error;
        let err = SlackError::Api {
            error: "test".into(),
            code: None,
            ok: false,
        };
        assert!(err.source().is_none());
    }

    #[test]
    fn error_source_unauthorized_is_none() {
        use std::error::Error;
        let err = SlackError::Unauthorized;
        assert!(err.source().is_none());
    }

    #[test]
    fn error_source_rate_limited_is_none() {
        use std::error::Error;
        let err = SlackError::RateLimited {
            retry_after_secs: 5,
        };
        assert!(err.source().is_none());
    }

    #[test]
    fn error_source_channel_not_found_is_none() {
        use std::error::Error;
        let err = SlackError::ChannelNotFound {
            channel: "C1".into(),
        };
        assert!(err.source().is_none());
    }

    #[test]
    fn error_source_user_not_found_is_none() {
        use std::error::Error;
        let err = SlackError::UserNotFound { user: "U1".into() };
        assert!(err.source().is_none());
    }

    // ---- SlackResult type alias ----

    #[test]
    fn slack_result_ok() {
        let result: SlackResult<u32> = Ok(42);
        let Ok(val) = result else {
            panic!("expected Ok")
        };
        assert_eq!(val, 42);
    }

    #[test]
    fn slack_result_err() {
        let result: SlackResult<u32> = Err(SlackError::Unauthorized);
        assert!(result.is_err());
    }

    // ---- From<serde_json::Error> conversion ----

    #[test]
    fn from_serde_json_error() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("!!!").unwrap_err();
        let slack_err: SlackError = json_err.into();
        assert!(matches!(slack_err, SlackError::Json(_)));
    }

    // ---- Api with ok=true (structurally valid but unusual) ----

    #[test]
    fn api_with_ok_true_still_maps_to_external() {
        let err = SlackError::Api {
            error: "some_error".into(),
            code: None,
            ok: true,
        };
        // Even with ok=true, the error string drives mapping
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::External { .. }));
    }

    #[test]
    fn api_with_ok_true_display_still_works() {
        let err = SlackError::Api {
            error: "weird".into(),
            code: Some("200".into()),
            ok: true,
        };
        let msg = err.to_string();
        assert!(msg.contains("weird"));
    }

    // ---- retry_after Duration values ----

    #[test]
    fn retry_after_returns_correct_duration() {
        let err = SlackError::RateLimited {
            retry_after_secs: 120,
        };
        let dur = err.retry_after().unwrap();
        assert_eq!(dur, Duration::from_secs(120));
    }

    #[test]
    fn retry_after_zero_seconds() {
        let err = SlackError::RateLimited {
            retry_after_secs: 0,
        };
        let dur = err.retry_after().unwrap();
        assert_eq!(dur, Duration::from_secs(0));
        assert!(err.is_retryable());
        // FCP mapping should have 0 ms
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::RateLimited {
                retry_after_ms: 0,
                ..
            }
        ));
    }

    // ---- Edge: ChannelNotFound with empty string ----

    #[test]
    fn channel_not_found_empty_channel_string() {
        let err = SlackError::ChannelNotFound {
            channel: String::new(),
        };
        let msg = err.to_string();
        assert!(msg.contains("Channel not found:"));
        let fcp = err.to_fcp_error();
        assert!(
            matches!(fcp, FcpError::ResourceNotFound { resource } if resource.contains("channel:"))
        );
    }

    // ---- Edge: UserNotFound with empty string ----

    #[test]
    fn user_not_found_empty_user_string() {
        let err = SlackError::UserNotFound {
            user: String::new(),
        };
        let msg = err.to_string();
        assert!(msg.contains("User not found:"));
        let fcp = err.to_fcp_error();
        assert!(
            matches!(fcp, FcpError::ResourceNotFound { resource } if resource.contains("user:"))
        );
    }

    // ---- Json variant is not retryable ----

    #[test]
    fn json_error_is_not_retryable() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        let err = SlackError::Json(json_err);
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn api_error_unicode_error_string() {
        let err = SlackError::Api {
            error: "エラー_テスト".into(),
            code: None,
            ok: false,
        };
        let s = err.to_string();
        assert!(s.contains("エラー_テスト"));
    }

    #[test]
    fn channel_not_found_long_id() {
        let long_id = "C".to_string() + &"0".repeat(100);
        let err = SlackError::ChannelNotFound {
            channel: long_id.clone(),
        };
        assert!(err.to_string().contains(&long_id));
    }

    #[test]
    fn user_not_found_long_id() {
        let long_id = "U".to_string() + &"0".repeat(100);
        let err = SlackError::UserNotFound {
            user: long_id.clone(),
        };
        assert!(err.to_string().contains(&long_id));
    }

    #[test]
    fn rate_limited_large_value() {
        let err = SlackError::RateLimited {
            retry_after_secs: u64::MAX,
        };
        assert!(err.is_retryable());
        let dur = err.retry_after().unwrap();
        assert_eq!(dur.as_secs(), u64::MAX);
    }

    // ── ConnectorErrorMapping trait tests ────────────────────────────

    fn from_async(err: AsyncError) -> SlackError {
        <SlackError as ConnectorErrorMapping>::from_async_error(err)
    }

    #[test]
    fn connector_error_mapping_timeout() {
        let err = from_async(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(matches!(
            err,
            SlackError::Http {
                is_timeout: true,
                ..
            }
        ));
        assert!(err.to_string().contains("5000"));
        assert!(err.is_retryable());
    }

    #[test]
    fn connector_error_mapping_cancelled() {
        let err = from_async(AsyncError::Cancelled);
        assert!(matches!(err, SlackError::Http { .. }));
        assert!(err.to_string().contains("cancelled"));
    }

    #[test]
    fn connector_error_mapping_runtime() {
        let err = from_async(AsyncError::Runtime {
            message: "runtime failure".into(),
        });
        assert!(matches!(err, SlackError::Http { .. }));
        assert!(err.to_string().contains("runtime failure"));
    }

    #[test]
    fn connector_error_mapping_channel_closed() {
        let err = from_async(AsyncError::ChannelClosed);
        assert!(matches!(err, SlackError::Http { .. }));
    }

    #[test]
    fn connector_error_mapping_channel_full() {
        let err = from_async(AsyncError::ChannelFull);
        assert!(matches!(err, SlackError::Http { .. }));
    }

    // ── Replay safety (br-kxd3e) ─────────────────────────────────────

    /// Only a connection-establishment failure proves Slack never saw the
    /// request. `from_http_client_error` must carry that distinction through
    /// instead of collapsing every transport failure into one shape.
    #[test]
    fn connect_phase_failures_are_replay_safe() {
        let never_sent = SlackError::from_http_client_error(&HttpClientError::ConnectError(
            std::io::Error::other("connection refused"),
        ));
        assert!(
            never_sent.replay_is_safe(),
            "a TCP connect failure means no request bytes were written"
        );

        let dns = SlackError::from_http_client_error(&HttpClientError::DnsError(
            std::io::Error::other("nxdomain"),
        ));
        assert!(dns.replay_is_safe());
    }

    /// The class that motivated the bead: a failure observed after the body
    /// may have been fully written must NOT be replayed.
    #[test]
    fn post_transmission_failures_are_not_replay_safe() {
        let io = SlackError::from_http_client_error(&HttpClientError::Io(std::io::Error::other(
            "connection reset",
        )));
        assert!(
            !io.replay_is_safe(),
            "an I/O failure can land after the request was sent"
        );

        // The total-request timeout is applied by `time::timeout` around the
        // whole call, so it elapses after Slack may have already acted.
        let timed_out = SlackError::timeout(Duration::from_millis(50));
        assert!(
            !timed_out.replay_is_safe(),
            "the request timeout is not proof the request never arrived"
        );
        assert!(
            timed_out.is_retryable(),
            "still retryable in general — replay safety is the separate axis"
        );

        // Same for the async-core timeout path.
        assert!(!from_async(AsyncError::Timeout { timeout_ms: 5000 }).replay_is_safe());
    }

    /// A rate-limited request was refused WITHOUT being performed, so it stays
    /// safe to replay. Guarding this wrong would silently disable backoff.
    #[test]
    fn rate_limited_is_replay_safe() {
        let err = SlackError::RateLimited {
            retry_after_secs: 30,
        };
        assert!(
            err.replay_is_safe(),
            "429 means Slack rejected the request without doing the work"
        );
    }

    #[test]
    fn connector_error_mapping_trait_to_fcp_error() {
        let err = from_async(AsyncError::Timeout { timeout_ms: 1000 });
        let fcp = <SlackError as ConnectorErrorMapping>::to_fcp_error(&err);
        assert!(matches!(
            fcp,
            FcpError::External {
                retryable: true,
                ..
            }
        ));
    }

    #[test]
    fn connector_error_mapping_trait_is_retryable() {
        let err = from_async(AsyncError::Cancelled);
        assert!(<SlackError as ConnectorErrorMapping>::is_retryable(&err));
    }

    #[test]
    fn connector_error_mapping_trait_retry_after_none_for_transport() {
        let err = from_async(AsyncError::Timeout { timeout_ms: 100 });
        assert!(<SlackError as ConnectorErrorMapping>::retry_after(&err).is_none());
    }
}
