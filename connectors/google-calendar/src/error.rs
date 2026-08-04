//! Google Calendar-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use thiserror::Error;

/// Google Calendar-specific errors.
#[derive(Error, Debug)]
pub enum GoogleCalendarError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Google Calendar API returned an error
    #[error("Google Calendar API error: {message} (code: {code})")]
    Api { code: u32, message: String },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    /// Invalid or expired token
    #[error("Invalid or expired Google Calendar credentials")]
    Unauthorized,

    /// Event not found
    #[error("Event not found: {event_id}")]
    EventNotFound { event_id: String },

    /// Calendar not found
    #[error("Calendar not found: {calendar_id}")]
    CalendarNotFound { calendar_id: String },
}

impl GoogleCalendarError {
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
    /// Distinct from [`Self::is_retryable`]: a rate-limited request was refused
    /// WITHOUT being performed, so replaying it is safe; a 5xx means Google
    /// received it and may already have created the event and mailed the
    /// invitations.
    #[must_use]
    pub fn replay_is_safe(&self) -> bool {
        match self {
            Self::RateLimited { .. } => true,
            Self::Api { code, .. } => *code == 429,
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
                service: "google-calendar".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api { code, message } => {
                if *code == 401 {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid or insufficient Google Calendar credentials".into(),
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
                        service: "google-calendar".into(),
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
                message: "Invalid or expired Google Calendar credentials".into(),
            },
            Self::EventNotFound { event_id } => FcpError::ResourceNotFound {
                resource: format!("event:{event_id}"),
            },
            Self::CalendarNotFound { calendar_id } => FcpError::ResourceNotFound {
                resource: format!("calendar:{calendar_id}"),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for Google Calendar operations.
pub type GCalResult<T> = Result<T, GoogleCalendarError>;

impl ConnectorErrorMapping for GoogleCalendarError {
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
    use fcp_prelude::FcpError;

    // ── Display message tests ──────────────────────────────────────────────

    #[test]
    fn display_http_error() {
        // Build a reqwest::Error by attempting an invalid URL
        let http_err = reqwest::Client::new().get("://bad").build().unwrap_err();
        let err = GoogleCalendarError::Http(http_err);
        let msg = err.to_string();
        assert!(msg.starts_with("HTTP error: "), "got: {msg}");
    }

    #[test]
    fn display_json_error() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("{invalid}").unwrap_err();
        let err = GoogleCalendarError::Json(json_err);
        let msg = err.to_string();
        assert!(msg.starts_with("JSON error: "), "got: {msg}");
    }

    #[test]
    fn display_api_error() {
        let err = GoogleCalendarError::Api {
            code: 403,
            message: "forbidden".into(),
        };
        assert_eq!(
            err.to_string(),
            "Google Calendar API error: forbidden (code: 403)"
        );
    }

    #[test]
    fn display_rate_limited() {
        let err = GoogleCalendarError::RateLimited {
            retry_after_secs: 42,
        };
        assert_eq!(err.to_string(), "Rate limited, retry after 42s");
    }

    #[test]
    fn display_unauthorized() {
        let err = GoogleCalendarError::Unauthorized;
        assert_eq!(
            err.to_string(),
            "Invalid or expired Google Calendar credentials"
        );
    }

    #[test]
    fn display_event_not_found() {
        let err = GoogleCalendarError::EventNotFound {
            event_id: "abc123".into(),
        };
        assert_eq!(err.to_string(), "Event not found: abc123");
    }

    #[test]
    fn display_calendar_not_found() {
        let err = GoogleCalendarError::CalendarNotFound {
            calendar_id: "work@group.calendar.google.com".into(),
        };
        assert_eq!(
            err.to_string(),
            "Calendar not found: work@group.calendar.google.com"
        );
    }

    // ── Debug trait tests ──────────────────────────────────────────────────

    #[test]
    fn debug_api_error() {
        let err = GoogleCalendarError::Api {
            code: 500,
            message: "internal".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"), "got: {dbg}");
        assert!(dbg.contains("500"), "got: {dbg}");
        assert!(dbg.contains("internal"), "got: {dbg}");
    }

    #[test]
    fn debug_unauthorized() {
        let err = GoogleCalendarError::Unauthorized;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Unauthorized"), "got: {dbg}");
    }

    #[test]
    fn debug_rate_limited() {
        let err = GoogleCalendarError::RateLimited {
            retry_after_secs: 10,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RateLimited"), "got: {dbg}");
        assert!(dbg.contains("10"), "got: {dbg}");
    }

    #[test]
    fn debug_event_not_found() {
        let err = GoogleCalendarError::EventNotFound {
            event_id: "e42".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("EventNotFound"), "got: {dbg}");
        assert!(dbg.contains("e42"), "got: {dbg}");
    }

    #[test]
    fn debug_calendar_not_found() {
        let err = GoogleCalendarError::CalendarNotFound {
            calendar_id: "c99".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("CalendarNotFound"), "got: {dbg}");
        assert!(dbg.contains("c99"), "got: {dbg}");
    }

    #[test]
    fn debug_json_error() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("!!!").unwrap_err();
        let err = GoogleCalendarError::Json(json_err);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Json"), "got: {dbg}");
    }

    // ── std::error::Error trait tests ──────────────────────────────────────

    #[test]
    fn std_error_source_json() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("nope").unwrap_err();
        let err = GoogleCalendarError::Json(json_err);
        let source = std::error::Error::source(&err);
        assert!(source.is_some(), "Json variant should have a source");
    }

    #[test]
    fn std_error_source_http() {
        let http_err = reqwest::Client::new().get("://bad").build().unwrap_err();
        let err = GoogleCalendarError::Http(http_err);
        let source = std::error::Error::source(&err);
        assert!(source.is_some(), "Http variant should have a source");
    }

    #[test]
    fn std_error_source_none_for_non_wrapped() {
        let err = GoogleCalendarError::Unauthorized;
        assert!(
            std::error::Error::source(&err).is_none(),
            "Unauthorized should have no source"
        );

        let err2 = GoogleCalendarError::Api {
            code: 500,
            message: "err".into(),
        };
        assert!(
            std::error::Error::source(&err2).is_none(),
            "Api should have no source"
        );

        let err3 = GoogleCalendarError::EventNotFound {
            event_id: "e".into(),
        };
        assert!(
            std::error::Error::source(&err3).is_none(),
            "EventNotFound should have no source"
        );

        let err4 = GoogleCalendarError::CalendarNotFound {
            calendar_id: "c".into(),
        };
        assert!(
            std::error::Error::source(&err4).is_none(),
            "CalendarNotFound should have no source"
        );

        let err5 = GoogleCalendarError::RateLimited {
            retry_after_secs: 5,
        };
        assert!(
            std::error::Error::source(&err5).is_none(),
            "RateLimited should have no source"
        );
    }

    // ── is_retryable tests ─────────────────────────────────────────────────

    #[test]
    fn is_retryable_http() {
        let http_err = reqwest::Client::new().get("://bad").build().unwrap_err();
        let err = GoogleCalendarError::Http(http_err);
        assert!(err.is_retryable(), "Http errors should be retryable");
    }

    #[test]
    fn is_retryable_rate_limited() {
        let err = GoogleCalendarError::RateLimited {
            retry_after_secs: 1,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_api_429() {
        let err = GoogleCalendarError::Api {
            code: 429,
            message: String::new(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_api_500() {
        let err = GoogleCalendarError::Api {
            code: 500,
            message: String::new(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_api_502() {
        let err = GoogleCalendarError::Api {
            code: 502,
            message: String::new(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_api_503() {
        let err = GoogleCalendarError::Api {
            code: 503,
            message: String::new(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn not_retryable_json() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        let err = GoogleCalendarError::Json(json_err);
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_unauthorized() {
        assert!(!GoogleCalendarError::Unauthorized.is_retryable());
    }

    #[test]
    fn not_retryable_event_not_found() {
        let err = GoogleCalendarError::EventNotFound {
            event_id: "x".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_calendar_not_found() {
        let err = GoogleCalendarError::CalendarNotFound {
            calendar_id: "x".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_api_400() {
        let err = GoogleCalendarError::Api {
            code: 400,
            message: String::new(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_api_401() {
        let err = GoogleCalendarError::Api {
            code: 401,
            message: String::new(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_api_403() {
        let err = GoogleCalendarError::Api {
            code: 403,
            message: String::new(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_api_404() {
        let err = GoogleCalendarError::Api {
            code: 404,
            message: String::new(),
        };
        assert!(!err.is_retryable());
    }

    // ── retry_after tests ──────────────────────────────────────────────────

    #[test]
    fn retry_after_rate_limited_returns_duration() {
        let err = GoogleCalendarError::RateLimited {
            retry_after_secs: 60,
        };
        let dur = err.retry_after().expect("should return Some");
        assert_eq!(dur, Duration::from_secs(60));
    }

    #[test]
    fn retry_after_rate_limited_zero_secs() {
        let err = GoogleCalendarError::RateLimited {
            retry_after_secs: 0,
        };
        let dur = err.retry_after().expect("should return Some");
        assert_eq!(dur, Duration::from_secs(0));
    }

    #[test]
    fn retry_after_none_for_all_non_rate_limited() {
        assert!(GoogleCalendarError::Unauthorized.retry_after().is_none());
        assert!(
            GoogleCalendarError::EventNotFound {
                event_id: "x".into()
            }
            .retry_after()
            .is_none()
        );
        assert!(
            GoogleCalendarError::CalendarNotFound {
                calendar_id: "x".into()
            }
            .retry_after()
            .is_none()
        );
        assert!(
            GoogleCalendarError::Api {
                code: 429,
                message: String::new()
            }
            .retry_after()
            .is_none()
        );
        assert!(
            GoogleCalendarError::Api {
                code: 500,
                message: String::new()
            }
            .retry_after()
            .is_none()
        );

        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        assert!(GoogleCalendarError::Json(json_err).retry_after().is_none());
    }

    // ── to_fcp_error mapping tests ─────────────────────────────────────────

    #[test]
    fn fcp_error_http_maps_to_external() {
        let http_err = reqwest::Client::new().get("://bad").build().unwrap_err();
        let err = GoogleCalendarError::Http(http_err);
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "google-calendar");
                assert!(retryable, "Http errors are retryable");
            }
            other => panic!("Expected FcpError::External, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_api_401_maps_to_unauthorized() {
        let err = GoogleCalendarError::Api {
            code: 401,
            message: "bad token".into(),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(
                    message.contains("Google Calendar"),
                    "message should mention Google Calendar: {message}"
                );
            }
            other => panic!("Expected FcpError::Unauthorized, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_api_429_maps_to_rate_limited() {
        let err = GoogleCalendarError::Api {
            code: 429,
            message: "rate limited".into(),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 60_000);
                assert!(violation.is_none());
            }
            other => panic!("Expected FcpError::RateLimited, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_api_404_maps_to_resource_not_found() {
        let err = GoogleCalendarError::Api {
            code: 404,
            message: "calendar not found".into(),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "calendar not found");
            }
            other => panic!("Expected FcpError::ResourceNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_api_500_maps_to_external_retryable() {
        let err = GoogleCalendarError::Api {
            code: 500,
            message: "server error".into(),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "google-calendar");
                assert_eq!(message, "server error");
                assert_eq!(status_code, Some(500));
                assert!(retryable);
            }
            other => panic!("Expected FcpError::External, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_api_502_maps_to_external_retryable() {
        let err = GoogleCalendarError::Api {
            code: 502,
            message: "bad gateway".into(),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                retryable,
                status_code,
                ..
            } => {
                assert!(retryable);
                assert_eq!(status_code, Some(502));
            }
            other => panic!("Expected FcpError::External, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_api_503_maps_to_external_retryable() {
        let err = GoogleCalendarError::Api {
            code: 503,
            message: "service unavailable".into(),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                retryable,
                status_code,
                ..
            } => {
                assert!(retryable);
                assert_eq!(status_code, Some(503));
            }
            other => panic!("Expected FcpError::External, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_api_403_maps_to_external_not_retryable() {
        let err = GoogleCalendarError::Api {
            code: 403,
            message: "forbidden".into(),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                retryable,
                status_code,
                service,
                ..
            } => {
                assert!(!retryable);
                assert_eq!(status_code, Some(403));
                assert_eq!(service, "google-calendar");
            }
            other => panic!("Expected FcpError::External, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_api_400_maps_to_external_not_retryable() {
        let err = GoogleCalendarError::Api {
            code: 400,
            message: "bad request".into(),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                retryable,
                status_code,
                ..
            } => {
                assert!(!retryable);
                assert_eq!(status_code, Some(400));
            }
            other => panic!("Expected FcpError::External, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_rate_limited_correct_ms_conversion() {
        let err = GoogleCalendarError::RateLimited {
            retry_after_secs: 30,
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 30_000);
                assert!(violation.is_none());
            }
            other => panic!("Expected FcpError::RateLimited, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_rate_limited_zero_secs() {
        let err = GoogleCalendarError::RateLimited {
            retry_after_secs: 0,
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::RateLimited { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, 0);
            }
            other => panic!("Expected FcpError::RateLimited, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_rate_limited_large_value() {
        let err = GoogleCalendarError::RateLimited {
            retry_after_secs: 3600,
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::RateLimited { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, 3_600_000);
            }
            other => panic!("Expected FcpError::RateLimited, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_unauthorized_maps_to_fcp_unauthorized() {
        let err = GoogleCalendarError::Unauthorized;
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("expired"), "message: {message}");
                assert!(message.contains("Google Calendar"), "message: {message}");
            }
            other => panic!("Expected FcpError::Unauthorized, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_event_not_found_resource_format() {
        let err = GoogleCalendarError::EventNotFound {
            event_id: "abc123def".into(),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "event:abc123def");
            }
            other => panic!("Expected FcpError::ResourceNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_calendar_not_found_resource_format() {
        let err = GoogleCalendarError::CalendarNotFound {
            calendar_id: "user@example.com".into(),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "calendar:user@example.com");
            }
            other => panic!("Expected FcpError::ResourceNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_json_maps_to_internal() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = GoogleCalendarError::Json(json_err);
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Internal { message } => {
                assert!(
                    message.starts_with("JSON error: "),
                    "message should start with 'JSON error: ': {message}"
                );
            }
            other => panic!("Expected FcpError::Internal, got: {other:?}"),
        }
    }

    // ── From trait conversion tests ────────────────────────────────────────

    #[test]
    fn from_serde_json_error() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err: GoogleCalendarError = json_err.into();
        assert!(matches!(err, GoogleCalendarError::Json(_)));
    }

    #[test]
    fn from_reqwest_error() {
        let http_err = reqwest::Client::new().get("://bad").build().unwrap_err();
        let err: GoogleCalendarError = http_err.into();
        assert!(matches!(err, GoogleCalendarError::Http(_)));
    }

    // ── GCalResult type alias tests ────────────────────────────────────────

    #[test]
    fn gcal_result_ok() {
        let result: GCalResult<i32> = Ok(42);
        assert!(matches!(result, Ok(42)));
    }

    #[test]
    fn gcal_result_err() {
        let result: GCalResult<i32> = Err(GoogleCalendarError::Unauthorized);
        assert!(result.is_err());
    }

    // ── Edge case tests ────────────────────────────────────────────────────

    #[test]
    fn api_error_empty_message() {
        let err = GoogleCalendarError::Api {
            code: 500,
            message: String::new(),
        };
        assert_eq!(err.to_string(), "Google Calendar API error:  (code: 500)");
        // to_fcp_error should still work with empty message
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::External { .. }));
    }

    #[test]
    fn api_error_unusual_code() {
        // A code that doesn't match any special branch (not 401/404/429/500/502/503)
        let err = GoogleCalendarError::Api {
            code: 418,
            message: "I'm a teapot".into(),
        };
        assert!(!err.is_retryable());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                status_code,
                retryable,
                message,
                ..
            } => {
                assert_eq!(status_code, Some(418));
                assert!(!retryable);
                assert_eq!(message, "I'm a teapot");
            }
            other => panic!("Expected FcpError::External, got: {other:?}"),
        }
    }

    #[test]
    fn event_not_found_empty_id() {
        let err = GoogleCalendarError::EventNotFound {
            event_id: String::new(),
        };
        assert_eq!(err.to_string(), "Event not found: ");
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "event:");
            }
            other => panic!("Expected FcpError::ResourceNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn calendar_not_found_empty_id() {
        let err = GoogleCalendarError::CalendarNotFound {
            calendar_id: String::new(),
        };
        assert_eq!(err.to_string(), "Calendar not found: ");
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "calendar:");
            }
            other => panic!("Expected FcpError::ResourceNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn api_error_retry_after_is_none_even_for_retryable_codes() {
        // retry_after only returns Some for RateLimited variant, not Api variant
        for code in [429, 500, 502, 503] {
            let err = GoogleCalendarError::Api {
                code,
                message: String::new(),
            };
            assert!(
                err.retry_after().is_none(),
                "Api(code={code}) should have no retry_after"
            );
        }
    }

    #[test]
    fn fcp_error_api_external_has_correct_service_name() {
        // All External mappings should use "google-calendar" as service
        for code in [400, 403, 418, 500, 502, 503] {
            let err = GoogleCalendarError::Api {
                code,
                message: "test".into(),
            };
            let fcp = err.to_fcp_error();
            if let FcpError::External { service, .. } = fcp {
                assert_eq!(
                    service, "google-calendar",
                    "service should be google-calendar for code {code}"
                );
            }
            // 401/404/429 map to different variants, skip those
        }
    }

    #[test]
    fn fcp_error_api_external_retry_after_is_none() {
        // Api errors that map to External have retry_after=None (since Api.retry_after() is None)
        let err = GoogleCalendarError::Api {
            code: 500,
            message: "error".into(),
        };
        let fcp = err.to_fcp_error();
        if let FcpError::External { retry_after, .. } = fcp {
            assert!(retry_after.is_none());
        } else {
            panic!("Expected FcpError::External");
        }
    }

    #[test]
    fn fcp_error_http_retry_after_is_none() {
        // Http errors map to External with retry_after from self.retry_after() which is None
        let http_err = reqwest::Client::new().get("://bad").build().unwrap_err();
        let err = GoogleCalendarError::Http(http_err);
        let fcp = err.to_fcp_error();
        if let FcpError::External { retry_after, .. } = fcp {
            assert!(retry_after.is_none());
        } else {
            panic!("Expected FcpError::External");
        }
    }
}
