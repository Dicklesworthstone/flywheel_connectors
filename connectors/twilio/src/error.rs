//! Twilio-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;

/// Twilio API error.
#[derive(Debug, thiserror::Error)]
pub enum TwilioError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Twilio API error: {message}")]
    Api {
        message: String,
        status_code: Option<u16>,
        error_code: Option<String>,
    },

    #[error("Rate limited")]
    RateLimited { retry_after_ms: u64 },

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Not found: {resource}")]
    NotFound { resource: String },

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

pub type TwilioResult<T> = Result<T, TwilioError>;

impl TwilioError {
    /// Check if this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, Some(500..=599 | 429)),
            Self::Json(_) | Self::Unauthorized | Self::NotFound { .. } | Self::InvalidInput(_) => {
                false
            }
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "twilio".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::Api {
                message,
                status_code,
                ..
            } => {
                if *status_code == Some(401) || *status_code == Some(403) {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: message.clone(),
                    }
                } else if *status_code == Some(429) {
                    FcpError::RateLimited {
                        retry_after_ms: 60_000,
                        violation: None,
                    }
                } else {
                    FcpError::External {
                        service: "twilio".into(),
                        message: message.clone(),
                        status_code: *status_code,
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Twilio API authentication failed".into(),
            },
            Self::NotFound { resource } => FcpError::ResourceNotFound {
                resource: resource.clone(),
            },
            Self::InvalidInput(message) => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
        }
    }
}

impl ConnectorErrorMapping for TwilioError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                message: format!("deadline exceeded after {timeout_ms}ms"),
                status_code: Some(408),
                error_code: None,
            },
            AsyncError::Cancelled => Self::Api {
                message: "request cancelled".into(),
                status_code: None,
                error_code: None,
            },
            other => Self::Api {
                message: other.to_string(),
                status_code: None,
                error_code: None,
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

    // ── Display message tests ────────────────────────────────────────────

    #[test]
    fn display_http_error() {
        // We cannot easily construct a reqwest::Error, so test via From trait
        // by checking the other Display variants that we can construct.
        let err = TwilioError::Api {
            message: "something broke".into(),
            status_code: Some(500),
            error_code: None,
        };
        let display = format!("{err}");
        assert_eq!(display, "Twilio API error: something broke");
    }

    #[test]
    fn display_json_error() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("{{bad}}").unwrap_err();
        let err = TwilioError::Json(json_err);
        let display = format!("{err}");
        assert!(display.starts_with("JSON error: "), "got: {display}");
    }

    #[test]
    fn display_api_error() {
        let err = TwilioError::Api {
            message: "Account suspended".into(),
            status_code: Some(403),
            error_code: Some("20006".into()),
        };
        assert_eq!(format!("{err}"), "Twilio API error: Account suspended");
    }

    #[test]
    fn display_rate_limited() {
        let err = TwilioError::RateLimited {
            retry_after_ms: 5000,
        };
        assert_eq!(format!("{err}"), "Rate limited");
    }

    #[test]
    fn display_unauthorized() {
        let err = TwilioError::Unauthorized;
        assert_eq!(format!("{err}"), "Unauthorized");
    }

    #[test]
    fn display_not_found() {
        let err = TwilioError::NotFound {
            resource: "message:SM999".into(),
        };
        assert_eq!(format!("{err}"), "Not found: message:SM999");
    }

    // ── is_retryable tests ───────────────────────────────────────────────

    #[test]
    fn retryable_rate_limited() {
        assert!(TwilioError::RateLimited { retry_after_ms: 1 }.is_retryable());
    }

    #[test]
    fn retryable_api_429() {
        assert!(
            TwilioError::Api {
                message: String::new(),
                status_code: Some(429),
                error_code: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn retryable_api_5xx_range() {
        for code in [500, 501, 502, 503, 504, 599] {
            let err = TwilioError::Api {
                message: String::new(),
                status_code: Some(code),
                error_code: None,
            };
            assert!(err.is_retryable(), "API {code} should be retryable");
        }
    }

    #[test]
    fn not_retryable_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        assert!(!TwilioError::Json(json_err).is_retryable());
    }

    #[test]
    fn not_retryable_unauthorized() {
        assert!(!TwilioError::Unauthorized.is_retryable());
    }

    #[test]
    fn not_retryable_not_found() {
        assert!(
            !TwilioError::NotFound {
                resource: "x".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_4xx_non_429() {
        for code in [400, 401, 403, 404, 405, 409, 422] {
            let err = TwilioError::Api {
                message: String::new(),
                status_code: Some(code),
                error_code: None,
            };
            assert!(!err.is_retryable(), "API {code} should NOT be retryable");
        }
    }

    #[test]
    fn not_retryable_api_no_status_code() {
        let err = TwilioError::Api {
            message: "no status".into(),
            status_code: None,
            error_code: None,
        };
        assert!(!err.is_retryable());
    }

    // ── retry_after tests ────────────────────────────────────────────────

    #[test]
    fn retry_after_rate_limited_returns_duration() {
        let err = TwilioError::RateLimited {
            retry_after_ms: 3000,
        };
        let dur = err.retry_after().expect("should have retry_after");
        assert_eq!(dur.as_millis(), 3000);
    }

    #[test]
    fn retry_after_rate_limited_zero_ms() {
        let err = TwilioError::RateLimited { retry_after_ms: 0 };
        let dur = err.retry_after().expect("should have retry_after");
        assert_eq!(dur.as_millis(), 0);
    }

    #[test]
    fn retry_after_none_for_non_rate_limited_variants() {
        assert!(TwilioError::Unauthorized.retry_after().is_none());
        assert!(
            TwilioError::NotFound {
                resource: "x".into()
            }
            .retry_after()
            .is_none()
        );
        assert!(
            TwilioError::Api {
                message: String::new(),
                status_code: Some(429),
                error_code: None,
            }
            .retry_after()
            .is_none()
        );
        assert!(
            TwilioError::Api {
                message: String::new(),
                status_code: Some(500),
                error_code: None,
            }
            .retry_after()
            .is_none()
        );
    }

    // ── to_fcp_error mapping tests ───────────────────────────────────────

    #[test]
    fn fcp_json_maps_to_internal() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = TwilioError::Json(json_err);
        let fcp = err.to_fcp_error();
        assert!(matches!(
            &fcp,
            FcpError::Internal { message } if message.contains("JSON error")
        ));
    }

    #[test]
    fn fcp_api_401_maps_to_unauthorized() {
        let err = TwilioError::Api {
            message: "bad creds".into(),
            status_code: Some(401),
            error_code: None,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            &fcp,
            FcpError::Unauthorized { code: 2001, message } if message == "bad creds"
        ));
    }

    #[test]
    fn fcp_api_403_maps_to_unauthorized() {
        let err = TwilioError::Api {
            message: "forbidden".into(),
            status_code: Some(403),
            error_code: None,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            &fcp,
            FcpError::Unauthorized { code: 2001, message } if message == "forbidden"
        ));
    }

    #[test]
    fn fcp_api_429_maps_to_rate_limited_with_60s() {
        let err = TwilioError::Api {
            message: "rate limited".into(),
            status_code: Some(429),
            error_code: None,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            &fcp,
            FcpError::RateLimited {
                retry_after_ms: 60_000,
                violation: None,
            }
        ));
    }

    #[test]
    fn fcp_api_500_maps_to_retryable_external() {
        let err = TwilioError::Api {
            message: "server error".into(),
            status_code: Some(500),
            error_code: None,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            &fcp,
            FcpError::External {
                service,
                message,
                status_code: Some(500),
                retryable: true,
                ..
            } if service == "twilio" && message == "server error"
        ));
    }

    #[test]
    fn fcp_api_502_503_map_to_retryable_external() {
        for code in [502, 503] {
            let err = TwilioError::Api {
                message: format!("error {code}"),
                status_code: Some(code),
                error_code: None,
            };
            let fcp = err.to_fcp_error();
            assert!(matches!(
                &fcp,
                FcpError::External {
                    retryable: true,
                    status_code: Some(status_code),
                    ..
                } if *status_code == code
            ));
        }
    }

    #[test]
    fn fcp_api_no_status_maps_to_external_not_retryable() {
        let err = TwilioError::Api {
            message: "unknown".into(),
            status_code: None,
            error_code: Some("20003".into()),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            &fcp,
            FcpError::External {
                service,
                message,
                status_code: None,
                retryable: false,
                ..
            } if service == "twilio" && message == "unknown"
        ));
    }

    #[test]
    fn fcp_api_400_maps_to_non_retryable_external() {
        let err = TwilioError::Api {
            message: "bad request".into(),
            status_code: Some(400),
            error_code: None,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            &fcp,
            FcpError::External {
                retryable: false,
                status_code: Some(400),
                ..
            }
        ));
    }

    #[test]
    fn fcp_rate_limited_variant_preserves_ms() {
        let err = TwilioError::RateLimited {
            retry_after_ms: 5000,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            &fcp,
            FcpError::RateLimited {
                retry_after_ms: 5000,
                violation: None,
            }
        ));
    }

    #[test]
    fn fcp_rate_limited_zero_ms() {
        let err = TwilioError::RateLimited { retry_after_ms: 0 };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::RateLimited {
                retry_after_ms: 0,
                violation: None,
            }
        ));
    }

    #[test]
    fn fcp_unauthorized_variant() {
        let err = TwilioError::Unauthorized;
        let fcp = err.to_fcp_error();
        assert!(matches!(
            &fcp,
            FcpError::Unauthorized { code: 2001, message }
                if message == "Twilio API authentication failed"
        ));
    }

    #[test]
    fn fcp_not_found_preserves_resource() {
        let err = TwilioError::NotFound {
            resource: "message:SM123".into(),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            &fcp,
            FcpError::ResourceNotFound { resource } if resource == "message:SM123"
        ));
    }

    #[test]
    fn fcp_not_found_empty_resource() {
        let err = TwilioError::NotFound {
            resource: String::new(),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            &fcp,
            FcpError::ResourceNotFound { resource } if resource.is_empty()
        ));
    }

    // ── Debug format tests ───────────────────────────────────────────────

    #[test]
    fn debug_format_all_variants() {
        let variants: Vec<TwilioError> = vec![
            TwilioError::Api {
                message: "err".into(),
                status_code: Some(500),
                error_code: Some("20001".into()),
            },
            TwilioError::RateLimited {
                retry_after_ms: 1000,
            },
            TwilioError::Unauthorized,
            TwilioError::NotFound {
                resource: "call:CA1".into(),
            },
        ];
        for v in &variants {
            let debug = format!("{v:?}");
            assert!(!debug.is_empty(), "Debug should produce non-empty output");
        }
    }

    #[test]
    fn debug_api_contains_fields() {
        let err = TwilioError::Api {
            message: "test msg".into(),
            status_code: Some(422),
            error_code: Some("21211".into()),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("test msg"), "debug: {debug}");
        assert!(debug.contains("422"), "debug: {debug}");
        assert!(debug.contains("21211"), "debug: {debug}");
    }

    // ── std::error::Error trait tests ────────────────────────────────────

    #[test]
    fn error_trait_source_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        let err = TwilioError::Json(json_err);
        // Json variant has #[from] so source() should return Some
        let source = std::error::Error::source(&err);
        assert!(source.is_some(), "Json variant should have a source");
    }

    #[test]
    fn error_trait_source_api_none() {
        let err = TwilioError::Api {
            message: "x".into(),
            status_code: None,
            error_code: None,
        };
        let source = std::error::Error::source(&err);
        assert!(source.is_none(), "Api variant should have no source");
    }

    #[test]
    fn error_trait_source_rate_limited_none() {
        let err = TwilioError::RateLimited {
            retry_after_ms: 100,
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn error_trait_source_unauthorized_none() {
        assert!(std::error::Error::source(&TwilioError::Unauthorized).is_none());
    }

    #[test]
    fn error_trait_source_not_found_none() {
        let err = TwilioError::NotFound {
            resource: "r".into(),
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    // ── From trait conversion tests ──────────────────────────────────────

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("nope").unwrap_err();
        let err: TwilioError = json_err.into();
        assert!(matches!(err, TwilioError::Json(_)));
        assert!(!err.is_retryable());
    }

    // ── Edge case tests ──────────────────────────────────────────────────

    #[test]
    fn api_with_empty_message() {
        let err = TwilioError::Api {
            message: String::new(),
            status_code: Some(500),
            error_code: None,
        };
        assert_eq!(format!("{err}"), "Twilio API error: ");
        assert!(err.is_retryable());
        let fcp = err.to_fcp_error();
        assert!(matches!(
            &fcp,
            FcpError::External { message, .. } if message.is_empty()
        ));
    }

    #[test]
    fn api_with_error_code_and_no_status() {
        let err = TwilioError::Api {
            message: "something".into(),
            status_code: None,
            error_code: Some("30008".into()),
        };
        // No status code means not retryable, maps to External
        assert!(!err.is_retryable());
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::External { .. }));
    }

    #[test]
    fn rate_limited_large_retry_after() {
        let err = TwilioError::RateLimited {
            retry_after_ms: u64::MAX,
        };
        let dur = err.retry_after().unwrap();
        assert_eq!(dur.as_millis(), u128::from(u64::MAX));
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::RateLimited {
                retry_after_ms,
                ..
            } if retry_after_ms == u64::MAX
        ));
    }

    #[test]
    fn fcp_api_message_preserved_in_unauthorized_mapping() {
        let err = TwilioError::Api {
            message: "Custom auth failure message".into(),
            status_code: Some(401),
            error_code: Some("20003".into()),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            &fcp,
            FcpError::Unauthorized { message, .. } if message == "Custom auth failure message"
        ));
    }

    #[test]
    fn fcp_external_service_is_always_twilio() {
        for code in [400, 404, 500, 502] {
            let err = TwilioError::Api {
                message: "x".into(),
                status_code: Some(code),
                error_code: None,
            };
            let fcp = err.to_fcp_error();
            if let FcpError::External { service, .. } = fcp {
                assert_eq!(service, "twilio");
            }
        }
    }

    #[test]
    fn fcp_external_retry_after_is_none_for_api_errors() {
        // Api errors never have retry_after (only RateLimited variant does)
        let err = TwilioError::Api {
            message: "x".into(),
            status_code: Some(503),
            error_code: None,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            &fcp,
            FcpError::External { retry_after, .. } if retry_after.is_none()
        ));
    }

    // ── Additional edge cases ───────────────────────────────────────────

    #[test]
    fn api_error_with_all_fields_set() {
        let err = TwilioError::Api {
            message: "Queue overflow".into(),
            status_code: Some(503),
            error_code: Some("30010".into()),
        };
        assert!(err.is_retryable());
        let fcp = err.to_fcp_error();
        assert!(matches!(
            &fcp,
            FcpError::External {
                service,
                message,
                retryable: true,
                ..
            } if service == "twilio" && message == "Queue overflow"
        ));
    }

    #[test]
    fn not_found_with_empty_resource_display() {
        let err = TwilioError::NotFound {
            resource: String::new(),
        };
        assert_eq!(format!("{err}"), "Not found: ");
    }

    #[test]
    fn rate_limited_with_one_ms() {
        let err = TwilioError::RateLimited { retry_after_ms: 1 };
        let dur = err.retry_after().unwrap();
        assert_eq!(dur.as_millis(), 1);
        assert!(err.is_retryable());
    }

    #[test]
    fn api_with_unicode_message() {
        let err = TwilioError::Api {
            message: "Error: \u{1F6D1} service down".into(),
            status_code: Some(500),
            error_code: None,
        };
        let display = format!("{err}");
        assert!(display.contains("\u{1F6D1}"));
    }

    #[test]
    fn fcp_api_404_maps_to_external_not_retryable() {
        let err = TwilioError::Api {
            message: "resource gone".into(),
            status_code: Some(404),
            error_code: None,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            &fcp,
            FcpError::External {
                retryable: false,
                status_code: Some(404),
                ..
            }
        ));
    }

    #[test]
    fn fcp_api_422_maps_to_external_not_retryable() {
        let err = TwilioError::Api {
            message: "unprocessable entity".into(),
            status_code: Some(422),
            error_code: Some("21611".into()),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            &fcp,
            FcpError::External {
                retryable: false,
                status_code: Some(422),
                service,
                ..
            } if service == "twilio"
        ));
    }

    #[test]
    fn is_retryable_api_504_gateway_timeout() {
        let err = TwilioError::Api {
            message: "gateway timeout".into(),
            status_code: Some(504),
            error_code: None,
        };
        assert!(err.is_retryable());
    }
}
