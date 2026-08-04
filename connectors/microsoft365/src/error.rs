//! Microsoft 365 Graph API error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;

/// Microsoft 365 Graph API error.
#[derive(Debug, thiserror::Error)]
pub enum M365Error {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Graph API error: {message}")]
    Api {
        message: String,
        status_code: Option<u16>,
        error_code: Option<String>,
    },

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Rate limited")]
    RateLimit { retry_after_ms: u64 },
}

pub type M365Result<T> = Result<T, M365Error>;

impl M365Error {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimit { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, Some(500..=599 | 429)),
            Self::Serialization(_) | Self::InvalidConfig(_) => false,
        }
    }

    /// Whether replaying the request that produced this error cannot duplicate
    /// a side effect (br-kxd3e).
    ///
    /// Distinct from [`Self::is_retryable`]: Graph throttles a request WITHOUT
    /// performing it, so a 429 is safe to replay; a 5xx means Graph received
    /// the request and may already have sent the mail or created the event.
    #[must_use]
    pub fn replay_is_safe(&self) -> bool {
        match self {
            Self::RateLimit { .. } => true,
            Self::Api { status_code, .. } => *status_code == Some(429),
            Self::Http(e) => !fcp_sdk::migration::transport_error_reached_service(e),
            Self::Serialization(_) | Self::InvalidConfig(_) => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimit { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "microsoft365".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Serialization(e) => FcpError::Internal {
                message: format!("Serialization error: {e}"),
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
                } else if *status_code == Some(404) {
                    FcpError::ResourceNotFound {
                        resource: message.clone(),
                    }
                } else if *status_code == Some(429) {
                    FcpError::RateLimited {
                        retry_after_ms: 60_000,
                        violation: None,
                    }
                } else {
                    FcpError::External {
                        service: "microsoft365".into(),
                        message: message.clone(),
                        status_code: *status_code,
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::InvalidConfig(msg) => FcpError::InvalidRequest {
                code: 1003,
                message: msg.clone(),
            },
            Self::RateLimit { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
        }
    }
}

impl ConnectorErrorMapping for M365Error {
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

    // ---- is_retryable ----

    #[test]
    fn rate_limit_is_retryable() {
        let err = M365Error::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn serialization_error_not_retryable() {
        let inner = serde_json::from_str::<serde_json::Value>("bad json").unwrap_err();
        let err = M365Error::Serialization(inner);
        assert!(!err.is_retryable());
    }

    #[test]
    fn invalid_config_not_retryable() {
        let err = M365Error::InvalidConfig("missing field".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_500_is_retryable() {
        let err = M365Error::Api {
            message: "server error".into(),
            status_code: Some(500),
            error_code: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_503_is_retryable() {
        let err = M365Error::Api {
            message: "service unavailable".into(),
            status_code: Some(503),
            error_code: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_429_is_retryable() {
        let err = M365Error::Api {
            message: "throttled".into(),
            status_code: Some(429),
            error_code: Some("TooManyRequests".into()),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_400_not_retryable() {
        let err = M365Error::Api {
            message: "bad request".into(),
            status_code: Some(400),
            error_code: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_404_not_retryable() {
        let err = M365Error::Api {
            message: "not found".into(),
            status_code: Some(404),
            error_code: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_no_status_not_retryable() {
        let err = M365Error::Api {
            message: "unknown".into(),
            status_code: None,
            error_code: None,
        };
        assert!(!err.is_retryable());
    }

    // ---- retry_after ----

    #[test]
    fn rate_limit_has_retry_after() {
        let err = M365Error::RateLimit {
            retry_after_ms: 5000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn non_rate_limit_errors_have_no_retry_after() {
        let err = M365Error::InvalidConfig("bad".into());
        assert_eq!(err.retry_after(), None);

        let err = M365Error::Api {
            message: "error".into(),
            status_code: Some(500),
            error_code: None,
        };
        assert_eq!(err.retry_after(), None);
    }

    // ---- to_fcp_error ----

    #[test]
    fn api_401_maps_to_unauthorized() {
        let err = M365Error::Api {
            message: "access denied".into(),
            status_code: Some(401),
            error_code: Some("Unauthorized".into()),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("access denied"));
            }
            other => panic!("Expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn api_403_maps_to_unauthorized() {
        let err = M365Error::Api {
            message: "forbidden".into(),
            status_code: Some(403),
            error_code: None,
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, .. } => assert_eq!(code, 2001),
            other => panic!("Expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn api_404_maps_to_resource_not_found() {
        let err = M365Error::Api {
            message: "message not found".into(),
            status_code: Some(404),
            error_code: None,
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.contains("message not found"));
            }
            other => panic!("Expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn api_429_maps_to_rate_limited() {
        let err = M365Error::Api {
            message: "throttled".into(),
            status_code: Some(429),
            error_code: None,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, 60_000);
            }
            other => panic!("Expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn api_500_maps_to_external() {
        let err = M365Error::Api {
            message: "internal error".into(),
            status_code: Some(500),
            error_code: None,
        };
        match err.to_fcp_error() {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "microsoft365");
                assert!(retryable);
            }
            other => panic!("Expected External, got {other:?}"),
        }
    }

    #[test]
    fn serialization_error_maps_to_internal() {
        let inner = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = M365Error::Serialization(inner);
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.contains("Serialization error"));
            }
            other => panic!("Expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn invalid_config_maps_to_invalid_request() {
        let err = M365Error::InvalidConfig("bad config".into());
        match err.to_fcp_error() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert!(message.contains("bad config"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn rate_limit_maps_to_rate_limited() {
        let err = M365Error::RateLimit {
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

    // ---- Display ----

    #[test]
    fn error_display_messages() {
        assert_eq!(
            M365Error::InvalidConfig("no token".into()).to_string(),
            "Invalid configuration: no token"
        );
        assert_eq!(
            M365Error::RateLimit { retry_after_ms: 0 }.to_string(),
            "Rate limited"
        );
        let api_err = M365Error::Api {
            message: "test error".into(),
            status_code: Some(500),
            error_code: None,
        };
        assert!(api_err.to_string().contains("test error"));
    }

    // ---- Display for all variants (content verification) ----

    #[test]
    fn display_invalid_config_contains_inner_message() {
        let err = M365Error::InvalidConfig("tenant_id missing".into());
        let display = err.to_string();
        assert_eq!(display, "Invalid configuration: tenant_id missing");
    }

    #[test]
    fn display_api_contains_message_field() {
        let err = M365Error::Api {
            message: "Request_BadRequest".into(),
            status_code: Some(400),
            error_code: Some("BadRequest".into()),
        };
        let display = err.to_string();
        assert_eq!(display, "Graph API error: Request_BadRequest");
    }

    #[test]
    fn display_rate_limit_is_static() {
        let err = M365Error::RateLimit {
            retry_after_ms: 999_999,
        };
        assert_eq!(err.to_string(), "Rate limited");
    }

    #[test]
    fn display_serialization_contains_serde_message() {
        let inner = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let inner_msg = inner.to_string();
        let err = M365Error::Serialization(inner);
        let display = err.to_string();
        assert!(
            display.contains(&inner_msg),
            "Expected display '{display}' to contain serde message '{inner_msg}'"
        );
        assert!(display.starts_with("Serialization error: "));
    }

    // ---- Debug formatting ----

    #[test]
    fn debug_format_contains_variant_name() {
        let err = M365Error::InvalidConfig("x".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidConfig"), "got: {debug}");

        let err2 = M365Error::RateLimit { retry_after_ms: 42 };
        let debug2 = format!("{err2:?}");
        assert!(debug2.contains("RateLimit"), "got: {debug2}");
        assert!(debug2.contains("42"), "got: {debug2}");

        let err3 = M365Error::Api {
            message: "boom".into(),
            status_code: Some(500),
            error_code: Some("InternalError".into()),
        };
        let debug3 = format!("{err3:?}");
        assert!(debug3.contains("Api"), "got: {debug3}");
        assert!(debug3.contains("boom"), "got: {debug3}");
        assert!(debug3.contains("InternalError"), "got: {debug3}");
    }

    // ---- M365Result Ok and Err usage ----

    #[test]
    fn m365result_ok_unwraps() {
        let result: M365Result<u32> = Ok(42);
        let Ok(val) = result else {
            panic!("expected Ok")
        };
        assert_eq!(val, 42);
    }

    #[test]
    fn m365result_err_is_err() {
        let result: M365Result<u32> = Err(M365Error::InvalidConfig("bad".into()));
        assert!(result.is_err());
        let Err(err) = result else {
            panic!("expected Err")
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn m365result_with_complex_type() {
        let result: M365Result<Vec<String>> = Ok(vec!["hello".into()]);
        let Ok(val) = result else {
            panic!("expected Ok")
        };
        assert_eq!(val.len(), 1);
    }

    // ---- From serde_json::Error conversion ----

    #[test]
    fn from_serde_json_error() {
        let serde_err = serde_json::from_str::<bool>("not_bool").unwrap_err();
        let err: M365Error = serde_err.into();
        match &err {
            M365Error::Serialization(_) => {}
            other => panic!("Expected Serialization, got {other:?}"),
        }
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    // ---- Error trait (dyn std::error::Error) ----

    #[test]
    fn error_trait_is_object_safe() {
        let err = M365Error::InvalidConfig("oops".into());
        let boxed: Box<dyn std::error::Error> = Box::new(err);
        assert!(boxed.to_string().contains("oops"));
    }

    #[test]
    fn error_trait_source_for_serialization() {
        let inner = serde_json::from_str::<u32>("null").unwrap_err();
        let err = M365Error::Serialization(inner);
        let dyn_err: &dyn std::error::Error = &err;
        // Serialization variant wraps a serde error, so source should be Some
        assert!(dyn_err.source().is_some());
    }

    #[test]
    fn error_trait_source_for_non_wrapping_variants() {
        let err = M365Error::InvalidConfig("test".into());
        let dyn_err: &dyn std::error::Error = &err;
        // InvalidConfig doesn't wrap another error
        assert!(dyn_err.source().is_none());

        let err2 = M365Error::RateLimit {
            retry_after_ms: 100,
        };
        let dyn_err2: &dyn std::error::Error = &err2;
        assert!(dyn_err2.source().is_none());
    }

    // ---- to_fcp_error: Api with error_code set ----

    #[test]
    fn to_fcp_error_api_with_error_code_passes_message() {
        let err = M365Error::Api {
            message: "insufficient permissions".into(),
            status_code: Some(403),
            error_code: Some("Authorization_RequestDenied".into()),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert_eq!(message, "insufficient permissions");
            }
            other => panic!("Expected Unauthorized, got {other:?}"),
        }
    }

    // ---- to_fcp_error: Api with no status_code maps to External ----

    #[test]
    fn to_fcp_error_api_no_status_code_maps_to_external() {
        let err = M365Error::Api {
            message: "connection lost".into(),
            status_code: None,
            error_code: None,
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                retry_after,
            } => {
                assert_eq!(service, "microsoft365");
                assert_eq!(message, "connection lost");
                assert!(status_code.is_none());
                assert!(!retryable);
                assert!(retry_after.is_none());
            }
            other => panic!("Expected External, got {other:?}"),
        }
    }

    // ---- Api edge status codes ----

    #[test]
    fn api_200_as_error_maps_to_external_not_retryable() {
        let err = M365Error::Api {
            message: "unexpected success status as error".into(),
            status_code: Some(200),
            error_code: None,
        };
        assert!(!err.is_retryable());
        match err.to_fcp_error() {
            FcpError::External {
                retryable,
                status_code,
                ..
            } => {
                assert!(!retryable);
                assert_eq!(status_code, Some(200));
            }
            other => panic!("Expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_502_is_retryable_maps_to_external() {
        let err = M365Error::Api {
            message: "bad gateway".into(),
            status_code: Some(502),
            error_code: None,
        };
        assert!(err.is_retryable());
        match err.to_fcp_error() {
            FcpError::External {
                retryable,
                status_code,
                ..
            } => {
                assert!(retryable);
                assert_eq!(status_code, Some(502));
            }
            other => panic!("Expected External, got {other:?}"),
        }
    }

    // ---- RateLimit with retry_after_ms = 0 ----

    #[test]
    fn rate_limit_zero_retry_after() {
        let err = M365Error::RateLimit { retry_after_ms: 0 };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 0);
                assert!(violation.is_none());
            }
            other => panic!("Expected RateLimited, got {other:?}"),
        }
    }

    // ---- InvalidConfig with empty string ----

    #[test]
    fn invalid_config_empty_string() {
        let err = M365Error::InvalidConfig(String::new());
        assert_eq!(err.to_string(), "Invalid configuration: ");
        assert!(!err.is_retryable());
        match err.to_fcp_error() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert_eq!(message, "");
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    // ---- is_retryable boundary: Api 599 ----

    #[test]
    fn api_599_is_retryable() {
        let err = M365Error::Api {
            message: "edge of 5xx range".into(),
            status_code: Some(599),
            error_code: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_600_not_retryable() {
        let err = M365Error::Api {
            message: "above 5xx range".into(),
            status_code: Some(600),
            error_code: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn api_499_not_retryable() {
        let err = M365Error::Api {
            message: "below 5xx range (not 429)".into(),
            status_code: Some(499),
            error_code: None,
        };
        assert!(!err.is_retryable());
    }

    // ---- Verify all to_fcp_error branches ----

    #[test]
    fn to_fcp_error_serialization_is_internal() {
        let inner = serde_json::from_str::<serde_json::Value>("[}").unwrap_err();
        let err = M365Error::Serialization(inner);
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.starts_with("Serialization error: "));
            }
            other => panic!("Expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limit_large_value() {
        let err = M365Error::RateLimit {
            retry_after_ms: u64::MAX,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, u64::MAX);
            }
            other => panic!("Expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_401_message_preserved() {
        let err = M365Error::Api {
            message: "CompactToken validation failed".into(),
            status_code: Some(401),
            error_code: Some("InvalidAuthenticationToken".into()),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { message, .. } => {
                assert_eq!(message, "CompactToken validation failed");
            }
            other => panic!("Expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_404_message_preserved() {
        let err = M365Error::Api {
            message: "User 'abc' not found".into(),
            status_code: Some(404),
            error_code: Some("Request_ResourceNotFound".into()),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "User 'abc' not found");
            }
            other => panic!("Expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_500_external_details() {
        let err = M365Error::Api {
            message: "UnknownError".into(),
            status_code: Some(500),
            error_code: Some("InternalServerError".into()),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                retry_after,
            } => {
                assert_eq!(service, "microsoft365");
                assert_eq!(message, "UnknownError");
                assert_eq!(status_code, Some(500));
                assert!(retryable);
                assert!(retry_after.is_none());
            }
            other => panic!("Expected External, got {other:?}"),
        }
    }
}
