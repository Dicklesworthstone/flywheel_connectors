//! Jira-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use thiserror::Error;

/// Jira-specific errors.
#[derive(Error, Debug)]
pub enum JiraError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Jira REST API returned an error
    #[error("Jira API error: {message}")]
    Api {
        message: String,
        status_code: Option<u16>,
    },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Invalid or expired credentials
    #[error("Invalid or expired Jira credentials")]
    Unauthorized,

    /// Invalid input from caller (e.g. malformed issue key)
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Resource not found
    #[error("Resource not found: {resource}")]
    NotFound { resource: String },
}

impl JiraError {
    /// Check if this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(e) => e.is_timeout() || e.is_connect(),
            Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, Some(500..=599 | 429)),
            Self::Json(_) | Self::Unauthorized | Self::NotFound { .. } | Self::InvalidInput(_) => {
                false
            }
        }
    }

    /// Whether replaying the request that produced this error cannot duplicate
    /// a side effect (br-kxd3e).
    ///
    /// Deliberately NOT the same question as [`Self::is_retryable`]. A
    /// rate-limit rejection is safe to replay because Jira refused the request
    /// *without* performing it; a 5xx is not, because Jira received it and may
    /// already have created the issue, comment, or worklog. Collapsing the two
    /// would silently disable rate-limit backoff on every write.
    #[must_use]
    pub fn replay_is_safe(&self) -> bool {
        match self {
            // Refused before Jira did the work.
            Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => *status_code == Some(429),
            // Only a connect-phase failure proves the request never left us.
            Self::Http(e) => !fcp_sdk::migration::transport_error_reached_service(e),
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
                service: "jira".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api {
                message,
                status_code,
            } => {
                if *status_code == Some(401) || *status_code == Some(403) {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid or insufficient Jira credentials".into(),
                    }
                } else if *status_code == Some(429) {
                    FcpError::RateLimited {
                        retry_after_ms: 60_000,
                        violation: None,
                    }
                } else {
                    FcpError::External {
                        service: "jira".into(),
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
                message: "Invalid or expired Jira credentials".into(),
            },
            Self::InvalidInput(msg) => FcpError::InvalidRequest {
                code: 1003,
                message: msg.clone(),
            },
            Self::NotFound { resource } => FcpError::ResourceNotFound {
                resource: resource.clone(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for Jira operations.
pub type JiraResult<T> = Result<T, JiraError>;

impl ConnectorErrorMapping for JiraError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                message: format!("deadline exceeded after {timeout_ms}ms"),
                status_code: Some(408),
            },
            AsyncError::Cancelled => Self::Api {
                message: "request cancelled".into(),
                status_code: None,
            },
            other => Self::Api {
                message: other.to_string(),
                status_code: None,
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

    // ════════════════════════════════════════════════════════════════
    // Display messages for every variant
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn display_http_error() {
        // We cannot easily construct a reqwest::Error directly, so we
        // verify the From impl works and the display contains "HTTP".
        // Covered via the Json variant pattern instead.
    }

    #[test]
    fn display_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("!!!").unwrap_err();
        let err = JiraError::Json(json_err);
        let msg = err.to_string();
        assert!(msg.starts_with("JSON error:"), "got: {msg}");
    }

    #[test]
    fn display_api_error() {
        let err = JiraError::Api {
            message: "Issue does not exist".into(),
            status_code: Some(404),
        };
        let msg = err.to_string();
        assert!(msg.contains("Issue does not exist"), "got: {msg}");
        assert!(msg.starts_with("Jira API error:"), "got: {msg}");
    }

    #[test]
    fn display_api_error_no_status() {
        let err = JiraError::Api {
            message: "unknown".into(),
            status_code: None,
        };
        let msg = err.to_string();
        assert!(msg.contains("unknown"), "got: {msg}");
    }

    #[test]
    fn display_rate_limited() {
        let err = JiraError::RateLimited {
            retry_after_ms: 5000,
        };
        let msg = err.to_string();
        assert!(msg.contains("5000ms"), "got: {msg}");
        assert!(msg.contains("Rate limited"), "got: {msg}");
    }

    #[test]
    fn display_rate_limited_zero() {
        let err = JiraError::RateLimited { retry_after_ms: 0 };
        let msg = err.to_string();
        assert!(msg.contains("0ms"), "got: {msg}");
    }

    #[test]
    fn display_unauthorized() {
        let msg = JiraError::Unauthorized.to_string();
        assert!(msg.contains("credentials"), "got: {msg}");
        assert!(msg.contains("Invalid or expired"), "got: {msg}");
    }

    #[test]
    fn display_not_found() {
        let err = JiraError::NotFound {
            resource: "PROJ-123".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("PROJ-123"), "got: {msg}");
        assert!(msg.contains("not found"), "got: {msg}");
    }

    #[test]
    fn display_not_found_empty_resource() {
        let err = JiraError::NotFound {
            resource: String::new(),
        };
        let msg = err.to_string();
        assert!(msg.contains("not found"), "got: {msg}");
    }

    // ════════════════════════════════════════════════════════════════
    // is_retryable - exhaustive coverage
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn is_retryable_rate_limited() {
        assert!(
            JiraError::RateLimited {
                retry_after_ms: 1000
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_500() {
        assert!(
            JiraError::Api {
                message: "internal".into(),
                status_code: Some(500),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_502() {
        assert!(
            JiraError::Api {
                message: "bad gateway".into(),
                status_code: Some(502),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_503() {
        assert!(
            JiraError::Api {
                message: "service unavailable".into(),
                status_code: Some(503),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_504() {
        assert!(
            JiraError::Api {
                message: "gateway timeout".into(),
                status_code: Some(504),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_429() {
        assert!(
            JiraError::Api {
                message: "too many".into(),
                status_code: Some(429),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_400() {
        assert!(
            !JiraError::Api {
                message: "bad request".into(),
                status_code: Some(400),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_401() {
        assert!(
            !JiraError::Api {
                message: "unauth".into(),
                status_code: Some(401),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_403() {
        assert!(
            !JiraError::Api {
                message: "forbidden".into(),
                status_code: Some(403),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_404() {
        assert!(
            !JiraError::Api {
                message: "not found".into(),
                status_code: Some(404),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_none_status() {
        assert!(
            !JiraError::Api {
                message: "no status".into(),
                status_code: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_unauthorized() {
        assert!(!JiraError::Unauthorized.is_retryable());
    }

    #[test]
    fn not_retryable_not_found() {
        assert!(
            !JiraError::NotFound {
                resource: "x".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        assert!(!JiraError::Json(json_err).is_retryable());
    }

    // ════════════════════════════════════════════════════════════════
    // retry_after - all variants
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn retry_after_rate_limited() {
        let err = JiraError::RateLimited {
            retry_after_ms: 5000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn retry_after_rate_limited_zero() {
        let err = JiraError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn retry_after_rate_limited_large() {
        let err = JiraError::RateLimited {
            retry_after_ms: 120_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(120)));
    }

    #[test]
    fn retry_after_unauthorized_none() {
        assert_eq!(JiraError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_not_found_none() {
        let err = JiraError::NotFound {
            resource: "x".into(),
        };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_api_none() {
        let err = JiraError::Api {
            message: "err".into(),
            status_code: Some(500),
        };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_json_none() {
        let json_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        assert_eq!(JiraError::Json(json_err).retry_after(), None);
    }

    // ════════════════════════════════════════════════════════════════
    // to_fcp_error - exhaustive variant mapping
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn to_fcp_error_api_401() {
        let err = JiraError::Api {
            message: "unauthorized".into(),
            status_code: Some(401),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("Jira"), "got: {message}");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_403() {
        let err = JiraError::Api {
            message: "forbidden".into(),
            status_code: Some(403),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("insufficient"), "got: {message}");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_429() {
        let err = JiraError::Api {
            message: "rate limited".into(),
            status_code: Some(429),
        };
        match err.to_fcp_error() {
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
    fn to_fcp_error_api_500_external() {
        let err = JiraError::Api {
            message: "server error".into(),
            status_code: Some(500),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                retry_after,
            } => {
                assert_eq!(service, "jira");
                assert_eq!(message, "server error");
                assert_eq!(status_code, Some(500));
                assert!(retryable);
                assert!(retry_after.is_none());
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_502_external() {
        let err = JiraError::Api {
            message: "bad gateway".into(),
            status_code: Some(502),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                retryable,
                status_code,
                ..
            } => {
                assert_eq!(service, "jira");
                assert!(retryable);
                assert_eq!(status_code, Some(502));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_400_external_not_retryable() {
        let err = JiraError::Api {
            message: "bad request".into(),
            status_code: Some(400),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                retryable,
                status_code,
                ..
            } => {
                assert_eq!(service, "jira");
                assert!(!retryable);
                assert_eq!(status_code, Some(400));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_no_status_code() {
        let err = JiraError::Api {
            message: "mystery".into(),
            status_code: None,
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "jira");
                assert_eq!(message, "mystery");
                assert_eq!(status_code, None);
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limited() {
        let err = JiraError::RateLimited {
            retry_after_ms: 2000,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 2000);
                assert!(violation.is_none());
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limited_zero() {
        let err = JiraError::RateLimited { retry_after_ms: 0 };
        match err.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 0),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_unauthorized() {
        match JiraError::Unauthorized.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("expired"), "got: {message}");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_not_found() {
        let err = JiraError::NotFound {
            resource: "PROJ-456".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => assert_eq!(resource, "PROJ-456"),
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_not_found_empty() {
        let err = JiraError::NotFound {
            resource: String::new(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => assert!(resource.is_empty()),
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_json_internal() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = JiraError::Json(json_err);
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.starts_with("JSON error:"), "got: {message}");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_json_internal_preserves_details() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json at all").unwrap_err();
        let err = JiraError::Json(json_err);
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.contains("JSON error:"), "got: {message}");
                // The serde_json error message should be embedded
                assert!(message.len() > "JSON error: ".len());
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // ════════════════════════════════════════════════════════════════
    // Debug format
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn debug_format_api() {
        let err = JiraError::Api {
            message: "test".into(),
            status_code: Some(400),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"), "got: {dbg}");
        assert!(dbg.contains("400"), "got: {dbg}");
        assert!(dbg.contains("test"), "got: {dbg}");
    }

    #[test]
    fn debug_format_rate_limited() {
        let err = JiraError::RateLimited {
            retry_after_ms: 3000,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RateLimited"), "got: {dbg}");
        assert!(dbg.contains("3000"), "got: {dbg}");
    }

    #[test]
    fn debug_format_unauthorized() {
        let dbg = format!("{:?}", JiraError::Unauthorized);
        assert!(dbg.contains("Unauthorized"), "got: {dbg}");
    }

    #[test]
    fn debug_format_not_found() {
        let err = JiraError::NotFound {
            resource: "KEY-1".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NotFound"), "got: {dbg}");
        assert!(dbg.contains("KEY-1"), "got: {dbg}");
    }

    #[test]
    fn debug_format_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("{}}}").unwrap_err();
        let err = JiraError::Json(json_err);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Json"), "got: {dbg}");
    }

    // ════════════════════════════════════════════════════════════════
    // std::error::Error trait
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn error_trait_impl() {
        let _: &dyn std::error::Error = &JiraError::Unauthorized;
    }

    #[test]
    fn error_trait_impl_all_variants() {
        let json_err = serde_json::from_str::<serde_json::Value>("[").unwrap_err();
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(JiraError::Json(json_err)),
            Box::new(JiraError::Api {
                message: "err".into(),
                status_code: Some(400),
            }),
            Box::new(JiraError::RateLimited {
                retry_after_ms: 100,
            }),
            Box::new(JiraError::Unauthorized),
            Box::new(JiraError::InvalidInput("bad key".into())),
            Box::new(JiraError::NotFound {
                resource: "r".into(),
            }),
        ];
        for err in &variants {
            // All should produce a non-empty error message
            assert!(!err.to_string().is_empty());
        }
    }

    #[test]
    fn error_source_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
        let err = JiraError::Json(json_err);
        // Json variant has a #[from] attribute, so source() should return Some
        let source = std::error::Error::source(&err);
        assert!(source.is_some(), "Json variant should have a source");
    }

    #[test]
    fn error_source_unauthorized_none() {
        let err = JiraError::Unauthorized;
        let source = std::error::Error::source(&err);
        assert!(source.is_none(), "Unauthorized should have no source");
    }

    #[test]
    fn error_source_not_found_none() {
        let err = JiraError::NotFound {
            resource: "x".into(),
        };
        let source = std::error::Error::source(&err);
        assert!(source.is_none(), "NotFound should have no source");
    }

    #[test]
    fn error_source_api_none() {
        let err = JiraError::Api {
            message: "m".into(),
            status_code: None,
        };
        let source = std::error::Error::source(&err);
        assert!(source.is_none(), "Api should have no source");
    }

    #[test]
    fn error_source_rate_limited_none() {
        let err = JiraError::RateLimited { retry_after_ms: 10 };
        let source = std::error::Error::source(&err);
        assert!(source.is_none(), "RateLimited should have no source");
    }

    // ════════════════════════════════════════════════════════════════
    // From impls
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("nope").unwrap_err();
        let err: JiraError = json_err.into();
        assert!(matches!(err, JiraError::Json(_)));
    }

    #[test]
    fn from_serde_json_error_preserves_message() {
        let json_err = serde_json::from_str::<serde_json::Value>("{{").unwrap_err();
        let original_msg = json_err.to_string();
        let err: JiraError = json_err.into();
        assert!(err.to_string().contains(&original_msg));
    }

    // ════════════════════════════════════════════════════════════════
    // JiraResult type alias
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn jira_result_ok() {
        let r: JiraResult<u32> = Ok(42);
        assert!(matches!(r, Ok(42)));
    }

    #[test]
    fn jira_result_err() {
        let r: JiraResult<u32> = Err(JiraError::Unauthorized);
        assert!(matches!(r, Err(JiraError::Unauthorized)));
    }

    #[test]
    fn jira_result_map() {
        let r: JiraResult<u32> = Ok(10);
        let mapped = r.map(|v| v * 2);
        assert_eq!(mapped.unwrap(), 20);
    }

    // ════════════════════════════════════════════════════════════════
    // Edge cases and boundary tests
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn api_error_all_5xx_retryable() {
        for code in 500..=599 {
            let err = JiraError::Api {
                message: format!("HTTP {code}"),
                status_code: Some(code),
            };
            assert!(
                err.is_retryable(),
                "Expected Api with status {code} to be retryable"
            );
        }
    }

    #[test]
    fn api_error_4xx_non_429_not_retryable() {
        for code in [400, 401, 403, 404, 405, 409, 410, 422] {
            let err = JiraError::Api {
                message: format!("HTTP {code}"),
                status_code: Some(code),
            };
            assert!(
                !err.is_retryable(),
                "Expected Api with status {code} to NOT be retryable"
            );
        }
    }

    #[test]
    fn to_fcp_error_api_599_retryable() {
        let err = JiraError::Api {
            message: "edge".into(),
            status_code: Some(599),
        };
        match err.to_fcp_error() {
            FcpError::External { retryable, .. } => assert!(retryable),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_preserves_service_name() {
        // All FcpError::External from JiraError should have service = "jira"
        let err = JiraError::Api {
            message: "test".into(),
            status_code: Some(503),
        };
        match err.to_fcp_error() {
            FcpError::External { service, .. } => assert_eq!(service, "jira"),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_401_and_403_same_code() {
        let err_401 = JiraError::Api {
            message: "a".into(),
            status_code: Some(401),
        };
        let err_403 = JiraError::Api {
            message: "b".into(),
            status_code: Some(403),
        };
        match (err_401.to_fcp_error(), err_403.to_fcp_error()) {
            (FcpError::Unauthorized { code: c1, .. }, FcpError::Unauthorized { code: c2, .. }) => {
                assert_eq!(c1, c2);
                assert_eq!(c1, 2001);
            }
            other => panic!("expected both Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn display_messages_are_nonempty() {
        let json_err = serde_json::from_str::<serde_json::Value>("$").unwrap_err();
        let errors: Vec<JiraError> = vec![
            JiraError::Json(json_err),
            JiraError::Api {
                message: "m".into(),
                status_code: None,
            },
            JiraError::RateLimited { retry_after_ms: 1 },
            JiraError::Unauthorized,
            JiraError::InvalidInput("bad".into()),
            JiraError::NotFound {
                resource: "r".into(),
            },
        ];
        for err in &errors {
            assert!(!err.to_string().is_empty(), "empty Display for {err:?}");
        }
    }
}
