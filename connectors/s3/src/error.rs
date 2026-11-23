//! S3-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use thiserror::Error;

/// S3-specific errors.
#[derive(Error, Debug)]
pub enum S3Error {
    /// Invalid local input, rejected before provider access.
    #[error("Invalid S3 input: {0}")]
    InvalidInput(String),

    /// A delivered response cannot establish a complete successful outcome.
    #[error("S3 response could not be verified: {0}")]
    InvalidResponse(String),

    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// S3 API returned an error
    #[error("S3 API error: {message} (code: {code})")]
    Api {
        code: String,
        message: String,
        status_code: Option<u16>,
    },

    /// Rate limited
    #[error("Rate limited (retry after {retry_after_ms}ms)")]
    RateLimited { retry_after_ms: u64 },

    /// Unauthorized (invalid credentials)
    #[error("Unauthorized")]
    Unauthorized,

    /// Object not found
    #[error("Object not found: {key}")]
    NotFound { key: String },

    /// Bucket not found
    #[error("Bucket not found: {bucket}")]
    BucketNotFound { bucket: String },
}

impl S3Error {
    /// Check if this error is retryable.
    ///
    /// Note: not `const fn` because we match on string error codes in `Api`.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(error) => error.is_connect(),
            Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => {
                matches!(status_code, Some(500..=599 | 429))
            }
            Self::Unauthorized | Self::NotFound { .. } | Self::BucketNotFound { .. } => false,
            Self::Json(_) | Self::InvalidInput(_) | Self::InvalidResponse(_) => false,
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
            Self::InvalidInput(message) => FcpError::InvalidRequest {
                code: 1001,
                message: message.clone(),
            },
            Self::InvalidResponse(message) => FcpError::External {
                service: "s3".into(),
                message: message.clone(),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
            Self::Http(e) => FcpError::External {
                service: "s3".into(),
                message: "S3 HTTP transport failed".into(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api {
                code,
                message,
                status_code,
            } => {
                if *status_code == Some(401) || *status_code == Some(403) {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid S3 credentials".into(),
                    }
                } else if *status_code == Some(429) {
                    FcpError::RateLimited {
                        retry_after_ms: 30_000,
                        violation: None,
                    }
                } else if *status_code == Some(404) {
                    FcpError::ResourceNotFound {
                        resource: message.clone(),
                    }
                } else {
                    FcpError::External {
                        service: "s3".into(),
                        message: format!("{code}: {message}"),
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
                message: "Invalid S3 credentials".into(),
            },
            Self::NotFound { key } => FcpError::ResourceNotFound {
                resource: format!("object:{key}"),
            },
            Self::BucketNotFound { bucket } => FcpError::ResourceNotFound {
                resource: format!("bucket:{bucket}"),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for S3 operations.
pub type S3Result<T> = Result<T, S3Error>;

impl ConnectorErrorMapping for S3Error {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                code: "Timeout".into(),
                message: format!("deadline exceeded after {timeout_ms}ms"),
                status_code: Some(408),
            },
            AsyncError::Cancelled => Self::Api {
                code: "Cancelled".into(),
                message: "request cancelled".into(),
                status_code: None,
            },
            other => Self::Api {
                code: "AsyncError".into(),
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

    // ---- Display ----

    #[test]
    fn display_api_error() {
        let err = S3Error::Api {
            code: "NoSuchKey".into(),
            message: "The specified key does not exist.".into(),
            status_code: Some(404),
        };
        let s = err.to_string();
        assert!(s.contains("NoSuchKey"));
        assert!(s.contains("does not exist"));
    }

    #[test]
    fn display_rate_limited() {
        let err = S3Error::RateLimited {
            retry_after_ms: 5000,
        };
        assert!(err.to_string().contains("Rate limited"));
    }

    #[test]
    fn display_unauthorized() {
        let err = S3Error::Unauthorized;
        assert!(err.to_string().contains("Unauthorized"));
    }

    #[test]
    fn display_not_found() {
        let err = S3Error::NotFound {
            key: "my-object.txt".into(),
        };
        assert!(err.to_string().contains("my-object.txt"));
    }

    #[test]
    fn display_bucket_not_found() {
        let err = S3Error::BucketNotFound {
            bucket: "my-bucket".into(),
        };
        assert!(err.to_string().contains("my-bucket"));
    }

    // ---- is_retryable ----

    #[test]
    fn is_retryable_rate_limited() {
        assert!(
            S3Error::RateLimited {
                retry_after_ms: 1000
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_500() {
        assert!(
            S3Error::Api {
                code: "InternalError".into(),
                message: "internal".into(),
                status_code: Some(500),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_503() {
        assert!(
            S3Error::Api {
                code: "SlowDown".into(),
                message: "slow down".into(),
                status_code: Some(503),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_400() {
        assert!(
            !S3Error::Api {
                code: "InvalidArgument".into(),
                message: "bad".into(),
                status_code: Some(400),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_unauthorized() {
        assert!(!S3Error::Unauthorized.is_retryable());
    }

    #[test]
    fn not_retryable_not_found() {
        assert!(!S3Error::NotFound { key: "x".into() }.is_retryable());
    }

    #[test]
    fn not_retryable_bucket_not_found() {
        assert!(!S3Error::BucketNotFound { bucket: "x".into() }.is_retryable());
    }

    #[test]
    fn not_retryable_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        assert!(!S3Error::Json(json_err).is_retryable());
    }

    // ---- retry_after ----

    #[test]
    fn retry_after_rate_limited() {
        let err = S3Error::RateLimited {
            retry_after_ms: 5000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn retry_after_other_none() {
        assert_eq!(S3Error::Unauthorized.retry_after(), None);
        assert_eq!(S3Error::NotFound { key: "x".into() }.retry_after(), None);
    }

    // ---- to_fcp_error ----

    #[test]
    fn to_fcp_error_api_401_unauthorized() {
        let err = S3Error::Api {
            code: "AccessDenied".into(),
            message: "denied".into(),
            status_code: Some(401),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("S3 credentials"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_403_unauthorized() {
        let err = S3Error::Api {
            code: "AccessDenied".into(),
            message: "forbidden".into(),
            status_code: Some(403),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn to_fcp_error_api_429_rate_limited() {
        let err = S3Error::Api {
            code: "SlowDown".into(),
            message: "slow down".into(),
            status_code: Some(429),
        };
        match err.to_fcp_error() {
            FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 30_000),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_404_resource_not_found() {
        let err = S3Error::Api {
            code: "NoSuchKey".into(),
            message: "The specified key does not exist.".into(),
            status_code: Some(404),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.contains("does not exist"));
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_500_external() {
        let err = S3Error::Api {
            code: "InternalError".into(),
            message: "server error".into(),
            status_code: Some(500),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "s3");
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limited() {
        let err = S3Error::RateLimited {
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
    fn to_fcp_error_unauthorized() {
        match S3Error::Unauthorized.to_fcp_error() {
            FcpError::Unauthorized { code, .. } => assert_eq!(code, 2001),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_not_found() {
        let err = S3Error::NotFound {
            key: "data/file.csv".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.contains("object:data/file.csv"));
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_bucket_not_found() {
        let err = S3Error::BucketNotFound {
            bucket: "my-bucket".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.contains("bucket:my-bucket"));
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_json_internal() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = S3Error::Json(json_err);
        match err.to_fcp_error() {
            FcpError::Internal { message } => assert!(message.contains("JSON error")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // ---- From impls ----

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("nope").unwrap_err();
        let err: S3Error = json_err.into();
        assert!(matches!(err, S3Error::Json(_)));
    }

    // ---- Result alias ----

    #[test]
    fn s3_result_ok() {
        let r: S3Result<u32> = Ok(42);
        assert!(r.is_ok());
    }

    #[test]
    fn s3_result_err() {
        let r: S3Result<u32> = Err(S3Error::Unauthorized);
        assert!(r.is_err());
    }

    // ---- std::error::Error trait ----

    #[test]
    fn error_trait_impl() {
        let err = S3Error::Unauthorized;
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn error_trait_source_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err = S3Error::Json(json_err);
        // Json variant wraps a serde_json::Error via #[from], so source should be Some
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn error_trait_source_none_for_leaf_variants() {
        // Leaf variants without #[from] should have no source
        assert!(std::error::Error::source(&S3Error::Unauthorized).is_none());
        assert!(std::error::Error::source(&S3Error::NotFound { key: "k".into() }).is_none());
        assert!(
            std::error::Error::source(&S3Error::BucketNotFound { bucket: "b".into() }).is_none()
        );
        assert!(
            std::error::Error::source(&S3Error::RateLimited {
                retry_after_ms: 100
            })
            .is_none()
        );
        assert!(
            std::error::Error::source(&S3Error::Api {
                code: "X".into(),
                message: "Y".into(),
                status_code: None,
            })
            .is_none()
        );
    }

    // ---- Debug format ----

    #[test]
    fn debug_format_api_error() {
        let err = S3Error::Api {
            code: "NoSuchKey".into(),
            message: "key not found".into(),
            status_code: Some(404),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("NoSuchKey"));
        assert!(dbg.contains("404"));
    }

    #[test]
    fn debug_format_rate_limited() {
        let err = S3Error::RateLimited {
            retry_after_ms: 7777,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RateLimited"));
        assert!(dbg.contains("7777"));
    }

    #[test]
    fn debug_format_unauthorized() {
        let dbg = format!("{:?}", S3Error::Unauthorized);
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn debug_format_not_found() {
        let err = S3Error::NotFound {
            key: "deep/path/obj".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NotFound"));
        assert!(dbg.contains("deep/path/obj"));
    }

    #[test]
    fn debug_format_bucket_not_found() {
        let err = S3Error::BucketNotFound {
            bucket: "archive-2026".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("BucketNotFound"));
        assert!(dbg.contains("archive-2026"));
    }

    #[test]
    fn debug_format_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("!!!").unwrap_err();
        let err = S3Error::Json(json_err);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Json"));
    }

    // ---- Display completeness ----

    #[test]
    fn display_http_error_contains_message() {
        // We cannot easily construct a reqwest::Error, but we can test via
        // to_string on the Json variant to ensure Display works for all branches.
        let json_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        let err = S3Error::Json(json_err);
        let s = err.to_string();
        assert!(s.contains("JSON error"));
    }

    #[test]
    fn display_api_error_includes_code_and_message() {
        let err = S3Error::Api {
            code: "SlowDown".into(),
            message: "Please reduce request rate".into(),
            status_code: Some(503),
        };
        let s = err.to_string();
        assert!(s.contains("SlowDown"));
        assert!(s.contains("Please reduce request rate"));
        assert!(s.contains("S3 API error"));
    }

    // ---- is_retryable edge cases ----

    #[test]
    fn is_retryable_api_429() {
        assert!(
            S3Error::Api {
                code: "SlowDown".into(),
                message: "slow".into(),
                status_code: Some(429),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_502() {
        assert!(
            S3Error::Api {
                code: "BadGateway".into(),
                message: "bad gateway".into(),
                status_code: Some(502),
            }
            .is_retryable()
        );
    }

    #[test]
    fn is_retryable_api_599() {
        assert!(
            S3Error::Api {
                code: "Weird".into(),
                message: "edge".into(),
                status_code: Some(599),
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_none_status() {
        assert!(
            !S3Error::Api {
                code: "Unknown".into(),
                message: "no status".into(),
                status_code: None,
            }
            .is_retryable()
        );
    }

    #[test]
    fn not_retryable_api_200() {
        // Technically odd, but the logic is clear: 200 is not in 500..=599|429
        assert!(
            !S3Error::Api {
                code: "OK".into(),
                message: "ok".into(),
                status_code: Some(200),
            }
            .is_retryable()
        );
    }

    // ---- retry_after edge cases ----

    #[test]
    fn retry_after_zero_ms() {
        let err = S3Error::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn retry_after_large_value() {
        let err = S3Error::RateLimited {
            retry_after_ms: 3_600_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn retry_after_api_none() {
        let err = S3Error::Api {
            code: "X".into(),
            message: "Y".into(),
            status_code: Some(500),
        };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_bucket_not_found_none() {
        let err = S3Error::BucketNotFound { bucket: "b".into() };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_json_none() {
        let json_err = serde_json::from_str::<serde_json::Value>("x").unwrap_err();
        assert_eq!(S3Error::Json(json_err).retry_after(), None);
    }

    // ---- to_fcp_error edge cases ----

    #[test]
    fn to_fcp_error_api_none_status_external() {
        let err = S3Error::Api {
            code: "WeirdError".into(),
            message: "something happened".into(),
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
                assert_eq!(service, "s3");
                assert!(message.contains("WeirdError"));
                assert!(message.contains("something happened"));
                assert_eq!(status_code, None);
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_200_external() {
        // Non-auth, non-rate-limit, non-404 status → External
        let err = S3Error::Api {
            code: "Weird".into(),
            message: "odd".into(),
            status_code: Some(200),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "s3");
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_500_is_retryable_in_external() {
        let err = S3Error::Api {
            code: "InternalError".into(),
            message: "crash".into(),
            status_code: Some(500),
        };
        match err.to_fcp_error() {
            FcpError::External {
                retryable,
                retry_after,
                ..
            } => {
                assert!(retryable);
                // retry_after comes from self.retry_after() which is None for Api
                assert_eq!(retry_after, None);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_503_retryable() {
        let err = S3Error::Api {
            code: "ServiceUnavailable".into(),
            message: "try again".into(),
            status_code: Some(503),
        };
        match err.to_fcp_error() {
            FcpError::External { retryable, .. } => assert!(retryable),
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_not_found_format() {
        let err = S3Error::NotFound {
            key: "path/to/deep/file.bin".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "object:path/to/deep/file.bin");
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_bucket_not_found_format() {
        let err = S3Error::BucketNotFound {
            bucket: "prod-assets".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "bucket:prod-assets");
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_rate_limited_preserves_ms() {
        let err = S3Error::RateLimited {
            retry_after_ms: 12_345,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 12_345);
                assert!(violation.is_none());
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_json_contains_original_message() {
        let json_err =
            serde_json::from_str::<serde_json::Value>("not valid json at all").unwrap_err();
        let msg = json_err.to_string();
        let err = S3Error::Json(json_err);
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.contains("JSON error"));
                assert!(message.contains(&msg));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_http_external_service_s3() {
        // We can't easily construct a reqwest::Error, but we test
        // the Api fallback branch with a generic status code instead
        let err = S3Error::Api {
            code: "Timeout".into(),
            message: "request timed out".into(),
            status_code: Some(504),
        };
        match err.to_fcp_error() {
            FcpError::External { service, .. } => {
                assert_eq!(service, "s3");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_429_rate_limited_has_fixed_retry() {
        // The API 429 path uses a hard-coded 30_000ms
        let err = S3Error::Api {
            code: "SlowDown".into(),
            message: "reduce rate".into(),
            status_code: Some(429),
        };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 30_000);
                assert!(violation.is_none());
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_unauthorized_code_is_2001() {
        match S3Error::Unauthorized.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("S3"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_403_code_is_2001() {
        let err = S3Error::Api {
            code: "AccessDenied".into(),
            message: "forbidden".into(),
            status_code: Some(403),
        };
        match err.to_fcp_error() {
            FcpError::Unauthorized { code, .. } => assert_eq!(code, 2001),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    // ---- From<reqwest::Error> via #[from] ----
    // (We can't easily unit-test this without a real reqwest error, but the
    // client integration tests cover it through the HTTP contract harness.)

    // ---- S3Result alias with question mark ----

    #[test]
    fn s3_result_question_mark_propagation() {
        fn inner() -> S3Result<u32> {
            let r: S3Result<u32> = Err(S3Error::Unauthorized);
            let _val = r?;
            Ok(0)
        }
        assert!(inner().is_err());
    }

    #[test]
    fn display_unauthorized_nonempty() {
        let err = S3Error::Unauthorized;
        let s = err.to_string();
        assert!(!s.is_empty());
    }

    #[test]
    fn display_not_found_contains_key() {
        let err = S3Error::NotFound {
            key: "path/to/file".into(),
        };
        let s = err.to_string();
        assert!(s.contains("path/to/file"));
    }

    #[test]
    fn display_bucket_not_found_contains_name() {
        let err = S3Error::BucketNotFound {
            bucket: "my-bucket".into(),
        };
        let s = err.to_string();
        assert!(s.contains("my-bucket"));
    }

    #[test]
    fn display_rate_limited_contains_ms() {
        let err = S3Error::RateLimited {
            retry_after_ms: 5000,
        };
        let s = err.to_string();
        assert!(s.contains("5000"));
    }

    #[test]
    fn debug_unauthorized_variant_name() {
        let dbg = format!("{:?}", S3Error::Unauthorized);
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn debug_not_found_includes_key() {
        let err = S3Error::NotFound {
            key: "test.txt".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NotFound"));
        assert!(dbg.contains("test.txt"));
    }

    #[test]
    fn debug_bucket_not_found_variant() {
        let err = S3Error::BucketNotFound {
            bucket: "gone".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("BucketNotFound"));
    }

    #[test]
    fn s3_result_ok_is_ok() {
        let r: S3Result<String> = Ok("data".into());
        assert!(r.is_ok());
    }
}
