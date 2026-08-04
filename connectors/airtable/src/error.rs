//! Airtable-specific error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use thiserror::Error;

/// Airtable-specific errors.
#[derive(Error, Debug)]
pub enum AirtableError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Airtable API returned an error
    #[error("Airtable API error: {error_type} - {message}")]
    Api {
        error_type: String,
        message: String,
        status_code: Option<u16>,
    },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    /// Invalid or expired token
    #[error("Invalid or expired Airtable token")]
    Unauthorized,

    /// Base not found
    #[error("Base not found: {base_id}")]
    BaseNotFound { base_id: String },

    /// Record not found
    #[error("Record not found: {record_id}")]
    RecordNotFound { record_id: String },

    /// Table not found
    #[error("Table not found: {table_id}")]
    TableNotFound { table_id: String },

    /// Attachment URL violates connector network constraints.
    #[error("Invalid attachment URL: {message}")]
    InvalidAttachmentUrl { message: String },

    /// Attachment exceeds the connector's response size limit.
    #[error("Attachment download exceeds maximum allowed size of {max_bytes} bytes")]
    AttachmentTooLarge { max_bytes: u64 },
}

impl AirtableError {
    /// Check if this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { error_type, .. } => {
                matches!(
                    error_type.as_str(),
                    "SERVER_ERROR" | "SERVICE_UNAVAILABLE" | "REQUEST_TIMEOUT" | "GATEWAY_TIMEOUT"
                )
            }
            _ => false,
        }
    }

    /// Whether replaying the request that produced this error cannot duplicate
    /// a side effect (br-kxd3e).
    ///
    /// Distinct from `is_retryable`: a rate-limited request was refused
    /// WITHOUT being performed, so it stays safe to replay; a 5xx means the
    /// service received the request and may already have applied it.
    #[must_use]
    pub fn replay_is_safe(&self) -> bool {
        match self {
            Self::RateLimited { .. } => true,
            Self::Api { error_type, .. } => error_type.as_str() == "RATE_LIMITED",
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
                service: "airtable".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api {
                error_type,
                message,
                status_code,
            } => {
                if error_type == "AUTHENTICATION_REQUIRED"
                    || error_type == "INVALID_API_KEY"
                    || *status_code == Some(401)
                    || *status_code == Some(403)
                {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid or insufficient Airtable token".into(),
                    }
                } else if error_type == "NOT_FOUND" || *status_code == Some(404) {
                    FcpError::ResourceNotFound {
                        resource: message.clone(),
                    }
                } else if matches!(
                    error_type.as_str(),
                    "INVALID_REQUEST" | "INVALID_REQUEST_UNKNOWN"
                ) {
                    FcpError::InvalidRequest {
                        code: 1003,
                        message: message.clone(),
                    }
                } else {
                    FcpError::External {
                        service: "airtable".into(),
                        message: format!("{error_type}: {message}"),
                        status_code: *status_code,
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
                message: "Invalid or expired Airtable token".into(),
            },
            Self::BaseNotFound { base_id } => FcpError::ResourceNotFound {
                resource: format!("base:{base_id}"),
            },
            Self::RecordNotFound { record_id } => FcpError::ResourceNotFound {
                resource: format!("record:{record_id}"),
            },
            Self::TableNotFound { table_id } => FcpError::ResourceNotFound {
                resource: format!("table:{table_id}"),
            },
            Self::InvalidAttachmentUrl { message } => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::AttachmentTooLarge { max_bytes } => FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "Attachment download exceeds maximum allowed size of {max_bytes} bytes"
                ),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for Airtable operations.
pub type AirtableResult<T> = Result<T, AirtableError>;

impl ConnectorErrorMapping for AirtableError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::Api {
                error_type: "TIMEOUT".into(),
                message: format!("deadline exceeded after {timeout_ms}ms"),
                status_code: Some(408),
            },
            AsyncError::Cancelled => Self::Api {
                error_type: "CANCELLED".into(),
                message: "request cancelled".into(),
                status_code: None,
            },
            other => Self::Api {
                error_type: "ASYNC_ERROR".into(),
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
    use fcp_prelude::FcpError;

    // ── Display messages ────────────────────────────────────────

    #[test]
    fn display_api_error() {
        let err = AirtableError::Api {
            error_type: "INVALID_REQUEST".into(),
            message: "Bad field".into(),
            status_code: Some(422),
        };
        assert_eq!(
            err.to_string(),
            "Airtable API error: INVALID_REQUEST - Bad field"
        );
    }

    #[test]
    fn display_rate_limited() {
        let err = AirtableError::RateLimited {
            retry_after_secs: 30,
        };
        assert_eq!(err.to_string(), "Rate limited, retry after 30s");
    }

    #[test]
    fn display_unauthorized() {
        let err = AirtableError::Unauthorized;
        assert_eq!(err.to_string(), "Invalid or expired Airtable token");
    }

    #[test]
    fn display_base_not_found() {
        let err = AirtableError::BaseNotFound {
            base_id: "app123".into(),
        };
        assert_eq!(err.to_string(), "Base not found: app123");
    }

    #[test]
    fn display_record_not_found() {
        let err = AirtableError::RecordNotFound {
            record_id: "rec456".into(),
        };
        assert_eq!(err.to_string(), "Record not found: rec456");
    }

    #[test]
    fn display_table_not_found() {
        let err = AirtableError::TableNotFound {
            table_id: "tblABC".into(),
        };
        assert_eq!(err.to_string(), "Table not found: tblABC");
    }

    #[test]
    fn display_invalid_attachment_url() {
        let err = AirtableError::InvalidAttachmentUrl {
            message: "Attachment URL must use https".into(),
        };
        assert_eq!(
            err.to_string(),
            "Invalid attachment URL: Attachment URL must use https"
        );
    }

    #[test]
    fn display_attachment_too_large() {
        let err = AirtableError::AttachmentTooLarge { max_bytes: 1024 };
        assert_eq!(
            err.to_string(),
            "Attachment download exceeds maximum allowed size of 1024 bytes"
        );
    }

    #[test]
    fn display_json_error() {
        let json_err = serde_json::from_str::<i32>("bad").unwrap_err();
        let err = AirtableError::Json(json_err);
        assert!(err.to_string().starts_with("JSON error:"));
    }

    // ── is_retryable ─────────────────────────────────────────────

    #[test]
    fn rate_limited_is_retryable() {
        let err = AirtableError::RateLimited {
            retry_after_secs: 5,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn invalid_attachment_url_maps_to_invalid_request() {
        let err = AirtableError::InvalidAttachmentUrl {
            message: "bad attachment host".into(),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::InvalidRequest { code: 1003, message }
                if message == "bad attachment host"
        ));
    }

    #[test]
    fn attachment_too_large_maps_to_invalid_request() {
        let err = AirtableError::AttachmentTooLarge { max_bytes: 2048 };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::InvalidRequest { code: 1003, message }
                if message.contains("2048")
        ));
    }

    #[test]
    fn server_error_api_is_retryable() {
        for error_type in [
            "SERVER_ERROR",
            "SERVICE_UNAVAILABLE",
            "REQUEST_TIMEOUT",
            "GATEWAY_TIMEOUT",
        ] {
            let err = AirtableError::Api {
                error_type: error_type.into(),
                message: "oops".into(),
                status_code: Some(500),
            };
            assert!(err.is_retryable(), "{error_type} should be retryable");
        }
    }

    #[test]
    fn client_error_api_not_retryable() {
        for error_type in [
            "INVALID_REQUEST",
            "NOT_FOUND",
            "AUTHENTICATION_REQUIRED",
            "INVALID_API_KEY",
        ] {
            let err = AirtableError::Api {
                error_type: error_type.into(),
                message: "no".into(),
                status_code: Some(400),
            };
            assert!(!err.is_retryable(), "{error_type} should NOT be retryable");
        }
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!AirtableError::Unauthorized.is_retryable());
    }

    #[test]
    fn base_not_found_not_retryable() {
        let err = AirtableError::BaseNotFound {
            base_id: "x".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn record_not_found_not_retryable() {
        let err = AirtableError::RecordNotFound {
            record_id: "x".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn table_not_found_not_retryable() {
        let err = AirtableError::TableNotFound {
            table_id: "x".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn json_error_not_retryable() {
        let json_err = serde_json::from_str::<i32>("bad").unwrap_err();
        let err = AirtableError::Json(json_err);
        assert!(!err.is_retryable());
    }

    // ── retry_after ──────────────────────────────────────────────

    #[test]
    fn retry_after_rate_limited() {
        let err = AirtableError::RateLimited {
            retry_after_secs: 42,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(42)));
    }

    #[test]
    fn retry_after_zero() {
        let err = AirtableError::RateLimited {
            retry_after_secs: 0,
        };
        assert_eq!(err.retry_after(), Some(Duration::ZERO));
    }

    #[test]
    fn retry_after_none_for_other_errors() {
        assert!(AirtableError::Unauthorized.retry_after().is_none());
        let api = AirtableError::Api {
            error_type: "SERVER_ERROR".into(),
            message: "x".into(),
            status_code: Some(500),
        };
        assert!(api.retry_after().is_none());
    }

    // ── to_fcp_error ─────────────────────────────────────────────

    #[test]
    fn to_fcp_error_rate_limited() {
        let err = AirtableError::RateLimited {
            retry_after_secs: 10,
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::RateLimited {
                retry_after_ms: 10_000,
                violation: None,
            }
        ));
    }

    #[test]
    fn to_fcp_error_unauthorized_variant() {
        assert!(matches!(
            AirtableError::Unauthorized.to_fcp_error(),
            FcpError::Unauthorized { code: 2001, ref message } if message.contains("Airtable")
        ));
    }

    #[test]
    fn to_fcp_error_api_auth_required() {
        let err = AirtableError::Api {
            error_type: "AUTHENTICATION_REQUIRED".into(),
            message: "need auth".into(),
            status_code: Some(401),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn to_fcp_error_api_invalid_key() {
        let err = AirtableError::Api {
            error_type: "INVALID_API_KEY".into(),
            message: "bad key".into(),
            status_code: Some(401),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn to_fcp_error_api_403_status() {
        let err = AirtableError::Api {
            error_type: "FORBIDDEN".into(),
            message: "denied".into(),
            status_code: Some(403),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn to_fcp_error_api_not_found() {
        let err = AirtableError::Api {
            error_type: "NOT_FOUND".into(),
            message: "record xyz".into(),
            status_code: Some(404),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::ResourceNotFound { ref resource } if resource == "record xyz"
        ));
    }

    #[test]
    fn to_fcp_error_api_404_status_non_not_found_type() {
        let err = AirtableError::Api {
            error_type: "UNKNOWN_ERROR".into(),
            message: "gone".into(),
            status_code: Some(404),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::ResourceNotFound { .. }
        ));
    }

    #[test]
    fn to_fcp_error_api_server_error_retryable() {
        let err = AirtableError::Api {
            error_type: "SERVER_ERROR".into(),
            message: "internal".into(),
            status_code: Some(500),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::External {
                ref service,
                retryable,
                retry_after: None,
                ..
            } if service == "airtable" && retryable
        ));
    }

    #[test]
    fn to_fcp_error_api_client_error_not_retryable() {
        let err = AirtableError::Api {
            error_type: "INVALID_REQUEST".into(),
            message: "bad".into(),
            status_code: Some(422),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::InvalidRequest { code: 1003, ref message } if message == "bad"
        ));
    }

    #[test]
    fn to_fcp_error_api_invalid_request_unknown_maps_to_invalid_request() {
        let err = AirtableError::Api {
            error_type: "INVALID_REQUEST_UNKNOWN".into(),
            message: "Unknown field names in formula".into(),
            status_code: Some(422),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::InvalidRequest { code: 1003, ref message }
                if message == "Unknown field names in formula"
        ));
    }

    #[test]
    fn to_fcp_error_base_not_found() {
        let err = AirtableError::BaseNotFound {
            base_id: "appXYZ".into(),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::ResourceNotFound { ref resource } if resource == "base:appXYZ"
        ));
    }

    #[test]
    fn to_fcp_error_record_not_found() {
        let err = AirtableError::RecordNotFound {
            record_id: "rec123".into(),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::ResourceNotFound { ref resource } if resource == "record:rec123"
        ));
    }

    #[test]
    fn to_fcp_error_table_not_found() {
        let err = AirtableError::TableNotFound {
            table_id: "tblABC".into(),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::ResourceNotFound { ref resource } if resource == "table:tblABC"
        ));
    }

    #[test]
    fn to_fcp_error_json() {
        let json_err = serde_json::from_str::<i32>("nope").unwrap_err();
        let err = AirtableError::Json(json_err);
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::Internal { ref message } if message.starts_with("JSON error:")
        ));
    }

    // ── Debug format ─────────────────────────────────────────────

    #[test]
    fn debug_format_contains_variant_name() {
        let err = AirtableError::Unauthorized;
        assert!(format!("{err:?}").contains("Unauthorized"));

        let err = AirtableError::RateLimited {
            retry_after_secs: 5,
        };
        assert!(format!("{err:?}").contains("RateLimited"));

        let err = AirtableError::BaseNotFound {
            base_id: "x".into(),
        };
        assert!(format!("{err:?}").contains("BaseNotFound"));
    }

    // ── std::error::Error trait ──────────────────────────────────

    #[test]
    fn implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(AirtableError::Unauthorized);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn json_error_source_chain() {
        let json_err = serde_json::from_str::<i32>("bad").unwrap_err();
        let err = AirtableError::Json(json_err);
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err.source().is_some());
    }

    // ── Api error with no status code ────────────────────────────

    #[test]
    fn api_error_no_status_code() {
        let err = AirtableError::Api {
            error_type: "SERVER_ERROR".into(),
            message: "oops".into(),
            status_code: None,
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::External {
                status_code: None,
                ..
            }
        ));
    }

    // ── Result type alias ────────────────────────────────────────

    #[test]
    fn result_type_alias_compiles() {
        let ok: AirtableResult<u32> = Ok(42);
        assert!(matches!(ok, Ok(42)));

        let err: AirtableResult<u32> = Err(AirtableError::Unauthorized);
        assert!(err.is_err());
    }

    // ── Additional error coverage ────────────────────────────────

    #[test]
    fn display_http_error() {
        // Create an HTTP error via reqwest builder failure
        let err = reqwest::Client::builder()
            .build()
            .unwrap()
            .get("://invalid")
            .build();
        if let Err(e) = err {
            let ae = AirtableError::Http(e);
            let display = ae.to_string();
            assert!(display.starts_with("HTTP error:"), "got: {display}");
        }
    }

    #[test]
    fn http_error_is_retryable() {
        let err = reqwest::Client::builder()
            .build()
            .unwrap()
            .get("://invalid")
            .build();
        if let Err(e) = err {
            let ae = AirtableError::Http(e);
            assert!(ae.is_retryable());
        }
    }

    #[test]
    fn retry_after_large_value() {
        let err = AirtableError::RateLimited {
            retry_after_secs: 3600,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn to_fcp_error_rate_limited_zero() {
        let err = AirtableError::RateLimited {
            retry_after_secs: 0,
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::RateLimited {
                retry_after_ms: 0,
                ..
            }
        ));
    }

    #[test]
    fn to_fcp_error_api_service_unavailable_retryable() {
        let err = AirtableError::Api {
            error_type: "SERVICE_UNAVAILABLE".into(),
            message: "service down".into(),
            status_code: Some(503),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::External {
                ref service,
                retryable,
                ..
            } if service == "airtable" && retryable
        ));
    }

    #[test]
    fn to_fcp_error_api_gateway_timeout_retryable() {
        let err = AirtableError::Api {
            error_type: "GATEWAY_TIMEOUT".into(),
            message: "timeout".into(),
            status_code: Some(504),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::External {
                retryable: true,
                ..
            }
        ));
    }

    #[test]
    fn to_fcp_error_api_request_timeout_retryable() {
        let err = AirtableError::Api {
            error_type: "REQUEST_TIMEOUT".into(),
            message: "timed out".into(),
            status_code: Some(408),
        };
        assert!(err.is_retryable());
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::External {
                retryable: true,
                ..
            }
        ));
    }

    #[test]
    fn to_fcp_error_api_external_message_format() {
        let err = AirtableError::Api {
            error_type: "INVALID_PERMISSIONS".into(),
            message: "insufficient access".into(),
            status_code: Some(422),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::External { ref message, .. }
                if message.contains("INVALID_PERMISSIONS")
                    && message.contains("insufficient access")
        ));
    }

    #[test]
    fn debug_format_api_error() {
        let err = AirtableError::Api {
            error_type: "INVALID_REQUEST".into(),
            message: "test msg".into(),
            status_code: Some(422),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("INVALID_REQUEST"));
    }

    #[test]
    fn debug_format_table_not_found() {
        let err = AirtableError::TableNotFound {
            table_id: "tbl999".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("TableNotFound"));
        assert!(dbg.contains("tbl999"));
    }

    #[test]
    fn debug_format_record_not_found() {
        let err = AirtableError::RecordNotFound {
            record_id: "rec999".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RecordNotFound"));
        assert!(dbg.contains("rec999"));
    }

    #[test]
    fn json_error_display_contains_details() {
        let json_err = serde_json::from_str::<Vec<i32>>("not_json").unwrap_err();
        let err = AirtableError::Json(json_err);
        let display = err.to_string();
        assert!(display.contains("JSON error:"));
    }

    #[test]
    fn to_fcp_error_json_internal_message() {
        let json_err = serde_json::from_str::<bool>("invalid").unwrap_err();
        let err = AirtableError::Json(json_err);
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::Internal { ref message } if message.contains("JSON error:")
        ));
    }

    #[test]
    fn api_error_401_status_maps_to_unauthorized() {
        let err = AirtableError::Api {
            error_type: "SOME_TYPE".into(),
            message: "bad token".into(),
            status_code: Some(401),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn api_error_403_status_maps_to_unauthorized() {
        let err = AirtableError::Api {
            error_type: "FORBIDDEN".into(),
            message: "no access".into(),
            status_code: Some(403),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn api_error_invalid_api_key_maps_to_unauthorized() {
        let err = AirtableError::Api {
            error_type: "INVALID_API_KEY".into(),
            message: "bad key".into(),
            status_code: Some(401),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn api_error_authentication_required_maps_to_unauthorized() {
        let err = AirtableError::Api {
            error_type: "AUTHENTICATION_REQUIRED".into(),
            message: "login".into(),
            status_code: None,
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn unauthorized_display_message() {
        let err = AirtableError::Unauthorized;
        assert_eq!(err.to_string(), "Invalid or expired Airtable token");
    }

    #[test]
    fn base_not_found_display() {
        let err = AirtableError::BaseNotFound {
            base_id: "appXYZ".into(),
        };
        assert!(err.to_string().contains("appXYZ"));
    }

    #[test]
    fn table_not_found_display() {
        let err = AirtableError::TableNotFound {
            table_id: "tblABC".into(),
        };
        assert!(err.to_string().contains("tblABC"));
    }

    #[test]
    fn record_not_found_display() {
        let err = AirtableError::RecordNotFound {
            record_id: "rec123".into(),
        };
        assert!(err.to_string().contains("rec123"));
    }
}
