//! SQLite-specific error types.

#![allow(clippy::doc_markdown)]

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use rusqlite::ffi::ErrorCode;
use thiserror::Error;

/// Result alias for SQLite operations.
pub type SqliteResult<T> = Result<T, SqliteError>;

/// SQLite-specific errors.
#[derive(Error, Debug)]
pub enum SqliteError {
    /// Underlying SQLite error.
    #[error("SQLite error: {0}")]
    Rusqlite(#[from] rusqlite::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid connector configuration.
    #[error("invalid SQLite configuration: {0}")]
    InvalidConfig(String),

    /// Invalid database path.
    #[error("invalid SQLite path: {0}")]
    InvalidPath(String),

    /// Invalid operation input.
    #[error("invalid SQLite input: {0}")]
    InvalidInput(String),

    /// SQLite safety policy violation.
    #[error("SQLite safety policy rejected the statement: {0}")]
    Policy(String),

    /// SQLite query error.
    #[error("SQLite query error: {0}")]
    Query(String),

    /// SQLite transaction error.
    #[error("SQLite transaction error: {0}")]
    Transaction(String),

    /// SQLite schema error.
    #[error("SQLite schema error: {0}")]
    Schema(String),

    /// SQLite pragma error.
    #[error("SQLite pragma error: {0}")]
    Pragma(String),

    /// The shared invocation deadline expired during SQLite execution.
    #[error("SQLite execution deadline exceeded; inspect transaction state before retrying")]
    DeadlineExceeded,

    /// The complete result cannot be returned within the bounded native surface.
    #[error("SQLite result exceeds the {limit} {resource} limit; narrow the query")]
    ResultLimit {
        /// Bounded resource, without query text or database contents.
        resource: &'static str,
        /// Effective limit for this invocation.
        limit: u64,
    },
}

impl SqliteError {
    const fn sqlite_error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Rusqlite(rusqlite::Error::SqliteFailure(error, _)) => Some(error.code),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self.sqlite_error_code(),
            Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
        )
    }

    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        None
    }

    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::InvalidConfig(message)
            | Self::InvalidPath(message)
            | Self::InvalidInput(message)
            | Self::Policy(message)
            | Self::Transaction(message) => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::Json(error) => FcpError::Internal {
                message: format!("JSON error: {error}"),
            },
            Self::Query(message) | Self::Schema(message) | Self::Pragma(message) => {
                FcpError::External {
                    service: "sqlite".into(),
                    message: message.clone(),
                    status_code: None,
                    retryable: false,
                    retry_after: None,
                }
            }
            Self::DeadlineExceeded | Self::ResultLimit { .. } => FcpError::External {
                service: "sqlite".into(),
                message: self.to_string(),
                status_code: None,
                // Neither an interrupted write nor an unavailable result is
                // evidence that it is safe to repeat the original operation.
                retryable: false,
                retry_after: None,
            },
            Self::Rusqlite(rusqlite::Error::MultipleStatement) => FcpError::InvalidRequest {
                code: 1003,
                message: "only a single SQL statement is allowed".into(),
            },
            Self::Rusqlite(rusqlite::Error::InvalidQuery) => FcpError::InvalidRequest {
                code: 1003,
                message: "statement violates the SQLite safety policy".into(),
            },
            Self::Rusqlite(rusqlite::Error::ExecuteReturnedResults) => FcpError::InvalidRequest {
                code: 1003,
                message: "statement returned rows; use sqlite.query or sqlite.explain instead"
                    .into(),
            },
            Self::Rusqlite(error) => match self.sqlite_error_code() {
                Some(ErrorCode::AuthorizationForStatementDenied) => FcpError::InvalidRequest {
                    code: 1003,
                    message: "statement denied by the SQLite safety policy".into(),
                },
                Some(ErrorCode::ConstraintViolation) => FcpError::External {
                    service: "sqlite".into(),
                    message: error.to_string(),
                    status_code: Some(409),
                    retryable: false,
                    retry_after: None,
                },
                Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => FcpError::External {
                    service: "sqlite".into(),
                    message: error.to_string(),
                    status_code: None,
                    retryable: true,
                    retry_after: None,
                },
                Some(ErrorCode::OperationInterrupted) => Self::DeadlineExceeded.to_fcp_error(),
                Some(ErrorCode::PermissionDenied | ErrorCode::ReadOnly) => FcpError::External {
                    service: "sqlite".into(),
                    message: error.to_string(),
                    status_code: Some(403),
                    retryable: false,
                    retry_after: None,
                },
                Some(ErrorCode::CannotOpen | ErrorCode::NotADatabase) => FcpError::External {
                    service: "sqlite".into(),
                    message: error.to_string(),
                    status_code: Some(400),
                    retryable: false,
                    retry_after: None,
                },
                _ => FcpError::External {
                    service: "sqlite".into(),
                    message: error.to_string(),
                    status_code: None,
                    retryable: self.is_retryable(),
                    retry_after: self.retry_after(),
                },
            },
        }
    }
}

impl ConnectorErrorMapping for SqliteError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { .. } => Self::DeadlineExceeded,
            AsyncError::Cancelled => Self::Query("request cancelled".into()),
            other => Self::Query(other.to_string()),
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
    fn invalid_path_maps_to_invalid_request() {
        let error = SqliteError::InvalidPath(".. not allowed".into());
        let fcp = error.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("..")),
            other => panic!("unexpected mapping: {other:?}"),
        }
    }

    #[test]
    fn constraint_violation_maps_to_conflict() {
        let error = SqliteError::Rusqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: ErrorCode::ConstraintViolation,
                extended_code: 0,
            },
            Some("constraint failed".into()),
        ));

        let fcp = error.to_fcp_error();
        match fcp {
            FcpError::External { status_code, .. } => assert_eq!(status_code, Some(409)),
            other => panic!("unexpected mapping: {other:?}"),
        }
    }
}
