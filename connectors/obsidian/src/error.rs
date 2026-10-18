//! Obsidian connector error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use thiserror::Error;

/// Obsidian connector errors.
#[derive(Error, Debug)]
pub enum ObsidianError {
    /// Filesystem I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Vault path does not exist or is not a directory.
    #[error("Invalid vault path: {0}")]
    InvalidVault(String),

    /// Path traversal attempt detected.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Note not found.
    #[error("Note not found: {0}")]
    NotFound(String),

    /// Note already exists (for create).
    #[error("Note already exists: {0}")]
    AlreadyExists(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Async operation error (timeout, cancellation).
    #[error("Async error: {0}")]
    Async(String),
}

impl ObsidianError {
    /// Whether this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Io(e) => matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::TimedOut
            ),
            Self::Async(_) => true,
            Self::Json(_)
            | Self::InvalidVault(_)
            | Self::InvalidInput(_)
            | Self::NotFound(_)
            | Self::AlreadyExists(_)
            | Self::Config(_) => false,
        }
    }

    /// Suggested retry-after delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        None
    }

    /// Convert to FCP error taxonomy.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Io(e) => FcpError::Internal {
                message: format!("Filesystem error: {e}"),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::InvalidVault(msg) => FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid vault: {msg}"),
            },
            Self::InvalidInput(msg) => FcpError::InvalidRequest {
                code: 1008,
                message: format!("Invalid input: {msg}"),
            },
            Self::NotFound(msg) => FcpError::InvalidRequest {
                code: 1004,
                message: format!("Not found: {msg}"),
            },
            Self::AlreadyExists(msg) => FcpError::InvalidRequest {
                code: 1009,
                message: format!("Already exists: {msg}"),
            },
            Self::Config(msg) => FcpError::InvalidRequest {
                code: 1001,
                message: format!("Configuration error: {msg}"),
            },
            Self::Async(msg) => FcpError::Internal {
                message: format!("Async error: {msg}"),
            },
        }
    }
}

impl ConnectorErrorMapping for ObsidianError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => {
                Self::Async(format!("operation timed out after {timeout_ms}ms"))
            }
            AsyncError::Cancelled => Self::Async("operation cancelled".into()),
            other => Self::Async(format!("async error: {other}")),
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

pub type ObsidianResult<T> = Result<T, ObsidianError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_retryable_on_would_block() {
        let err = ObsidianError::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "resource temporarily unavailable",
        ));
        assert!(err.is_retryable());
    }

    #[test]
    fn io_error_not_retryable_on_not_found() {
        let err = ObsidianError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert!(!err.is_retryable());
    }

    #[test]
    fn invalid_vault_not_retryable() {
        let err = ObsidianError::InvalidVault("path does not exist".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn invalid_input_maps_to_invalid_request() {
        let err = ObsidianError::InvalidInput("path traversal detected".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(
            fcp_err,
            FcpError::InvalidRequest { code: 1008, .. }
        ));
    }

    #[test]
    fn not_found_maps_to_invalid_request() {
        let err = ObsidianError::NotFound("test.md".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(
            fcp_err,
            FcpError::InvalidRequest { code: 1004, .. }
        ));
    }

    #[test]
    fn already_exists_maps_to_invalid_request() {
        let err = ObsidianError::AlreadyExists("existing.md".into());
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(
            fcp_err,
            FcpError::InvalidRequest { code: 1009, .. }
        ));
    }

    #[test]
    fn config_error_not_retryable() {
        let err = ObsidianError::Config("missing vault_path".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn from_async_timeout() {
        let err = ObsidianError::from_async_error(AsyncError::Timeout { timeout_ms: 5000 });
        assert!(matches!(err, ObsidianError::Async(_)));
        assert!(err.is_retryable());
    }

    #[test]
    fn from_async_cancelled() {
        let err = ObsidianError::from_async_error(AsyncError::Cancelled);
        assert!(matches!(err, ObsidianError::Async(_)));
    }

    #[test]
    fn from_async_channel_closed() {
        let err = ObsidianError::from_async_error(AsyncError::ChannelClosed);
        assert!(matches!(err, ObsidianError::Async(_)));
    }

    #[test]
    fn retry_after_always_none() {
        let err = ObsidianError::NotFound("x.md".into());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn error_display_format() {
        let err = ObsidianError::InvalidInput("../../../etc/passwd".into());
        let display = format!("{err}");
        assert!(display.contains("Invalid input"));
        assert!(display.contains("../../../etc/passwd"));
    }

    #[test]
    fn io_error_maps_to_internal() {
        let err = ObsidianError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "permission denied",
        ));
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::Internal { .. }));
    }

    #[test]
    fn json_error_maps_to_internal() {
        let err: ObsidianError = serde_json::from_str::<serde_json::Value>("invalid")
            .unwrap_err()
            .into();
        let fcp_err = ConnectorErrorMapping::to_fcp_error(&err);
        assert!(matches!(fcp_err, FcpError::Internal { .. }));
    }
}
