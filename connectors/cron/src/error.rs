//! Cron connector error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use thiserror::Error;

/// Result alias for cron operations.
pub type CronResult<T> = Result<T, CronError>;

/// Cron connector errors.
#[derive(Error, Debug)]
pub enum CronError {
    /// Invalid cron expression
    #[error("Invalid cron expression: {expression}")]
    InvalidExpression { expression: String },

    /// Schedule not found
    #[error("Schedule not found: {schedule_id}")]
    ScheduleNotFound { schedule_id: String },

    /// Duplicate schedule name
    #[error("Duplicate schedule name: {name}")]
    DuplicateName { name: String },

    /// All configured schedule slots are occupied.
    #[error("Schedule limit reached ({limit})")]
    ScheduleCapacity { limit: usize },

    /// Internal error
    #[error("Internal error: {message}")]
    Internal { message: String },
}

impl CronError {
    /// Convert to an `FcpError`.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::InvalidExpression { expression } => FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid cron expression: {expression}"),
            },
            Self::ScheduleNotFound { schedule_id } => FcpError::ResourceNotFound {
                resource: format!("schedule:{schedule_id}"),
            },
            Self::DuplicateName { name } => FcpError::Conflict {
                message: format!("Schedule with name '{name}' already exists"),
            },
            Self::ScheduleCapacity { limit } => FcpError::ResourceExhausted {
                resource: format!("cron schedule slots (max_schedules={limit})"),
            },
            Self::Internal { message } => FcpError::Internal {
                message: message.clone(),
            },
        }
    }
}

impl ConnectorErrorMapping for CronError {
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
        false
    }

    fn retry_after(&self) -> Option<Duration> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_expression_display() {
        let err = CronError::InvalidExpression {
            expression: "bad expr".into(),
        };
        assert_eq!(err.to_string(), "Invalid cron expression: bad expr");
    }

    #[test]
    fn schedule_not_found_display() {
        let err = CronError::ScheduleNotFound {
            schedule_id: "sched_123".into(),
        };
        assert_eq!(err.to_string(), "Schedule not found: sched_123");
    }

    #[test]
    fn duplicate_name_display() {
        let err = CronError::DuplicateName {
            name: "my-job".into(),
        };
        assert_eq!(err.to_string(), "Duplicate schedule name: my-job");
    }

    #[test]
    fn internal_display() {
        let err = CronError::Internal {
            message: "something broke".into(),
        };
        assert_eq!(err.to_string(), "Internal error: something broke");
    }

    #[test]
    fn invalid_expression_to_fcp_error() {
        match (CronError::InvalidExpression {
            expression: "* *".into(),
        })
        .to_fcp_error()
        {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert!(message.contains("* *"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn schedule_not_found_to_fcp_error() {
        match (CronError::ScheduleNotFound {
            schedule_id: "sched_abc".into(),
        })
        .to_fcp_error()
        {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.contains("sched_abc"));
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_name_to_fcp_error() {
        match (CronError::DuplicateName {
            name: "my-job".into(),
        })
        .to_fcp_error()
        {
            FcpError::Conflict { message } => {
                assert!(message.contains("my-job"));
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn internal_to_fcp_error() {
        match (CronError::Internal {
            message: "oops".into(),
        })
        .to_fcp_error()
        {
            FcpError::Internal { message } => {
                assert_eq!(message, "oops");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn error_debug_invalid_expression() {
        let err = CronError::InvalidExpression {
            expression: "bad".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("InvalidExpression"));
        assert!(dbg.contains("bad"));
    }

    #[test]
    fn error_debug_schedule_not_found() {
        let err = CronError::ScheduleNotFound {
            schedule_id: "sched_xyz".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ScheduleNotFound"));
        assert!(dbg.contains("sched_xyz"));
    }

    #[test]
    fn error_debug_duplicate_name() {
        let err = CronError::DuplicateName { name: "dup".into() };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("DuplicateName"));
        assert!(dbg.contains("dup"));
    }

    #[test]
    fn error_debug_internal() {
        let err = CronError::Internal {
            message: "boom".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Internal"));
        assert!(dbg.contains("boom"));
    }

    #[test]
    fn invalid_expression_display_empty() {
        let err = CronError::InvalidExpression {
            expression: String::new(),
        };
        assert_eq!(err.to_string(), "Invalid cron expression: ");
    }

    #[test]
    fn schedule_not_found_display_long_id() {
        let id = "sched_".to_string() + &"x".repeat(100);
        let err = CronError::ScheduleNotFound {
            schedule_id: id.clone(),
        };
        assert!(err.to_string().contains(&id));
    }

    #[test]
    fn duplicate_name_to_fcp_conflict_contains_name() {
        match (CronError::DuplicateName {
            name: "weekly-sync".into(),
        })
        .to_fcp_error()
        {
            FcpError::Conflict { message } => {
                assert!(message.contains("weekly-sync"));
                assert!(message.contains("already exists"));
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn invalid_expression_to_fcp_error_contains_expression() {
        match (CronError::InvalidExpression {
            expression: "*/abc * * * *".into(),
        })
        .to_fcp_error()
        {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert!(message.contains("*/abc * * * *"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn schedule_not_found_to_fcp_resource_format() {
        match (CronError::ScheduleNotFound {
            schedule_id: "sched_test_123".into(),
        })
        .to_fcp_error()
        {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "schedule:sched_test_123");
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn internal_to_fcp_error_preserves_message() {
        let msg = "something went terribly wrong with the scheduler";
        match (CronError::Internal {
            message: msg.into(),
        })
        .to_fcp_error()
        {
            FcpError::Internal { message } => {
                assert_eq!(message, msg);
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn internal_error_empty_message() {
        let err = CronError::Internal {
            message: String::new(),
        };
        assert_eq!(err.to_string(), "Internal error: ");
    }
}
