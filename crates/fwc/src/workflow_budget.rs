//! Monotone execution deadlines for pipelines, recipes, maps, and batches.
//!
//! Discovery, introspection and credential resolution consume the run budget.
//! A child step inherits what remains. Preflight and invocation share that
//! deadline; neither successful setup, preflight nor a new step renews the
//! parent budget. Response finalization has a separate transport allowance.

use std::time::{Duration, Instant};

/// Largest accepted total workflow budget, in milliseconds (one day).
pub const MAX_WORKFLOW_TIMEOUT_MS: u64 = 86_400_000;
/// Host invocation ceiling and largest accepted individual step budget.
pub const MAX_STEP_TIMEOUT_MS: u64 = 60_000;

/// An optional monotonic deadline that can be narrowed for each child step.
#[derive(Clone, Copy, Debug)]
pub struct ExecutionBudget {
    deadline: Option<Instant>,
}

/// The remaining budget cannot authorize another millisecond of execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeadlineExpired;

impl std::fmt::Display for DeadlineExpired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("workflow execution deadline expired")
    }
}

impl std::error::Error for DeadlineExpired {}

impl ExecutionBudget {
    /// Inputs come from validated pipeline/step timeout fields. Overflow fails
    /// closed even if a caller bypasses that validation.
    #[must_use]
    pub fn start(timeout_ms: Option<u64>, now: Instant) -> Self {
        Self {
            deadline: timeout_ms
                .map(|value| now.checked_add(Duration::from_millis(value)).unwrap_or(now)),
        }
    }

    /// Narrow to the earlier of the run deadline and this step's deadline.
    /// An omitted step timeout inherits the parent's exact deadline.
    #[must_use]
    pub fn for_step(self, timeout_ms: Option<u64>, now: Instant) -> Self {
        let step = Self::start(timeout_ms, now);
        Self {
            deadline: match (self.deadline, step.deadline) {
                (Some(parent), Some(child)) => Some(parent.min(child)),
                (parent, child) => parent.or(child),
            },
        }
    }

    /// Round down so a serialized millisecond budget never grants extra time.
    /// Less than one full millisecond is already exhausted for dispatch.
    ///
    /// # Errors
    /// Returns `DeadlineExpired` when fewer than one millisecond remains.
    pub fn remaining_ms(self, now: Instant) -> Result<Option<u64>, DeadlineExpired> {
        self.deadline
            .map(|deadline| {
                let milliseconds = deadline.saturating_duration_since(now).as_millis();
                if milliseconds == 0 {
                    return Err(DeadlineExpired);
                }
                Ok(u64::try_from(milliseconds).unwrap_or(u64::MAX))
            })
            .transpose()
    }

    /// Bound preflight by both the host read timeout and the remaining budget.
    ///
    /// # Errors
    /// Returns `DeadlineExpired` before sending when the budget is exhausted.
    pub fn preflight_timeout(
        self,
        read_timeout: Duration,
        now: Instant,
    ) -> Result<Duration, DeadlineExpired> {
        Ok(self.remaining_ms(now)?.map_or(read_timeout, |remaining| {
            read_timeout.min(Duration::from_millis(remaining))
        }))
    }

    /// Return the remaining execution time, capped at the host's ceiling.
    /// This excludes the separate response-finalization transport allowance.
    ///
    /// # Errors
    /// Returns `DeadlineExpired` instead of authorizing a zero-length dispatch.
    pub fn invocation_timeout_ms(self, now: Instant) -> Result<Option<u64>, DeadlineExpired> {
        Ok(self
            .remaining_ms(now)?
            .map(|remaining| remaining.min(MAX_STEP_TIMEOUT_MS)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_share_the_original_workflow_deadline() {
        let start = Instant::now();
        let run = ExecutionBudget::start(Some(1_000), start);
        let first = run.for_step(Some(800), start);
        assert_eq!(
            first.remaining_ms(start + Duration::from_millis(300)),
            Ok(Some(500))
        );
        let next = run.for_step(Some(800), start + Duration::from_millis(700));
        assert_eq!(
            next.remaining_ms(start + Duration::from_millis(700)),
            Ok(Some(300))
        );
        assert_eq!(
            next.remaining_ms(start + Duration::from_secs(1)),
            Err(DeadlineExpired)
        );
    }

    #[test]
    fn preflight_time_is_not_regranted_to_invocation() {
        let start = Instant::now();
        let step = ExecutionBudget::start(None, start).for_step(Some(750), start);
        assert_eq!(
            step.preflight_timeout(Duration::from_secs(30), start),
            Ok(Duration::from_millis(750))
        );
        assert_eq!(
            step.invocation_timeout_ms(start + Duration::from_millis(500)),
            Ok(Some(250))
        );
        assert_eq!(
            step.invocation_timeout_ms(start + Duration::from_millis(750)),
            Err(DeadlineExpired)
        );
    }

    #[test]
    fn unspecified_budget_preserves_host_limits_and_bounds_preflight() {
        let now = Instant::now();
        let unbounded = ExecutionBudget::start(None, now).for_step(None, now);
        assert_eq!(unbounded.invocation_timeout_ms(now), Ok(None));
        assert_eq!(
            unbounded.preflight_timeout(Duration::from_secs(30), now),
            Ok(Duration::from_secs(30))
        );
        let long_run = ExecutionBudget::start(Some(MAX_WORKFLOW_TIMEOUT_MS), now);
        assert_eq!(
            long_run.invocation_timeout_ms(now),
            Ok(Some(MAX_STEP_TIMEOUT_MS))
        );
        assert_eq!(
            long_run.preflight_timeout(Duration::from_secs(30), now),
            Ok(Duration::from_secs(30))
        );
    }

    #[test]
    fn unconfigured_step_inherits_parent_and_short_step_cannot_widen_it() {
        let now = Instant::now();
        let run = ExecutionBudget::start(Some(1_000), now);
        assert_eq!(run.for_step(None, now).remaining_ms(now), Ok(Some(1_000)));
        assert_eq!(
            run.for_step(Some(100), now).remaining_ms(now),
            Ok(Some(100))
        );
        assert_eq!(
            run.for_step(Some(2_000), now).remaining_ms(now),
            Ok(Some(1_000))
        );
    }

    #[test]
    fn deadline_expiry_never_becomes_a_zero_or_renewed_request_budget() {
        let now = Instant::now();
        let budget = ExecutionBudget::start(Some(2), now);
        assert_eq!(
            budget.remaining_ms(now + Duration::from_micros(1)),
            Ok(Some(1))
        );
        for elapsed in [
            Duration::from_micros(1_001),
            Duration::from_millis(2),
            Duration::from_secs(10),
        ] {
            let at = now + elapsed;
            assert_eq!(budget.invocation_timeout_ms(at), Err(DeadlineExpired));
            assert_eq!(
                budget.preflight_timeout(Duration::from_secs(30), at),
                Err(DeadlineExpired)
            );
            assert_eq!(
                budget.for_step(Some(5_000), at).remaining_ms(at),
                Err(DeadlineExpired)
            );
        }
    }
}
