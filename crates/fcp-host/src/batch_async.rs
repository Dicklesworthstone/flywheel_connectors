//! Async execution for the existing validated batch contract (bead 2b2l).
//!
//! Futures are owned by the batch, not detached onto a runtime. Admission is
//! bounded before invoking the handler factory; responses retain submission order
//! even when independent operations finish out of order.

use std::collections::HashMap;
use std::future::Future;
use std::time::{Duration, Instant};

use futures_util::stream::{FuturesUnordered, StreamExt};

use crate::{
    BatchExecutor, BatchInvokeRequest, BatchInvokeResponse, BatchOperation,
    BatchOperationError, BatchScheduleReport, BatchSchedulerMode, BatchStatus,
    HostResult, OperationResult, OperationResultStatus,
};

// A timer need not represent the entire caller-supplied u64 millisecond budget.
// Re-arm bounded waits using the original elapsed-time budget, never a renewed
// per-operation deadline or an overflowing Instant + user_duration expression.
const MAX_TIMER_WAIT: Duration = Duration::from_secs(60);

impl BatchExecutor {
    /// Execute independent batch operations concurrently, up to `max_parallelism`.
    ///
    /// Uses the same whole-batch validation, zone checks, topological tiers, and
    /// adaptive scheduling plan as [`Self::execute_sync`]. No handler is called
    /// until validation succeeds. A dependency must have succeeded before its
    /// dependent is admitted; unrelated branches may continue after a failure.
    /// Results and counters use the existing [`BatchInvokeResponse`] wire shape.
    ///
    /// `stop_on_first_error` stops admission when the first failure is observed.
    /// Already admitted handlers are drained until completion or the overall
    /// deadline; their known results are retained, not incorrectly called skipped.
    /// At the deadline, never-admitted operations are skipped with `BATCH_TIMEOUT`.
    /// Admitted operations without an observed result instead fail with
    /// `BATCH_OUTCOME_UNKNOWN` and no retry hint: dropping a future does not prove
    /// that a remote side effect was cancelled. This executor never retries work.
    ///
    /// The budget includes planning and is checked before every admission and
    /// after every completion. Handlers must be cooperative async functions:
    /// neither a blocking factory nor a blocking future poll can be preempted.
    /// Futures can borrow the request and need not be `Send` or `'static`.
    /// Dropping the batch drops its in-flight futures, without spawning detached
    /// tasks or promising to undo side effects already performed by a handler.
    /// Use the host's capability/lease enforcement inside the handler; batch zone
    /// validation is not a substitute for operation authorization.
    ///
    /// # Errors
    /// Returns a validation/planning error before any handler is invoked.
    /// Operation failures and deadline expiration are captured in the response.
    #[allow(clippy::future_not_send)]
    pub async fn execute_async<'a, F, Fut>(
        &self,
        request: &'a BatchInvokeRequest,
        mut handler: F,
    ) -> HostResult<BatchInvokeResponse>
    where
        F: FnMut(&'a BatchOperation) -> Fut,
        Fut: Future<Output = Result<serde_json::Value, BatchOperationError>>,
    {
        let started_at = Instant::now();
        let (plan, report) = self.plan_with_schedule_report(request)?;
        let report = matches!(request.options.scheduler.mode, BatchSchedulerMode::Adaptive)
            .then_some(report);
        let mut run = BatchRun::new(request, started_at);
        let limit = usize::try_from(request.options.max_parallelism)
            .unwrap_or(usize::MAX)
            .min(request.operations.len());

        'tiers: for tier in &plan.tiers {
            let mut waiting = tier.operation_ids.iter();
            let mut active = FuturesUnordered::new();
            loop {
                run.check_deadline();
                if run.timed_out() {
                    break 'tiers;
                }
                while run.halt.is_none() && active.len() < limit {
                    run.check_deadline();
                    if run.halt.is_some() {
                        break;
                    }
                    let Some(id) = waiting.next() else {
                        break;
                    };
                    let index = run.indices[id.as_str()];
                    let operation = &request.operations[index];
                    if !run.dependencies_succeeded(operation) {
                        run.results[index] = Some(skipped(
                            operation,
                            "DEP_FAILED",
                            "dependency did not complete successfully",
                        ));
                        continue;
                    }
                    // A factory may perform work before returning its future.
                    // Record admission first so even an unpolled future is not
                    // mistaken for an operation whose execution never began.
                    run.admitted_at[index] = Some(Instant::now());
                    let future = handler(operation);
                    active.push(async move { (index, future.await) });
                }
                run.check_deadline();
                if run.timed_out() {
                    break 'tiers;
                }
                if active.is_empty() {
                    break;
                }
                if let Ok(Some((index, result))) = fcp_async_core::time::timeout(
                    run.remaining().min(MAX_TIMER_WAIT),
                    active.next(),
                )
                .await
                {
                    run.record(index, result);
                }
                // A timer expiration merely wakes the original budget check.
                // It never restarts a handler or refreshes the batch deadline.
            }
            if run.halt.is_some() {
                break;
            }
        }
        run.check_deadline();
        Ok(run.finish(report))
    }
}

#[derive(Clone, Copy)]
enum Halt {
    FirstError,
    Timeout,
}

struct BatchRun<'a> {
    request: &'a BatchInvokeRequest,
    started_at: Instant,
    timeout: Duration,
    indices: HashMap<&'a str, usize>,
    results: Vec<Option<OperationResult>>,
    admitted_at: Vec<Option<Instant>>,
    halt: Option<Halt>,
}

impl<'a> BatchRun<'a> {
    fn new(request: &'a BatchInvokeRequest, started_at: Instant) -> Self {
        Self {
            request,
            started_at,
            timeout: Duration::from_millis(request.options.timeout_ms),
            indices: request.operations.iter().enumerate()
                .map(|(index, operation)| (operation.id.as_str(), index)).collect(),
            results: vec![None; request.operations.len()],
            admitted_at: vec![None; request.operations.len()],
            halt: None,
        }
    }

    fn remaining(&self) -> Duration {
        self.timeout.saturating_sub(self.started_at.elapsed())
    }

    fn check_deadline(&mut self) {
        if self.remaining().is_zero() {
            self.halt = Some(Halt::Timeout);
        }
    }

    const fn timed_out(&self) -> bool {
        matches!(self.halt, Some(Halt::Timeout))
    }

    fn dependencies_succeeded(&self, operation: &BatchOperation) -> bool {
        operation.depends_on.iter().all(|id| {
            self.results[self.indices[id.as_str()]].as_ref()
                .is_some_and(|result| result.status == OperationResultStatus::Success)
        })
    }

    fn record(&mut self, index: usize, result: Result<serde_json::Value, BatchOperationError>) {
        let duration_ms = self.admitted_at[index].map_or(0, elapsed_millis);
        let (status, output, error) = match result {
            Ok(value) => (OperationResultStatus::Success, Some(value), None),
            Err(error) => {
                if self.request.options.stop_on_first_error && self.halt.is_none() {
                    self.halt = Some(Halt::FirstError);
                }
                (OperationResultStatus::Error, None, Some(error))
            }
        };
        self.results[index] = Some(OperationResult {
            id: self.request.operations[index].id.clone(),
            status,
            output,
            error,
            duration_ms,
        });
    }

    fn finish(mut self, schedule_report: Option<BatchScheduleReport>) -> BatchInvokeResponse {
        let (skip_code, skip_message) = match self.halt {
            Some(Halt::Timeout) => ("BATCH_TIMEOUT", "batch timeout exceeded before admission"),
            _ => ("BATCH_ABORTED", "batch stopped before admission"),
        };
        let results: Vec<_> = self.request.operations.iter().enumerate().map(|(index, operation)| {
            self.results[index].take().unwrap_or_else(|| {
                if let Some(started_at) = self.admitted_at[index] {
                    OperationResult {
                        id: operation.id.clone(),
                        status: OperationResultStatus::Error,
                        output: None,
                        error: Some(operation_error(
                            "BATCH_OUTCOME_UNKNOWN",
                            "batch deadline interrupted an admitted operation; side effects may have occurred; do not retry without reconciliation",
                        )),
                        duration_ms: elapsed_millis(started_at),
                    }
                } else {
                    skipped(operation, skip_code, skip_message)
                }
            })
        }).collect();
        let completed = results.iter().filter(|r| r.status == OperationResultStatus::Success).count();
        let failed = results.iter().filter(|r| r.status == OperationResultStatus::Error).count();
        let skipped = results.len() - completed - failed;
        let status = if self.halt.is_some() {
            BatchStatus::Aborted
        } else if failed == 0 && skipped == 0 {
            BatchStatus::Success
        } else if completed == 0 {
            BatchStatus::AllFailed
        } else {
            BatchStatus::PartialSuccess
        };
        BatchInvokeResponse {
            status, completed, failed, skipped, results,
            total_duration_ms: elapsed_millis(self.started_at),
            schedule_report,
        }
    }
}

fn elapsed_millis(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn operation_error(code: &str, message: &str) -> BatchOperationError {
    BatchOperationError { code: code.to_owned(), message: message.to_owned(), retry_after_ms: None }
}

fn skipped(operation: &BatchOperation, code: &str, message: &str) -> OperationResult {
    OperationResult {
        id: operation.id.clone(),
        status: OperationResultStatus::Skipped,
        output: None,
        error: Some(operation_error(code, message)),
        duration_ms: 0,
    }
}
