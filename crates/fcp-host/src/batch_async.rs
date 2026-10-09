//! Async execution for the existing validated batch contract (bead 2b2l).
//!
//! Futures are owned by the batch, not detached onto a runtime. Admission is
//! bounded before invoking the handler factory; responses retain submission order
//! even when independent operations finish out of order. Dependencies release
//! their own successors without imposing a barrier on unrelated branches.

use std::collections::{BTreeSet, HashMap};
use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::{Duration, Instant};

use fcp_async_core::{AsyncError, ExecutionContext};
use futures_util::stream::{FuturesUnordered, StreamExt};

use crate::{
    BatchExecutor, BatchInvokeRequest, BatchInvokeResponse, BatchOperation,
    BatchOperationError, BatchScheduleReport, BatchSchedulerMode, BatchStatus,
    ExecutionPlan, HostResult, OperationResult, OperationResultStatus,
};

// A timer need not represent the entire caller-supplied u64 millisecond budget.
// Re-arm bounded waits using the original elapsed-time budget, never a renewed
// per-operation deadline or an overflowing Instant + user_duration expression.
const MAX_TIMER_WAIT: Duration = Duration::from_secs(60);

impl BatchExecutor {
    /// Execute independent batch operations concurrently, up to `max_parallelism`.
    ///
    /// Uses the same whole-batch validation, zone checks, and deterministic or
    /// adaptive planning preference as [`Self::execute_sync`]. No handler is
    /// called until validation succeeds. Unlike synchronous tier execution, a
    /// dependent becomes eligible as soon as its own dependencies finish; an
    /// unrelated slow operation does not impose a batch-wide tier barrier.
    /// Among currently ready operations, the original plan order wins. A
    /// dependency must have succeeded before its dependent is admitted;
    /// unrelated branches may continue after a failure. Results and counters
    /// use the existing [`BatchInvokeResponse`] wire shape.
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
        handler: F,
    ) -> HostResult<BatchInvokeResponse>
    where
        F: FnMut(&'a BatchOperation) -> Fut,
        Fut: Future<Output = Result<serde_json::Value, BatchOperationError>>,
    {
        self.execute_async_inner(request, None, handler).await
    }

    /// Execute a batch under an existing FCP cancellation/deadline context.
    ///
    /// Unlike wrapping the entire batch in `context.run(...)`, this method
    /// returns the accumulated per-operation results when the context stops it.
    /// The earlier of the context deadline and the batch budget wins; neither
    /// is renewed while waiting. Cancellation takes precedence when both are
    /// observed together, including before admission and during error draining.
    ///
    /// Cancellation skips never-admitted work with `BATCH_CANCELLED` and drops
    /// unresolved admitted futures, reporting those as `BATCH_OUTCOME_UNKNOWN`.
    /// Known results remain intact. This does not acknowledge cancellation of
    /// external side effects or authorize retries. It never cancels or extends
    /// the supplied context itself. Authorize user cancellation before triggering
    /// that context, just as for the host's existing cancellation controller.
    ///
    /// Ready-heavy batches periodically yield so a cancellation task on the same
    /// executor can run. Blocking handler factories, polls, and destructors still
    /// cannot be preempted. Other semantics match [`Self::execute_async`].
    ///
    /// # Errors
    /// Returns validation/planning failures before any handler is invoked.
    /// Cancellation, timeout, and operation failures are represented in the batch
    /// response rather than discarding partial results in a top-level error.
    #[allow(clippy::future_not_send)]
    pub async fn execute_async_with_context<'a, F, Fut>(
        &self,
        request: &'a BatchInvokeRequest,
        context: &ExecutionContext,
        handler: F,
    ) -> HostResult<BatchInvokeResponse>
    where
        F: FnMut(&'a BatchOperation) -> Fut,
        Fut: Future<Output = Result<serde_json::Value, BatchOperationError>>,
    {
        self.execute_async_inner(request, Some(context), handler).await
    }

    #[allow(clippy::future_not_send)]
    async fn execute_async_inner<'a, F, Fut>(
        &self,
        request: &'a BatchInvokeRequest,
        context: Option<&ExecutionContext>,
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
        let mut dependencies = DependencyQueue::new(request, &plan, &run.indices);
        let limit = usize::try_from(request.options.max_parallelism)
            .unwrap_or(usize::MAX)
            .min(request.operations.len());
        let mut cooperative_steps = 0_u8;
        let mut active = FuturesUnordered::new();

        loop {
            run.check_limits(context);
            if run.interrupted() {
                break;
            }
            while run.halt.is_none() && active.len() < limit {
                run.check_limits(context);
                if run.halt.is_some() {
                    break;
                }
                let Some(index) = dependencies.pop_ready() else {
                    break;
                };
                let operation = &request.operations[index];
                if !run.dependencies_succeeded(operation) {
                    run.results[index] = Some(skipped(
                        operation,
                        "DEP_FAILED",
                        "dependency did not complete successfully",
                    ));
                    // A skipped node is settled too. Release its descendants
                    // into failure propagation, never into handler execution.
                    dependencies.complete(index);
                    cooperate(&mut cooperative_steps).await;
                    continue;
                }
                // A factory may perform work before returning its future.
                // Record admission first so even an unpolled future is not
                // mistaken for an operation whose execution never began.
                run.admitted_at[index] = Some(Instant::now());
                let future = handler(operation);
                active.push(async move { (index, future.await) });
                cooperate(&mut cooperative_steps).await;
            }
            run.check_limits(context);
            if run.interrupted() || active.is_empty() {
                break;
            }
            let next = fcp_async_core::time::timeout(
                run.remaining(context).min(MAX_TIMER_WAIT),
                active.next(),
            );
            let result = match context {
                Some(context) => context.run(next).await.and_then(std::convert::identity),
                None => next.await,
            };
            match result {
                Ok(Some((index, result))) => {
                    run.record(index, result);
                    dependencies.complete(index);
                }
                Ok(None) => break,
                Err(AsyncError::Timeout { .. }) => {}
                Err(AsyncError::Cancelled) => run.halt = Some(Halt::Cancelled),
                Err(_) => run.halt = Some(Halt::RuntimeFailure),
            }
            // A timer expiration merely wakes the original budget check.
            // It never restarts a handler or refreshes the batch deadline.
            cooperate(&mut cooperative_steps).await;
        }
        // Release handler-owned resources before constructing the final response.
        // Unresolved admissions remain recorded as outcome-unknown, not skipped.
        drop(active);
        run.check_limits(context);
        Ok(run.finish(report))
    }
}

/// A completion-driven ready frontier over the already validated dependency DAG.
/// A plan supplies deterministic preference, not barriers between unrelated work.
struct DependencyQueue {
    remaining: Vec<usize>,
    dependents: Vec<Vec<usize>>,
    ranks: Vec<usize>,
    ready: BTreeSet<(usize, usize)>,
}

impl DependencyQueue {
    fn new(
        request: &BatchInvokeRequest,
        plan: &ExecutionPlan,
        indices: &HashMap<&str, usize>,
    ) -> Self {
        let count = request.operations.len();
        let mut queue = Self {
            remaining: vec![0; count],
            dependents: vec![Vec::new(); count],
            ranks: vec![0; count],
            ready: BTreeSet::new(),
        };
        for (rank, id) in plan.tiers.iter().flat_map(|tier| &tier.operation_ids).enumerate() {
            queue.ranks[indices[id.as_str()]] = rank;
        }
        for (index, operation) in request.operations.iter().enumerate() {
            queue.remaining[index] = operation.depends_on.len();
            for dependency in &operation.depends_on {
                queue.dependents[indices[dependency.as_str()]].push(index);
            }
            if queue.remaining[index] == 0 {
                queue.ready.insert((queue.ranks[index], index));
            }
        }
        queue
    }

    fn pop_ready(&mut self) -> Option<usize> {
        self.ready.pop_first().map(|(_, index)| index)
    }

    fn complete(&mut self, index: usize) {
        // Each operation settles once. Repeated dependency references have
        // matching counts and edges, so they cannot schedule a handler twice.
        for &dependent in &self.dependents[index] {
            debug_assert!(self.remaining[dependent] > 0);
            self.remaining[dependent] -= 1;
            if self.remaining[dependent] == 0 {
                self.ready.insert((self.ranks[dependent], dependent));
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Halt {
    FirstError,
    Timeout,
    Cancelled,
    RuntimeFailure,
}

// One batch must not monopolize a local executor merely because all its
// factories/futures are immediately ready. No detached task is needed to yield.
async fn cooperate(steps: &mut u8) {
    *steps += 1;
    if *steps < 64 {
        return;
    }
    *steps = 0;
    let mut yielded = false;
    poll_fn(|cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }).await;
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

    fn remaining(&self, context: Option<&ExecutionContext>) -> Duration {
        let batch_remaining = self.timeout.saturating_sub(self.started_at.elapsed());
        context.and_then(ExecutionContext::remaining_budget)
            .map_or(batch_remaining, |remaining| remaining.min(batch_remaining))
    }

    fn check_limits(&mut self, context: Option<&ExecutionContext>) {
        if matches!(self.halt, Some(Halt::Cancelled | Halt::RuntimeFailure)) {
            return;
        }
        if context.is_some_and(ExecutionContext::is_cancelled) {
            self.halt = Some(Halt::Cancelled);
        } else if self.remaining(context).is_zero() {
            self.halt = Some(Halt::Timeout);
        }
    }

    const fn interrupted(&self) -> bool {
        matches!(self.halt, Some(Halt::Timeout | Halt::Cancelled | Halt::RuntimeFailure))
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
            Some(Halt::Cancelled) => ("BATCH_CANCELLED", "batch context cancelled before admission"),
            Some(Halt::RuntimeFailure) => ("BATCH_RUNTIME_ERROR", "batch runtime failed before admission"),
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
                            "batch interrupted an admitted operation; side effects may have occurred; do not retry without reconciliation",
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
