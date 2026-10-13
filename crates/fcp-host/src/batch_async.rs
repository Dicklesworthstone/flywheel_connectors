//! Async execution for the existing validated batch contract (bead 2b2l).
//!
//! Futures are owned by the batch, not detached onto a runtime. Admission is
//! bounded before invoking the handler factory; responses retain submission order
//! even when independent operations finish out of order. Dependencies release
//! their own successors without imposing a barrier on unrelated branches.

use std::collections::{BTreeSet, HashMap};
use std::future::{Future, Ready, poll_fn, ready};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::pin;
use std::task::Poll;
use std::time::{Duration, Instant};

use fcp_async_core::{AsyncError, ExecutionContext};
use futures_util::FutureExt;
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

/// Outcome of delivering batch results to a caller-provided sink.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchDeliveryStatus {
    /// Every result was acknowledged by the sink.
    Complete,
    /// The sink returned an error; no later delivery was attempted.
    Rejected,
    /// The sink unwound; no later delivery was attempted.
    Panicked,
    /// Delivery stopped at a cancellation, deadline, or runtime boundary.
    /// An unacknowledged callback may already have delivered bytes. Its
    /// operation result remains in the final response and must not be retried.
    Interrupted,
}

/// A complete accounting of execution, even if incremental delivery failed.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BatchStreamingResponse {
    /// Final results in submission order, including undelivered results.
    pub response: BatchInvokeResponse,
    /// Number of callbacks that returned success, not proof of remote receipt.
    pub acknowledged_results: usize,
    /// Whether all results reached the sink without refusal or interruption.
    pub delivery_status: BatchDeliveryStatus,
}

type SilentResultSink = fn(&OperationResult) -> Result<(), BatchOperationError>;

// The associated future retains conditional Send just like the concrete sink.
// Immediate callbacks remain synchronous, including final timeout accounting.
// Waiting callbacks instead share the batch's original execution budget.
trait ResultSink {
    type Pending: Future<Output = Result<(), BatchOperationError>>;

    const WAIT_FOR_CAPACITY: bool;

    fn begin(&mut self, result: &OperationResult) -> Self::Pending;
}

struct ImmediateSink<S>(S);

impl<S> ResultSink for ImmediateSink<S>
where
    S: FnMut(&OperationResult) -> Result<(), BatchOperationError>,
{
    type Pending = Ready<Result<(), BatchOperationError>>;

    const WAIT_FOR_CAPACITY: bool = false;

    fn begin(&mut self, result: &OperationResult) -> Self::Pending {
        ready((self.0)(result))
    }
}

struct WaitingSink<S>(S);

impl<S, Fut> ResultSink for WaitingSink<S>
where
    S: FnMut(OperationResult) -> Fut,
    Fut: Future<Output = Result<(), BatchOperationError>>,
{
    type Pending = Fut;

    const WAIT_FOR_CAPACITY: bool = true;

    fn begin(&mut self, result: &OperationResult) -> Self::Pending {
        // The final response keeps the authoritative observed result. At most
        // one extra result is owned by the pending delivery future.
        (self.0)(result.clone())
    }
}

// Retain the concrete callback type across await points. Erasing it into a
// non-Send trait object makes even callback-free batches unspawnable by the
// host. Generic ownership preserves Send when available without requiring it
// from callers on a local executor.
struct ResultDelivery<S> {
    sink: Option<S>,
    acknowledged: usize,
    status: BatchDeliveryStatus,
}

impl<S> ResultDelivery<S>
where
    S: ResultSink,
{
    #[allow(clippy::future_not_send)]
    async fn deliver(
        &mut self,
        result: &OperationResult,
        started_at: Instant,
        timeout: Duration,
        context: Option<&ExecutionContext>,
    ) -> bool {
        // Final accounting after cancellation must not start another waiting
        // callback. The immediate API still offers its nonblocking final items.
        if self.sink.is_some()
            && S::WAIT_FOR_CAPACITY
            && delivery_stopped(started_at, timeout, context)
        {
            return self.stop(BatchDeliveryStatus::Interrupted);
        }
        let Some(sink) = self.sink.as_mut() else {
            return self.status == BatchDeliveryStatus::Complete;
        };
        let pending = match catch_unwind(AssertUnwindSafe(|| sink.begin(result))) {
            Ok(pending) => pending,
            Err(_) => return self.stop(BatchDeliveryStatus::Panicked),
        };
        let mut pending = pin!(AssertUnwindSafe(pending).catch_unwind());
        // Borrow the same pinned delivery future on every bounded timer wake.
        // Restarting a callback after timeout could duplicate an external send.
        let outcome = loop {
            if !S::WAIT_FOR_CAPACITY {
                break pending.as_mut().await;
            }
            if delivery_stopped(started_at, timeout, context) {
                return self.stop(BatchDeliveryStatus::Interrupted);
            }
            let next = fcp_async_core::time::timeout(
                delivery_remaining(started_at, timeout, context).min(MAX_TIMER_WAIT),
                pending.as_mut(),
            );
            let outcome = match context {
                Some(context) => context.run(next).await.and_then(std::convert::identity),
                None => next.await,
            };
            match outcome {
                Ok(outcome) => break outcome,
                Err(AsyncError::Timeout { .. }) => {}
                Err(_) => return self.stop(BatchDeliveryStatus::Interrupted),
            }
        };
        // A failed or interrupted callback may already have sent bytes. Never
        // retry it, expose its payload, or invoke that same sink again.
        let status = match outcome {
            Ok(Ok(())) => {
                self.acknowledged += 1;
                return true;
            }
            Ok(Err(_)) => BatchDeliveryStatus::Rejected,
            Err(_) => BatchDeliveryStatus::Panicked,
        };
        self.stop(status)
    }

    fn stop(&mut self, status: BatchDeliveryStatus) -> bool {
        self.status = status;
        self.sink = None;
        false
    }
}

fn delivery_remaining(
    started_at: Instant,
    timeout: Duration,
    context: Option<&ExecutionContext>,
) -> Duration {
    let remaining = timeout.saturating_sub(started_at.elapsed());
    context.and_then(ExecutionContext::remaining_budget)
        .map_or(remaining, |inherited| remaining.min(inherited))
}

fn delivery_stopped(
    started_at: Instant,
    timeout: Duration,
    context: Option<&ExecutionContext>,
) -> bool {
    context.is_some_and(ExecutionContext::is_cancelled)
        || delivery_remaining(started_at, timeout, context).is_zero()
}

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
    /// With unwinding enabled, a panic in a factory or future poll stops all new
    /// admission, even when `stop_on_first_error` is false. The panicked operation
    /// has an unknown external outcome; other admitted operations are drained
    /// under the original budget. The factory is never reused after a panic.
    /// Panic payloads are not copied into responses; the process panic hook is
    /// unchanged. Aborting panics and panics in destructors are not contained.
    ///
    /// The budget includes planning and is checked before every admission and
    /// after every completion. Handlers must be cooperative async functions:
    /// neither a blocking factory nor a blocking future poll can be preempted.
    /// Futures can borrow the request and need not be `Send` or `'static`.
    /// The returned future is `Send` when its handler and handler futures are
    /// `Send`; local-only handlers remain supported.
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
        self.execute_async_inner(request, None, handler, None::<ImmediateSink<SilentResultSink>>)
            .await
            .map(|result| result.response)
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
        self.execute_async_inner(request, Some(context), handler, None::<ImmediateSink<SilentResultSink>>)
            .await
            .map(|result| result.response)
    }

    /// Deliver results as operations settle, without waiting for unrelated work.
    ///
    /// The sink sees completion order; the returned response retains submission
    /// order. Each result is offered at most once, including dependency failures
    /// and the final accounting of interrupted or never-admitted operations.
    /// The sink borrows each result, so the executor adds no output queue or
    /// detached delivery task. Use a bounded, nonblocking sink (for example a
    /// channel's `try_send`) to make backpressure explicit.
    ///
    /// A sink error or unwinding panic disables further delivery and stops new
    /// admission. Already admitted work drains under the original budget and
    /// context; all observed outcomes remain in the final response. Rejection
    /// does not mean an operation failed or that no bytes were delivered. This
    /// API never retries either execution or delivery. Callback error and panic
    /// payloads are not copied to the response. The process panic hook remains
    /// unchanged; blocking sinks, aborting panics, and destructor panics cannot
    /// be contained. Sink acknowledgements do not prove durable storage.
    /// Dropping this future stops delivery and drops owned handler futures;
    /// unlike context cancellation, it cannot return final accounting.
    ///
    /// # Errors
    /// Returns validation/planning errors before invoking either callback.
    /// Execution and delivery failures are captured in the returned accounting.
    #[allow(clippy::future_not_send)]
    pub async fn execute_async_streaming<'a, F, Fut, S>(
        &self,
        request: &'a BatchInvokeRequest,
        context: Option<&ExecutionContext>,
        handler: F,
        on_result: S,
    ) -> HostResult<BatchStreamingResponse>
    where
        F: FnMut(&'a BatchOperation) -> Fut,
        Fut: Future<Output = Result<serde_json::Value, BatchOperationError>>,
        S: FnMut(&OperationResult) -> Result<(), BatchOperationError>,
    {
        self.execute_async_inner(request, context, handler, Some(ImmediateSink(on_result)))
            .await
    }

    /// Deliver batch results through a sink that can wait for bounded capacity.
    ///
    /// Unlike [`Self::execute_async_streaming`], a temporarily full channel need
    /// not abort the batch: the callback can await its send. Only one delivery
    /// is active. While it waits, no new handlers are admitted and owned handler
    /// futures are not polled. Already-started external effects may still run.
    /// Use independently driven receivers; a callback must not wait on another
    /// operation in this same batch, since that operation cannot make progress
    /// until the delivery completes. Such waits still end at the batch deadline.
    ///
    /// Execution, backpressure and final delivery share the original budget and
    /// optional context. Cancellation or timeout drops the pending delivery,
    /// disables later callbacks, and returns `BatchDeliveryStatus::Interrupted`.
    /// Observed operation outcomes stay intact even if their delivery did not
    /// finish. Unresolved admitted operations remain `BATCH_OUTCOME_UNKNOWN`;
    /// never-admitted operations are skipped. After the deadline, final results
    /// are available only in the returned response, not through new callbacks.
    ///
    /// Each callback receives one owned clone; no extra unbounded output queue
    /// or detached task is created. The final response still retains all results
    /// and is not byte-bounded. Callback success is not a durable acknowledgement.
    /// No operation or delivery is retried. Refusal and unwinding panic stop new
    /// admission and drain already admitted work under the remaining budget.
    /// Blocking callbacks/polls, destructor panics, and panic-abort are outside
    /// containment. Dropping the batch cannot return its final accounting.
    ///
    /// The returned future is `Send` when both callbacks and their futures are
    /// `Send`. Borrowing and local-only futures are also supported. Operation
    /// authorization and capability/lease enforcement remain the handler's job.
    ///
    /// # Errors
    /// Returns validation/planning errors before invoking either callback.
    /// Execution and delivery failures are included in the final response.
    #[allow(clippy::future_not_send)]
    pub async fn execute_async_streaming_wait<'a, F, Fut, S, DeliveryFut>(
        &self,
        request: &'a BatchInvokeRequest,
        context: Option<&ExecutionContext>,
        handler: F,
        on_result: S,
    ) -> HostResult<BatchStreamingResponse>
    where
        F: FnMut(&'a BatchOperation) -> Fut,
        Fut: Future<Output = Result<serde_json::Value, BatchOperationError>>,
        S: FnMut(OperationResult) -> DeliveryFut,
        DeliveryFut: Future<Output = Result<(), BatchOperationError>>,
    {
        self.execute_async_inner(request, context, handler, Some(WaitingSink(on_result)))
            .await
    }

    #[allow(clippy::future_not_send)]
    async fn execute_async_inner<'a, F, Fut, S>(
        &self,
        request: &'a BatchInvokeRequest,
        context: Option<&ExecutionContext>,
        mut handler: F,
        sink: Option<S>,
    ) -> HostResult<BatchStreamingResponse>
    where
        F: FnMut(&'a BatchOperation) -> Fut,
        Fut: Future<Output = Result<serde_json::Value, BatchOperationError>>,
        S: ResultSink,
    {
        let started_at = Instant::now();
        let (plan, report) = self.plan_with_schedule_report(request)?;
        let report = matches!(request.options.scheduler.mode, BatchSchedulerMode::Adaptive)
            .then_some(report);
        let mut run = BatchRun::new(request, started_at);
        let mut delivery = ResultDelivery {
            sink,
            acknowledged: 0,
            status: BatchDeliveryStatus::Complete,
        };
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
                    run.deliver_recorded(index, &mut delivery, context).await;
                    cooperate(&mut cooperative_steps).await;
                    continue;
                }
                // A factory may perform work before returning its future.
                // Record admission first so even an unpolled future is not
                // mistaken for an operation whose execution never began.
                run.admitted_at[index] = Some(Instant::now());
                // AssertUnwindSafe is deliberately local to the handler boundary.
                // After any panic we stop admission rather than calling a factory
                // whose captured state may have been left partially mutated.
                match catch_unwind(AssertUnwindSafe(|| handler(operation))) {
                    Ok(future) => active.push(async move {
                        (index, AssertUnwindSafe(future).catch_unwind().await)
                    }),
                    Err(_) => {
                        run.record_panicked(index);
                        dependencies.complete(index);
                        run.deliver_recorded(index, &mut delivery, context).await;
                    }
                }
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
                    match result {
                        Ok(result) => run.record(index, result),
                        Err(_) => run.record_panicked(index),
                    }
                    dependencies.complete(index);
                    run.deliver_recorded(index, &mut delivery, context).await;
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
        let response = run.finish(report, &mut delivery, context).await;
        Ok(BatchStreamingResponse {
            response,
            acknowledged_results: delivery.acknowledged,
            delivery_status: delivery.status,
        })
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
    HandlerPanic,
    DeliveryFailure,
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

    fn record_panicked(&mut self, index: usize) {
        if !self.interrupted() {
            self.halt = Some(Halt::HandlerPanic);
        }
        self.record(index, Err(operation_error(
            "BATCH_OUTCOME_UNKNOWN",
            "batch handler panicked after admission; side effects may have occurred; do not retry without reconciliation",
        )));
    }

    #[allow(clippy::future_not_send)]
    async fn deliver_recorded<S>(
        &mut self,
        index: usize,
        delivery: &mut ResultDelivery<S>,
        context: Option<&ExecutionContext>,
    )
    where
        S: ResultSink,
    {
        let Some(result) = &self.results[index] else {
            return;
        };
        let delivered = delivery.deliver(result, self.started_at, self.timeout, context).await;
        if S::WAIT_FOR_CAPACITY {
            self.check_limits(context);
        }
        if !delivered && !self.interrupted() {
            self.halt = Some(Halt::DeliveryFailure);
        }
    }

    #[allow(clippy::future_not_send)]
    async fn finish<S>(
        mut self,
        schedule_report: Option<BatchScheduleReport>,
        delivery: &mut ResultDelivery<S>,
        context: Option<&ExecutionContext>,
    ) -> BatchInvokeResponse
    where
        S: ResultSink,
    {
        let (skip_code, skip_message) = match self.halt {
            Some(Halt::Timeout) => ("BATCH_TIMEOUT", "batch timeout exceeded before admission"),
            Some(Halt::Cancelled) => ("BATCH_CANCELLED", "batch context cancelled before admission"),
            Some(Halt::RuntimeFailure) => ("BATCH_RUNTIME_ERROR", "batch runtime failed before admission"),
            Some(Halt::HandlerPanic) => ("BATCH_PANICKED", "batch handler panicked before this operation was admitted"),
            Some(Halt::DeliveryFailure) => ("BATCH_RESULT_DELIVERY_FAILED", "batch result sink failed before this operation was admitted"),
            _ => ("BATCH_ABORTED", "batch stopped before admission"),
        };
        let mut results = Vec::with_capacity(self.request.operations.len());
        for index in 0..self.request.operations.len() {
            if let Some(result) = self.results[index].take() {
                // This result was already offered when it settled. In
                // particular, never redeliver after a sink accepted then failed.
                results.push(result);
                continue;
            }
            let operation = &self.request.operations[index];
            let result = if let Some(started_at) = self.admitted_at[index] {
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
            };
            let delivered = delivery.deliver(&result, self.started_at, self.timeout, context).await;
            if S::WAIT_FOR_CAPACITY {
                self.check_limits(context);
            }
            if !delivered && !self.interrupted() {
                self.halt = Some(Halt::DeliveryFailure);
            }
            results.push(result);
        }
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

#[cfg(test)]
mod send_tests {
    use std::cell::Cell;
    use std::future::{Future, ready};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;

    use super::*;
    use crate::{BatchOptions, BatchScheduleHint};

    fn request() -> BatchInvokeRequest {
        BatchInvokeRequest {
            operations: vec![BatchOperation {
                id: "a".to_owned(),
                tool: "test.echo".to_owned(),
                input: json!({"value": 42}),
                depends_on: vec![],
                zone: None,
                scheduler: BatchScheduleHint::default(),
            }],
            options: BatchOptions::default(),
        }
    }

    // Passing the *returned* future through this bound catches type erasure
    // even when every callback captured by the public method is thread-safe.
    fn require_send<F: Future + Send>(future: F) -> F {
        future
    }

    #[fcp_async_core::runtime::test]
    async fn callback_free_batch_is_send() {
        let executor = BatchExecutor::new();
        let request = request();
        let response = require_send(executor.execute_async(&request, |operation| {
            ready(Ok(operation.input.clone()))
        })).await.unwrap();
        assert_eq!(response.completed, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn context_batch_is_send() {
        let executor = BatchExecutor::new();
        let request = request();
        let context = ExecutionContext::background();
        let response = require_send(executor.execute_async_with_context(
            &request, &context, |operation| ready(Ok(operation.input.clone())),
        )).await.unwrap();
        assert_eq!(response.completed, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn streaming_batch_preserves_borrowed_send_callbacks() {
        let executor = BatchExecutor::new();
        let request = request();
        let observed = AtomicUsize::new(0);
        let response = require_send(executor.execute_async_streaming(
            &request, None, |operation| ready(Ok(operation.input.clone())),
            |_| {
                observed.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
        )).await.unwrap();
        assert_eq!(response.response.completed, 1);
        assert_eq!(response.acknowledged_results, 1);
        assert_eq!(observed.load(Ordering::Relaxed), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn local_only_streaming_callbacks_still_work() {
        let executor = BatchExecutor::new();
        let request = request();
        let observed = Cell::new(0);
        let response = executor.execute_async_streaming(
            &request, None, |operation| ready(Ok(operation.input.clone())),
            |_| { observed.set(observed.get() + 1); Ok(()) },
        ).await.unwrap();
        assert_eq!(response.delivery_status, BatchDeliveryStatus::Complete);
        assert_eq!(observed.get(), 1);
    }
}

#[cfg(test)]
mod waiting_delivery_tests {
    use std::cell::{Cell, RefCell};
    use std::future::{pending, ready};
    use std::rc::Rc;
    use std::task::Waker;

    use futures_util::poll;
    use serde_json::json;

    use super::*;
    use crate::{BatchOptions, BatchScheduleHint};

    #[derive(Default)]
    struct Gate {
        open: Cell<bool>,
        waker: RefCell<Option<Waker>>,
    }

    impl Gate {
        async fn wait(&self) {
            poll_fn(|cx| {
                if self.open.get() {
                    Poll::Ready(())
                } else {
                    *self.waker.borrow_mut() = Some(cx.waker().clone());
                    Poll::Pending
                }
            }).await;
        }

        fn release(&self) {
            self.open.set(true);
            if let Some(waker) = self.waker.borrow_mut().take() {
                waker.wake();
            }
        }
    }

    struct DropCount<'a>(&'a Cell<usize>);

    impl Drop for DropCount<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    fn request(parallelism: u32) -> BatchInvokeRequest {
        BatchInvokeRequest {
            operations: ["a", "b", "c"].into_iter().map(|id| BatchOperation {
                id: id.to_owned(),
                tool: "test.echo".to_owned(),
                input: json!({"id": id}),
                depends_on: vec![],
                zone: None,
                scheduler: BatchScheduleHint::default(),
            }).collect(),
            options: BatchOptions {
                max_parallelism: parallelism,
                stop_on_first_error: false,
                ..BatchOptions::default()
            },
        }
    }

    fn require_send<F: Future + Send>(future: F) -> F {
        future
    }

    #[fcp_async_core::runtime::test]
    async fn waiting_sink_preserves_send_without_requiring_sync() {
        let executor = BatchExecutor::new();
        let request = request(1);
        // Cell is Send but not Sync. Ownership, not a shared callback borrow,
        // must determine whether the batch can move between runtime workers.
        let calls = Cell::new(0);
        let response = require_send(executor.execute_async_streaming_wait(
            &request, None, |op| ready(Ok(op.input.clone())),
            move |_| {
                calls.set(calls.get() + 1);
                ready(Ok(()))
            },
        )).await.unwrap();
        assert_eq!(response.delivery_status, BatchDeliveryStatus::Complete);
        assert_eq!(response.acknowledged_results, 3);
    }

    #[fcp_async_core::runtime::test]
    async fn pending_delivery_pauses_admission_and_resumes_exactly_once() {
        let executor = BatchExecutor::new();
        let request = request(1);
        let gate = Rc::new(Gate::default());
        let admitted = RefCell::new(Vec::new());
        let delivered = RefCell::new(Vec::new());
        let mut batch = Box::pin(executor.execute_async_streaming_wait(
            &request, None,
            |op| {
                admitted.borrow_mut().push(op.id.clone());
                ready(Ok(op.input.clone()))
            },
            |result| {
                delivered.borrow_mut().push(result.id.clone());
                let gate = Rc::clone(&gate);
                async move { gate.wait().await; Ok(()) }
            },
        ));
        assert!(poll!(batch.as_mut()).is_pending());
        assert!(poll!(batch.as_mut()).is_pending());
        assert_eq!(*admitted.borrow(), ["a"]);
        assert_eq!(*delivered.borrow(), ["a"], "do not recreate a pending send");
        gate.release();
        let result = batch.await.unwrap();
        assert_eq!(*admitted.borrow(), ["a", "b", "c"]);
        assert_eq!(*delivered.borrow(), ["a", "b", "c"]);
        assert_eq!(result.response.status, BatchStatus::Success);
        assert_eq!(result.delivery_status, BatchDeliveryStatus::Complete);
        assert_eq!(result.acknowledged_results, 3);
    }

    #[fcp_async_core::runtime::test]
    async fn capacity_one_channel_waits_without_aborting_or_reordering_final_results() {
        let executor = BatchExecutor::new();
        let mut request = request(1);
        request.operations.reverse();
        let (sender, mut receiver) = fcp_async_core::channel::bounded("batch-results", 1);
        let admitted = RefCell::new(Vec::new());
        let mut batch = Box::pin(executor.execute_async_streaming_wait(
            &request, None,
            |op| {
                admitted.borrow_mut().push(op.id.clone());
                ready(Ok(op.input.clone()))
            },
            |result| {
                let sender = sender.clone();
                async move {
                    sender.send(result).await.map_err(|_| {
                        operation_error("CLOSED", "result receiver closed")
                    })
                }
            },
        ));
        // a occupies the channel; b has completed but its send must wait.
        assert!(poll!(batch.as_mut()).is_pending());
        assert_eq!(*admitted.borrow(), ["a", "b"]);
        assert_eq!(receiver.recv().await.unwrap().id, "a");
        // Freeing capacity acknowledges b and allows c to run, exactly once.
        assert!(poll!(batch.as_mut()).is_pending());
        assert_eq!(*admitted.borrow(), ["a", "b", "c"]);
        assert_eq!(receiver.recv().await.unwrap().id, "b");
        let result = batch.await.unwrap();
        assert_eq!(receiver.recv().await.unwrap().id, "c");
        assert_eq!(result.delivery_status, BatchDeliveryStatus::Complete);
        assert_eq!(result.acknowledged_results, 3);
        assert_eq!(result.response.status, BatchStatus::Success);
        assert_eq!(result.response.results.iter().map(|item| item.id.as_str())
            .collect::<Vec<_>>(), ["c", "b", "a"]);
    }

    #[fcp_async_core::runtime::test]
    async fn closed_channel_keeps_acknowledged_and_undelivered_provider_successes() {
        let executor = BatchExecutor::new();
        let request = request(1);
        let (sender, receiver) = fcp_async_core::channel::bounded("batch-disconnect", 1);
        let mut batch = Box::pin(executor.execute_async_streaming_wait(
            &request, None, |op| ready(Ok(op.input.clone())),
            |result| {
                let sender = sender.clone();
                async move {
                    sender.send(result).await.map_err(|_| {
                        operation_error("CLOSED", "private receiver error")
                    })
                }
            },
        ));
        assert!(poll!(batch.as_mut()).is_pending());
        drop(receiver);
        let result = batch.await.unwrap();
        assert_eq!(result.delivery_status, BatchDeliveryStatus::Rejected);
        assert_eq!(result.acknowledged_results, 1);
        assert_eq!(result.response.completed, 2);
        assert_eq!(result.response.failed, 0);
        assert_eq!(result.response.skipped, 1);
        assert_eq!(result.response.results[1].output, Some(json!({"id": "b"})));
        assert!(!serde_json::to_string(&result).unwrap().contains("private receiver"));
    }

    #[fcp_async_core::runtime::test]
    async fn cancellation_preserves_observed_success_and_releases_pending_delivery() {
        let executor = BatchExecutor::new();
        let request = request(2);
        let context = ExecutionContext::background();
        let calls = Cell::new(0);
        let drops = Cell::new(0);
        let mut batch = Box::pin(executor.execute_async_streaming_wait(
            &request, Some(&context),
            |op| async move {
                if op.id != "a" { pending::<()>().await; }
                Ok(op.input.clone())
            },
            |_| {
                calls.set(calls.get() + 1);
                let guard = DropCount(&drops);
                async move {
                    let _guard = guard;
                    pending::<()>().await;
                    Ok(())
                }
            },
        ));
        assert!(poll!(batch.as_mut()).is_pending());
        context.cancel();
        let result = batch.await.unwrap();
        assert_eq!(result.delivery_status, BatchDeliveryStatus::Interrupted);
        assert_eq!(result.acknowledged_results, 0);
        assert_eq!(calls.get(), 1);
        assert_eq!(drops.get(), 1);
        assert_eq!((result.response.completed, result.response.failed, result.response.skipped), (1, 1, 1));
        assert_eq!(result.response.results[0].output, Some(json!({"id": "a"})));
        let uncertain = result.response.results[1].error.as_ref().unwrap();
        assert_eq!(uncertain.code, "BATCH_OUTCOME_UNKNOWN");
        assert_eq!(uncertain.retry_after_ms, None);
        assert_eq!(result.response.results[2].error.as_ref().unwrap().code, "BATCH_CANCELLED");
    }

    #[fcp_async_core::runtime::test]
    async fn delivery_wait_honors_both_inherited_and_batch_deadlines() {
        for inherit_shorter in [true, false] {
            let executor = BatchExecutor::new();
            let mut request = request(1);
            request.options.timeout_ms = if inherit_shorter { 60_000 } else { 250 };
            let context = ExecutionContext::request_scoped(if inherit_shorter {
                Duration::from_millis(250)
            } else {
                Duration::from_secs(60)
            });
            let result = fcp_async_core::time::timeout(
                Duration::from_secs(5),
                executor.execute_async_streaming_wait(
                    &request, Some(&context), |op| ready(Ok(op.input.clone())),
                    |_| pending::<Result<(), BatchOperationError>>(),
                ),
            ).await.expect("delivery must not renew its budget").unwrap();
            assert_eq!(result.delivery_status, BatchDeliveryStatus::Interrupted);
            assert_eq!(result.response.status, BatchStatus::Aborted);
            assert_eq!(result.response.completed, 1);
            assert_eq!(result.response.skipped, 2);
            assert_eq!(result.response.failed, 0, "delivery timeout is not provider failure");
            assert_eq!(result.response.results[1].error.as_ref().unwrap().code, "BATCH_TIMEOUT");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn original_budget_is_checked_before_the_delivery_factory() {
        let request = request(1);
        let calls = Cell::new(0);
        let mut delivery = ResultDelivery {
            sink: Some(WaitingSink(|_: OperationResult| {
                calls.set(calls.get() + 1);
                ready(Ok(()))
            })),
            acknowledged: 0,
            status: BatchDeliveryStatus::Complete,
        };
        let result = skipped(&request.operations[0], "TEST", "not dispatched");
        assert!(!delivery.deliver(&result, Instant::now(), Duration::ZERO, None).await);
        assert_eq!(calls.get(), 0);
        assert_eq!(delivery.status, BatchDeliveryStatus::Interrupted);
    }

    #[fcp_async_core::runtime::test]
    async fn refusal_after_pending_stops_admission_but_drains_existing_work() {
        let executor = BatchExecutor::new();
        let request = request(2);
        let gate = Gate::default();
        let calls = Cell::new(0);
        let mut batch = Box::pin(executor.execute_async_streaming_wait(
            &request, None, |op| ready(Ok(op.input.clone())),
            |_| {
                calls.set(calls.get() + 1);
                let gate = &gate;
                async move {
                    gate.wait().await;
                    Err(operation_error("PRIVATE", "private sink failure"))
                }
            },
        ));
        assert!(poll!(batch.as_mut()).is_pending());
        gate.release();
        let result = batch.await.unwrap();
        assert_eq!(result.delivery_status, BatchDeliveryStatus::Rejected);
        assert_eq!(calls.get(), 1);
        assert_eq!(result.acknowledged_results, 0);
        assert_eq!((result.response.completed, result.response.failed, result.response.skipped), (2, 0, 1));
        assert_eq!(result.response.results[2].error.as_ref().unwrap().code, "BATCH_RESULT_DELIVERY_FAILED");
        assert!(!serde_json::to_string(&result).unwrap().contains("private sink"));
    }

    #[cfg(panic = "unwind")]
    #[fcp_async_core::runtime::test]
    async fn delivery_factory_and_poll_panics_are_contained() {
        for factory_panics in [true, false] {
            let executor = BatchExecutor::new();
            let request = request(2);
            let calls = Cell::new(0);
            let result = executor.execute_async_streaming_wait(
                &request, None, |op| ready(Ok(op.input.clone())),
                |_| {
                    calls.set(calls.get() + 1);
                    assert!(!factory_panics, "private delivery factory panic");
                    async {
                        // Yield once to exercise panic containment after an
                        // earlier Pending result, not only on first poll.
                        let mut steps = 63;
                        cooperate(&mut steps).await;
                        panic!("private delivery poll panic");
                        #[allow(unreachable_code)]
                        Ok::<(), BatchOperationError>(())
                    }
                },
            ).await.unwrap();
            assert_eq!(result.delivery_status, BatchDeliveryStatus::Panicked);
            assert_eq!(result.acknowledged_results, 0);
            assert_eq!(calls.get(), 1);
            assert_eq!(result.response.completed, 2);
            assert_eq!(result.response.skipped, 1);
            assert!(!serde_json::to_string(&result).unwrap().contains("private delivery"));
        }
    }

    #[fcp_async_core::runtime::test]
    async fn validation_and_pre_cancelled_context_never_invoke_callbacks() {
        let executor = BatchExecutor::new();
        let mut request = request(1);
        request.operations[0].depends_on.push("missing".to_owned());
        let calls = Cell::new(0);
        assert!(executor.execute_async_streaming_wait(
            &request, None,
            |_| { calls.set(calls.get() + 1); ready(Ok(json!(null))) },
            |_| { calls.set(calls.get() + 1); ready(Ok(())) },
        ).await.is_err());
        assert_eq!(calls.get(), 0);

        request.operations[0].depends_on.clear();
        let context = ExecutionContext::background();
        context.cancel();
        let result = executor.execute_async_streaming_wait(
            &request, Some(&context),
            |_| { calls.set(calls.get() + 1); ready(Ok(json!(null))) },
            |_| { calls.set(calls.get() + 1); ready(Ok(())) },
        ).await.unwrap();
        assert_eq!(result.response.skipped, 3);
        assert_eq!(result.delivery_status, BatchDeliveryStatus::Interrupted);
        assert_eq!(result.acknowledged_results, 0);
        assert_eq!(calls.get(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn dependency_skips_are_delivered_without_dispatching_their_handlers() {
        let executor = BatchExecutor::new();
        let mut request = request(1);
        request.operations[1].depends_on.push("a".to_owned());
        request.operations[2].depends_on.push("b".to_owned());
        let calls = Cell::new(0);
        let delivered = RefCell::new(Vec::new());
        let result = executor.execute_async_streaming_wait(
            &request, None,
            |_| {
                calls.set(calls.get() + 1);
                ready(Err(operation_error("REFUSED", "provider refused")))
            },
            |result| {
                delivered.borrow_mut().push((result.id, result.status));
                ready(Ok(()))
            },
        ).await.unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(result.acknowledged_results, 3);
        assert_eq!(result.delivery_status, BatchDeliveryStatus::Complete);
        assert_eq!(delivered.borrow()[1].1, OperationResultStatus::Skipped);
        assert_eq!(delivered.borrow()[2].1, OperationResultStatus::Skipped);
        assert_eq!(result.response.skipped, 2);
    }

    #[fcp_async_core::runtime::test]
    async fn dropping_batch_releases_its_pending_delivery() {
        let executor = BatchExecutor::new();
        let request = request(1);
        let drops = Cell::new(0);
        let mut batch = Box::pin(executor.execute_async_streaming_wait(
            &request, None, |op| ready(Ok(op.input.clone())),
            |_| {
                let guard = DropCount(&drops);
                async move {
                    let _guard = guard;
                    pending::<()>().await;
                    Ok(())
                }
            },
        ));
        assert!(poll!(batch.as_mut()).is_pending());
        assert_eq!(drops.get(), 0);
        drop(batch);
        assert_eq!(drops.get(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn sink_owns_a_copy_and_cannot_rewrite_execution_evidence() {
        let executor = BatchExecutor::new();
        let request = request(1);
        let result = executor.execute_async_streaming_wait(
            &request, None, |op| ready(Ok(op.input.clone())),
            |mut delivered| async move {
                delivered.output = Some(json!({"tampered": true}));
                delivered.status = OperationResultStatus::Error;
                Ok(())
            },
        ).await.unwrap();
        assert_eq!(result.response.completed, 3);
        assert_eq!(result.response.results[0].output, Some(json!({"id": "a"})));
        assert_eq!(result.acknowledged_results, 3);
    }
}

#[cfg(all(test, panic = "unwind"))]
mod panic_tests {
    use std::cell::{Cell, RefCell};
    use std::future::{pending, ready};

    use futures_util::poll;
    use serde_json::json;

    use super::*;
    use crate::{BatchOptions, BatchScheduleHint};

    fn operation(id: &str, dependencies: &[&str]) -> BatchOperation {
        BatchOperation {
            id: id.to_owned(),
            tool: "test.echo".to_owned(),
            input: json!({ "id": id }),
            depends_on: dependencies.iter().map(|id| (*id).to_owned()).collect(),
            zone: None,
            scheduler: BatchScheduleHint::default(),
        }
    }

    fn request(operations: Vec<BatchOperation>) -> BatchInvokeRequest {
        BatchInvokeRequest {
            operations,
            options: BatchOptions {
                max_parallelism: 2,
                stop_on_first_error: false,
                ..BatchOptions::default()
            },
        }
    }

    fn assert_unknown(result: &OperationResult) {
        assert_eq!(result.status, OperationResultStatus::Error);
        assert!(result.output.is_none());
        let error = result.error.as_ref().unwrap();
        assert_eq!(error.code, "BATCH_OUTCOME_UNKNOWN");
        assert_eq!(error.retry_after_ms, None);
    }

    #[fcp_async_core::runtime::test]
    async fn factory_panic_stops_admission_and_drains_previously_created_futures() {
        let executor = BatchExecutor::new();
        let request = request(vec![operation("a", &[]), operation("b", &[]), operation("c", &[])]);
        let calls = RefCell::new(Vec::new());
        let response = executor.execute_async(&request, |operation| {
            calls.borrow_mut().push(operation.id.clone());
            assert_ne!(operation.id, "b", "private factory panic payload");
            ready(Ok(operation.input.clone()))
        }).await.unwrap();

        assert_eq!(*calls.borrow(), ["a", "b"]);
        assert_eq!(response.status, BatchStatus::Aborted);
        assert_eq!((response.completed, response.failed, response.skipped), (1, 1, 1));
        assert_eq!(response.results[0].output, Some(json!({ "id": "a" })));
        assert_unknown(&response.results[1]);
        assert_eq!(response.results[2].error.as_ref().unwrap().code, "BATCH_PANICKED");
        assert!(!serde_json::to_string(&response).unwrap().contains("private factory"));
    }

    #[fcp_async_core::runtime::test]
    async fn poll_panic_preserves_other_results_without_releasing_dependents() {
        let executor = BatchExecutor::new();
        let request = request(vec![operation("a", &[]), operation("b", &[]), operation("c", &["a"])]);
        let calls = RefCell::new(Vec::new());
        let response = executor.execute_async(&request, |operation| {
            calls.borrow_mut().push(operation.id.clone());
            async move {
                assert_ne!(operation.id, "a", "private poll panic payload");
                Ok(operation.input.clone())
            }
        }).await.unwrap();

        assert_eq!(*calls.borrow(), ["a", "b"]);
        assert_eq!(response.status, BatchStatus::Aborted);
        assert_eq!((response.completed, response.failed, response.skipped), (1, 1, 1));
        assert_unknown(&response.results[0]);
        assert_eq!(response.results[1].output, Some(json!({ "id": "b" })));
        assert_eq!(response.results[2].status, OperationResultStatus::Skipped);
        assert!(!serde_json::to_string(&response).unwrap().contains("private poll"));
    }

    #[fcp_async_core::runtime::test]
    async fn panic_after_pending_keeps_already_observed_success() {
        let executor = BatchExecutor::new();
        let request = request(vec![operation("a", &[]), operation("b", &[]), operation("c", &["a"])]);
        let release = Cell::new(false);
        let mut batch = Box::pin(executor.execute_async(&request, |operation| {
            let release = &release;
            async move {
                if operation.id == "a" {
                    poll_fn(|cx| {
                        if release.get() {
                            Poll::Ready(())
                        } else {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    }).await;
                    std::panic::panic_any(17_u8);
                }
                Ok(operation.input.clone())
            }
        }));
        assert!(poll!(batch.as_mut()).is_pending());
        release.set(true);
        let response = batch.await.unwrap();
        assert_unknown(&response.results[0]);
        assert_eq!(response.results[1].status, OperationResultStatus::Success);
        assert_eq!(response.results[2].status, OperationResultStatus::Skipped);
        assert_eq!((response.completed, response.failed, response.skipped), (1, 1, 1));
    }

    #[fcp_async_core::runtime::test]
    async fn cancellation_during_panic_drain_preserves_unknown_outcomes() {
        let executor = BatchExecutor::new();
        let request = request(vec![operation("a", &[]), operation("b", &[]), operation("c", &[])]);
        let context = ExecutionContext::background();
        let mut batch = Box::pin(executor.execute_async_with_context(&request, &context, |operation| {
            async move {
                assert_ne!(operation.id, "a", "handler failed");
                pending::<()>().await;
                Ok(json!(null))
            }
        }));
        assert!(poll!(batch.as_mut()).is_pending());
        context.cancel();
        let response = batch.await.unwrap();
        assert_unknown(&response.results[0]);
        assert_unknown(&response.results[1]);
        assert_eq!(response.results[2].status, OperationResultStatus::Skipped);
        assert_eq!(response.results[2].error.as_ref().unwrap().code, "BATCH_CANCELLED");
        assert_eq!(response.status, BatchStatus::Aborted);
        assert_eq!((response.completed, response.failed, response.skipped), (0, 2, 1));
    }

    #[fcp_async_core::runtime::test]
    async fn multiple_admitted_panics_are_each_accounted_for() {
        let executor = BatchExecutor::new();
        let request = request(vec![operation("a", &[]), operation("b", &[]), operation("c", &[])]);
        let response = executor.execute_async(&request, |operation| async move {
            assert_ne!(operation.id, "a", "first admitted panic");
            assert_ne!(operation.id, "b", "second admitted panic");
            Ok(operation.input.clone())
        }).await.unwrap();
        assert_unknown(&response.results[0]);
        assert_unknown(&response.results[1]);
        assert_eq!(response.results[2].status, OperationResultStatus::Skipped);
        assert_eq!((response.completed, response.failed, response.skipped), (0, 2, 1));
    }
}

#[cfg(test)]
mod streaming_tests {
    use std::cell::{Cell, RefCell};
    use std::future::ready;
    use std::task::Waker;

    use futures_util::poll;
    use serde_json::json;

    use super::*;
    use crate::{BatchOptions, BatchScheduleHint};

    fn operation(id: &str, dependencies: &[&str]) -> BatchOperation {
        BatchOperation {
            id: id.to_owned(),
            tool: "test.echo".to_owned(),
            input: json!({ "id": id }),
            depends_on: dependencies.iter().map(|id| (*id).to_owned()).collect(),
            zone: None,
            scheduler: BatchScheduleHint::default(),
        }
    }

    fn request(operations: Vec<BatchOperation>, parallelism: u32) -> BatchInvokeRequest {
        BatchInvokeRequest {
            operations,
            options: BatchOptions {
                max_parallelism: parallelism,
                stop_on_first_error: false,
                ..BatchOptions::default()
            },
        }
    }

    #[derive(Default)]
    struct Gate {
        open: Cell<bool>,
        waker: RefCell<Option<Waker>>,
    }

    impl Gate {
        async fn wait(&self) {
            poll_fn(|cx| {
                if self.open.get() {
                    Poll::Ready(())
                } else {
                    *self.waker.borrow_mut() = Some(cx.waker().clone());
                    Poll::Pending
                }
            }).await;
        }

        fn release(&self) {
            self.open.set(true);
            if let Some(waker) = self.waker.borrow_mut().take() {
                waker.wake();
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn delivers_fast_result_before_slow_peer_and_preserves_submission_order() {
        let executor = BatchExecutor::new();
        let request = request(vec![operation("a", &[]), operation("b", &[])], 2);
        let gate = Gate::default();
        let delivered = RefCell::new(Vec::new());
        let mut batch = Box::pin(executor.execute_async_streaming(&request, None, |operation| {
            let gate = &gate;
            async move {
                if operation.id == "a" { gate.wait().await; }
                Ok(operation.input.clone())
            }
        }, |result| {
            delivered.borrow_mut().push(result.id.clone());
            Ok(())
        }));

        assert!(poll!(batch.as_mut()).is_pending());
        assert_eq!(*delivered.borrow(), ["b"]);
        gate.release();
        let streamed = batch.await.unwrap();
        assert_eq!(*delivered.borrow(), ["b", "a"]);
        assert_eq!(streamed.delivery_status, BatchDeliveryStatus::Complete);
        assert_eq!(streamed.acknowledged_results, 2);
        assert_eq!(streamed.response.status, BatchStatus::Success);
        assert_eq!(streamed.response.results.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["a", "b"]);
    }

    #[fcp_async_core::runtime::test]
    async fn bounded_sink_refusal_stops_admission_but_retains_admitted_successes() {
        let executor = BatchExecutor::new();
        let request = request(vec![operation("a", &[]), operation("b", &[]), operation("c", &[])], 2);
        let calls = RefCell::new(Vec::new());
        let attempts = Cell::new(0);
        let (sender, _receiver) = std::sync::mpsc::sync_channel(0);
        let streamed = executor.execute_async_streaming(&request, None, |operation| {
            calls.borrow_mut().push(operation.id.clone());
            ready(Ok(operation.input.clone()))
        }, |result| {
            attempts.set(attempts.get() + 1);
            sender.try_send(result.clone()).map_err(|_| {
                operation_error("SINK_FULL", "private delivery failure payload")
            })
        }).await.unwrap();

        assert_eq!(*calls.borrow(), ["a", "b"]);
        assert_eq!(attempts.get(), 1);
        assert_eq!(streamed.acknowledged_results, 0);
        assert_eq!(streamed.delivery_status, BatchDeliveryStatus::Rejected);
        let response = &streamed.response;
        assert_eq!(response.status, BatchStatus::Aborted);
        assert_eq!((response.completed, response.failed, response.skipped), (2, 0, 1));
        assert_eq!(response.results[0].output, Some(json!({ "id": "a" })));
        assert_eq!(response.results[1].output, Some(json!({ "id": "b" })));
        assert_eq!(response.results[2].error.as_ref().unwrap().code, "BATCH_RESULT_DELIVERY_FAILED");
        assert!(!serde_json::to_string(&streamed).unwrap().contains("private delivery"));
    }

    #[fcp_async_core::runtime::test]
    async fn acknowledgements_count_only_successful_callbacks_and_are_not_replayed() {
        let executor = BatchExecutor::new();
        let request = request(vec![operation("a", &[]), operation("b", &[]), operation("c", &[])], 1);
        let delivered = RefCell::new(Vec::new());
        let streamed = executor.execute_async_streaming(&request, None, |operation| {
            ready(Ok(operation.input.clone()))
        }, |result| {
            delivered.borrow_mut().push(result.id.clone());
            if result.id == "b" {
                Err(operation_error("CLOSED", "result receiver disconnected"))
            } else {
                Ok(())
            }
        }).await.unwrap();

        assert_eq!(*delivered.borrow(), ["a", "b"]);
        assert_eq!(streamed.acknowledged_results, 1);
        assert_eq!(streamed.delivery_status, BatchDeliveryStatus::Rejected);
        assert_eq!((streamed.response.completed, streamed.response.failed, streamed.response.skipped), (2, 0, 1));
    }

    #[fcp_async_core::runtime::test]
    async fn sink_cancellation_delivers_final_unknown_and_unadmitted_accounting() {
        let executor = BatchExecutor::new();
        let request = request(vec![operation("a", &[]), operation("b", &[]), operation("c", &[])], 2);
        let context = ExecutionContext::background();
        let gate = Gate::default();
        let delivered = RefCell::new(Vec::new());
        let streamed = executor.execute_async_streaming(&request, Some(&context), |operation| {
            let gate = &gate;
            async move {
                if operation.id == "a" { gate.wait().await; }
                Ok(operation.input.clone())
            }
        }, |result| {
            delivered.borrow_mut().push(result.id.clone());
            if result.id == "b" { context.cancel(); }
            Ok(())
        }).await.unwrap();

        assert_eq!(*delivered.borrow(), ["b", "a", "c"]);
        assert_eq!(streamed.delivery_status, BatchDeliveryStatus::Complete);
        assert_eq!(streamed.acknowledged_results, 3);
        let response = streamed.response;
        assert_eq!(response.status, BatchStatus::Aborted);
        assert_eq!((response.completed, response.failed, response.skipped), (1, 1, 1));
        assert_eq!(response.results[0].error.as_ref().unwrap().code, "BATCH_OUTCOME_UNKNOWN");
        assert_eq!(response.results[0].error.as_ref().unwrap().retry_after_ms, None);
        assert_eq!(response.results[1].status, OperationResultStatus::Success);
        assert_eq!(response.results[2].error.as_ref().unwrap().code, "BATCH_CANCELLED");
    }

    #[fcp_async_core::runtime::test]
    async fn dependency_failures_are_delivered_once_without_invoking_dependents() {
        let executor = BatchExecutor::new();
        let request = request(vec![operation("a", &[]), operation("b", &["a"]), operation("c", &["b"])], 1);
        let calls = Cell::new(0);
        let delivered = RefCell::new(Vec::new());
        let streamed = executor.execute_async_streaming(&request, None, |_| {
            calls.set(calls.get() + 1);
            ready(Err(operation_error("PROVIDER_REFUSED", "provider refused operation")))
        }, |result| {
            delivered.borrow_mut().push(result.id.clone());
            Ok(())
        }).await.unwrap();

        assert_eq!(calls.get(), 1);
        assert_eq!(*delivered.borrow(), ["a", "b", "c"]);
        assert_eq!(streamed.acknowledged_results, 3);
        assert_eq!(streamed.delivery_status, BatchDeliveryStatus::Complete);
        assert_eq!(streamed.response.status, BatchStatus::AllFailed);
        for result in &streamed.response.results[1..] {
            assert_eq!(result.error.as_ref().unwrap().code, "DEP_FAILED");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn invalid_request_invokes_neither_handler_nor_sink() {
        let executor = BatchExecutor::new();
        let request = request(vec![operation("a", &[]), operation("a", &[])], 2);
        let called = Cell::new(false);
        let delivered = Cell::new(false);
        let result = executor.execute_async_streaming(&request, None, |_| {
            called.set(true);
            ready(Ok(json!(null)))
        }, |_| {
            delivered.set(true);
            Ok(())
        }).await;

        assert!(result.is_err());
        assert!(!called.get());
        assert!(!delivered.get());
    }

    #[fcp_async_core::runtime::test]
    async fn exhausted_budget_delivers_unadmitted_results_without_execution() {
        let executor = BatchExecutor::new();
        let mut request = request(vec![operation("a", &[]), operation("b", &[])], 2);
        request.options.timeout_ms = 0;
        let called = Cell::new(false);
        let delivered = RefCell::new(Vec::new());
        let streamed = executor.execute_async_streaming(&request, None, |_| {
            called.set(true);
            ready(Ok(json!(null)))
        }, |result| {
            delivered.borrow_mut().push(result.id.clone());
            Ok(())
        }).await.unwrap();

        assert!(!called.get());
        assert_eq!(*delivered.borrow(), ["a", "b"]);
        assert_eq!(streamed.acknowledged_results, 2);
        assert_eq!(streamed.delivery_status, BatchDeliveryStatus::Complete);
        assert_eq!(streamed.response.skipped, 2);
        for result in &streamed.response.results {
            assert_eq!(result.error.as_ref().unwrap().code, "BATCH_TIMEOUT");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn refusal_during_final_accounting_keeps_timeout_results() {
        let executor = BatchExecutor::new();
        let mut request = request(vec![operation("a", &[]), operation("b", &[])], 2);
        request.options.timeout_ms = 0;
        let attempts = Cell::new(0);
        let streamed = executor.execute_async_streaming(&request, None, |_| {
            ready(Ok(json!(null)))
        }, |_| {
            attempts.set(attempts.get() + 1);
            Err(operation_error("CLOSED", "receiver disconnected"))
        }).await.unwrap();

        assert_eq!(attempts.get(), 1);
        assert_eq!(streamed.acknowledged_results, 0);
        assert_eq!(streamed.delivery_status, BatchDeliveryStatus::Rejected);
        assert_eq!(streamed.response.skipped, 2);
        for result in &streamed.response.results {
            assert_eq!(result.error.as_ref().unwrap().code, "BATCH_TIMEOUT");
        }
    }

    #[cfg(panic = "unwind")]
    #[fcp_async_core::runtime::test]
    async fn sink_panic_disables_delivery_but_does_not_reclassify_successes() {
        let executor = BatchExecutor::new();
        let request = request(vec![operation("a", &[]), operation("b", &[]), operation("c", &[])], 2);
        let attempts = Cell::new(0);
        let streamed = executor.execute_async_streaming(&request, None, |operation| {
            ready(Ok(operation.input.clone()))
        }, |_| {
            attempts.set(attempts.get() + 1);
            panic!("private sink panic payload");
        }).await.unwrap();

        assert_eq!(attempts.get(), 1);
        assert_eq!(streamed.acknowledged_results, 0);
        assert_eq!(streamed.delivery_status, BatchDeliveryStatus::Panicked);
        assert_eq!((streamed.response.completed, streamed.response.failed, streamed.response.skipped), (2, 0, 1));
        assert!(!serde_json::to_string(&streamed).unwrap().contains("private sink"));
    }
}
