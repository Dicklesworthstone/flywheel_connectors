//! Explicit byte budgets for retained batch provider results.
//!
//! The existing executor remains the sole owner of DAG admission, cancellation,
//! draining and panic containment. Quotas are checked before it retains a
//! provider result, not after constructing the final response.

use std::future::Future;
use std::io::{self, Write};
use std::sync::Mutex;

use fcp_async_core::ExecutionContext;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    BatchExecutor, BatchInvokeRequest, BatchInvokeResponse, BatchOperation,
    BatchOperationError, HostError, HostResult, OperationResultStatus,
};

/// Serialized provider-result limits, excluding fixed scheduler accounting.
///
/// Both successful JSON values and provider errors consume the shared budget.
/// These are encoded-byte limits, not exact heap or peak-allocation limits:
/// handlers construct their values before the executor can inspect them. Request
/// input, result IDs, scheduler reports and fixed synthesized errors are excluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchResultLimits {
    /// Maximum encoded bytes retained from any one provider result.
    pub per_result_bytes: usize,
    /// Maximum encoded bytes retained across all provider results in the batch.
    pub total_result_bytes: usize,
}

impl Default for BatchResultLimits {
    fn default() -> Self {
        Self {
            per_result_bytes: 1024 * 1024,
            total_result_bytes: 16 * 1024 * 1024,
        }
    }
}

impl BatchResultLimits {
    fn validate(self) -> HostResult<()> {
        if self.per_result_bytes == 0
            || self.total_result_bytes == 0
            || self.per_result_bytes > self.total_result_bytes
        {
            return Err(HostError::InvalidFilter(
                "batch result limits must be positive and per-result must not exceed total".into(),
            ));
        }
        Ok(())
    }
}

/// Execution accounting with explicit retained-result budget consumption.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchBoundedResponse {
    /// Submission-ordered results, including fixed errors for withheld payloads.
    pub response: BatchInvokeResponse,
    /// The caller-selected limits enforced for this execution.
    pub limits: BatchResultLimits,
    /// Encoded bytes of provider payloads actually retained in the response.
    pub retained_result_bytes: usize,
    /// Provider results withheld because retention or encoding failed.
    /// This is not the number of failed or cancelled external effects.
    pub withheld_results: usize,
}

#[derive(Clone, Copy)]
enum RetentionFailure {
    Limit,
    Encoding,
}

impl RetentionFailure {
    fn error(self, admitted: bool) -> BatchOperationError {
        let (code, message) = match (self, admitted) {
            (Self::Limit, true) => (
                "BATCH_RESULT_LIMIT",
                "operation returned a result that exceeded the retained-result budget; its external effects were not undone; do not retry without reconciliation",
            ),
            (Self::Encoding, true) => (
                "BATCH_RESULT_ENCODING_FAILED",
                "operation returned a result that could not be encoded; its external effects were not undone; do not retry without reconciliation",
            ),
            (Self::Limit, false) => (
                "BATCH_RESULT_LIMIT",
                "batch retained-result budget was exhausted before this operation was admitted",
            ),
            (Self::Encoding, false) => (
                "BATCH_RESULT_ENCODING_FAILED",
                "batch result encoding failed before this operation was admitted",
            ),
        };
        BatchOperationError {
            code: code.to_owned(),
            message: message.to_owned(),
            retry_after_ms: None,
        }
    }
}

/// Counts encoded bytes without allocating another copy of the provider output.
struct ByteCounter {
    limit: usize,
    written: usize,
    exceeded: bool,
}

impl Write for ByteCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.written) {
            self.exceeded = true;
            return Err(io::Error::other("batch result byte limit exceeded"));
        }
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ResultBudget {
    limits: BatchResultLimits,
    retained: usize,
    withheld: usize,
    stop: Option<RetentionFailure>,
}

impl ResultBudget {
    fn retain(
        &mut self,
        result: Result<Value, BatchOperationError>,
    ) -> Result<Value, BatchOperationError> {
        let available = self.limits.total_result_bytes.saturating_sub(self.retained);
        let mut counter = ByteCounter {
            limit: available.min(self.limits.per_result_bytes),
            written: 0,
            exceeded: false,
        };
        let encoded = match &result {
            Ok(value) => serde_json::to_writer(&mut counter, value),
            Err(error) => serde_json::to_writer(&mut counter, error),
        };
        if encoded.is_ok() {
            self.retained += counter.written;
            return result;
        }
        let failure = if counter.exceeded {
            RetentionFailure::Limit
        } else {
            RetentionFailure::Encoding
        };
        self.withheld += 1;
        self.stop.get_or_insert(failure);
        // Drop, never truncate, an oversized payload. The replacement must not
        // include the discarded provider error, output, or a retry-after hint.
        Err(failure.error(true))
    }
}

impl BatchExecutor {
    /// Execute with per-result and aggregate encoded provider-result budgets.
    ///
    /// Reuses the completion-driven executor and its optional parent context.
    /// Oversized successes and errors are replaced with `BATCH_RESULT_LIMIT`,
    /// without truncating a JSON value or retaining a second serialization.
    /// An encoding failure similarly becomes `BATCH_RESULT_ENCODING_FAILED`.
    /// Both stop new admission; already admitted work drains under the original
    /// execution budget and its results undergo the same retention checks.
    ///
    /// A withheld result does not imply that the provider operation failed or
    /// that no side effect occurred. No operation or delivery is retried, and
    /// withheld results never release dependents as successful. Known results
    /// that fit remain available even after another result exhausts its limit.
    /// Allocation inside a handler cannot be preempted or bounded by this API.
    ///
    /// The returned future remains conditionally `Send`; borrowed and local-only
    /// handlers are supported. No lock is held across an await or user callback.
    /// Existing unbounded APIs are unchanged: callers opt in to these limits.
    ///
    /// # Errors
    /// Returns invalid limits or whole-batch validation/planning errors before
    /// any handler is called. Execution and retention failures are accounted for
    /// in the returned response rather than discarding known partial results.
    #[allow(clippy::future_not_send)]
    pub async fn execute_async_bounded<'a, F, Fut>(
        &self,
        request: &'a BatchInvokeRequest,
        context: Option<&ExecutionContext>,
        limits: BatchResultLimits,
        mut handler: F,
    ) -> HostResult<BatchBoundedResponse>
    where
        F: FnMut(&'a BatchOperation) -> Fut,
        Fut: Future<Output = Result<Value, BatchOperationError>>,
    {
        limits.validate()?;
        let budget = Mutex::new(ResultBudget {
            limits,
            retained: 0,
            withheld: 0,
            stop: None,
        });
        let shared = &budget;
        let mut streamed = self
            .execute_async_streaming(
                request,
                context,
                |operation| {
                    let future = handler(operation);
                    async move {
                        let result = future.await;
                        shared.lock().expect("batch result budget lock").retain(result)
                    }
                },
                |_| {
                    let stop = shared.lock().expect("batch result budget lock").stop;
                    stop.map_or(Ok(()), |failure| Err(failure.error(false)))
                },
            )
            .await?;
        let budget = budget.into_inner().expect("batch result budget lock");
        if let Some(failure) = budget.stop {
            // The private callback is an admission stop signal, not a remote
            // delivery sink. Report that actual reason for never-admitted work.
            // Cancellation and timeout codes retain their higher precedence.
            for result in &mut streamed.response.results {
                if result.status == OperationResultStatus::Skipped
                    && result.error.as_ref().is_some_and(|error| {
                        error.code == "BATCH_RESULT_DELIVERY_FAILED"
                    })
                {
                    result.error = Some(failure.error(false));
                }
            }
        }
        Ok(BatchBoundedResponse {
            response: streamed.response,
            limits,
            retained_result_bytes: budget.retained,
            withheld_results: budget.withheld,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::future::{pending, ready};

    use futures_util::poll;
    use serde_json::json;

    use super::*;
    use crate::{BatchOptions, BatchScheduleHint, BatchStatus};

    fn request(count: usize, parallelism: u32) -> BatchInvokeRequest {
        BatchInvokeRequest {
            operations: (0..count)
                .map(|index| BatchOperation {
                    id: format!("op-{index}"),
                    tool: "test.echo".into(),
                    input: Value::Null,
                    depends_on: Vec::new(),
                    zone: None,
                    scheduler: BatchScheduleHint::default(),
                })
                .collect(),
            options: BatchOptions {
                max_parallelism: parallelism,
                stop_on_first_error: false,
                ..BatchOptions::default()
            },
        }
    }

    fn limits(per_result_bytes: usize, total_result_bytes: usize) -> BatchResultLimits {
        BatchResultLimits { per_result_bytes, total_result_bytes }
    }

    #[test]
    fn encoded_unicode_and_escapes_are_charged_at_the_exact_boundary() {
        let value = json!("\"\n世界");
        let size = serde_json::to_vec(&value).unwrap().len();
        let mut budget = ResultBudget {
            limits: limits(size, size), retained: 0, withheld: 0, stop: None,
        };
        assert_eq!(budget.retain(Ok(value.clone())).unwrap(), value);
        assert_eq!(budget.retained, size);
        assert_eq!(budget.withheld, 0);
        assert_eq!(budget.retain(Ok(Value::Null)).unwrap_err().code, "BATCH_RESULT_LIMIT");
        assert_eq!(budget.retained, size);
        assert_eq!(budget.withheld, 1);
    }

    #[test]
    fn rejected_measurement_does_not_consume_remaining_retention_capacity() {
        let mut budget = ResultBudget {
            limits: limits(8, 8), retained: 0, withheld: 0, stop: None,
        };
        assert!(budget.retain(Ok(json!(["too large"]))).is_err());
        assert_eq!(budget.retained, 0);
        assert_eq!(budget.retain(Ok(Value::Null)).unwrap(), Value::Null);
        assert_eq!(budget.retained, 4);
        assert!(budget.stop.is_some(), "successful draining cannot reopen admission");
    }

    #[fcp_async_core::runtime::test]
    async fn invalid_limits_never_call_the_factory() {
        let executor = BatchExecutor::new();
        let request = request(1, 1);
        for limits in [limits(0, 8), limits(8, 0), limits(9, 8)] {
            let calls = Cell::new(0);
            let result = executor.execute_async_bounded(&request, None, limits, |_| {
                calls.set(calls.get() + 1);
                ready(Ok(Value::Null))
            }).await;
            assert!(result.is_err());
            assert_eq!(calls.get(), 0);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn aggregate_limit_stops_new_admission_without_discarding_known_prefix() {
        let executor = BatchExecutor::new();
        let request = request(4, 1);
        let calls = Cell::new(0);
        let bounded = executor.execute_async_bounded(&request, None, limits(6, 6), |_| {
            calls.set(calls.get() + 1);
            ready(Ok(Value::Null))
        }).await.unwrap();
        assert_eq!(calls.get(), 2);
        assert_eq!(bounded.retained_result_bytes, 4);
        assert_eq!(bounded.withheld_results, 1);
        assert_eq!(bounded.response.status, BatchStatus::Aborted);
        assert_eq!((bounded.response.completed, bounded.response.failed, bounded.response.skipped), (1, 1, 2));
        assert_eq!(bounded.response.results[0].output, Some(Value::Null));
        assert!(bounded.response.results[1].output.is_none());
        for result in &bounded.response.results[1..] {
            let error = result.error.as_ref().unwrap();
            assert_eq!(error.code, "BATCH_RESULT_LIMIT");
            assert_eq!(error.retry_after_ms, None);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn oversized_first_result_stops_factories_and_drains_admitted_small_result() {
        let executor = BatchExecutor::new();
        let request = request(3, 2);
        let calls = RefCell::new(Vec::new());
        let bounded = executor.execute_async_bounded(&request, None, limits(8, 8), |op| {
            calls.borrow_mut().push(op.id.clone());
            ready(Ok(if op.id == "op-0" { json!("large private payload") } else { Value::Null }))
        }).await.unwrap();
        assert_eq!(*calls.borrow(), ["op-0", "op-1"]);
        assert_eq!(bounded.retained_result_bytes, 4);
        assert_eq!(bounded.withheld_results, 1);
        assert_eq!((bounded.response.completed, bounded.response.failed, bounded.response.skipped), (1, 1, 1));
        assert_eq!(bounded.response.results[1].output, Some(Value::Null));
        assert!(!serde_json::to_string(&bounded).unwrap().contains("private payload"));
    }

    #[fcp_async_core::runtime::test]
    async fn oversized_provider_errors_are_withheld_without_retry_hints_or_payloads() {
        let executor = BatchExecutor::new();
        let request = request(2, 1);
        let bounded = executor.execute_async_bounded(&request, None, limits(16, 16), |_| {
            ready(Err(BatchOperationError {
                code: "PROVIDER_ERROR".into(),
                message: "private provider details".repeat(10),
                retry_after_ms: Some(5_000),
            }))
        }).await.unwrap();
        assert_eq!(bounded.retained_result_bytes, 0);
        assert_eq!(bounded.withheld_results, 1);
        let error = bounded.response.results[0].error.as_ref().unwrap();
        assert_eq!(error.code, "BATCH_RESULT_LIMIT");
        assert_eq!(error.retry_after_ms, None);
        let wire = serde_json::to_string(&bounded).unwrap();
        assert!(!wire.contains("private provider"));
        assert!(!wire.contains("PROVIDER_ERROR"));
    }

    #[fcp_async_core::runtime::test]
    async fn ordinary_provider_errors_keep_their_codes_and_retry_information() {
        let executor = BatchExecutor::new();
        let request = request(1, 1);
        let error = BatchOperationError {
            code: "RATE_LIMITED".into(), message: "provider refused".into(), retry_after_ms: Some(17),
        };
        let expected_size = serde_json::to_vec(&error).unwrap().len();
        let bounded = executor.execute_async_bounded(
            &request, None, limits(expected_size, expected_size), |_| ready(Err(error.clone())),
        ).await.unwrap();
        assert_eq!(bounded.retained_result_bytes, expected_size);
        assert_eq!(bounded.withheld_results, 0);
        assert_eq!(bounded.response.status, BatchStatus::AllFailed);
        let retained = bounded.response.results[0].error.as_ref().unwrap();
        assert_eq!(retained.code, error.code);
        assert_eq!(retained.retry_after_ms, Some(17));
    }

    #[fcp_async_core::runtime::test]
    async fn a_withheld_success_does_not_release_its_dependent() {
        let executor = BatchExecutor::new();
        let mut request = request(2, 2);
        request.operations[1].depends_on = vec!["op-0".into()];
        let calls = Cell::new(0);
        let bounded = executor.execute_async_bounded(&request, None, limits(4, 4), |_| {
            calls.set(calls.get() + 1);
            ready(Ok(json!("too large")))
        }).await.unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(bounded.response.results[1].status, OperationResultStatus::Skipped);
        assert_eq!(bounded.withheld_results, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn cancelled_context_keeps_cancellation_accounting_and_zero_retained_bytes() {
        let executor = BatchExecutor::new();
        let request = request(2, 2);
        let context = ExecutionContext::background();
        context.cancel();
        let calls = Cell::new(0);
        let bounded = executor.execute_async_bounded(&request, Some(&context), limits(8, 8), |_| {
            calls.set(calls.get() + 1);
            ready(Ok(Value::Null))
        }).await.unwrap();
        assert_eq!(calls.get(), 0);
        assert_eq!(bounded.retained_result_bytes, 0);
        assert_eq!(bounded.withheld_results, 0);
        assert_eq!(bounded.response.skipped, 2);
        assert!(bounded.response.results.iter().all(|result| result.error.as_ref().unwrap().code == "BATCH_CANCELLED"));
    }

    #[fcp_async_core::runtime::test]
    async fn cancellation_during_limit_drain_preserves_unknown_and_known_outcomes() {
        let executor = BatchExecutor::new();
        let request = request(3, 2);
        let context = ExecutionContext::background();
        let mut run = Box::pin(executor.execute_async_bounded(
            &request, Some(&context), limits(8, 8), |op| async move {
                if op.id == "op-1" { pending::<()>().await; }
                Ok(json!("oversized"))
            },
        ));
        assert!(poll!(run.as_mut()).is_pending());
        context.cancel();
        let bounded = run.await.unwrap();
        assert_eq!(bounded.withheld_results, 1);
        assert_eq!(bounded.response.results[0].error.as_ref().unwrap().code, "BATCH_RESULT_LIMIT");
        assert_eq!(bounded.response.results[1].error.as_ref().unwrap().code, "BATCH_OUTCOME_UNKNOWN");
        assert_eq!(bounded.response.results[2].error.as_ref().unwrap().code, "BATCH_CANCELLED");
    }

    #[test]
    fn bounded_execution_retains_send_for_send_handlers() {
        fn assert_send<T: Send>(_: T) {}
        let executor = BatchExecutor::new();
        let request = request(1, 1);
        assert_send(executor.execute_async_bounded(
            &request, None, BatchResultLimits::default(), |_| ready(Ok(Value::Null)),
        ));
    }

    #[test]
    fn byte_counter_refuses_overflow_without_wrapping_or_partial_accounting() {
        let mut counter = ByteCounter { limit: usize::MAX, written: usize::MAX - 1, exceeded: false };
        assert!(counter.write_all(b"12").is_err());
        assert_eq!(counter.written, usize::MAX - 1);
        assert!(counter.exceeded);
    }

    #[test]
    fn per_result_limit_applies_even_when_aggregate_budget_has_room() {
        let mut budget = ResultBudget {
            limits: limits(4, 1000), retained: 0, withheld: 0, stop: None,
        };
        let error = budget.retain(Ok(json!([1, 2, 3]))).unwrap_err();
        assert_eq!(error.code, "BATCH_RESULT_LIMIT");
        assert_eq!(budget.retained, 0);
        assert_eq!(budget.withheld, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn invalid_graph_does_not_run_a_factory_or_measure_provider_output() {
        let executor = BatchExecutor::new();
        let mut request = request(2, 1);
        request.operations[1].depends_on = vec!["absent".into()];
        let calls = Cell::new(0);
        let result = executor.execute_async_bounded(&request, None, limits(8, 8), |_| {
            calls.set(calls.get() + 1);
            ready(Ok(Value::Null))
        }).await;
        assert!(result.is_err());
        assert_eq!(calls.get(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn expired_batch_budget_never_dispatches_or_reports_a_retention_failure() {
        let executor = BatchExecutor::new();
        let mut request = request(2, 1);
        request.options.timeout_ms = 0;
        let calls = Cell::new(0);
        let bounded = executor.execute_async_bounded(&request, None, limits(8, 8), |_| {
            calls.set(calls.get() + 1);
            ready(Ok(Value::Null))
        }).await.unwrap();
        assert_eq!(calls.get(), 0);
        assert_eq!(bounded.withheld_results, 0);
        assert_eq!(bounded.retained_result_bytes, 0);
        assert_eq!(bounded.response.status, BatchStatus::Aborted);
        assert!(bounded.response.results.iter().all(|result| result.error.as_ref().unwrap().code == "BATCH_TIMEOUT"));
    }
}
