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
    BatchDeliveryStatus, BatchExecutor, BatchInvokeRequest, BatchInvokeResponse, BatchOperation,
    BatchOperationError, HostError, HostResult, OperationResult,
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

/// Byte-bounded provider results and independent streaming-delivery accounting.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchBoundedStreamingResponse {
    /// Final retained results and encoded-byte budget accounting.
    pub bounded: BatchBoundedResponse,
    /// User callbacks that returned success, including fixed accounting records.
    /// This is not proof of remote receipt or durable storage.
    pub acknowledged_results: usize,
    /// Whether every result was acknowledged without refusal or interruption.
    pub delivery_status: BatchDeliveryStatus,
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
    #[allow(clippy::future_not_send, clippy::missing_panics_doc)]
    pub async fn execute_async_bounded<'a, F, Fut>(
        &self,
        request: &'a BatchInvokeRequest,
        context: Option<&ExecutionContext>,
        limits: BatchResultLimits,
        handler: F,
    ) -> HostResult<BatchBoundedResponse>
    where
        F: FnMut(&'a BatchOperation) -> Fut,
        Fut: Future<Output = Result<Value, BatchOperationError>>,
    {
        self.execute_async_bounded_observed(request, context, limits, handler, |_| Ok(()))
            .await
    }

    /// Bound retained provider results while awaiting incremental sink capacity.
    ///
    /// Provider values and errors pass the encoded-byte checks before the sink
    /// receives an owned clone. Oversized payloads are replaced with fixed
    /// errors, never truncated or passed through. Retention failure stops new
    /// admission independently of delivery: admitted work drains and the sink
    /// can still acknowledge its retained results and all skipped records.
    ///
    /// Only one delivery is active. While it waits, no new handler is admitted
    /// and other owned handler futures are not polled. Use an independently
    /// driven receiver; waiting on another operation in this batch cannot make
    /// progress until delivery finishes. Waiting, draining and final delivery
    /// share the original batch and optional parent deadlines.
    ///
    /// A real sink refusal, unwinding panic, cancellation or timeout keeps the
    /// ordinary streaming delivery status. Known results remain in the response
    /// even when undelivered. Neither execution nor delivery is retried, and
    /// withholding a payload does not undo an external effect. Cancellation
    /// preserves outcome-unknown accounting for unresolved admitted operations.
    ///
    /// The byte limit covers retained encoded provider results, not peak heap
    /// usage, allocation inside handlers, fixed accounting, or extra storage
    /// retained by the callback. At most one additional result clone belongs to
    /// the pending delivery. No mutex is held during a user callback or await.
    /// Borrowing and local-only callbacks are supported; the future is `Send`
    /// when both callbacks and their futures are `Send`.
    ///
    /// # Errors
    /// Returns limit and batch validation errors before either callback runs.
    /// Runtime, retention and delivery failures remain in response accounting.
    #[allow(clippy::future_not_send, clippy::missing_panics_doc)]
    pub async fn execute_async_bounded_wait<'a, F, Fut, S, DeliveryFut>(
        &self,
        request: &'a BatchInvokeRequest,
        context: Option<&ExecutionContext>,
        limits: BatchResultLimits,
        mut handler: F,
        on_result: S,
    ) -> HostResult<BatchBoundedStreamingResponse>
    where
        F: FnMut(&'a BatchOperation) -> Fut,
        Fut: Future<Output = Result<Value, BatchOperationError>>,
        S: FnMut(OperationResult) -> DeliveryFut,
        DeliveryFut: Future<Output = Result<(), BatchOperationError>>,
    {
        limits.validate()?;
        let budget = Mutex::new(ResultBudget {
            limits,
            retained: 0,
            withheld: 0,
            stop: None,
        });
        let shared = &budget;
        let streamed = self
            .execute_async_streaming_wait_guarded(
                request,
                context,
                |operation| {
                    let future = handler(operation);
                    async move {
                        let result = future.await;
                        shared
                            .lock()
                            .expect("batch result budget lock")
                            .retain(result)
                    }
                },
                on_result,
                || {
                    let stop = shared.lock().expect("batch result budget lock").stop;
                    stop.map_or(Ok(()), |failure| Err(failure.error(false)))
                },
            )
            .await?;
        let budget = budget.into_inner().expect("batch result budget lock");
        Ok(BatchBoundedStreamingResponse {
            bounded: BatchBoundedResponse {
                response: streamed.response,
                limits,
                retained_result_bytes: budget.retained,
                withheld_results: budget.withheld,
            },
            acknowledged_results: streamed.acknowledged_results,
            delivery_status: streamed.delivery_status,
        })
    }

    /// Observe retention-checked results before dependent work can be admitted.
    ///
    /// This composes byte-bounded execution with the existing completion-driven
    /// result sink. The observer sees only the retained result, never an
    /// oversized provider payload that was withheld. Successful observation
    /// happens before that operation releases its dependents, allowing callers
    /// to resolve data dependencies without racing admission or bypassing quotas.
    ///
    /// A retention failure stops admission independently of observation. The
    /// observer can still receive retained results from already admitted work
    /// and the final skipped records, each with the same reason as the response.
    ///
    /// The observer must be nonblocking and bound any additional state it keeps.
    /// It runs without the result-budget mutex held. A refusal or unwind stops
    /// new admission and further observation; already admitted work drains and
    /// its known results remain in the final response. Neither handler execution
    /// nor observation is retried. Observer failure does not undo an effect or
    /// change a known successful provider result into a failed external action.
    /// The batch reports aborted delivery through its existing status and
    /// skipped-member error accounting. Cancellation and deadline semantics are
    /// unchanged, including immediate observation of final accounting records.
    ///
    /// # Errors
    /// Returns validation errors before any handler or observer is called.
    /// Runtime, retention and observation failures remain in batch accounting.
    #[allow(clippy::future_not_send)]
    pub async fn execute_async_bounded_observed<'a, F, Fut, S>(
        &self,
        request: &'a BatchInvokeRequest,
        context: Option<&ExecutionContext>,
        limits: BatchResultLimits,
        mut handler: F,
        observer: S,
    ) -> HostResult<BatchBoundedResponse>
    where
        F: FnMut(&'a BatchOperation) -> Fut,
        Fut: Future<Output = Result<Value, BatchOperationError>>,
        S: FnMut(&OperationResult) -> Result<(), BatchOperationError>,
    {
        limits.validate()?;
        let budget = Mutex::new(ResultBudget {
            limits,
            retained: 0,
            withheld: 0,
            stop: None,
        });
        let shared = &budget;
        let streamed = self
            .execute_async_streaming_guarded(
                request,
                context,
                |operation| {
                    let future = handler(operation);
                    async move {
                        let result = future.await;
                        shared
                            .lock()
                            .expect("batch result budget lock")
                            .retain(result)
                    }
                },
                observer,
                || {
                    let stop = shared.lock().expect("batch result budget lock").stop;
                    stop.map_or(Ok(()), |failure| Err(failure.error(false)))
                },
            )
            .await?;
        let budget = budget.into_inner().expect("batch result budget lock");
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
    use crate::{BatchOptions, BatchScheduleHint, BatchStatus, OperationResultStatus};

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
        BatchResultLimits {
            per_result_bytes,
            total_result_bytes,
        }
    }

    #[test]
    fn encoded_unicode_and_escapes_are_charged_at_the_exact_boundary() {
        let value = json!("\"\n世界");
        let size = serde_json::to_vec(&value).unwrap().len();
        let mut budget = ResultBudget {
            limits: limits(size, size),
            retained: 0,
            withheld: 0,
            stop: None,
        };
        assert_eq!(budget.retain(Ok(value.clone())).unwrap(), value);
        assert_eq!(budget.retained, size);
        assert_eq!(budget.withheld, 0);
        assert_eq!(
            budget.retain(Ok(Value::Null)).unwrap_err().code,
            "BATCH_RESULT_LIMIT"
        );
        assert_eq!(budget.retained, size);
        assert_eq!(budget.withheld, 1);
    }

    #[test]
    fn rejected_measurement_does_not_consume_remaining_retention_capacity() {
        let mut budget = ResultBudget {
            limits: limits(8, 8),
            retained: 0,
            withheld: 0,
            stop: None,
        };
        assert!(budget.retain(Ok(json!(["too large"]))).is_err());
        assert_eq!(budget.retained, 0);
        assert_eq!(budget.retain(Ok(Value::Null)).unwrap(), Value::Null);
        assert_eq!(budget.retained, 4);
        assert!(
            budget.stop.is_some(),
            "successful draining cannot reopen admission"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn invalid_limits_never_call_the_factory() {
        let executor = BatchExecutor::new();
        let request = request(1, 1);
        for limits in [limits(0, 8), limits(8, 0), limits(9, 8)] {
            let calls = Cell::new(0);
            let result = executor
                .execute_async_bounded(&request, None, limits, |_| {
                    calls.set(calls.get() + 1);
                    ready(Ok(Value::Null))
                })
                .await;
            assert!(result.is_err());
            assert_eq!(calls.get(), 0);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn aggregate_limit_stops_new_admission_without_discarding_known_prefix() {
        let executor = BatchExecutor::new();
        let request = request(4, 1);
        let calls = Cell::new(0);
        let bounded = executor
            .execute_async_bounded(&request, None, limits(6, 6), |_| {
                calls.set(calls.get() + 1);
                ready(Ok(Value::Null))
            })
            .await
            .unwrap();
        assert_eq!(calls.get(), 2);
        assert_eq!(bounded.retained_result_bytes, 4);
        assert_eq!(bounded.withheld_results, 1);
        assert_eq!(bounded.response.status, BatchStatus::Aborted);
        assert_eq!(
            (
                bounded.response.completed,
                bounded.response.failed,
                bounded.response.skipped
            ),
            (1, 1, 2)
        );
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
        let bounded = executor
            .execute_async_bounded(&request, None, limits(8, 8), |op| {
                calls.borrow_mut().push(op.id.clone());
                ready(Ok(if op.id == "op-0" {
                    json!("large private payload")
                } else {
                    Value::Null
                }))
            })
            .await
            .unwrap();
        assert_eq!(*calls.borrow(), ["op-0", "op-1"]);
        assert_eq!(bounded.retained_result_bytes, 4);
        assert_eq!(bounded.withheld_results, 1);
        assert_eq!(
            (
                bounded.response.completed,
                bounded.response.failed,
                bounded.response.skipped
            ),
            (1, 1, 1)
        );
        assert_eq!(bounded.response.results[1].output, Some(Value::Null));
        assert!(
            !serde_json::to_string(&bounded)
                .unwrap()
                .contains("private payload")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn oversized_provider_errors_are_withheld_without_retry_hints_or_payloads() {
        let executor = BatchExecutor::new();
        let request = request(2, 1);
        let bounded = executor
            .execute_async_bounded(&request, None, limits(16, 16), |_| {
                ready(Err(BatchOperationError {
                    code: "PROVIDER_ERROR".into(),
                    message: "private provider details".repeat(10),
                    retry_after_ms: Some(5_000),
                }))
            })
            .await
            .unwrap();
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
            code: "RATE_LIMITED".into(),
            message: "provider refused".into(),
            retry_after_ms: Some(17),
        };
        let expected_size = serde_json::to_vec(&error).unwrap().len();
        let bounded = executor
            .execute_async_bounded(&request, None, limits(expected_size, expected_size), |_| {
                ready(Err(error.clone()))
            })
            .await
            .unwrap();
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
        let bounded = executor
            .execute_async_bounded(&request, None, limits(4, 4), |_| {
                calls.set(calls.get() + 1);
                ready(Ok(json!("too large")))
            })
            .await
            .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(
            bounded.response.results[1].status,
            OperationResultStatus::Skipped
        );
        assert_eq!(bounded.withheld_results, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn cancelled_context_keeps_cancellation_accounting_and_zero_retained_bytes() {
        let executor = BatchExecutor::new();
        let request = request(2, 2);
        let context = ExecutionContext::background();
        context.cancel();
        let calls = Cell::new(0);
        let bounded = executor
            .execute_async_bounded(&request, Some(&context), limits(8, 8), |_| {
                calls.set(calls.get() + 1);
                ready(Ok(Value::Null))
            })
            .await
            .unwrap();
        assert_eq!(calls.get(), 0);
        assert_eq!(bounded.retained_result_bytes, 0);
        assert_eq!(bounded.withheld_results, 0);
        assert_eq!(bounded.response.skipped, 2);
        assert!(
            bounded
                .response
                .results
                .iter()
                .all(|result| result.error.as_ref().unwrap().code == "BATCH_CANCELLED")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn cancellation_during_limit_drain_preserves_unknown_and_known_outcomes() {
        let executor = BatchExecutor::new();
        let request = request(3, 2);
        let context = ExecutionContext::background();
        let mut run = Box::pin(executor.execute_async_bounded(
            &request,
            Some(&context),
            limits(8, 8),
            |op| async move {
                if op.id == "op-1" {
                    pending::<()>().await;
                }
                Ok(json!("oversized"))
            },
        ));
        assert!(poll!(run.as_mut()).is_pending());
        context.cancel();
        let bounded = run.await.unwrap();
        assert_eq!(bounded.withheld_results, 1);
        assert_eq!(
            bounded.response.results[0].error.as_ref().unwrap().code,
            "BATCH_RESULT_LIMIT"
        );
        assert_eq!(
            bounded.response.results[1].error.as_ref().unwrap().code,
            "BATCH_OUTCOME_UNKNOWN"
        );
        assert_eq!(
            bounded.response.results[2].error.as_ref().unwrap().code,
            "BATCH_CANCELLED"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn retention_stop_still_observes_drained_and_skipped_records() {
        let executor = BatchExecutor::new();
        let request = request(3, 2);
        let observed = RefCell::new(Vec::new());
        let bounded = executor
            .execute_async_bounded_observed(
                &request,
                None,
                limits(8, 8),
                |op| {
                    ready(Ok(if op.id == "op-0" {
                        json!("private oversized payload")
                    } else {
                        Value::Null
                    }))
                },
                |result| {
                    observed.borrow_mut().push(result.clone());
                    Ok(())
                },
            )
            .await
            .unwrap();

        assert_eq!(observed.borrow().len(), 3);
        assert_eq!(bounded.retained_result_bytes, 4);
        assert_eq!(bounded.withheld_results, 1);
        assert_eq!(
            (
                bounded.response.completed,
                bounded.response.failed,
                bounded.response.skipped
            ),
            (1, 1, 1)
        );
        for observed in observed.borrow().iter() {
            let final_result = bounded
                .response
                .results
                .iter()
                .find(|result| result.id == observed.id)
                .unwrap();
            assert_eq!(
                serde_json::to_value(observed).unwrap(),
                serde_json::to_value(final_result).unwrap()
            );
        }
        assert_eq!(
            observed.borrow()[2].error.as_ref().unwrap().code,
            "BATCH_RESULT_LIMIT"
        );
        assert!(
            !serde_json::to_string(&*observed.borrow())
                .unwrap()
                .contains("private oversized")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn sink_refusal_is_not_rewritten_by_later_drain_overflow() {
        let executor = BatchExecutor::new();
        let request = request(3, 2);
        let observations = Cell::new(0);
        let bounded = executor
            .execute_async_bounded_observed(
                &request,
                None,
                limits(8, 8),
                |op| {
                    ready(Ok(if op.id == "op-0" {
                        Value::Null
                    } else {
                        json!("private oversized payload")
                    }))
                },
                |_| {
                    observations.set(observations.get() + 1);
                    Err(BatchOperationError {
                        code: "SINK_CLOSED".into(),
                        message: "private delivery error".into(),
                        retry_after_ms: None,
                    })
                },
            )
            .await
            .unwrap();

        assert_eq!(observations.get(), 1);
        assert_eq!(bounded.retained_result_bytes, 4);
        assert_eq!(bounded.withheld_results, 1);
        assert_eq!(
            bounded.response.results[1].error.as_ref().unwrap().code,
            "BATCH_RESULT_LIMIT"
        );
        assert_eq!(
            bounded.response.results[2].error.as_ref().unwrap().code,
            "BATCH_RESULT_DELIVERY_FAILED"
        );
        assert!(
            !serde_json::to_string(&bounded)
                .unwrap()
                .contains("private delivery")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn earlier_provider_stop_keeps_its_cause_when_drain_exceeds_the_limit() {
        let executor = BatchExecutor::new();
        let mut request = request(3, 2);
        request.options.stop_on_first_error = true;
        let error = BatchOperationError {
            code: "PROVIDER_REFUSED".into(),
            message: "refused".into(),
            retry_after_ms: None,
        };
        let error_bytes = serde_json::to_vec(&error).unwrap().len();
        let bounded = executor
            .execute_async_bounded(&request, None, limits(128, 128), |op| {
                ready(if op.id == "op-0" {
                    Err(error.clone())
                } else {
                    Ok(json!("oversized".repeat(32)))
                })
            })
            .await
            .unwrap();

        assert_eq!(bounded.retained_result_bytes, error_bytes);
        assert_eq!(bounded.withheld_results, 1);
        assert_eq!(
            bounded.response.results[0].error.as_ref().unwrap().code,
            "PROVIDER_REFUSED"
        );
        assert_eq!(
            bounded.response.results[1].error.as_ref().unwrap().code,
            "BATCH_RESULT_LIMIT"
        );
        assert_eq!(
            bounded.response.results[2].error.as_ref().unwrap().code,
            "BATCH_ABORTED"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn bounded_wait_backpressure_delivers_limit_and_final_records_exactly_once() {
        let executor = BatchExecutor::new();
        let request = request(4, 1);
        let admitted = Cell::new(0);
        let (sender, mut receiver) = fcp_async_core::channel::bounded("bounded-batch-results", 1);
        let mut batch = Box::pin(executor.execute_async_bounded_wait(
            &request,
            None,
            limits(6, 6),
            |_| {
                admitted.set(admitted.get() + 1);
                ready(Ok(Value::Null))
            },
            |result| {
                let sender = sender.clone();
                async move {
                    sender.send(result).await.map_err(|_| BatchOperationError {
                        code: "SINK_CLOSED".into(),
                        message: "private receiver failure".into(),
                        retry_after_ms: None,
                    })
                }
            },
        ));

        assert!(poll!(batch.as_mut()).is_pending());
        assert_eq!(admitted.get(), 2);
        let mut delivered = vec![receiver.recv().await.unwrap()];
        assert_eq!(delivered[0].output, Some(Value::Null));
        assert!(poll!(batch.as_mut()).is_pending());
        delivered.push(receiver.recv().await.unwrap());
        assert!(poll!(batch.as_mut()).is_pending());
        delivered.push(receiver.recv().await.unwrap());
        let streamed = batch.await.unwrap();
        assert_eq!(streamed.acknowledged_results, 4);
        delivered.push(receiver.recv().await.unwrap());

        assert_eq!(admitted.get(), 2);
        assert_eq!(streamed.delivery_status, BatchDeliveryStatus::Complete);
        let bounded = streamed.bounded;
        assert_eq!(bounded.retained_result_bytes, 4);
        assert_eq!(bounded.withheld_results, 1);
        assert_eq!(bounded.response.status, BatchStatus::Aborted);
        assert_eq!(
            (
                bounded.response.completed,
                bounded.response.failed,
                bounded.response.skipped
            ),
            (1, 1, 2)
        );
        assert_eq!(
            serde_json::to_value(&delivered).unwrap(),
            serde_json::to_value(&bounded.response.results).unwrap()
        );
        for result in &delivered[1..] {
            assert_eq!(result.error.as_ref().unwrap().code, "BATCH_RESULT_LIMIT");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn bounded_wait_preserves_exact_boundary_and_submission_order() {
        let executor = BatchExecutor::new();
        let mut request = request(3, 1);
        request.operations.reverse();
        let observed = RefCell::new(Vec::new());
        let streamed = executor
            .execute_async_bounded_wait(
                &request,
                None,
                limits(4, 12),
                |_| ready(Ok(Value::Null)),
                |result| {
                    observed.borrow_mut().push(result.id);
                    ready(Ok(()))
                },
            )
            .await
            .unwrap();

        assert_eq!(*observed.borrow(), ["op-0", "op-1", "op-2"]);
        assert_eq!(streamed.acknowledged_results, 3);
        assert_eq!(streamed.delivery_status, BatchDeliveryStatus::Complete);
        assert_eq!(streamed.bounded.retained_result_bytes, 12);
        assert_eq!(streamed.bounded.withheld_results, 0);
        assert_eq!(streamed.bounded.response.status, BatchStatus::Success);
        assert_eq!(
            streamed
                .bounded
                .response
                .results
                .iter()
                .map(|result| result.id.as_str())
                .collect::<Vec<_>>(),
            ["op-2", "op-1", "op-0"]
        );
    }

    #[fcp_async_core::runtime::test]
    async fn bounded_wait_channel_rejection_keeps_successes_and_real_delivery_status() {
        let executor = BatchExecutor::new();
        let request = request(3, 1);
        let (sender, receiver) = fcp_async_core::channel::bounded("bounded-batch-disconnect", 1);
        let mut batch = Box::pin(executor.execute_async_bounded_wait(
            &request,
            None,
            limits(4, 12),
            |_| ready(Ok(Value::Null)),
            |result| {
                let sender = sender.clone();
                async move {
                    sender.send(result).await.map_err(|_| BatchOperationError {
                        code: "SINK_CLOSED".into(),
                        message: "private receiver failure".into(),
                        retry_after_ms: None,
                    })
                }
            },
        ));

        assert!(poll!(batch.as_mut()).is_pending());
        drop(receiver);
        let streamed = batch.await.unwrap();
        assert_eq!(streamed.acknowledged_results, 1);
        assert_eq!(streamed.delivery_status, BatchDeliveryStatus::Rejected);
        assert_eq!(streamed.bounded.retained_result_bytes, 8);
        assert_eq!(streamed.bounded.withheld_results, 0);
        assert_eq!(
            (
                streamed.bounded.response.completed,
                streamed.bounded.response.failed,
                streamed.bounded.response.skipped
            ),
            (2, 0, 1)
        );
        assert_eq!(
            streamed.bounded.response.results[1].output,
            Some(Value::Null)
        );
        assert_eq!(
            streamed.bounded.response.results[2]
                .error
                .as_ref()
                .unwrap()
                .code,
            "BATCH_RESULT_DELIVERY_FAILED"
        );
        assert!(
            !serde_json::to_string(&streamed)
                .unwrap()
                .contains("private receiver")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn cancellation_of_blocked_limit_delivery_keeps_known_and_unknown_outcomes() {
        struct DeliveryDrop<'a>(&'a Cell<usize>);
        impl Drop for DeliveryDrop<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }

        let executor = BatchExecutor::new();
        let request = request(3, 2);
        let context = ExecutionContext::background();
        let calls = Cell::new(0);
        let drops = Cell::new(0);
        let mut batch = Box::pin(executor.execute_async_bounded_wait(
            &request,
            Some(&context),
            limits(8, 8),
            |op| async move {
                if op.id == "op-1" {
                    pending::<()>().await;
                }
                Ok(json!("private oversized payload"))
            },
            |_| {
                calls.set(calls.get() + 1);
                let guard = DeliveryDrop(&drops);
                async move {
                    let _guard = guard;
                    pending::<()>().await;
                    Ok(())
                }
            },
        ));

        assert!(poll!(batch.as_mut()).is_pending());
        context.cancel();
        let streamed = batch.await.unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(drops.get(), 1);
        assert_eq!(streamed.acknowledged_results, 0);
        assert_eq!(streamed.delivery_status, BatchDeliveryStatus::Interrupted);
        assert_eq!(streamed.bounded.retained_result_bytes, 0);
        assert_eq!(streamed.bounded.withheld_results, 1);
        let response = streamed.bounded.response;
        assert_eq!(
            (response.completed, response.failed, response.skipped),
            (0, 2, 1)
        );
        assert_eq!(
            response.results[0].error.as_ref().unwrap().code,
            "BATCH_RESULT_LIMIT"
        );
        assert_eq!(
            response.results[1].error.as_ref().unwrap().code,
            "BATCH_OUTCOME_UNKNOWN"
        );
        assert_eq!(
            response.results[2].error.as_ref().unwrap().code,
            "BATCH_CANCELLED"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn bounded_delivery_wait_uses_the_earlier_original_deadline() {
        use std::time::Duration;

        for inherited_shorter in [true, false] {
            let executor = BatchExecutor::new();
            let mut request = request(3, 1);
            request.options.timeout_ms = if inherited_shorter { 60_000 } else { 250 };
            let context = ExecutionContext::request_scoped(if inherited_shorter {
                Duration::from_millis(250)
            } else {
                Duration::from_secs(60)
            });
            let streamed = fcp_async_core::time::timeout(
                Duration::from_secs(5),
                executor.execute_async_bounded_wait(
                    &request,
                    Some(&context),
                    limits(4, 12),
                    |_| ready(Ok(Value::Null)),
                    |_| pending::<Result<(), BatchOperationError>>(),
                ),
            )
            .await
            .expect("backpressure must not renew the execution budget")
            .unwrap();

            assert_eq!(streamed.acknowledged_results, 0);
            assert_eq!(streamed.delivery_status, BatchDeliveryStatus::Interrupted);
            assert_eq!(streamed.bounded.retained_result_bytes, 4);
            assert_eq!(streamed.bounded.withheld_results, 0);
            let response = streamed.bounded.response;
            assert_eq!(
                (response.completed, response.failed, response.skipped),
                (1, 0, 2)
            );
            assert_eq!(response.results[0].output, Some(Value::Null));
            for result in &response.results[1..] {
                assert_eq!(result.error.as_ref().unwrap().code, "BATCH_TIMEOUT");
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn cancellation_at_completion_preserves_result_without_late_delivery() {
        let executor = BatchExecutor::new();
        let request = request(2, 1);
        let context = ExecutionContext::background();
        let delivered = Cell::new(0);
        let streamed = executor
            .execute_async_bounded_wait(
                &request,
                Some(&context),
                limits(4, 8),
                |_| async {
                    context.cancel();
                    Ok(Value::Null)
                },
                |_| {
                    delivered.set(delivered.get() + 1);
                    ready(Ok(()))
                },
            )
            .await
            .unwrap();

        assert_eq!(delivered.get(), 0);
        assert_eq!(streamed.acknowledged_results, 0);
        assert_eq!(streamed.delivery_status, BatchDeliveryStatus::Interrupted);
        assert_eq!(streamed.bounded.retained_result_bytes, 4);
        assert_eq!(streamed.bounded.response.completed, 1);
        assert_eq!(streamed.bounded.response.skipped, 1);
        assert_eq!(
            streamed.bounded.response.results[0].output,
            Some(Value::Null)
        );
        assert_eq!(
            streamed.bounded.response.results[1]
                .error
                .as_ref()
                .unwrap()
                .code,
            "BATCH_CANCELLED"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn bounded_wait_validation_and_pre_cancelled_context_never_call_user_code() {
        let executor = BatchExecutor::new();
        let mut request = request(2, 1);
        let calls = Cell::new(0);
        for invalid in [limits(0, 8), limits(8, 0), limits(9, 8)] {
            assert!(
                executor
                    .execute_async_bounded_wait(
                        &request,
                        None,
                        invalid,
                        |_| {
                            calls.set(calls.get() + 1);
                            ready(Ok(Value::Null))
                        },
                        |_| {
                            calls.set(calls.get() + 1);
                            ready(Ok(()))
                        },
                    )
                    .await
                    .is_err()
            );
        }
        request.operations[1].depends_on.push("missing".into());
        assert!(
            executor
                .execute_async_bounded_wait(
                    &request,
                    None,
                    limits(4, 8),
                    |_| {
                        calls.set(calls.get() + 1);
                        ready(Ok(Value::Null))
                    },
                    |_| {
                        calls.set(calls.get() + 1);
                        ready(Ok(()))
                    },
                )
                .await
                .is_err()
        );
        request.operations[1].depends_on.clear();
        let context = ExecutionContext::background();
        context.cancel();
        let streamed = executor
            .execute_async_bounded_wait(
                &request,
                Some(&context),
                limits(4, 8),
                |_| {
                    calls.set(calls.get() + 1);
                    ready(Ok(Value::Null))
                },
                |_| {
                    calls.set(calls.get() + 1);
                    ready(Ok(()))
                },
            )
            .await
            .unwrap();
        assert_eq!(calls.get(), 0);
        assert_eq!(streamed.acknowledged_results, 0);
        assert_eq!(streamed.delivery_status, BatchDeliveryStatus::Interrupted);
        assert_eq!(streamed.bounded.retained_result_bytes, 0);
        assert_eq!(streamed.bounded.withheld_results, 0);
        assert_eq!(streamed.bounded.response.skipped, 2);
    }

    #[cfg(panic = "unwind")]
    #[fcp_async_core::runtime::test]
    async fn bounded_wait_contains_sink_panics_without_exposing_withheld_payloads() {
        for factory_panics in [true, false] {
            let executor = BatchExecutor::new();
            let request = request(3, 2);
            let streamed = executor
                .execute_async_bounded_wait(
                    &request,
                    None,
                    limits(8, 8),
                    |op| {
                        ready(Ok(if op.id == "op-0" {
                            json!("private oversized payload")
                        } else {
                            Value::Null
                        }))
                    },
                    |_| {
                        assert!(!factory_panics, "private sink factory panic");
                        async {
                            panic!("private sink poll panic");
                            #[allow(unreachable_code)]
                            Ok::<(), BatchOperationError>(())
                        }
                    },
                )
                .await
                .unwrap();
            assert_eq!(streamed.delivery_status, BatchDeliveryStatus::Panicked);
            assert_eq!(streamed.acknowledged_results, 0);
            assert_eq!(streamed.bounded.retained_result_bytes, 4);
            assert_eq!(streamed.bounded.withheld_results, 1);
            assert_eq!(streamed.bounded.response.completed, 1);
            assert_eq!(streamed.bounded.response.failed, 1);
            assert_eq!(streamed.bounded.response.skipped, 1);
            assert!(
                !serde_json::to_string(&streamed)
                    .unwrap()
                    .contains("private")
            );
        }
    }

    #[test]
    fn bounded_wait_is_send_without_requiring_sync_callbacks() {
        fn assert_send<T: Send>(_: T) {}
        let executor = BatchExecutor::new();
        let request = request(1, 1);
        let callbacks = Cell::new(0);
        assert_send(executor.execute_async_bounded_wait(
            &request,
            None,
            limits(4, 4),
            |_| ready(Ok(Value::Null)),
            move |_| {
                callbacks.set(callbacks.get() + 1);
                ready(Ok(()))
            },
        ));
    }

    #[test]
    fn bounded_execution_retains_send_for_send_handlers() {
        fn assert_send<T: Send>(_: T) {}
        let executor = BatchExecutor::new();
        let request = request(1, 1);
        assert_send(executor.execute_async_bounded(
            &request,
            None,
            BatchResultLimits::default(),
            |_| ready(Ok(Value::Null)),
        ));
    }

    #[test]
    fn byte_counter_refuses_overflow_without_wrapping_or_partial_accounting() {
        let mut counter = ByteCounter {
            limit: usize::MAX,
            written: usize::MAX - 1,
            exceeded: false,
        };
        assert!(counter.write_all(b"12").is_err());
        assert_eq!(counter.written, usize::MAX - 1);
        assert!(counter.exceeded);
    }

    #[test]
    fn per_result_limit_applies_even_when_aggregate_budget_has_room() {
        let mut budget = ResultBudget {
            limits: limits(4, 1000),
            retained: 0,
            withheld: 0,
            stop: None,
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
        let result = executor
            .execute_async_bounded(&request, None, limits(8, 8), |_| {
                calls.set(calls.get() + 1);
                ready(Ok(Value::Null))
            })
            .await;
        assert!(result.is_err());
        assert_eq!(calls.get(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn expired_batch_budget_never_dispatches_or_reports_a_retention_failure() {
        let executor = BatchExecutor::new();
        let mut request = request(2, 1);
        request.options.timeout_ms = 0;
        let calls = Cell::new(0);
        let bounded = executor
            .execute_async_bounded(&request, None, limits(8, 8), |_| {
                calls.set(calls.get() + 1);
                ready(Ok(Value::Null))
            })
            .await
            .unwrap();
        assert_eq!(calls.get(), 0);
        assert_eq!(bounded.withheld_results, 0);
        assert_eq!(bounded.retained_result_bytes, 0);
        assert_eq!(bounded.response.status, BatchStatus::Aborted);
        assert!(
            bounded
                .response
                .results
                .iter()
                .all(|result| result.error.as_ref().unwrap().code == "BATCH_TIMEOUT")
        );
    }
}
