//! Retention and dependency-order contracts for observed batch execution.

use std::cell::{Cell, RefCell};
use std::future::{pending, ready};

use fcp_async_core::ExecutionContext;
use fcp_host::{
    BatchExecutor, BatchInvokeRequest, BatchOperation, BatchOperationError, BatchOptions,
    BatchResultLimits, BatchScheduleHint, BatchStatus, OperationResultStatus,
};
use futures_util::poll;
use serde_json::{Value, json};

fn request(dependent: bool, parallelism: u32) -> BatchInvokeRequest {
    BatchInvokeRequest {
        operations: (0..3)
            .map(|index| BatchOperation {
                id: format!("op-{index}"),
                tool: "test.echo".into(),
                input: Value::Null,
                depends_on: if dependent && index == 1 {
                    vec!["op-0".into()]
                } else {
                    Vec::new()
                },
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

fn refusal() -> BatchOperationError {
    BatchOperationError {
        code: "OBSERVER_REFUSED".into(),
        message: "private observer detail".into(),
        retry_after_ms: Some(10),
    }
}

#[fcp_async_core::runtime::test]
async fn retained_output_is_observed_before_its_dependent_factory_runs() {
    let executor = BatchExecutor::new();
    let request = request(true, 2);
    let observed = RefCell::new(Vec::new());
    let result = executor
        .execute_async_bounded_observed(
            &request,
            None,
            BatchResultLimits::default(),
            |operation| {
                if operation.id == "op-1" {
                    assert!(observed.borrow().contains(&"op-0".to_owned()));
                }
                ready(Ok(json!({"id": operation.id})))
            },
            |result| {
                assert_eq!(result.status, OperationResultStatus::Success);
                assert_eq!(result.output.as_ref().unwrap()["id"], result.id);
                observed.borrow_mut().push(result.id.clone());
                Ok(())
            },
        )
        .await
        .unwrap();
    assert_eq!(result.response.completed, 3);
    assert_eq!(observed.borrow().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn a_withheld_payload_never_reaches_the_observer_as_a_success() {
    let executor = BatchExecutor::new();
    let request = request(true, 1);
    let calls = Cell::new(0);
    let observations = RefCell::new(Vec::new());
    let result = executor
        .execute_async_bounded_observed(
            &request,
            None,
            BatchResultLimits { per_result_bytes: 4, total_result_bytes: 4 },
            |_| {
                calls.set(calls.get() + 1);
                ready(Ok(json!("private oversized value")))
            },
            |result| {
                observations.borrow_mut().push(result.clone());
                Ok(())
            },
        )
        .await
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(result.withheld_results, 1);
    assert_eq!(result.retained_result_bytes, 0);
    assert_eq!(observations.borrow().len(), 1);
    let observations = observations.borrow();
    assert!(observations[0].output.is_none());
    assert_eq!(observations[0].error.as_ref().unwrap().code, "BATCH_RESULT_LIMIT");
    assert!(!serde_json::to_string(&*observations).unwrap().contains("private oversized"));
}

#[fcp_async_core::runtime::test]
async fn observer_failure_stops_admission_but_preserves_known_provider_success() {
    let executor = BatchExecutor::new();
    let request = request(true, 1);
    let calls = Cell::new(0);
    let observations = Cell::new(0);
    let result = executor
        .execute_async_bounded_observed(
            &request,
            None,
            BatchResultLimits::default(),
            |_| {
                calls.set(calls.get() + 1);
                ready(Ok(json!(42)))
            },
            |_| {
                observations.set(observations.get() + 1);
                Err(refusal())
            },
        )
        .await
        .unwrap();
    assert_eq!((calls.get(), observations.get()), (1, 1));
    assert_eq!(result.response.status, BatchStatus::Aborted);
    assert_eq!(result.response.completed, 1);
    assert_eq!(result.response.results[0].output, Some(json!(42)));
    assert_eq!(result.response.results[1].status, OperationResultStatus::Skipped);
    assert!(!serde_json::to_string(&result).unwrap().contains("private observer"));
}

#[fcp_async_core::runtime::test]
async fn failed_observation_still_drains_an_admitted_operation_under_parent_cancellation() {
    let executor = BatchExecutor::new();
    let request = request(false, 2);
    let context = ExecutionContext::background();
    let calls = Cell::new(0);
    let observations = Cell::new(0);
    let mut run = Box::pin(executor.execute_async_bounded_observed(
        &request,
        Some(&context),
        BatchResultLimits::default(),
        |operation| {
            calls.set(calls.get() + 1);
            async move {
                if operation.id == "op-1" {
                    pending::<()>().await;
                }
                Ok(Value::Null)
            }
        },
        |_| {
            observations.set(observations.get() + 1);
            Err(refusal())
        },
    ));
    assert!(poll!(run.as_mut()).is_pending());
    assert_eq!(calls.get(), 2);
    context.cancel();
    let result = run.await.unwrap();
    assert_eq!(observations.get(), 1);
    assert_eq!(result.response.results[0].output, Some(Value::Null));
    assert_eq!(result.response.results[1].error.as_ref().unwrap().code, "BATCH_OUTCOME_UNKNOWN");
    assert_eq!(result.response.results[2].error.as_ref().unwrap().code, "BATCH_CANCELLED");
}

#[test]
fn observed_execution_preserves_send_when_callbacks_are_send() {
    fn assert_send<T: Send>(_: T) {}
    let executor = BatchExecutor::new();
    let request = request(false, 1);
    assert_send(executor.execute_async_bounded_observed(
        &request,
        None,
        BatchResultLimits::default(),
        |_| ready(Ok(Value::Null)),
        |_| Ok(()),
    ));
}

#[cfg(panic = "unwind")]
#[fcp_async_core::runtime::test]
async fn observer_panic_is_contained_without_reinvoking_the_factory_or_observer() {
    let executor = BatchExecutor::new();
    let request = request(true, 1);
    let calls = Cell::new(0);
    let observations = Cell::new(0);
    let result = executor.execute_async_bounded_observed(
        &request,
        None,
        BatchResultLimits::default(),
        |_| {
            calls.set(calls.get() + 1);
            ready(Ok(Value::Null))
        },
        |_| {
            observations.set(observations.get() + 1);
            panic!("fixture observer panic");
        },
    ).await.unwrap();
    assert_eq!((calls.get(), observations.get()), (1, 1));
    assert_eq!(result.response.status, BatchStatus::Aborted);
    assert_eq!(result.response.results[0].output, Some(Value::Null));
    assert_eq!(result.response.skipped, 2);
    assert!(!serde_json::to_string(&result).unwrap().contains("fixture observer panic"));
}

#[fcp_async_core::runtime::test]
async fn invalid_limits_call_neither_factory_nor_observer() {
    let executor = BatchExecutor::new();
    let request = request(false, 1);
    assert!(executor.execute_async_bounded_observed(
        &request,
        None,
        BatchResultLimits { per_result_bytes: 0, total_result_bytes: 4 },
        |_| -> std::future::Ready<Result<Value, BatchOperationError>> { panic!("invalid admission") },
        |_| { panic!("invalid observation") },
    ).await.is_err());
}
