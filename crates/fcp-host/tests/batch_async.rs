//! Public batch executor contracts, using controlled futures instead of timing
//! guesses to establish overlap, admission bounds, drain behavior, and ordering.

use std::cell::{Cell, RefCell};
use std::future::{pending, poll_fn, ready};
use std::rc::Rc;
use std::task::{Poll, Waker};
use std::time::Duration;

use fcp_host::{
    BatchExecutor, BatchInvokeRequest, BatchInvokeResponse, BatchOperation,
    BatchOperationError, BatchOperationPriority, BatchOptions, BatchScheduleHint,
    BatchSchedulerMode, BatchStatus, BatchZoneValidator, OperationResultStatus,
    ZoneRegistry,
};
use futures_util::poll;
use serde_json::json;

fn op(id: &str, dependencies: &[&str]) -> BatchOperation {
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
        options: BatchOptions { max_parallelism: parallelism, ..BatchOptions::default() },
    }
}

fn failure() -> BatchOperationError {
    BatchOperationError { code: "PROVIDER_ERROR".into(), message: "refused".into(), retry_after_ms: Some(17) }
}

#[derive(Default)]
struct Gate {
    open: Cell<bool>,
    waker: RefCell<Option<Waker>>,
}

impl Gate {
    async fn wait(&self) {
        poll_fn(|cx| {
            if self.open.get() { Poll::Ready(()) } else {
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

#[derive(Default)]
struct Usage {
    active: Cell<usize>,
    peak: Cell<usize>,
    created: RefCell<Vec<String>>,
}

struct Reservation(Rc<Usage>);

impl Reservation {
    fn enter(usage: &Rc<Usage>, id: &str) -> Self {
        let active = usage.active.get() + 1;
        usage.active.set(active);
        usage.peak.set(usage.peak.get().max(active));
        usage.created.borrow_mut().push(id.to_owned());
        Self(Rc::clone(usage))
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.0.active.set(self.0.active.get() - 1);
    }
}

fn assert_accounting(response: &BatchInvokeResponse, expected: usize) {
    assert_eq!(response.results.len(), expected);
    assert_eq!(response.completed + response.failed + response.skipped, expected);
    assert_eq!(response.completed, response.results.iter().filter(|r| r.status == OperationResultStatus::Success).count());
    assert_eq!(response.failed, response.results.iter().filter(|r| r.status == OperationResultStatus::Error).count());
}

#[fcp_async_core::runtime::test]
async fn concurrent_futures_are_bounded_before_factory_calls_and_refill_free_slots() {
    let executor = BatchExecutor::new();
    let request = request(vec![op("d", &[]), op("c", &[]), op("b", &[]), op("a", &[])], 2);
    let usage = Rc::new(Usage::default());
    let gates = [Gate::default(), Gate::default(), Gate::default(), Gate::default()];
    let mut batch = Box::pin(executor.execute_async(&request, |op| {
        let reservation = Reservation::enter(&usage, &op.id);
        let gate = &gates[usize::from(op.id.as_bytes()[0] - b'a')];
        async move {
            let _reservation = reservation;
            gate.wait().await;
            Ok(op.input.clone())
        }
    }));
    assert!(poll!(batch.as_mut()).is_pending());
    assert_eq!(*usage.created.borrow(), ["a", "b"]);
    assert_eq!(usage.active.get(), 2);
    gates[1].release();
    assert!(poll!(batch.as_mut()).is_pending());
    assert_eq!(*usage.created.borrow(), ["a", "b", "c"]);
    assert_eq!(usage.active.get(), 2, "do not wait for the slow peer before refilling");
    gates[2].release();
    assert!(poll!(batch.as_mut()).is_pending());
    assert_eq!(*usage.created.borrow(), ["a", "b", "c", "d"]);
    gates[0].release();
    gates[3].release();
    let response = batch.await.unwrap();
    assert_eq!(usage.peak.get(), 2);
    assert_eq!(usage.active.get(), 0);
    assert_eq!(response.status, BatchStatus::Success);
    assert_eq!(response.results.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["d", "c", "b", "a"]);
    assert_accounting(&response, 4);
}

#[fcp_async_core::runtime::test]
async fn dependents_wait_for_success_and_transitive_failures_do_not_stop_other_branches() {
    let executor = BatchExecutor::new();
    let request = request(vec![op("a", &[]), op("b", &[]), op("c", &["a"]), op("d", &["c"]), op("e", &["b"])], 2);
    let calls = RefCell::new(Vec::new());
    let response = executor.execute_async(&request, |op| {
        calls.borrow_mut().push(op.id.clone());
        ready(if op.id == "a" { Err(failure()) } else { Ok(op.input.clone()) })
    }).await.unwrap();
    assert_eq!(*calls.borrow(), ["a", "b", "e"]);
    assert_eq!(response.status, BatchStatus::PartialSuccess);
    for index in [2, 3] {
        assert_eq!(response.results[index].status, OperationResultStatus::Skipped);
        assert_eq!(response.results[index].error.as_ref().unwrap().code, "DEP_FAILED");
    }
    assert_eq!(response.results[0].error.as_ref().unwrap().retry_after_ms, Some(17));
    assert_accounting(&response, 5);
}

#[fcp_async_core::runtime::test]
async fn dependency_tiers_do_not_overlap_even_when_one_parent_finishes_early() {
    let executor = BatchExecutor::new();
    let request = request(vec![op("a", &[]), op("b", &[]), op("c", &["a"])], 2);
    let usage = Rc::new(Usage::default());
    let slow = Gate::default();
    let mut batch = Box::pin(executor.execute_async(&request, |op| {
        let reservation = Reservation::enter(&usage, &op.id);
        let slow = &slow;
        async move {
            let _reservation = reservation;
            if op.id == "b" { slow.wait().await; }
            Ok(op.input.clone())
        }
    }));
    assert!(poll!(batch.as_mut()).is_pending());
    assert_eq!(*usage.created.borrow(), ["a", "b"]);
    slow.release();
    let response = batch.await.unwrap();
    assert_eq!(*usage.created.borrow(), ["a", "b", "c"]);
    assert_eq!(response.completed, 3);
}

#[fcp_async_core::runtime::test]
async fn first_error_stops_admission_but_drains_already_admitted_results() {
    let executor = BatchExecutor::new();
    let mut request = request(vec![op("a", &[]), op("b", &[]), op("c", &[]), op("d", &["b"])], 2);
    request.options.stop_on_first_error = true;
    let usage = Rc::new(Usage::default());
    let gates = [Gate::default(), Gate::default()];
    let mut batch = Box::pin(executor.execute_async(&request, |op| {
        let reservation = Reservation::enter(&usage, &op.id);
        let gates = &gates;
        async move {
            let _reservation = reservation;
            gates[usize::from(op.id.as_bytes()[0] - b'a')].wait().await;
            if op.id == "a" { Err(failure()) } else { Ok(op.input.clone()) }
        }
    }));
    assert!(poll!(batch.as_mut()).is_pending());
    gates[0].release();
    assert!(poll!(batch.as_mut()).is_pending());
    assert_eq!(*usage.created.borrow(), ["a", "b"]);
    gates[1].release();
    let response = batch.await.unwrap();
    assert_eq!(response.status, BatchStatus::Aborted);
    assert_eq!((response.completed, response.failed, response.skipped), (1, 1, 2));
    assert_eq!(response.results[1].status, OperationResultStatus::Success);
    assert_eq!(response.results[2].error.as_ref().unwrap().code, "BATCH_ABORTED");
    assert_eq!(usage.active.get(), 0);
    assert_accounting(&response, 4);
}

#[fcp_async_core::runtime::test]
async fn deadline_marks_admitted_work_unknown_and_unadmitted_work_skipped() {
    let executor = BatchExecutor::new();
    let mut request = request(vec![op("a", &[]), op("b", &[]), op("c", &[]), op("d", &["a"])], 2);
    request.options.timeout_ms = 250;
    let usage = Rc::new(Usage::default());
    let response = executor.execute_async(&request, |op| {
        let reservation = Reservation::enter(&usage, &op.id);
        async move {
            let _reservation = reservation;
            pending::<()>().await;
            Ok(json!(null))
        }
    }).await.unwrap();
    assert_eq!(*usage.created.borrow(), ["a", "b"]);
    assert_eq!((response.completed, response.failed, response.skipped), (0, 2, 2));
    assert_eq!(response.status, BatchStatus::Aborted);
    for result in &response.results[..2] {
        assert_eq!(result.status, OperationResultStatus::Error);
        let error = result.error.as_ref().unwrap();
        assert_eq!(error.code, "BATCH_OUTCOME_UNKNOWN");
        assert_eq!(error.retry_after_ms, None);
    }
    for result in &response.results[2..] {
        assert_eq!(result.error.as_ref().unwrap().code, "BATCH_TIMEOUT");
        assert_eq!(result.status, OperationResultStatus::Skipped);
    }
    assert_eq!(usage.active.get(), 0, "timed-out futures must be dropped before returning");
    assert_accounting(&response, 4);
}

#[fcp_async_core::runtime::test]
async fn timeout_while_draining_preserves_known_success_and_provider_failure() {
    let executor = BatchExecutor::new();
    let mut request = request(vec![op("a", &[]), op("b", &[]), op("c", &[]), op("d", &[])], 3);
    request.options.timeout_ms = 250;
    request.options.stop_on_first_error = true;
    let response = executor.execute_async(&request, |op| async move {
        match op.id.as_str() {
            "a" => Ok(op.input.clone()),
            "b" => Err(failure()),
            _ => { pending::<()>().await; Ok(json!(null)) }
        }
    }).await.unwrap();
    assert_eq!(response.status, BatchStatus::Aborted);
    assert_eq!(response.results[0].status, OperationResultStatus::Success);
    assert_eq!(response.results[1].error.as_ref().unwrap().code, "PROVIDER_ERROR");
    assert_eq!(response.results[2].error.as_ref().unwrap().code, "BATCH_OUTCOME_UNKNOWN");
    // Depending on which completion was observed first, d may have been
    // admitted before b failed. Its classification must match that fact.
    assert!(matches!(response.results[3].status, OperationResultStatus::Skipped | OperationResultStatus::Error));
    assert_accounting(&response, 4);
}

#[fcp_async_core::runtime::test]
async fn zero_deadline_never_constructs_a_handler_future_and_maximum_budget_does_not_overflow() {
    let executor = BatchExecutor::new();
    let mut request = request(vec![op("a", &[])], 1);
    request.options.timeout_ms = 0;
    let called = Cell::new(false);
    let response = executor.execute_async(&request, |_| {
        called.set(true);
        ready(Ok(json!(true)))
    }).await.unwrap();
    assert!(!called.get());
    assert_eq!(response.status, BatchStatus::Aborted);
    assert_eq!(response.results[0].error.as_ref().unwrap().code, "BATCH_TIMEOUT");
    request.options.timeout_ms = u64::MAX;
    let response = executor.execute_async(&request, |_| ready(Ok(json!(true)))).await.unwrap();
    assert_eq!(response.status, BatchStatus::Success);
}

#[fcp_async_core::runtime::test]
async fn validation_errors_happen_before_any_factory_or_side_effect() {
    let executor = BatchExecutor::new();
    let requests = [
        request(vec![], 1),
        request(vec![op("a", &[])], 0),
        request(vec![op("a", &[]), op("a", &[])], 1),
        request(vec![op("a", &["missing"])], 1),
        request(vec![op("a", &["b"]), op("b", &["a"])], 2),
    ];
    for request in &requests {
        let called = Cell::new(false);
        assert!(executor.execute_async(request, |_| {
            called.set(true);
            ready(Ok(json!(null)))
        }).await.is_err());
        assert!(!called.get());
    }
    let zone = serde_json::from_value(json!("z:work")).unwrap();
    let guarded = BatchExecutor::with_zone_validator(BatchZoneValidator::new(zone, ZoneRegistry::new()));
    let request = request(vec![op("unknown", &[])], 1);
    let called = Cell::new(false);
    assert!(guarded.execute_async(&request, |_| {
        called.set(true);
        ready(Ok(json!(null)))
    }).await.is_err());
    assert!(!called.get(), "unknown tools cannot bypass registered zone authority");
}

#[fcp_async_core::runtime::test]
async fn adaptive_admission_uses_existing_plan_and_keeps_the_submission_order_report() {
    let executor = BatchExecutor::new();
    let mut request = request(vec![op("a", &[]), op("b", &[]), op("c", &["a", "b"])], 1);
    request.options.scheduler.mode = BatchSchedulerMode::Adaptive;
    request.operations[1].scheduler.priority = BatchOperationPriority::Critical;
    let (plan, _) = executor.plan_with_schedule_report(&request).unwrap();
    let expected: Vec<_> = plan.tiers.iter().flat_map(|tier| tier.operation_ids.iter().cloned()).collect();
    let calls = RefCell::new(Vec::new());
    let response = executor.execute_async(&request, |op| {
        calls.borrow_mut().push(op.id.clone());
        ready(Ok(op.input.clone()))
    }).await.unwrap();
    assert_eq!(*calls.borrow(), expected);
    assert_eq!(calls.borrow()[0], "b");
    assert!(response.schedule_report.is_some());
    assert_eq!(response.results.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["a", "b", "c"]);
    let wire = serde_json::to_vec(&response).unwrap();
    let decoded: BatchInvokeResponse = serde_json::from_slice(&wire).unwrap();
    assert_accounting(&decoded, 3);
}

#[fcp_async_core::runtime::test]
async fn dropping_a_batch_releases_all_owned_futures_without_starting_waiting_work() {
    let executor = BatchExecutor::new();
    let request = request(vec![op("a", &[]), op("b", &[]), op("c", &[])], 2);
    let usage = Rc::new(Usage::default());
    let mut batch = Box::pin(executor.execute_async(&request, |op| {
        let reservation = Reservation::enter(&usage, &op.id);
        async move {
            let _reservation = reservation;
            pending::<()>().await;
            Ok(json!(null))
        }
    }));
    assert!(poll!(batch.as_mut()).is_pending());
    assert_eq!(usage.active.get(), 2);
    drop(batch);
    assert_eq!(usage.active.get(), 0);
    assert_eq!(*usage.created.borrow(), ["a", "b"]);
}

#[fcp_async_core::runtime::test]
async fn a_noncooperative_late_result_is_retained_without_admitting_the_next_operation() {
    let executor = BatchExecutor::new();
    let mut request = request(vec![op("a", &[]), op("b", &[])], 1);
    request.options.timeout_ms = 100;
    let calls = Cell::new(0);
    let response = executor.execute_async(&request, |_| {
        calls.set(calls.get() + 1);
        async {
            // Deliberately violate cooperative polling to pin the documented
            // limitation: no executor can preempt a blocking future poll.
            std::thread::sleep(Duration::from_millis(150));
            Ok(json!({ "committed": true }))
        }
    }).await.unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(response.status, BatchStatus::Aborted);
    assert_eq!(response.results[0].output, Some(json!({ "committed": true })));
    assert_eq!(response.results[1].error.as_ref().unwrap().code, "BATCH_TIMEOUT");
}
