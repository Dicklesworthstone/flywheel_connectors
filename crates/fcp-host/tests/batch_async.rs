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
async fn a_ready_dependent_does_not_wait_for_an_unrelated_slow_parent() {
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
    assert_eq!(*usage.created.borrow(), ["a", "b", "c"]);
    assert_eq!(usage.active.get(), 1, "only the unrelated blocked operation remains");
    slow.release();
    let response = batch.await.unwrap();
    assert_eq!(*usage.created.borrow(), ["a", "b", "c"]);
    assert_eq!(response.completed, 3);
    assert_eq!(usage.peak.get(), 2);
    assert_accounting(&response, 3);
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

mod context {
    use fcp_async_core::ExecutionContext;

    use super::*;

    #[fcp_async_core::runtime::test]
    async fn pre_cancelled_context_admits_nothing_and_wins_over_an_expired_budget() {
        let executor = BatchExecutor::new();
        let mut request = request(vec![op("a", &[]), op("b", &["a"])], 2);
        request.options.timeout_ms = 0;
        let context = ExecutionContext::request_scoped(Duration::ZERO);
        context.cancel();
        let called = Cell::new(false);
        let response = executor.execute_async_with_context(&request, &context, |_| {
            called.set(true);
            ready(Ok(json!(true)))
        }).await.unwrap();
        assert!(!called.get());
        assert_eq!(response.status, BatchStatus::Aborted);
        assert_eq!(response.skipped, 2);
        for result in &response.results {
            assert_eq!(result.error.as_ref().unwrap().code, "BATCH_CANCELLED");
        }
        assert_accounting(&response, 2);
    }

    #[fcp_async_core::runtime::test]
    async fn expired_context_admits_nothing_even_with_an_unlimited_batch_budget() {
        let executor = BatchExecutor::new();
        let mut request = request(vec![op("a", &[])], 1);
        request.options.timeout_ms = u64::MAX;
        let context = ExecutionContext::request_scoped(Duration::ZERO);
        let called = Cell::new(false);
        let response = executor.execute_async_with_context(&request, &context, |_| {
            called.set(true);
            ready(Ok(json!(true)))
        }).await.unwrap();
        assert!(!called.get());
        assert_eq!(response.results[0].error.as_ref().unwrap().code, "BATCH_TIMEOUT");
        assert!(!context.is_cancelled());
    }

    #[fcp_async_core::runtime::test]
    async fn cancellation_returns_partial_results_and_drops_unresolved_futures() {
        let executor = BatchExecutor::new();
        let request = request(vec![op("a", &[]), op("b", &[]), op("c", &["b"])], 1);
        let context = ExecutionContext::background();
        let usage = Rc::new(Usage::default());
        let mut batch = Box::pin(executor.execute_async_with_context(&request, &context, |op| {
            let reservation = Reservation::enter(&usage, &op.id);
            async move {
                let _reservation = reservation;
                if op.id != "a" { pending::<()>().await; }
                Ok(op.input.clone())
            }
        }));
        assert!(poll!(batch.as_mut()).is_pending());
        assert_eq!(*usage.created.borrow(), ["a", "b"]);
        context.cancel();
        let response = batch.await.unwrap();
        assert_eq!(response.status, BatchStatus::Aborted);
        assert_eq!(response.results[0].output, Some(json!({ "id": "a" })));
        assert_eq!(response.results[1].status, OperationResultStatus::Error);
        assert_eq!(response.results[1].error.as_ref().unwrap().code, "BATCH_OUTCOME_UNKNOWN");
        assert_eq!(response.results[1].error.as_ref().unwrap().retry_after_ms, None);
        assert_eq!(response.results[2].status, OperationResultStatus::Skipped);
        assert_eq!(response.results[2].error.as_ref().unwrap().code, "BATCH_CANCELLED");
        assert_eq!(usage.active.get(), 0);
        assert_accounting(&response, 3);
    }

    #[fcp_async_core::runtime::test]
    async fn the_earlier_deadline_wins_without_cancelling_the_callers_context() {
        for context_first in [false, true] {
            let executor = BatchExecutor::new();
            let mut request = request(vec![op("a", &[]), op("b", &["a"])], 1);
            request.options.timeout_ms = if context_first { 30_000 } else { 250 };
            let context = ExecutionContext::request_scoped(Duration::from_millis(
                if context_first { 250 } else { 30_000 },
            ));
            let usage = Rc::new(Usage::default());
            let response = fcp_async_core::time::timeout(Duration::from_secs(5),
                executor.execute_async_with_context(&request, &context, |op| {
                    let reservation = Reservation::enter(&usage, &op.id);
                    async move {
                        let _reservation = reservation;
                        pending::<()>().await;
                        Ok(json!(null))
                    }
                }),
            ).await.expect("the short deadline must win").unwrap();
            assert_eq!(response.status, BatchStatus::Aborted);
            assert_eq!(response.results[0].error.as_ref().unwrap().code, "BATCH_OUTCOME_UNKNOWN");
            assert_eq!(response.results[1].error.as_ref().unwrap().code, "BATCH_TIMEOUT");
            assert_eq!(usage.active.get(), 0);
            assert!(!context.is_cancelled(), "a batch must not cancel sibling work");
            if !context_first {
                assert!(!context.remaining_budget().unwrap().is_zero());
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn parent_context_cancellation_reaches_the_inherited_batch_context() {
        let executor = BatchExecutor::new();
        let request = request(vec![op("a", &[])], 1);
        let parent = ExecutionContext::background();
        let child = parent.child();
        let mut batch = Box::pin(executor.execute_async_with_context(&request, &child, |_| async {
            pending::<()>().await;
            Ok(json!(null))
        }));
        assert!(poll!(batch.as_mut()).is_pending());
        parent.cancel();
        let response = batch.await.unwrap();
        assert!(child.is_cancelled());
        assert_eq!(response.status, BatchStatus::Aborted);
        assert_eq!(response.results[0].error.as_ref().unwrap().code, "BATCH_OUTCOME_UNKNOWN");
    }

    #[fcp_async_core::runtime::test]
    async fn cancellation_interrupts_first_error_draining_without_erasing_the_provider_error() {
        let executor = BatchExecutor::new();
        let mut request = request(vec![op("a", &[]), op("b", &[]), op("c", &[])], 2);
        request.options.stop_on_first_error = true;
        let context = ExecutionContext::background();
        let calls = RefCell::new(Vec::new());
        let mut batch = Box::pin(executor.execute_async_with_context(&request, &context, |op| {
            calls.borrow_mut().push(op.id.clone());
            async move {
                if op.id == "a" { Err(failure()) } else {
                    pending::<()>().await;
                    Ok(json!(null))
                }
            }
        }));
        assert!(poll!(batch.as_mut()).is_pending());
        context.cancel();
        let response = batch.await.unwrap();
        assert_eq!(*calls.borrow(), ["a", "b"]);
        assert_eq!(response.results[0].error.as_ref().unwrap().code, "PROVIDER_ERROR");
        assert_eq!(response.results[0].error.as_ref().unwrap().retry_after_ms, Some(17));
        assert_eq!(response.results[1].error.as_ref().unwrap().code, "BATCH_OUTCOME_UNKNOWN");
        assert_eq!(response.results[2].error.as_ref().unwrap().code, "BATCH_CANCELLED");
        assert_accounting(&response, 3);
    }

    #[fcp_async_core::runtime::test]
    async fn cancellation_in_a_factory_stops_the_next_admission_before_polling_the_first_future() {
        let executor = BatchExecutor::new();
        let request = request(vec![op("a", &[]), op("b", &[]), op("c", &[])], 3);
        let context = ExecutionContext::background();
        let calls = Cell::new(0);
        let polled = Cell::new(false);
        let response = executor.execute_async_with_context(&request, &context, |_| {
            calls.set(calls.get() + 1);
            context.cancel();
            let polled = &polled;
            async move { polled.set(true); Ok(json!(true)) }
        }).await.unwrap();
        assert_eq!(calls.get(), 1);
        assert!(!polled.get());
        assert_eq!(response.results[0].error.as_ref().unwrap().code, "BATCH_OUTCOME_UNKNOWN",
            "factory admission may itself have performed a side effect");
        assert_eq!(response.skipped, 2);
    }

    #[fcp_async_core::runtime::test]
    async fn ready_heavy_work_yields_so_cancellation_on_the_same_executor_can_be_observed() {
        let executor = BatchExecutor::new();
        let request = request((0..128).map(|index| op(&format!("op-{index:03}"), &[])).collect(), 1);
        let context = ExecutionContext::background();
        let calls = Cell::new(0);
        let mut batch = Box::pin(executor.execute_async_with_context(&request, &context, |_| {
            calls.set(calls.get() + 1);
            ready(Ok(json!(true)))
        }));
        assert!(poll!(batch.as_mut()).is_pending(), "ready work must yield cooperatively");
        assert!(calls.get() > 0 && calls.get() < 128);
        context.cancel();
        let response = batch.await.unwrap();
        assert_eq!(response.status, BatchStatus::Aborted);
        assert!(response.completed > 0 && response.skipped > 0);
        assert_accounting(&response, 128);
    }
}

mod mesh {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;

    use fcp_core::TailscaleNodeId;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_host::mesh_routing::{MeshRouter, MeshRoutingSettings, unix_now_ms};
    use fcp_mesh::invoke_route::{
        DEFAULT_MESH_FORWARD_MAX_SKEW_MS, MeshForwardBody, MeshForwardEnvelope,
        MeshForwardReply, MeshPeerConfig, MeshPeerDirectory,
    };

    use super::*;

    #[fcp_async_core::runtime::test]
    async fn independent_batch_handlers_forward_signed_invokes_to_two_real_tcp_peers_concurrently() {
        let local_key = Ed25519SigningKey::from_bytes(&[71; 32]).unwrap();
        let origin = MeshPeerConfig {
            node_id: "entry".to_owned(),
            endpoint: "http://127.0.0.1:1".to_owned(),
            public_key_hex: hex::encode(local_key.verifying_key().to_bytes()),
        };
        let (received_tx, received_rx) = mpsc::channel();
        let mut peers = Vec::new();
        let mut releases = Vec::new();
        let mut servers = Vec::new();
        for (node, seed) in [("peer-b", 72), ("peer-c", 73)] {
            let key = Ed25519SigningKey::from_bytes(&[seed; 32]).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            peers.push(MeshPeerConfig {
                node_id: node.to_owned(),
                endpoint: format!("http://{}", listener.local_addr().unwrap()),
                public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            });
            let directory = MeshPeerDirectory::from_configs(
                TailscaleNodeId::new(node), std::slice::from_ref(&origin),
            ).unwrap();
            let received = received_tx.clone();
            let (release_tx, release_rx) = mpsc::channel();
            releases.push(release_tx);
            servers.push(thread::spawn(move || {
                let started = Instant::now();
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(started.elapsed() < Duration::from_secs(5), "invoke did not connect");
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("accept: {error}"),
                    }
                };
                socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                let envelope = {
                    let mut reader = BufReader::new(&mut socket);
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    assert_eq!(line, "POST /rpc/mesh/forward HTTP/1.1\r\n");
                    let mut length = None;
                    let mut header_bytes = line.len();
                    loop {
                        line.clear();
                        reader.read_line(&mut line).unwrap();
                        header_bytes += line.len();
                        assert!(!line.is_empty() && header_bytes <= 8192);
                        if line == "\r\n" { break; }
                        if let Some((name, value)) = line.split_once(':')
                            && name.eq_ignore_ascii_case("content-length")
                        {
                            length = Some(value.trim().parse::<usize>().unwrap());
                        }
                    }
                    let length = length.unwrap();
                    assert!(length <= 8192);
                    let mut body = vec![0; length];
                    reader.read_exact(&mut body).unwrap();
                    serde_json::from_slice::<MeshForwardEnvelope>(&body).unwrap()
                };
                envelope.verify(&directory, unix_now_ms(), DEFAULT_MESH_FORWARD_MAX_SKEW_MS).unwrap();
                assert!(matches!(&envelope.body, MeshForwardBody::Invoke { .. }));
                received.send(node).unwrap();
                // Neither peer responds until BOTH authenticated requests have
                // arrived. A sequential executor cannot pass this bounded barrier.
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                let reply = MeshForwardReply::sign(
                    &key, TailscaleNodeId::new(node), &envelope, 200,
                    json!({ "executor": node }).to_string(),
                );
                let body = serde_json::to_vec(&reply).unwrap();
                write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                socket.write_all(&body).unwrap();
            }));
        }
        drop(received_tx);
        let coordinator = thread::spawn(move || {
            let first = received_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let second = received_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_ne!(first, second);
            for release in releases { release.send(()).unwrap(); }
        });
        let router = MeshRouter::new(MeshRoutingSettings {
            node_id: TailscaleNodeId::new("entry"),
            signing_key: local_key,
            peers_json: serde_json::to_string(&peers).unwrap(),
            forward_timeout: Duration::from_secs(8),
        }).unwrap();
        let executor = BatchExecutor::new();
        let request = request(vec![op("peer-c", &[]), op("peer-b", &[])], 2);
        let response = executor.execute_async(&request, |op| {
            let router = &router;
            async move {
                let reply = router.forward(&TailscaleNodeId::new(op.id.clone()), MeshForwardBody::Invoke {
                    request_json: op.input.to_string(),
                    asserted_principal: None,
                }).await.map_err(|error| BatchOperationError {
                    code: "MESH_FORWARD_FAILED".to_owned(),
                    message: error.summary(),
                    retry_after_ms: None,
                })?;
                Ok(serde_json::from_str(&reply.body_json).unwrap())
            }
        }).await;
        coordinator.join().unwrap();
        for server in servers { server.join().unwrap(); }
        let response = response.unwrap();
        assert_eq!(response.status, BatchStatus::Success);
        assert_eq!(response.results[0].output, Some(json!({ "executor": "peer-c" })));
        assert_eq!(response.results[1].output, Some(json!({ "executor": "peer-b" })));
        assert_eq!(router.forward_usage().unwrap(), fcp_host::mesh_routing::MeshForwardUsage::default());
        assert_accounting(&response, 2);
    }
}

mod dependencies {
    use fcp_async_core::ExecutionContext;

    use super::*;

    #[fcp_async_core::runtime::test]
    async fn an_entire_fast_chain_progresses_while_an_unrelated_root_is_blocked() {
        let executor = BatchExecutor::new();
        let request = request(vec![
            op("e", &["d"]), op("d", &["c"]), op("c", &["a"]),
            op("b", &[]), op("a", &[]),
        ], 2);
        let slow = Gate::default();
        let usage = Rc::new(Usage::default());
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
        assert_eq!(*usage.created.borrow(), ["a", "b", "c", "d", "e"]);
        assert_eq!(usage.active.get(), 1);
        assert_eq!(usage.peak.get(), 2, "the bound is global, not per dependency depth");
        slow.release();
        let response = batch.await.unwrap();
        assert_eq!(response.status, BatchStatus::Success);
        assert_eq!(response.results.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["e", "d", "c", "b", "a"]);
        assert_eq!(usage.active.get(), 0);
        assert_accounting(&response, 5);
    }

    #[fcp_async_core::runtime::test]
    async fn fan_in_waits_for_every_parent_without_stalling_a_separate_ready_chain() {
        let executor = BatchExecutor::new();
        let request = request(vec![
            op("a", &[]), op("b", &[]), op("c", &["a"]),
            op("d", &["a", "b"]), op("e", &["c"]),
        ], 2);
        let slow = Gate::default();
        let calls = RefCell::new(Vec::new());
        let mut batch = Box::pin(executor.execute_async(&request, |op| {
            calls.borrow_mut().push(op.id.clone());
            let slow = &slow;
            async move {
                if op.id == "b" { slow.wait().await; }
                Ok(op.input.clone())
            }
        }));
        assert!(poll!(batch.as_mut()).is_pending());
        assert_eq!(*calls.borrow(), ["a", "b", "c", "e"]);
        slow.release();
        let response = batch.await.unwrap();
        assert_eq!(*calls.borrow(), ["a", "b", "c", "e", "d"]);
        assert_eq!(response.completed, 5);
        assert_accounting(&response, 5);
    }

    #[fcp_async_core::runtime::test]
    async fn duplicate_edges_and_diamond_dependencies_admit_each_handler_once() {
        let executor = BatchExecutor::new();
        let request = request(vec![
            op("a", &[]), op("b", &["a", "a"]), op("c", &["a"]),
            op("d", &["b", "c", "b"]),
        ], 3);
        let calls = RefCell::new(Vec::new());
        let response = executor.execute_async(&request, |op| {
            calls.borrow_mut().push(op.id.clone());
            ready(Ok(op.input.clone()))
        }).await.unwrap();
        assert_eq!(*calls.borrow(), ["a", "b", "c", "d"]);
        assert_eq!(response.completed, 4);
        assert_accounting(&response, 4);
    }

    #[fcp_async_core::runtime::test]
    async fn failed_descendants_are_settled_before_an_unrelated_root_is_cancelled() {
        let executor = BatchExecutor::new();
        let request = request(vec![
            op("a", &[]), op("b", &[]), op("c", &["a"]),
            op("d", &["c"]), op("e", &["b"]),
        ], 2);
        let context = ExecutionContext::background();
        let calls = RefCell::new(Vec::new());
        let mut batch = Box::pin(executor.execute_async_with_context(&request, &context, |op| {
            calls.borrow_mut().push(op.id.clone());
            async move {
                if op.id == "a" { Err(failure()) } else {
                    pending::<()>().await;
                    Ok(json!(null))
                }
            }
        }));
        assert!(poll!(batch.as_mut()).is_pending());
        context.cancel();
        let response = batch.await.unwrap();
        assert_eq!(*calls.borrow(), ["a", "b"]);
        for index in [2, 3] {
            assert_eq!(response.results[index].error.as_ref().unwrap().code, "DEP_FAILED");
        }
        assert_eq!(response.results[1].error.as_ref().unwrap().code, "BATCH_OUTCOME_UNKNOWN");
        assert_eq!(response.results[4].error.as_ref().unwrap().code, "BATCH_CANCELLED");
        assert_accounting(&response, 5);
    }

    #[fcp_async_core::runtime::test]
    async fn cancellation_preserves_cross_depth_results_and_releases_all_active_depths() {
        let executor = BatchExecutor::new();
        let request = request(vec![
            op("a", &[]), op("b", &[]), op("c", &["a"]), op("d", &["c"]),
        ], 2);
        let context = ExecutionContext::background();
        let usage = Rc::new(Usage::default());
        let mut batch = Box::pin(executor.execute_async_with_context(&request, &context, |op| {
            let reservation = Reservation::enter(&usage, &op.id);
            async move {
                let _reservation = reservation;
                if op.id != "a" { pending::<()>().await; }
                Ok(op.input.clone())
            }
        }));
        assert!(poll!(batch.as_mut()).is_pending());
        assert_eq!(*usage.created.borrow(), ["a", "b", "c"]);
        context.cancel();
        let response = batch.await.unwrap();
        assert_eq!(response.results[0].status, OperationResultStatus::Success);
        for index in [1, 2] {
            let error = response.results[index].error.as_ref().unwrap();
            assert_eq!(error.code, "BATCH_OUTCOME_UNKNOWN");
            assert_eq!(error.retry_after_ms, None);
        }
        assert_eq!(response.results[3].error.as_ref().unwrap().code, "BATCH_CANCELLED");
        assert_eq!(usage.active.get(), 0);
        assert_eq!(usage.peak.get(), 2);
        assert_accounting(&response, 4);
    }

    #[fcp_async_core::runtime::test]
    async fn a_dependent_failure_stops_new_work_but_drains_a_slower_root() {
        let executor = BatchExecutor::new();
        let mut request = request(vec![
            op("a", &[]), op("b", &[]), op("c", &["a"]),
            op("d", &["c"]), op("e", &["b"]),
        ], 2);
        request.options.stop_on_first_error = true;
        let slow = Gate::default();
        let calls = RefCell::new(Vec::new());
        let mut batch = Box::pin(executor.execute_async(&request, |op| {
            calls.borrow_mut().push(op.id.clone());
            let slow = &slow;
            async move {
                if op.id == "b" { slow.wait().await; }
                if op.id == "c" { Err(failure()) } else { Ok(op.input.clone()) }
            }
        }));
        assert!(poll!(batch.as_mut()).is_pending());
        assert_eq!(*calls.borrow(), ["a", "b", "c"]);
        slow.release();
        let response = batch.await.unwrap();
        assert_eq!(*calls.borrow(), ["a", "b", "c"]);
        assert_eq!(response.status, BatchStatus::Aborted);
        assert_eq!((response.completed, response.failed, response.skipped), (2, 1, 2));
        assert_eq!(response.results[2].error.as_ref().unwrap().retry_after_ms, Some(17));
        for index in [3, 4] {
            assert_eq!(response.results[index].error.as_ref().unwrap().code, "BATCH_ABORTED");
        }
        assert_accounting(&response, 5);
    }

    #[fcp_async_core::runtime::test]
    async fn the_ready_frontier_preserves_adaptive_order_and_the_global_bound() {
        let executor = BatchExecutor::new();
        let mut request = request(vec![
            op("a", &[]), op("b", &[]), op("c", &["b"]), op("d", &["b"]),
        ], 2);
        request.options.scheduler.mode = BatchSchedulerMode::Adaptive;
        request.operations[3].scheduler.priority = BatchOperationPriority::Critical;
        let slow = Gate::default();
        let usage = Rc::new(Usage::default());
        let mut batch = Box::pin(executor.execute_async(&request, |op| {
            let reservation = Reservation::enter(&usage, &op.id);
            let slow = &slow;
            async move {
                let _reservation = reservation;
                if op.id == "a" { slow.wait().await; }
                Ok(op.input.clone())
            }
        }));
        assert!(poll!(batch.as_mut()).is_pending());
        assert_eq!(*usage.created.borrow(), ["a", "b", "d", "c"]);
        assert_eq!(usage.peak.get(), 2);
        slow.release();
        let response = batch.await.unwrap();
        assert_eq!(response.status, BatchStatus::Success);
        assert!(response.schedule_report.is_some());
        assert_accounting(&response, 4);
    }

    #[fcp_async_core::runtime::test]
    async fn long_failure_chains_propagate_iteratively_and_keep_cancellation_responsive() {
        let executor = BatchExecutor::new();
        let mut operations = vec![op("a", &[]), op("b", &[])];
        let mut parent = "a".to_owned();
        for index in 0..1024 {
            let id = format!("n-{index:04}");
            operations.push(op(&id, &[&parent]));
            parent = id;
        }
        let request = request(operations, 2);
        let context = ExecutionContext::background();
        let calls = RefCell::new(Vec::new());
        let mut batch = Box::pin(executor.execute_async_with_context(&request, &context, |op| {
            calls.borrow_mut().push(op.id.clone());
            async move {
                if op.id == "a" { Err(failure()) } else {
                    pending::<()>().await;
                    Ok(json!(null))
                }
            }
        }));
        // Bounded manual polling crosses cooperative yields, never releases b,
        // and does not use sleep-based timing to infer failure propagation.
        for _ in 0..64 {
            assert!(poll!(batch.as_mut()).is_pending());
        }
        context.cancel();
        let response = batch.await.unwrap();
        assert_eq!(*calls.borrow(), ["a", "b"]);
        for result in &response.results[2..] {
            assert_eq!(result.status, OperationResultStatus::Skipped);
            assert_eq!(result.error.as_ref().unwrap().code, "DEP_FAILED");
        }
        assert_eq!(response.failed, 2);
        assert_accounting(&response, 1026);
    }
}
