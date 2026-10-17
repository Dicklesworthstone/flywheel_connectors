use std::cell::{Cell, RefCell};
use std::future::{pending, poll_fn, ready};
use std::rc::Rc;
use std::task::{Poll, Waker};

use futures_util::poll;

use super::*;

fn member(id: &str, dependencies: &[&str]) -> HttpBatchOperation {
    HttpBatchOperation {
        id: id.to_owned(),
        request: InvokeRequest {
            r#type: "invoke".to_owned(),
            id: RequestId(format!("invoke-{id}")),
            connector_id: ConnectorId::from_static("fcp.test:utility:1.0.0"),
            operation: OperationId::from_static("test.echo"),
            zone_id: "z:work".parse().unwrap(),
            input: json!({"id": id}),
            capability_token: fcp_core::CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: Some(format!("effect-{id}")),
            lease_seq: Some(7),
            deadline_ms: Some(1000),
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        },
        depends_on: dependencies.iter().map(|id| (*id).to_owned()).collect(),
        scheduler: BatchScheduleHint::default(),
    }
}

fn batch(operations: Vec<HttpBatchOperation>, parallelism: u32) -> HttpBatchInvokeRequest {
    HttpBatchInvokeRequest {
        operations,
        options: BatchOptions {
            max_parallelism: parallelism,
            stop_on_first_error: false,
            ..BatchOptions::default()
        },
    }
}

fn success(operation: &HttpBatchOperation) -> OperationResult {
    OperationResult {
        id: operation.id.clone(),
        status: OperationResultStatus::Success,
        output: Some(json!({"id": operation.request.id.0, "result": operation.request.input})),
        error: None,
        duration_ms: 0,
    }
}

fn failure(operation: &HttpBatchOperation) -> OperationResult {
    OperationResult {
        id: operation.id.clone(),
        status: OperationResultStatus::Error,
        output: None,
        error: Some(BatchOperationError {
            code: "PROVIDER_RATE_LIMITED".to_owned(),
            message: "provider rate limited".to_owned(),
            retry_after_ms: Some(5000),
        }),
        duration_ms: 0,
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
        })
        .await;
    }

    fn release(&self) {
        self.open.set(true);
        if let Some(waker) = self.waker.borrow_mut().take() {
            waker.wake();
        }
    }
}

#[fcp_async_core::runtime::test]
async fn http_adapter_refills_capacity_without_waiting_for_a_chunk_barrier() {
    let request = batch(
        vec![member("c", &[]), member("b", &[]), member("a", &[])],
        2,
    );
    let slow = Gate::default();
    let calls = RefCell::new(Vec::new());
    let mut run = Box::pin(execute_with(&request, Instant::now(), |operation, _| {
        calls.borrow_mut().push(operation.id.clone());
        let slow = &slow;
        async move {
            if operation.id == "a" {
                slow.wait().await;
            }
            success(operation)
        }
    }));
    assert!(poll!(run.as_mut()).is_pending());
    assert_eq!(*calls.borrow(), ["a", "b", "c"]);
    slow.release();
    let response = run.await.unwrap();
    assert_eq!(response.completed, 3);
    assert_eq!(
        response
            .results
            .iter()
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>(),
        ["c", "b", "a"]
    );
}

#[fcp_async_core::runtime::test]
async fn http_adapter_releases_a_dependent_before_an_unrelated_parent_finishes() {
    let request = batch(
        vec![member("a", &[]), member("b", &[]), member("c", &["a"])],
        2,
    );
    let slow = Gate::default();
    let calls = RefCell::new(Vec::new());
    let mut run = Box::pin(execute_with(&request, Instant::now(), |operation, _| {
        calls.borrow_mut().push(operation.id.clone());
        let slow = &slow;
        async move {
            if operation.id == "b" {
                slow.wait().await;
            }
            success(operation)
        }
    }));
    assert!(poll!(run.as_mut()).is_pending());
    assert_eq!(*calls.borrow(), ["a", "b", "c"]);
    slow.release();
    assert_eq!(run.await.unwrap().completed, 3);
}

#[fcp_async_core::runtime::test]
async fn http_adapter_stops_factories_on_first_error_but_drains_an_admitted_member() {
    let mut request = batch(
        vec![member("a", &[]), member("b", &[]), member("c", &[])],
        2,
    );
    request.options.stop_on_first_error = true;
    let slow = Gate::default();
    let calls = RefCell::new(Vec::new());
    let mut run = Box::pin(execute_with(&request, Instant::now(), |operation, _| {
        calls.borrow_mut().push(operation.id.clone());
        let slow = &slow;
        async move {
            if operation.id == "a" {
                failure(operation)
            } else {
                slow.wait().await;
                success(operation)
            }
        }
    }));
    assert!(poll!(run.as_mut()).is_pending());
    assert_eq!(*calls.borrow(), ["a", "b"]);
    slow.release();
    let response = run.await.unwrap();
    assert_eq!(response.status, BatchStatus::Aborted);
    assert_eq!(
        (response.completed, response.failed, response.skipped),
        (1, 1, 1)
    );
    assert_eq!(
        response.results[0].error.as_ref().unwrap().retry_after_ms,
        Some(5000)
    );
}

#[fcp_async_core::runtime::test]
async fn http_adapter_propagates_transitive_failure_without_invoking_dependents() {
    let request = batch(
        vec![member("a", &[]), member("b", &["a"]), member("c", &["b"])],
        2,
    );
    let calls = Cell::new(0);
    let response = execute_with(&request, Instant::now(), |operation, _| {
        calls.set(calls.get() + 1);
        ready(failure(operation))
    })
    .await
    .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(
        (response.completed, response.failed, response.skipped),
        (0, 1, 2)
    );
    for result in &response.results[1..] {
        assert_eq!(result.error.as_ref().unwrap().code, "DEP_FAILED");
    }
}

#[fcp_async_core::runtime::test]
async fn expired_http_batch_is_aborted_not_successful_and_never_dispatches() {
    let mut request = batch(vec![member("a", &[]), member("b", &[])], 2);
    request.options.timeout_ms = 0;
    let response = execute_with(
        &request,
        Instant::now(),
        |_, _| -> std::future::Ready<OperationResult> {
            panic!("expired batch cannot dispatch");
        },
    )
    .await
    .unwrap();
    assert_eq!(response.status, BatchStatus::Aborted);
    assert_eq!(
        (response.completed, response.failed, response.skipped),
        (0, 0, 2)
    );
    assert!(
        response
            .results
            .iter()
            .all(|result| result.error.as_ref().unwrap().code == "BATCH_TIMEOUT")
    );
}

#[fcp_async_core::runtime::test]
async fn http_deadline_keeps_admitted_work_unknown_and_unadmitted_work_skipped() {
    let mut request = batch(
        vec![member("a", &[]), member("b", &[]), member("c", &[])],
        2,
    );
    request.options.timeout_ms = 200;
    let calls = Cell::new(0);
    let mut run = Box::pin(execute_with(&request, Instant::now(), |operation, _| {
        calls.set(calls.get() + 1);
        async move {
            pending::<()>().await;
            success(operation)
        }
    }));
    assert!(poll!(run.as_mut()).is_pending());
    assert_eq!(calls.get(), 2);
    let response = run.await.unwrap();
    assert_eq!(response.status, BatchStatus::Aborted);
    assert_eq!(
        (response.completed, response.failed, response.skipped),
        (0, 2, 1)
    );
    for result in &response.results[..2] {
        let error = result.error.as_ref().unwrap();
        assert_eq!(error.code, "BATCH_OUTCOME_UNKNOWN");
        assert_eq!(error.retry_after_ms, None);
    }
    assert_eq!(
        response.results[2].error.as_ref().unwrap().code,
        "BATCH_TIMEOUT"
    );
}

#[fcp_async_core::runtime::test]
async fn every_http_member_receives_the_same_original_absolute_budget() {
    let request = batch(vec![member("a", &[]), member("b", &["a"])], 1);
    let started_at = Instant::now();
    let expected = started_at.checked_add(Duration::from_millis(request.options.timeout_ms));
    let response = execute_with(&request, started_at, |operation, deadline| {
        assert_eq!(deadline, expected);
        ready(success(operation))
    })
    .await
    .unwrap();
    assert_eq!(response.completed, 2);
}

#[fcp_async_core::runtime::test]
async fn huge_http_batch_budget_does_not_wrap_to_an_expired_deadline() {
    let mut request = batch(vec![member("a", &[])], 1);
    request.options.timeout_ms = u64::MAX;
    let response = execute_with(&request, Instant::now(), |operation, _| {
        ready(success(operation))
    })
    .await
    .unwrap();
    assert_eq!(response.completed, 1);
}

#[fcp_async_core::runtime::test]
async fn invalid_graph_never_dispatches_any_http_member() {
    let request = batch(vec![member("a", &[]), member("b", &["missing"])], 1);
    let calls = Cell::new(0);
    let result = execute_with(&request, Instant::now(), |operation, _| {
        calls.set(calls.get() + 1);
        ready(success(operation))
    })
    .await;
    assert!(result.is_err());
    assert_eq!(calls.get(), 0);
}

#[fcp_async_core::runtime::test]
async fn duplicate_durable_ids_and_invalid_late_members_fail_before_dispatch() {
    let mut duplicate = batch(vec![member("a", &[]), member("b", &[])], 2);
    duplicate.operations[1].request.id = duplicate.operations[0].request.id.clone();
    let mut invalid_key = batch(vec![member("a", &[]), member("b", &[])], 1);
    invalid_key.operations[1].request.idempotency_key = Some("x".repeat(129));
    let mut invalid_type = batch(vec![member("a", &[]), member("b", &[])], 1);
    invalid_type.operations[1].request.r#type = "simulate".to_owned();
    for request in [duplicate, invalid_key, invalid_type] {
        let calls = Cell::new(0);
        let result = execute_with(&request, Instant::now(), |operation, _| {
            calls.set(calls.get() + 1);
            ready(success(operation))
        })
        .await;
        assert!(result.is_err());
        assert_eq!(calls.get(), 0);
    }
}

#[fcp_async_core::runtime::test]
async fn scheduler_does_not_rewrite_member_authority_effect_binding_or_fencing() {
    let request = batch(vec![member("a", &[])], 1);
    let expected = serde_json::to_value(&request.operations[0].request).unwrap();
    execute_with(&request, Instant::now(), |operation, _| {
        assert_eq!(serde_json::to_value(&operation.request).unwrap(), expected);
        ready(success(operation))
    })
    .await
    .unwrap();
    assert_eq!(
        serde_json::to_value(&request.operations[0].request).unwrap(),
        expected
    );
}

#[fcp_async_core::runtime::test]
async fn mismatched_member_result_cannot_release_a_dependent() {
    let request = batch(vec![member("a", &[]), member("b", &["a"])], 1);
    let response = execute_with(&request, Instant::now(), |operation, _| {
        assert_eq!(operation.id, "a");
        let mut result = success(operation);
        result.id = "wrong".to_owned();
        ready(result)
    })
    .await
    .unwrap();
    assert_eq!(
        response.results[0].error.as_ref().unwrap().code,
        "BATCH_OUTCOME_UNKNOWN"
    );
    assert_eq!(
        response.results[1].error.as_ref().unwrap().code,
        "DEP_FAILED"
    );
}

#[test]
fn http_execution_future_preserves_send_when_its_callback_is_send() {
    fn assert_send<T: Send>(_: T) {}
    let request = batch(vec![member("a", &[])], 1);
    assert_send(execute_with(&request, Instant::now(), |operation, _| {
        ready(success(operation))
    }));
}

#[fcp_async_core::runtime::test]
async fn dropping_http_scheduler_drops_owned_handler_futures_without_new_admissions() {
    struct Guard(Rc<Cell<usize>>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.set(self.0.get() - 1);
        }
    }
    let request = batch(
        vec![member("a", &[]), member("b", &[]), member("c", &[])],
        2,
    );
    let active = Rc::new(Cell::new(0));
    let calls = Cell::new(0);
    let mut run = Box::pin(execute_with(&request, Instant::now(), |operation, _| {
        calls.set(calls.get() + 1);
        active.set(active.get() + 1);
        let guard = Guard(Rc::clone(&active));
        async move {
            let _guard = guard;
            pending::<()>().await;
            success(operation)
        }
    }));
    assert!(poll!(run.as_mut()).is_pending());
    assert_eq!(active.get(), 2);
    drop(run);
    assert_eq!(active.get(), 0);
    assert_eq!(calls.get(), 2);
}

#[test]
fn routed_members_cannot_extend_the_batch_deadline() {
    let started_at = Instant::now();
    let parent = started_at + Duration::from_millis(100);
    assert_eq!(
        route_deadline(started_at, Some(30_000), Some(parent)),
        parent
    );
    assert_eq!(route_deadline(started_at, None, Some(parent)), parent);
}

#[test]
fn routed_members_keep_a_shorter_explicit_member_deadline() {
    let started_at = Instant::now();
    let parent = started_at + Duration::from_secs(30);
    assert_eq!(
        route_deadline(started_at, Some(20), Some(parent)),
        started_at + Duration::from_millis(20),
    );
}

#[test]
fn routing_waits_cannot_renew_an_expired_parent_budget() {
    let parent = Instant::now();
    let later = parent + Duration::from_millis(100);
    assert_eq!(route_deadline(later, Some(30_000), Some(parent)), parent);
}

#[test]
fn a_non_batch_invoke_retains_the_existing_native_lifetime_limit() {
    let started_at = Instant::now();
    for timeout in [None, Some(0), Some(100), Some(u64::MAX)] {
        assert_eq!(
            route_deadline(started_at, timeout, None),
            invocation_deadline(started_at, timeout)
        );
    }
}

#[test]
fn remote_refusals_preserve_status_and_do_not_invent_retry_hints() {
    for status in [
        StatusCode::FORBIDDEN,
        StatusCode::CONFLICT,
        StatusCode::MISDIRECTED_REQUEST,
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::BAD_GATEWAY,
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::GATEWAY_TIMEOUT,
    ] {
        let error = route_failure((status, "remote outcome remains unknown".to_owned()));
        assert_eq!(error.code, format!("INVOKE_HTTP_{}", status.as_u16()));
        assert_eq!(error.message, "remote outcome remains unknown");
        assert_eq!(error.retry_after_ms, None);
    }
}

#[test]
fn mesh_provenance_and_receipt_fields_survive_batch_result_adaptation() {
    let operation = member("a", &[]);
    let mut result = success(&operation);
    let output = json!({
        "type": "response",
        "id": "invoke-a",
        "status": "ok",
        "receipt_id": "retained-receipt",
        "response_metadata": {
            "route": {
                "truth_source": "mesh-backed",
                "entry_node": "entry",
                "served_by": "peer",
                "hop_count": 1,
                "decision": "advertised_peer_forward"
            }
        }
    });
    result.output = Some(output.clone());
    assert_eq!(member_outcome("a", result).unwrap(), output);
}
