//! Exercises the same input-binding adapter used by the live HTTP handler.
//! The callback stands in for ordinary invoke dispatch, not its authorization.

use std::cell::{Cell, RefCell};
use std::future::{pending, ready};
use std::rc::Rc;

use fcp_core::{Provenance, ProvenanceStep, TaintLevel};
use futures_util::poll;

use super::*;

fn member(id: &str, dependencies: &[&str], input: Value) -> HttpBatchOperation {
    HttpBatchOperation {
        id: id.to_owned(),
        request: InvokeRequest {
            r#type: "invoke".to_owned(),
            id: RequestId(format!("invoke-{id}")),
            connector_id: ConnectorId::from_static("fcp.test:utility:1.0.0"),
            operation: OperationId::from_static("test.echo"),
            zone_id: "z:work".parse().unwrap(),
            input,
            capability_token: fcp_core::CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: Some(format!("effect-{id}")),
            lease_seq: Some(7),
            deadline_ms: Some(1_000),
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        },
        depends_on: dependencies.iter().map(|id| (*id).to_owned()).collect(),
        scheduler: BatchScheduleHint::default(),
    }
}

fn batch(operations: Vec<HttpBatchOperation>) -> HttpBatchInvokeRequest {
    HttpBatchInvokeRequest {
        operations,
        options: BatchOptions {
            max_parallelism: 4,
            stop_on_first_error: false,
            ..BatchOptions::default()
        },
    }
}

fn reference(operation: &str, pointer: &str) -> Value {
    json!({"$fcp_batch_ref": {"operation": operation, "pointer": pointer}})
}

fn success(operation: &HttpBatchOperation, output: Value) -> OperationResult {
    OperationResult {
        id: operation.id.clone(),
        status: OperationResultStatus::Success,
        output: Some(output),
        error: None,
        duration_ms: 0,
    }
}

fn echo(operation: &HttpBatchOperation) -> OperationResult {
    success(operation, json!({"result": operation.request.input}))
}

fn observed<'a>(response: &'a BatchInvokeResponse, id: &str) -> &'a OperationResult {
    response.results.iter().find(|result| result.id == id).unwrap()
}

#[fcp_async_core::runtime::test]
async fn dataflow_binds_typed_values_through_fan_out_and_fan_in() {
    let request = batch(vec![
        member("a", &[], json!({"id": 42, "tags": [true, null]})),
        member("b", &["a"], reference("a", "/result/id")),
        member("c", &["a"], reference("a", "/result/tags")),
        member("d", &["b", "c"], json!({
            "id": reference("b", "/result"),
            "tags": reference("c", "/result"),
        })),
    ]);
    let calls = RefCell::new(Vec::new());
    let result = execute_dataflow_with(&request, Instant::now(), |operation, _| {
        calls.borrow_mut().push(operation.id.clone());
        ready(echo(&operation))
    }).await.unwrap();
    assert_eq!(result.completed, 4);
    assert_eq!(calls.borrow().len(), 4);
    assert_eq!(observed(&result, "d").output.as_ref().unwrap()["result"],
        json!({"id": 42, "tags": [true, null]}));
    // The original request remains a template rather than being mutated in place.
    assert_eq!(request.operations[1].request.input, reference("a", "/result/id"));
}

#[fcp_async_core::runtime::test]
async fn dataflow_supports_pointer_escaping_empty_keys_and_null_values() {
    let request = batch(vec![
        member("a", &[], json!({"a/b": {"~": [null, 5]}, "": "empty-key"})),
        member("b", &["a"], json!({
            "null": reference("a", "/result/a~1b/~0/0"),
            "number": reference("a", "/result/a~1b/~0/1"),
            "empty": reference("a", "/result/"),
        })),
    ]);
    let result = execute_dataflow_with(&request, Instant::now(), |operation, _| {
        ready(echo(&operation))
    }).await.unwrap();
    assert_eq!(result.completed, 2);
    assert_eq!(observed(&result, "b").output.as_ref().unwrap()["result"],
        json!({"null": null, "number": 5, "empty": "empty-key"}));
}

#[fcp_async_core::runtime::test]
async fn dataflow_empty_pointer_can_select_an_entire_null_output() {
    let request = batch(vec![
        member("a", &[], Value::Null),
        member("b", &["a"], reference("a", "")),
    ]);
    let result = execute_dataflow_with(&request, Instant::now(), |operation, _| {
        if operation.id == "b" {
            assert_eq!(operation.request.input, Value::Null);
        }
        ready(success(&operation, Value::Null))
    }).await.unwrap();
    assert_eq!(result.completed, 2);
}

#[fcp_async_core::runtime::test]
async fn provider_marker_objects_are_inserted_literally_not_executed() {
    let marker = reference("unrequested-provider-chosen-operation", "/secret");
    let request = batch(vec![
        member("a", &[], Value::Null),
        member("b", &["a"], reference("a", "/result")),
    ]);
    let result = execute_dataflow_with(&request, Instant::now(), |operation, _| {
        if operation.id == "a" {
            ready(success(&operation, json!({"result": marker})))
        } else {
            assert_eq!(operation.request.input, marker);
            ready(echo(&operation))
        }
    }).await.unwrap();
    assert_eq!(result.completed, 2);
}

#[fcp_async_core::runtime::test]
async fn explicit_literal_escape_preserves_marker_shaped_input() {
    let literal = json!({"$fcp_batch_ref": false, "$fcp_batch_literal": "ordinary data"});
    let request = batch(vec![member("a", &[], json!({"$fcp_batch_literal": literal}))]);
    let result = execute_dataflow_with(&request, Instant::now(), |operation, _| {
        assert_eq!(operation.request.input, literal);
        assert!(operation.request.provenance.is_none());
        ready(echo(&operation))
    }).await.unwrap();
    assert_eq!(result.completed, 1);
}

#[fcp_async_core::runtime::test]
async fn binding_preserves_authority_and_ids_but_taints_new_provider_data() {
    let mut source = member("a", &[], json!({"id": 5}));
    source.request.provenance = Some(Provenance::tainted(source.request.zone_id.clone())
        .with_step(ProvenanceStep {
            timestamp_ms: 1,
            zone: source.request.zone_id.clone(),
            actor: "source-reader".into(),
            action: "external.read".into(),
            resource: "source-object".into(),
        }));
    let mut target = member("b", &["a"], reference("a", "/result/id"));
    target.request.provenance = Some(Provenance::new(target.request.zone_id.clone())
        .elevated_with("template-only-elevation"));
    let mut expected = serde_json::to_value(&target.request).unwrap();
    expected.as_object_mut().unwrap().remove("input");
    expected.as_object_mut().unwrap().remove("provenance");
    let request = batch(vec![source, target]);
    let result = execute_dataflow_with(&request, Instant::now(), |operation, _| {
        if operation.id == "b" {
            assert_eq!(operation.request.input, json!(5));
            let provenance = operation.request.provenance.as_ref().unwrap();
            assert_eq!(provenance.taint, TaintLevel::HighlyTainted);
            assert!(!provenance.elevated);
            assert!(provenance.elevation_token.is_none());
            assert!(provenance.chain.iter().any(|step| step.resource == "source-object"));
            assert!(provenance.chain.iter().any(|step| step.resource == "batch-result:invoke-a"));
            let mut actual = serde_json::to_value(&operation.request).unwrap();
            actual.as_object_mut().unwrap().remove("input");
            actual.as_object_mut().unwrap().remove("provenance");
            assert_eq!(actual, expected);
        }
        ready(echo(&operation))
    }).await.unwrap();
    assert_eq!(result.completed, 2);
}

#[fcp_async_core::runtime::test]
async fn malformed_and_undeclared_references_fail_before_any_dispatch() {
    let invalid = [
        reference("absent", "/result"),
        reference("b", "/result"),
        reference("a", "not-a-pointer"),
        reference("a", "/bad~2escape"),
        reference("a", "/trailing~"),
        json!({"$fcp_batch_ref": true}),
        json!({"$fcp_batch_ref": {"operation": "a", "pointer": "", "extra": 1}}),
        json!({"$fcp_batch_ref": {"operation": "a", "pointer": 7}}),
        json!({"$fcp_batch_ref": {"operation": "a", "pointer": ""}, "extra": 1}),
        json!({"$fcp_batch_literal": 1, "extra": 2}),
    ];
    for input in invalid {
        let request = batch(vec![member("a", &[], Value::Null), member("b", &["a"], input)]);
        let calls = Cell::new(0);
        let result = execute_dataflow_with(&request, Instant::now(), |operation, _| {
            calls.set(calls.get() + 1);
            ready(echo(&operation))
        }).await;
        assert!(result.is_err());
        assert_eq!(calls.get(), 0);
    }
    let request = batch(vec![
        member("a", &[], Value::Null),
        member("b", &[], reference("a", "/result")),
    ]);
    assert!(execute_dataflow_with(&request, Instant::now(), |_, _|
        -> std::future::Ready<OperationResult> { panic!("undeclared dependency dispatched") }
    ).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn cross_zone_data_and_provenance_fail_closed_before_dispatch() {
    for change in 0..3 {
        let source = member("a", &[], Value::Null);
        let mut target = member("b", &["a"], reference("a", "/result"));
        if change == 0 {
            target.request.zone_id = "z:private".parse().unwrap();
        } else {
            let mut provenance = Provenance::new(target.request.zone_id.clone());
            if change == 1 {
                provenance.origin_zone = "z:private".parse().unwrap();
            } else {
                provenance.chain.push(ProvenanceStep {
                    timestamp_ms: 1,
                    zone: "z:private".parse().unwrap(),
                    actor: "other-zone".into(),
                    action: "read".into(),
                    resource: "private-resource".into(),
                });
            }
            target.request.provenance = Some(provenance);
        }
        let request = batch(vec![source, target]);
        assert!(execute_dataflow_with(&request, Instant::now(), |_, _|
            -> std::future::Ready<OperationResult> { panic!("cross-zone binding dispatched") }
        ).await.is_err());
    }
}

#[fcp_async_core::runtime::test]
async fn missing_pointer_fails_one_member_and_skips_its_dependents() {
    let request = batch(vec![
        member("a", &[], json!({"present": 1})),
        member("b", &["a"], reference("a", "/result/absent")),
        member("c", &["b"], reference("b", "/result")),
        member("d", &[], json!("independent")),
    ]);
    let calls = RefCell::new(Vec::new());
    let result = execute_dataflow_with(&request, Instant::now(), |operation, _| {
        calls.borrow_mut().push(operation.id.clone());
        ready(echo(&operation))
    }).await.unwrap();
    assert_eq!(calls.borrow().len(), 2);
    assert!(!calls.borrow().contains(&"b".to_owned()));
    assert_eq!(observed(&result, "b").error.as_ref().unwrap().code, "BATCH_INPUT_REFERENCE_MISSING");
    assert_eq!(observed(&result, "c").status, OperationResultStatus::Skipped);
    assert_eq!(observed(&result, "d").status, OperationResultStatus::Success);
}

#[fcp_async_core::runtime::test]
async fn failed_or_withheld_sources_never_dispatch_a_consumer() {
    for withheld in [false, true] {
        let request = batch(vec![
            member("a", &[], Value::Null),
            member("b", &["a"], reference("a", "/result")),
        ]);
        let calls = Cell::new(0);
        let result = execute_dataflow_with(&request, Instant::now(), |operation, _| {
            calls.set(calls.get() + 1);
            assert_eq!(operation.id, "a");
            ready(if withheld {
                success(&operation, json!({"result": "x".repeat(1024 * 1024)}))
            } else {
                OperationResult {
                    id: operation.id,
                    status: OperationResultStatus::Error,
                    output: None,
                    error: Some(adapter_error("fixture provider failure")),
                    duration_ms: 0,
                }
            })
        }).await.unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(observed(&result, "b").status, OperationResultStatus::Skipped);
        assert!(observed(&result, "a").output.is_none());
        if withheld {
            assert_eq!(observed(&result, "a").error.as_ref().unwrap().code, "BATCH_RESULT_LIMIT");
        }
    }
}

#[fcp_async_core::runtime::test]
async fn expansion_is_bounded_before_constructing_the_consumer_future() {
    let request = batch(vec![
        member("a", &[], Value::Null),
        member("b", &["a"], json!([
            reference("a", "/result"), reference("a", "/result"),
        ])),
    ]);
    let calls = Cell::new(0);
    let result = execute_dataflow_with(&request, Instant::now(), |operation, _| {
        calls.set(calls.get() + 1);
        assert_eq!(operation.id, "a");
        ready(success(&operation, json!({"result": "x".repeat(600_000)})))
    }).await.unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(observed(&result, "a").status, OperationResultStatus::Success);
    assert_eq!(observed(&result, "b").error.as_ref().unwrap().code, "BATCH_INPUT_LIMIT");
}

#[fcp_async_core::runtime::test]
async fn template_depth_reference_count_and_literal_shape_are_bounded() {
    let mut deep = Value::Null;
    for _ in 0..66 {
        deep = json!([deep]);
    }
    for input in [
        deep.clone(),
        json!({"$fcp_batch_literal": deep}),
        Value::Array(vec![reference("a", "/result"); 129]),
        Value::Array(vec![Value::Null; 65_536]),
    ] {
        let request = batch(vec![
            member("a", &[], Value::Null),
            member("b", &["a"], input),
        ]);
        assert!(execute_dataflow_with(&request, Instant::now(), |_, _|
            -> std::future::Ready<OperationResult> { panic!("oversized template dispatched") }
        ).await.is_err());
    }
}

#[fcp_async_core::runtime::test]
async fn excessive_source_shape_stops_binding_without_erasing_its_known_result() {
    let request = batch(vec![
        member("a", &[], Value::Null),
        member("b", &["a"], reference("a", "/result")),
    ]);
    let calls = Cell::new(0);
    let result = execute_dataflow_with(&request, Instant::now(), |operation, _| {
        calls.set(calls.get() + 1);
        assert_eq!(operation.id, "a");
        // This fits the existing 1 MiB result budget but exceeds the extra
        // binding cache's visited-value bound, before that cache clones it.
        ready(success(&operation, json!({"result": vec![Value::Null; 65_536]})))
    }).await.unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(result.status, BatchStatus::Aborted);
    assert_eq!(observed(&result, "a").status, OperationResultStatus::Success);
    assert_eq!(observed(&result, "b").status, OperationResultStatus::Skipped);
}

#[fcp_async_core::runtime::test]
async fn ordinary_requests_remain_unchanged_and_share_the_original_deadline() {
    let request = batch(vec![member("a", &[], json!({"ordinary": [1, "two", null]}))]);
    let expected = serde_json::to_value(&request.operations[0].request).unwrap();
    let started = Instant::now();
    let deadline = started.checked_add(Duration::from_millis(request.options.timeout_ms));
    let result = execute_dataflow_with(&request, started, |operation, parent| {
        assert_eq!(parent, deadline);
        assert_eq!(serde_json::to_value(&operation.request).unwrap(), expected);
        ready(echo(&operation))
    }).await.unwrap();
    assert_eq!(result.completed, 1);
}

#[fcp_async_core::runtime::test]
async fn expired_dataflow_does_not_dispatch_or_invent_success() {
    let mut request = batch(vec![
        member("a", &[], Value::Null),
        member("b", &["a"], reference("a", "/result")),
    ]);
    request.options.timeout_ms = 0;
    let result = execute_dataflow_with(&request, Instant::now(), |_, _|
        -> std::future::Ready<OperationResult> { panic!("expired batch dispatched") }
    ).await.unwrap();
    assert_eq!(result.status, BatchStatus::Aborted);
    assert_eq!(result.skipped, 2);
}

#[fcp_async_core::runtime::test]
async fn abandoning_dataflow_drops_owned_futures_without_starting_dependents() {
    struct Guard(Rc<Cell<usize>>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let request = batch(vec![
        member("a", &[], Value::Null),
        member("b", &["a"], reference("a", "/result")),
    ]);
    let dropped = Rc::new(Cell::new(0));
    let calls = Cell::new(0);
    let mut run = Box::pin(execute_dataflow_with(&request, Instant::now(), |operation, _| {
        calls.set(calls.get() + 1);
        let guard = Guard(Rc::clone(&dropped));
        async move {
            let _guard = guard;
            pending::<()>().await;
            echo(&operation)
        }
    }));
    assert!(poll!(run.as_mut()).is_pending());
    assert_eq!(calls.get(), 1);
    drop(run);
    assert_eq!(dropped.get(), 1);
    assert_eq!(calls.get(), 1);
}

#[test]
fn production_dataflow_future_retains_send_for_send_handlers() {
    fn assert_send<T: Send>(_: T) {}
    let request = batch(vec![
        member("a", &[], Value::Null),
        member("b", &["a"], reference("a", "/result")),
    ]);
    assert_send(execute_dataflow_with(&request, Instant::now(), |operation, _| {
        ready(echo(&operation))
    }));
}

#[fcp_async_core::runtime::test]
async fn repeated_source_values_cannot_exceed_the_expanded_node_budget() {
    let request = batch(vec![
        member("a", &[], Value::Null),
        member("b", &["a"], json!([
            reference("a", "/result"), reference("a", "/result"),
        ])),
    ]);
    let calls = Cell::new(0);
    let result = execute_dataflow_with(&request, Instant::now(), |operation, _| {
        calls.set(calls.get() + 1);
        assert_eq!(operation.id, "a");
        // The source fits all source limits, and its repetition still encodes
        // below 1 MiB. Only the combined expanded node bound rejects it.
        ready(success(&operation, json!({"result": vec![Value::Null; 40_000]})))
    }).await.unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(observed(&result, "a").status, OperationResultStatus::Success);
    assert_eq!(observed(&result, "b").error.as_ref().unwrap().code, "BATCH_INPUT_LIMIT");
}

#[fcp_async_core::runtime::test]
async fn nested_source_values_cannot_exceed_the_expanded_depth_budget() {
    let mut template = reference("a", "/result");
    let mut source = Value::Null;
    for _ in 0..40 {
        template = json!([template]);
        source = json!([source]);
    }
    let request = batch(vec![
        member("a", &[], Value::Null),
        member("b", &["a"], template),
    ]);
    let calls = Cell::new(0);
    let result = execute_dataflow_with(&request, Instant::now(), |operation, _| {
        calls.set(calls.get() + 1);
        assert_eq!(operation.id, "a");
        ready(success(&operation, json!({"result": source})))
    }).await.unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(observed(&result, "a").status, OperationResultStatus::Success);
    assert_eq!(observed(&result, "b").error.as_ref().unwrap().code, "BATCH_INPUT_LIMIT");
}

#[fcp_async_core::runtime::test]
async fn expanded_depth_and_node_boundaries_are_inclusive() {
    for at_depth_boundary in [false, true] {
        let mut template = reference("a", "/result");
        let mut source = if at_depth_boundary { Value::Null } else {
            Value::Array(vec![Value::Null; 65_534])
        };
        if at_depth_boundary {
            for _ in 0..32 {
                template = json!([template]);
                source = json!([source]);
            }
        } else {
            template = json!([template]);
        }
        let request = batch(vec![
            member("a", &[], Value::Null),
            member("b", &["a"], template),
        ]);
        let result = execute_dataflow_with(&request, Instant::now(), |operation, _| {
            ready(if operation.id == "a" {
                success(&operation, json!({"result": source}))
            } else {
                success(&operation, Value::Null)
            })
        }).await.unwrap();
        assert_eq!(result.completed, 2);
    }
}
