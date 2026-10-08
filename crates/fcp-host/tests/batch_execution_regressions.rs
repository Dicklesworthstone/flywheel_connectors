//! Public batch-executor admission and lifecycle regression tests.

use fcp_host::{
    BatchExecutor, BatchInvokeRequest, BatchOperation, BatchOptions, BatchScheduleHint,
    BatchZoneValidator, ZoneRegistry,
};
use fcp_policy::ZoneId;

fn operation(id: &str, tool: &str, dependencies: &[&str]) -> BatchOperation {
    BatchOperation {
        id: id.to_owned(),
        tool: tool.to_owned(),
        input: serde_json::json!({}),
        depends_on: dependencies.iter().map(|id| (*id).to_owned()).collect(),
        zone: None,
        scheduler: BatchScheduleHint::default(),
    }
}

fn request(operations: Vec<BatchOperation>) -> BatchInvokeRequest {
    BatchInvokeRequest {
        operations,
        options: BatchOptions::default(),
    }
}

#[test]
fn explicit_zone_cannot_hide_a_privileged_binding() {
    for privileged in [ZoneId::owner(), ZoneId::private(), ZoneId::work()] {
        let mut registry = ZoneRegistry::new();
        registry.register("privileged.tool", privileged);
        let validator = BatchZoneValidator::new(ZoneId::public(), registry);
        let mut attempted = operation("attempt", "privileged.tool", &[]);
        attempted.zone = Some(ZoneId::public());

        let error = validator.validate(&[attempted]).unwrap_err();
        assert!(error.to_string().contains("zone boundary violations"));
        assert!(error.to_string().contains("attempt"));
    }
}

#[test]
fn explicit_zone_cannot_authorize_an_unregistered_tool() {
    let validator = BatchZoneValidator::new(ZoneId::owner(), ZoneRegistry::new());
    let mut attempted = operation("unknown", "unregistered.tool", &[]);
    attempted.zone = Some(ZoneId::public());

    let error = validator.validate(&[attempted]).unwrap_err();
    assert!(error.to_string().contains("missing zone mapping"));
    assert!(error.to_string().contains("unknown"));
}

#[test]
fn accessible_binding_does_not_authorize_a_privileged_override() {
    let mut registry = ZoneRegistry::new();
    registry.register("public.tool", ZoneId::public());
    let validator = BatchZoneValidator::new(ZoneId::work(), registry);
    let mut attempted = operation("attempt", "public.tool", &[]);
    attempted.zone = Some(ZoneId::owner());

    let error = validator.validate(&[attempted]).unwrap_err();
    assert!(error.to_string().contains("zone boundary violations"));
}

#[test]
fn accessible_binding_and_accessible_override_remain_valid() {
    let mut registry = ZoneRegistry::new();
    registry.register("public.tool", ZoneId::public());
    let validator = BatchZoneValidator::new(ZoneId::work(), registry);
    let mut attempted = operation("allowed", "public.tool", &[]);
    attempted.zone = Some(ZoneId::work());

    validator.validate(&[attempted]).unwrap();
}

#[test]
fn same_project_and_owner_access_remain_valid() {
    let project: ZoneId = "z:project:alpha".parse().unwrap();
    let mut registry = ZoneRegistry::new();
    registry.register("project.tool", project.clone());
    let validator = BatchZoneValidator::new(project.clone(), registry.clone());
    let mut attempted = operation("allowed", "project.tool", &[]);
    attempted.zone = Some(project);

    validator.validate(std::slice::from_ref(&attempted)).unwrap();
    BatchZoneValidator::new(ZoneId::owner(), registry)
        .validate(&[attempted])
        .unwrap();
}

#[test]
fn cross_project_binding_cannot_be_hidden_by_a_same_project_override() {
    let alpha: ZoneId = "z:project:alpha".parse().unwrap();
    let beta: ZoneId = "z:project:beta".parse().unwrap();
    let mut registry = ZoneRegistry::new();
    registry.register("other-project.tool", beta);
    let validator = BatchZoneValidator::new(alpha.clone(), registry);
    let mut attempted = operation("attempt", "other-project.tool", &[]);
    attempted.zone = Some(alpha);

    assert!(validator.validate(&[attempted]).is_err());
}

#[test]
fn invalid_batch_is_rejected_before_any_handler_is_called() {
    let mut registry = ZoneRegistry::new();
    registry.register("public.tool", ZoneId::public());
    registry.register("private.tool", ZoneId::private());
    let executor = BatchExecutor::with_zone_validator(BatchZoneValidator::new(
        ZoneId::public(),
        registry,
    ));
    let mut denied = operation("denied", "private.tool", &[]);
    denied.zone = Some(ZoneId::public());
    let batch = request(vec![operation("allowed", "public.tool", &[]), denied]);
    let calls = std::cell::Cell::new(0);

    let result = executor.execute_sync(&batch, |_| {
        calls.set(calls.get() + 1);
        Ok(serde_json::json!({}))
    });

    assert!(result.is_err());
    assert_eq!(calls.get(), 0);
}

#[test]
fn zero_timeout_aborts_instead_of_reporting_an_empty_success() {
    let executor = BatchExecutor::new();
    let mut batch = request(vec![
        operation("a", "tool", &[]),
        operation("b", "tool", &[]),
        operation("c", "tool", &["a"]),
    ]);
    batch.options.timeout_ms = 0;
    let calls = std::cell::Cell::new(0);

    let response = executor
        .execute_sync(&batch, |_| {
            calls.set(calls.get() + 1);
            Ok(serde_json::json!({}))
        })
        .unwrap();

    assert_eq!(calls.get(), 0);
    assert_eq!(response.status, fcp_host::BatchStatus::Aborted);
    assert_eq!(response.completed, 0);
    assert_eq!(response.failed, 0);
    assert_eq!(response.skipped, 3);
    for result in response.results {
        assert_eq!(result.status, fcp_host::OperationResultStatus::Skipped);
        assert_eq!(result.error.unwrap().code, "BATCH_TIMEOUT");
    }
}

#[test]
fn deadline_prevents_later_calls_in_the_same_tier_and_later_tiers() {
    const TIMEOUT_MS: u64 = 250;
    let executor = BatchExecutor::new();
    let mut batch = request(vec![
        operation("a", "tool", &[]),
        operation("b", "tool", &[]),
        operation("c", "tool", &["b"]),
    ]);
    batch.options.timeout_ms = TIMEOUT_MS;
    let calls = std::cell::RefCell::new(Vec::new());

    let response = executor
        .execute_sync(&batch, |op| {
            calls.borrow_mut().push(op.id.clone());
            if op.id == "a" {
                std::thread::sleep(std::time::Duration::from_millis(TIMEOUT_MS + 1));
            }
            Ok(serde_json::json!({"id": op.id}))
        })
        .unwrap();

    assert_eq!(*calls.borrow(), vec!["a"]);
    assert_eq!(response.status, fcp_host::BatchStatus::Aborted);
    assert_eq!(response.completed, 1);
    assert_eq!(response.failed, 0);
    assert_eq!(response.skipped, 2);
    assert_eq!(response.results[0].output.as_ref().unwrap()["id"], "a");
    for result in &response.results[1..] {
        assert_eq!(result.status, fcp_host::OperationResultStatus::Skipped);
        assert_eq!(result.error.as_ref().unwrap().code, "BATCH_TIMEOUT");
    }
}

#[test]
fn a_late_final_handler_keeps_its_known_result_but_aborts_the_batch() {
    const TIMEOUT_MS: u64 = 250;
    let executor = BatchExecutor::new();
    let mut batch = request(vec![operation("a", "tool", &[])]);
    batch.options.timeout_ms = TIMEOUT_MS;

    let response = executor
        .execute_sync(&batch, |_| {
            std::thread::sleep(std::time::Duration::from_millis(TIMEOUT_MS + 1));
            Ok(serde_json::json!({"side_effect_completed": true}))
        })
        .unwrap();

    assert_eq!(response.status, fcp_host::BatchStatus::Aborted);
    assert_eq!(response.completed, 1);
    assert_eq!(response.failed, 0);
    assert_eq!(response.skipped, 0);
    assert_eq!(response.results[0].status, fcp_host::OperationResultStatus::Success);
    assert_eq!(
        response.results[0].output.as_ref().unwrap()["side_effect_completed"],
        true
    );
}

#[test]
fn maximum_timeout_does_not_overflow_the_monotonic_clock() {
    let executor = BatchExecutor::new();
    let mut batch = request(vec![operation("a", "tool", &[])]);
    batch.options.timeout_ms = u64::MAX;

    let response = executor
        .execute_sync(&batch, |_| Ok(serde_json::json!({"ok": true})))
        .unwrap();

    assert_eq!(response.status, fcp_host::BatchStatus::Success);
    assert_eq!(response.completed, 1);
}

#[test]
fn first_error_still_stops_admission_without_relabeling_it_as_a_timeout() {
    let executor = BatchExecutor::new();
    let mut batch = request(vec![operation("a", "tool", &[]), operation("b", "tool", &[])]);
    batch.options.stop_on_first_error = true;
    batch.options.timeout_ms = u64::MAX;
    let calls = std::cell::Cell::new(0);

    let response = executor
        .execute_sync(&batch, |_| {
            calls.set(calls.get() + 1);
            Err(fcp_host::BatchOperationError {
                code: "PROVIDER_ERROR".to_owned(),
                message: "provider refused the operation".to_owned(),
                retry_after_ms: None,
            })
        })
        .unwrap();

    assert_eq!(calls.get(), 1);
    assert_eq!(response.status, fcp_host::BatchStatus::Aborted);
    assert_eq!(response.failed, 1);
    assert_eq!(response.skipped, 1);
    assert_eq!(
        response.results[0].error.as_ref().unwrap().code,
        "PROVIDER_ERROR"
    );
    assert!(response.results[1].error.is_none());
}
