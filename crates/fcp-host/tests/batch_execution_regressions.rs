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
