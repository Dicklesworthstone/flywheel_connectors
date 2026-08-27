//! `fcp_host` batch invoke request/response conformance.
//!
//! The host batch endpoint is an agent-facing wire contract. These tests pin
//! the JSON shape for request defaults, per-operation dependency metadata,
//! aggregate status strings, and result/error optional-field behavior.

use fcp_host::{
    BatchExecutor, BatchInvokeRequest, BatchInvokeResponse, BatchOperation, BatchOperationError,
    BatchOperationPriority, BatchOptions, BatchScheduleHint, BatchSchedulerMode,
    BatchSchedulerOptions, BatchStatus, OperationResult, OperationResultStatus,
};
use serde_json::json;

fn operation(id: &str) -> BatchOperation {
    BatchOperation {
        id: id.to_string(),
        tool: "fcp.test.echo".to_string(),
        input: json!({ "message": id }),
        depends_on: Vec::new(),
        zone: None,
        scheduler: BatchScheduleHint::default(),
    }
}

fn scheduled_operation(id: &str, estimated_duration_ms: u64) -> BatchOperation {
    let mut operation = operation(id);
    operation.scheduler = BatchScheduleHint {
        priority: BatchOperationPriority::Normal,
        estimated_duration_ms: Some(estimated_duration_ms),
        fairness_key: None,
    };
    operation
}

#[test]
fn batch_options_missing_fields_use_documented_defaults() {
    let options: BatchOptions = serde_json::from_value(json!({})).expect("options parse");

    assert_eq!(options.max_parallelism, 8);
    assert!(!options.stop_on_first_error);
    assert_eq!(options.timeout_ms, 30_000);
    assert_eq!(options.scheduler.mode, BatchSchedulerMode::Fifo);
}

#[test]
fn batch_operation_defaults_dependencies_and_omits_absent_zone() {
    let op: BatchOperation = serde_json::from_value(json!({
        "id": "fetch",
        "tool": "fcp.test.fetch",
        "input": { "key": "alpha" }
    }))
    .expect("operation parse");

    assert_eq!(op.depends_on, [] as [std::string::String; 0]);
    assert!(op.zone.is_none());
    assert_eq!(op.scheduler, BatchScheduleHint::default());

    let serialized = serde_json::to_value(&op).expect("operation serialize");
    assert_eq!(serialized["depends_on"], json!([]));
    assert!(
        serialized.get("zone").is_none(),
        "zone MUST be omitted when no per-operation zone override is present"
    );
    assert!(
        serialized.get("scheduler").is_none(),
        "default scheduler hints MUST be omitted from operation JSON"
    );
}

#[test]
fn batch_request_round_trips_dependency_edges_and_options() {
    let request = BatchInvokeRequest {
        operations: vec![
            operation("fetch"),
            BatchOperation {
                depends_on: vec!["fetch".to_string()],
                ..operation("transform")
            },
        ],
        options: BatchOptions {
            max_parallelism: 2,
            stop_on_first_error: true,
            timeout_ms: 5_000,
            ..Default::default()
        },
    };

    let value = serde_json::to_value(&request).expect("request serialize");
    assert_eq!(value["operations"][1]["depends_on"], json!(["fetch"]));
    assert_eq!(value["options"]["max_parallelism"], 2);
    assert_eq!(value["options"]["stop_on_first_error"], true);
    assert_eq!(value["options"]["timeout_ms"], 5_000);

    let parsed: BatchInvokeRequest = serde_json::from_value(value).expect("request parse");
    assert_eq!(parsed.operations.len(), 2);
    assert_eq!(parsed.operations[1].depends_on, vec!["fetch"]);
    assert!(parsed.options.stop_on_first_error);
}

#[test]
fn batch_status_wire_strings_are_snake_case() {
    let cases = [
        (BatchStatus::Success, "success"),
        (BatchStatus::PartialSuccess, "partial_success"),
        (BatchStatus::AllFailed, "all_failed"),
        (BatchStatus::Aborted, "aborted"),
    ];

    for (status, expected) in cases {
        assert_eq!(serde_json::to_value(status).unwrap(), json!(expected));
        let parsed: BatchStatus = serde_json::from_value(json!(expected)).unwrap();
        assert_eq!(parsed, status);
    }
}

#[test]
fn operation_result_status_wire_strings_are_snake_case() {
    let cases = [
        (OperationResultStatus::Success, "success"),
        (OperationResultStatus::Error, "error"),
        (OperationResultStatus::Skipped, "skipped"),
    ];

    for (status, expected) in cases {
        assert_eq!(serde_json::to_value(status).unwrap(), json!(expected));
        let parsed: OperationResultStatus = serde_json::from_value(json!(expected)).unwrap();
        assert_eq!(parsed, status);
    }
}

#[test]
fn successful_operation_result_omits_error_field() {
    let result = OperationResult {
        id: "fetch".to_string(),
        status: OperationResultStatus::Success,
        output: Some(json!({ "ok": true })),
        error: None,
        duration_ms: 7,
    };

    let value = serde_json::to_value(&result).expect("result serialize");
    assert_eq!(value["status"], json!("success"));
    assert!(value.get("error").is_none());
    assert_eq!(value["output"], json!({ "ok": true }));
}

#[test]
fn failed_operation_result_omits_output_and_preserves_retry_hint() {
    let result = OperationResult {
        id: "fetch".to_string(),
        status: OperationResultStatus::Error,
        output: None,
        error: Some(BatchOperationError {
            code: "rate_limited".to_string(),
            message: "too many requests".to_string(),
            retry_after_ms: Some(1_500),
        }),
        duration_ms: 9,
    };

    let value = serde_json::to_value(&result).expect("result serialize");
    assert_eq!(value["status"], json!("error"));
    assert!(value.get("output").is_none());
    assert_eq!(value["error"]["code"], json!("rate_limited"));
    assert_eq!(value["error"]["retry_after_ms"], json!(1_500));

    let parsed: OperationResult = serde_json::from_value(value).expect("result parse");
    assert_eq!(parsed.status, OperationResultStatus::Error);
    assert_eq!(
        parsed.error.expect("error present").retry_after_ms,
        Some(1_500)
    );
}

#[test]
fn batch_response_preserves_submission_order_and_counts() {
    let response = BatchInvokeResponse {
        status: BatchStatus::PartialSuccess,
        completed: 1,
        failed: 1,
        skipped: 1,
        results: vec![
            OperationResult {
                id: "fetch".to_string(),
                status: OperationResultStatus::Success,
                output: Some(json!({ "ok": true })),
                error: None,
                duration_ms: 4,
            },
            OperationResult {
                id: "transform".to_string(),
                status: OperationResultStatus::Error,
                output: None,
                error: Some(BatchOperationError {
                    code: "invalid_input".to_string(),
                    message: "transform rejected input".to_string(),
                    retry_after_ms: None,
                }),
                duration_ms: 2,
            },
            OperationResult {
                id: "store".to_string(),
                status: OperationResultStatus::Skipped,
                output: None,
                error: None,
                duration_ms: 0,
            },
        ],
        total_duration_ms: 6,
        schedule_report: None,
    };

    let value = serde_json::to_value(&response).expect("response serialize");
    assert_eq!(value["status"], json!("partial_success"));
    assert_eq!(value["completed"], 1);
    assert_eq!(value["failed"], 1);
    assert_eq!(value["skipped"], 1);
    assert_eq!(value["results"][0]["id"], json!("fetch"));
    assert_eq!(value["results"][1]["id"], json!("transform"));
    assert_eq!(value["results"][2]["id"], json!("store"));

    let parsed: BatchInvokeResponse = serde_json::from_value(value).expect("response parse");
    assert_eq!(parsed.status, BatchStatus::PartialSuccess);
    assert_eq!(parsed.results[2].status, OperationResultStatus::Skipped);
}

#[test]
fn adaptive_batch_response_wire_carries_queueing_summary() {
    let request = BatchInvokeRequest {
        operations: vec![
            scheduled_operation("long", 1_000),
            scheduled_operation("short", 1),
        ],
        options: BatchOptions {
            scheduler: BatchSchedulerOptions {
                mode: BatchSchedulerMode::Adaptive,
                max_consecutive_per_fairness_key: 2,
            },
            ..Default::default()
        },
    };
    let response = BatchExecutor::new()
        .execute_sync(&request, |_operation| Ok(json!({ "ok": true })))
        .expect("adaptive execute");

    let value = serde_json::to_value(&response).expect("response serialize");
    assert_eq!(
        value["schedule_report"]["queueing_summary"]["sample_count"],
        json!(2)
    );
    assert_eq!(
        value["schedule_report"]["queueing_summary"]["promoted_operations"],
        json!(1)
    );
    assert_eq!(
        value["schedule_report"]["queueing_summary"]["delayed_operations"],
        json!(1)
    );
    assert!(
        value["schedule_report"]["queueing_summary"]["scheduled_wait"]
            .get("p99_ms")
            .is_some(),
        "queueing summary MUST expose p99 wait for replay consumers"
    );

    let parsed: BatchInvokeResponse = serde_json::from_value(value).expect("response parse");
    let summary = parsed
        .schedule_report
        .expect("schedule report present")
        .queueing_summary
        .expect("queueing summary present");
    assert_eq!(summary.sample_count, 2);
    assert_eq!(summary.promoted_operations, 1);
}
