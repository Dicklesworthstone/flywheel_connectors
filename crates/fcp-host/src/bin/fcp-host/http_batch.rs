//! Live HTTP batches use the same completion-driven executor as library callers.
//!
//! Only the dependency graph is planned here. Capabilities, approval, revocation,
//! fencing and durable invocation ownership remain in the ordinary invoke path.
//! Dropping the HTTP waiter must not be interpreted as undoing an admitted effect.

use std::future::Future;

use fcp_async_core::ExecutionContext;

use super::*;

pub(super) async fn execute(
    state: Arc<AppState>,
    headers: HeaderMap,
    request: HttpBatchInvokeRequest,
) -> Result<BatchInvokeResponse, (StatusCode, String)> {
    let started_at = Instant::now();
    let asserted_principal = extract_principal_header(&headers).map(Arc::<str>::from);
    tracing::debug!(
        event = "batch_invoke_request",
        operation_count = request.operations.len(),
        max_parallelism = request.options.max_parallelism,
        stop_on_first_error = request.options.stop_on_first_error,
        timeout_ms = request.options.timeout_ms,
        "processing batch invoke request"
    );

    let response = execute_with(&request, started_at, |operation, deadline| {
        execute_batch_operation(
            Arc::clone(&state),
            operation.clone(),
            asserted_principal.clone(),
            deadline,
        )
    })
    .await
    .map_err(map_host_error)?;

    tracing::info!(
        event = "batch_invoke_response",
        operation_count = request.operations.len(),
        completed = response.completed,
        failed = response.failed,
        skipped = response.skipped,
        status = ?response.status,
        duration_ms = elapsed_millis(started_at),
        "batch invoke request complete"
    );
    Ok(response)
}

/// This adapter is also exercised with controlled futures in the bin tests.
/// It does not spawn tasks or invent authorization on behalf of its handler.
async fn execute_with<'a, F, Fut>(
    request: &'a HttpBatchInvokeRequest,
    started_at: Instant,
    mut handler: F,
) -> HostResult<BatchInvokeResponse>
where
    F: FnMut(&'a HttpBatchOperation, Option<Instant>) -> Fut,
    Fut: Future<Output = OperationResult>,
{
    let timeout = Duration::from_millis(request.options.timeout_ms);
    // Both planning and time waiting for earlier members consume the original
    // budget. Overflow is allowed only for the absolute Instant representation;
    // the relative elapsed-time envelope is still enforced by the context.
    let context = ExecutionContext::request_scoped(timeout.saturating_sub(started_at.elapsed()));
    let deadline = started_at.checked_add(timeout);
    let planning = request.planning_request();
    let executor = BatchExecutor::new();
    // Validate the graph/limits before allocating the lookup or inspecting
    // member metadata. Nothing has been dispatched at this boundary.
    executor.plan_with_schedule_report(&planning)?;
    validate_members(request)?;
    let members: HashMap<&str, &'a HttpBatchOperation> = request
        .operations
        .iter()
        .map(|operation| (operation.id.as_str(), operation))
        .collect();

    // Live HTTP batches must not revert to unbounded provider-result retention.
    // A withheld result is an unknown external effect, not a retry permit.
    let mut response = executor
        .execute_async_bounded(&planning, Some(&context), fcp_host::BatchResultLimits::default(), |planned| {
            let operation = members[planned.id.as_str()];
            let future = handler(operation, deadline);
            async move { member_outcome(&operation.id, future.await) }
        })
        .await?;
    response.response.total_duration_ms = elapsed_millis(started_at);
    Ok(response.response)
}

fn validate_members(request: &HttpBatchInvokeRequest) -> HostResult<()> {
    let mut invocation_ids = HashSet::with_capacity(request.operations.len());
    for operation in &request.operations {
        // A DAG ID and an invocation ID serve different roles. Distinct DAG
        // nodes must not alias the same durable invocation/replay identity.
        if !invocation_ids.insert(operation.request.id.0.as_str()) {
            return Err(HostError::InvalidFilter(
                "batch members must have distinct invocation request IDs".to_owned(),
            ));
        }
        if operation.request.r#type != "invoke" {
            return Err(HostError::InvalidFilter(
                "batch members must be invoke requests".to_owned(),
            ));
        }
        operation.request.validate_idempotency_key().map_err(|_| {
            HostError::InvalidFilter("batch member has an invalid idempotency key".to_owned())
        })?;
    }
    Ok(())
}

/// A transport/result-adapter defect must not release a dependent as successful.
/// Error details from a valid invocation remain unchanged, including retry hints.
fn member_outcome(
    expected_id: &str,
    result: OperationResult,
) -> Result<Value, BatchOperationError> {
    if result.id != expected_id {
        return Err(adapter_error("batch member returned a different result ID"));
    }
    match result.status {
        OperationResultStatus::Success if result.error.is_none() => result
            .output
            .ok_or_else(|| adapter_error("successful batch member omitted its output")),
        OperationResultStatus::Error => Err(result
            .error
            .unwrap_or_else(|| adapter_error("failed batch member omitted its error"))),
        _ => Err(adapter_error("batch member returned an inconsistent terminal result")),
    }
}

fn adapter_error(message: &str) -> BatchOperationError {
    BatchOperationError {
        code: "BATCH_OUTCOME_UNKNOWN".to_owned(),
        message: format!("{message}; do not retry without reconciliation"),
        retry_after_ms: None,
    }
}

/// Share the entry node's absolute budget across discovery, durable admission,
/// local dispatch and signed remote delivery. A per-member limit may narrow it.
pub(super) fn route_deadline(
    started_at: Instant,
    member_timeout_ms: Option<u64>,
    parent_deadline: Option<Instant>,
) -> Instant {
    let own_deadline = invocation_deadline(started_at, member_timeout_ms);
    parent_deadline.map_or(own_deadline, |parent| parent.min(own_deadline))
}

/// Preserve the actual HTTP refusal, without claiming an external effect did
/// not happen or translating a transport status into permission to retry.
pub(super) fn route_failure((status, message): (StatusCode, String)) -> BatchOperationError {
    BatchOperationError {
        code: format!("INVOKE_HTTP_{}", status.as_u16()),
        message,
        retry_after_ms: None,
    }
}

#[cfg(test)]
#[path = "http_batch_tests.rs"]
mod tests;
