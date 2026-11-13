//! Live HTTP batches use the same completion-driven executor as library callers.
//!
//! Dependency ordering and explicit same-zone input bindings are planned here.
//! Capabilities, approval, revocation, fencing and durable invocation ownership
//! remain in the ordinary invoke path.
//! Dropping the HTTP waiter must not be interpreted as undoing an admitted effect.

use std::future::Future;

use fcp_async_core::ExecutionContext;

use super::*;

#[path = "http_batch_dataflow.rs"]
mod dataflow;

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

    let response = execute_dataflow_with(&request, started_at, |operation, deadline| {
        execute_batch_operation(
            Arc::clone(&state),
            operation,
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
#[cfg(test)]
async fn execute_with<'a, F, Fut>(
    request: &'a HttpBatchInvokeRequest,
    started_at: Instant,
    handler: F,
) -> HostResult<BatchInvokeResponse>
where
    F: FnMut(&'a HttpBatchOperation, Option<Instant>) -> Fut,
    Fut: Future<Output = OperationResult>,
{
    execute_with_observer(request, started_at, handler, |_| Ok(())).await
}

/// The production dataflow adapter hands fully resolved requests to the normal
/// invoke path. No authority or idempotency fields are synthesized here.
#[allow(clippy::future_not_send)]
async fn execute_dataflow_with<F, Fut>(
    request: &HttpBatchInvokeRequest,
    started_at: Instant,
    mut handler: F,
) -> HostResult<BatchInvokeResponse>
where
    F: FnMut(HttpBatchOperation, Option<Instant>) -> Fut,
    Fut: Future<Output = OperationResult>,
{
    BatchExecutor::new().plan_with_schedule_report(&request.planning_request())?;
    validate_members(request)?;
    let flow = dataflow::Dataflow::compile(request)?;
    execute_with_observer(
        request,
        started_at,
        |operation, deadline| {
            let future = flow.resolve(operation).and_then(|resolved| {
                // Resolution is synchronous bounded work. A ready callback can
                // spend the final budget without yielding to a timer; check the
                // original deadline again before constructing an invoke future.
                if started_at.elapsed() >= Duration::from_millis(request.options.timeout_ms) {
                    return Err(BatchOperationError {
                        code: "BATCH_INPUT_TIMEOUT".into(),
                        message: "batch input resolution exhausted the deadline before invocation"
                            .into(),
                        retry_after_ms: None,
                    });
                }
                Ok(handler(resolved, deadline))
            });
            async move {
                match future {
                    Ok(future) => future.await,
                    Err(error) => OperationResult {
                        id: operation.id.clone(),
                        status: OperationResultStatus::Error,
                        output: None,
                        error: Some(error),
                        duration_ms: 0,
                    },
                }
            }
        },
        |result| flow.observe(result),
    )
    .await
}

/// Result retention, dataflow observation and delivery all precede dependency
/// release. A slow consumer uses the same deadline as planning and invocation.
#[allow(clippy::future_not_send)]
async fn execute_dataflow_wait_with<F, Fut, S, DeliveryFut>(
    request: &HttpBatchInvokeRequest,
    started_at: Instant,
    mut handler: F,
    mut on_result: S,
) -> HostResult<fcp_host::BatchBoundedStreamingResponse>
where
    F: FnMut(HttpBatchOperation, Option<Instant>) -> Fut,
    Fut: Future<Output = OperationResult>,
    S: FnMut(OperationResult) -> DeliveryFut,
    DeliveryFut: Future<Output = Result<(), BatchOperationError>>,
{
    let timeout = Duration::from_millis(request.options.timeout_ms);
    let context = ExecutionContext::request_scoped(timeout.saturating_sub(started_at.elapsed()));
    let deadline = started_at.checked_add(timeout);
    let planning = request.planning_request();
    let executor = BatchExecutor::new();
    executor.plan_with_schedule_report(&planning)?;
    validate_members(request)?;
    let flow = dataflow::Dataflow::compile(request)?;
    let members: HashMap<&str, &HttpBatchOperation> = request
        .operations
        .iter()
        .map(|operation| (operation.id.as_str(), operation))
        .collect();

    let mut response = executor
        .execute_async_bounded_wait(
            &planning,
            Some(&context),
            fcp_host::BatchResultLimits::default(),
            |planned| {
                let operation = members[planned.id.as_str()];
                let future = flow.resolve(operation).and_then(|resolved| {
                    // Synchronous resolution can consume the last budget
                    // without yielding. Do not construct another invoke then.
                    if started_at.elapsed() >= timeout {
                        return Err(BatchOperationError {
                            code: "BATCH_INPUT_TIMEOUT".into(),
                            message:
                                "batch input resolution exhausted the deadline before invocation"
                                    .into(),
                            retry_after_ms: None,
                        });
                    }
                    Ok(handler(resolved, deadline))
                });
                async move {
                    match future {
                        Ok(future) => member_outcome(&operation.id, future.await),
                        Err(error) => Err(error),
                    }
                }
            },
            |result| {
                // Observe only retention-checked results. Neither this lock nor
                // a borrow of the callback survives in the delivery future.
                let delivery = flow.observe(&result).map(|()| on_result(result));
                async move { delivery?.await }
            },
        )
        .await?;
    response.bounded.response.total_duration_ms = elapsed_millis(started_at);
    Ok(response)
}

#[allow(clippy::future_not_send)]
async fn execute_with_observer<'a, F, Fut, S>(
    request: &'a HttpBatchInvokeRequest,
    started_at: Instant,
    mut handler: F,
    observer: S,
) -> HostResult<BatchInvokeResponse>
where
    F: FnMut(&'a HttpBatchOperation, Option<Instant>) -> Fut,
    Fut: Future<Output = OperationResult>,
    S: FnMut(&OperationResult) -> Result<(), BatchOperationError>,
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
        .execute_async_bounded_observed(
            &planning,
            Some(&context),
            fcp_host::BatchResultLimits::default(),
            |planned| {
                let operation = members[planned.id.as_str()];
                let future = handler(operation, deadline);
                async move { member_outcome(&operation.id, future.await) }
            },
            observer,
        )
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
        OperationResultStatus::Error if result.output.is_none() => Err(result
            .error
            .unwrap_or_else(|| adapter_error("failed batch member omitted its error"))),
        _ => Err(adapter_error(
            "batch member returned an inconsistent terminal result",
        )),
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

/// One JSON object per line. The terminal record retains the complete,
/// submission-ordered response, including outcomes not incrementally delivered.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HttpBatchStreamRecord {
    Result {
        result: OperationResult,
    },
    Complete {
        batch: Box<fcp_host::BatchBoundedStreamingResponse>,
    },
    Error {
        error: BatchOperationError,
    },
}

/// Stream independent completions over the ordinary capability-checked invoke
/// path. Graph, member and input-reference validation finish before HTTP 200.
pub(super) async fn stream_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<HttpBatchInvokeRequest>,
) -> Result<Response, (StatusCode, String)> {
    use futures_util::StreamExt;

    let started_at = Instant::now();
    let asserted_principal = extract_principal_header(&headers).map(Arc::<str>::from);
    let records = stream_with(request, started_at, move |operation, deadline| {
        execute_batch_operation(
            Arc::clone(&state),
            operation,
            asserted_principal.clone(),
            deadline,
        )
    })
    .map_err(map_host_error)?;
    let mut response = Response::new(Body::from_stream(records.map(encode_stream_record)));
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

/// The body owns both the scheduler and its capacity-one delivery channel.
/// No detached producer survives a dropped body. Ordinary invocation jobs keep
/// their existing durable ownership: dropping a waiter does not undo an effect.
fn stream_with<F, Fut>(
    request: HttpBatchInvokeRequest,
    started_at: Instant,
    handler: F,
) -> HostResult<impl futures_util::Stream<Item = HttpBatchStreamRecord>>
where
    F: FnMut(HttpBatchOperation, Option<Instant>) -> Fut,
    Fut: Future<Output = OperationResult>,
{
    BatchExecutor::new().plan_with_schedule_report(&request.planning_request())?;
    validate_members(&request)?;
    // Reject malformed references before opening a successful response. Compile
    // again inside the owned future so no self-referential request is required.
    dataflow::Dataflow::compile(&request)?;

    let (sender, receiver) = mpsc::channel(1);
    let result_sender = sender.clone();
    let execution = async move {
        let outcome = execute_dataflow_wait_with(&request, started_at, handler, move |result| {
            let sender = result_sender.clone();
            async move {
                sender
                    .send(HttpBatchStreamRecord::Result { result })
                    .await
                    .map_err(|_| BatchOperationError {
                        code: "BATCH_STREAM_CLOSED".into(),
                        message: "batch result consumer closed".into(),
                        retry_after_ms: None,
                    })
            }
        })
        .await;
        let terminal = match outcome {
            Ok(batch) => HttpBatchStreamRecord::Complete {
                batch: Box::new(batch),
            },
            Err(_) => HttpBatchStreamRecord::Error {
                error: BatchOperationError {
                    code: "BATCH_STREAM_FAILED".into(),
                    message: "batch execution could not complete; reconcile member request IDs before retrying"
                        .into(),
                    retry_after_ms: None,
                },
            },
        };
        // Terminal accounting may be read after the execution budget elapsed.
        // Sending it admits no new work and cannot renew a member's deadline.
        // A full channel preserves all earlier result records before this one.
        let _ = sender.send(terminal).await;
        drop(sender);
    };
    Ok(drive_stream(execution, receiver))
}

/// Drive execution and delivery together on body demand. Retain the same pinned
/// scheduler future across every received record; never restart a pending send.
fn drive_stream<F>(
    execution: F,
    receiver: mpsc::Receiver<HttpBatchStreamRecord>,
) -> impl futures_util::Stream<Item = HttpBatchStreamRecord>
where
    F: Future<Output = ()>,
{
    use futures_util::future::{Either, select};

    futures_util::stream::unfold(
        (Box::pin(execution), receiver, false),
        |(mut execution, mut receiver, mut finished)| async move {
            let record = if finished {
                receiver.recv().await
            } else {
                let incoming = Box::pin(receiver.recv());
                match select(execution.as_mut(), incoming).await {
                    Either::Left(((), incoming)) => {
                        finished = true;
                        incoming.await
                    }
                    Either::Right((record, _)) => record,
                }
            };
            record.map(|record| (record, (execution, receiver, finished)))
        },
    )
}

fn encode_stream_record(record: HttpBatchStreamRecord) -> Result<Bytes, std::io::Error> {
    let mut bytes = serde_json::to_vec(&record)
        .map_err(|_| std::io::Error::other("batch stream record encoding failed"))?;
    bytes.push(b'\n');
    Ok(Bytes::from(bytes))
}

#[cfg(test)]
#[path = "http_batch_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "http_batch_dataflow_tests.rs"]
mod dataflow_tests;
