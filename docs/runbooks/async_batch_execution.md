# Asynchronous batch execution

`fcp_host::BatchExecutor::execute_async` runs independent operations concurrently
without blocking on synchronous handlers or spawning a task per operation. It
uses the existing batch request, response, validation, and scheduling contracts.
This is a host-library execution API, not a new HTTP endpoint or a claim that the
mesh-native deployment cutover is complete.

Call it from an FCP async runtime with a handler that performs the normal
capability, zone, lease, and connector-invoke checks. Use
`BatchExecutor::with_zone_validator` to reject a batch with inaccessible or
unregistered tools before any handler is constructed. An executor constructed
with `new()` deliberately has no batch zone validator; it does not authorize
operations on the caller's behalf.

```rust,no_run
use fcp_host::{BatchExecutor, BatchInvokeRequest, BatchOperationError};

async fn execute(request: &BatchInvokeRequest) {
    let response = BatchExecutor::new()
        .execute_async(request, |operation| async move {
            // Replace this example with the authorized host/mesh invocation.
            Ok::<_, BatchOperationError>(operation.input.clone())
        })
        .await
        .expect("valid batch");
    assert_eq!(response.results.len(), request.operations.len());
}
```

## Execution semantics

All validation and planning precede handler construction. Each dependency tier
uses the existing deterministic FIFO or adaptive order. At most
`max_parallelism` handlers are admitted at once, including futures that have not
yet been polled. A newly free slot is filled without waiting for other operations
in the same tier. Tiers remain sequential, preserving the existing plan contract.
A dependent runs only after all its dependencies succeeded. Failed dependencies
propagate `DEP_FAILED` skips, while independent branches can still complete.

Responses stay in original submission order regardless of completion order.
Provider error details and retry hints are preserved; the executor itself never
retries operations. Adaptive reports remain the planner's FIFO-versus-scheduled
counterfactual, not a measurement of actual concurrent queueing latency.

With `stop_on_first_error`, no new handler is admitted after a failure is observed.
Already admitted operations are drained until they finish or the overall batch
budget expires. This retains their actual results instead of describing possibly
executed operations as skipped. Multiple operations may already have been admitted
before the first failure is observed.

## Deadlines and unknown outcomes

The elapsed-time budget starts before planning and is never reset per operation
or per tier. A zero budget admits nothing. Very large budgets do not construct an
overflowing absolute deadline. Timer waits are bounded and recheck the original
budget. The response distinguishes:

| Operation state at expiration | Result |
| --- | --- |
| Result already observed | Preserve its success or provider error |
| Handler admitted, no result observed | Error `BATCH_OUTCOME_UNKNOWN`, with no retry hint |
| Handler never admitted | Skipped `BATCH_TIMEOUT` |

The overall status is `Aborted`, including when the final observed result arrived
late. Never infer that an external write was undone because its future was
dropped. Reconcile an unknown outcome using the connector's receipt/idempotency
mechanism before considering a retry. This executor does not create distributed
exactly-once guarantees.

Handlers must cooperate with asynchronous polling. A blocking factory, future
poll, or destructor cannot be preempted. Dropping the outer batch drops its owned
in-flight futures and does not start queued operations. It does not stop unrelated
tasks a handler chose to spawn, terminate a provider operation, or produce a
partial response to a caller that already discarded the batch future.

## Focused regression command

```sh
rch exec -- cargo test --locked -p fcp-host --test batch_async
```

The tests use controlled futures to check real overlap and slot refill, tier
ordering, failure propagation, stop-and-drain behavior, timeout accounting,
whole-batch rejection, adaptive planning, non-Send borrowing, and drop cleanup.
Timing-based deadline cases are bounded separately from the overlap assertions.
