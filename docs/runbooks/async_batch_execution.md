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

All validation and planning precede handler construction. A completion-driven
ready queue tracks each operation's outstanding dependencies. At most
`max_parallelism` handlers are admitted across the entire batch, including futures
that have not yet been polled and operations at different dependency depths.
A dependent becomes eligible when all its own dependencies have settled; it runs
only when every dependency succeeded. There is no barrier waiting for unrelated
operations in an earlier planning tier.

For example, with two slots and the dependency chain `a -> c -> d` alongside an
independent slow `b`, the executor can finish `c` and `d` while `b` is still
waiting. A join depending on both `a` and `b` still waits for both. Applications
requiring an ordering constraint must declare that dependency explicitly instead
of relying on the old accidental tier barrier. Synchronous execution and the
planner's tier representation remain unchanged.

Among currently ready operations, the existing deterministic FIFO/adaptive plan
order supplies the admission preference. Completion timing can change which nodes
are ready; the executor never starts a blocked higher-ranked node ahead of its
prerequisites. Failed and skipped dependencies propagate `DEP_FAILED` iteratively
through their descendants without stopping unrelated branches. Repeated references
to the same dependency cannot admit a handler twice.

Responses stay in original submission order regardless of completion order.
Provider error details and retry hints are preserved; the executor itself never
retries operations. Adaptive reports remain the planner's FIFO-versus-scheduled
counterfactual, not an execution trace or a measurement of actual concurrent
queueing latency. Interleaving dependency depths does not rewrite that report.

With `stop_on_first_error`, no new handler is admitted after a failure is observed.
Already admitted operations at any dependency depth are drained until they finish
or the overall batch budget expires. This retains their actual results instead of
describing possibly executed operations as skipped. Multiple operations may already
have been admitted before the first failure is observed.

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

## Inherited cancellation and request deadlines

Use `BatchExecutor::execute_async_with_context(request, &context, handler)` when
 the caller has an `fcp_async_core::ExecutionContext`. Do not wrap the whole batch
in `context.run(...)` when partial results matter: that would discard the batch
future and its accumulated response on cancellation or timeout.

The context-aware executor observes the existing context's cancellation and
remaining deadline at admission and while waiting for active operations. The
earlier of the context deadline and the batch budget wins. It never renews either
deadline and never cancels the caller's shared context itself. Cancellation from
a parent context reaches a batch using its inherited child context. Authorization
of a user-requested cancellation remains the caller's responsibility; this API
does not expose an unauthenticated cancellation endpoint.

Cancellation returns an `Aborted` response with all results already observed.
Never-admitted work is skipped with `BATCH_CANCELLED`; unresolved admitted work
is an error with `BATCH_OUTCOME_UNKNOWN` and no retry hint. Context deadline
expiration uses the existing timeout classification. Cancellation takes priority
when both are observed together and also interrupts stop-on-first-error draining.
This is a bounded local stop, not an acknowledgment that the provider rolled back
or even received a cancellation request.

Both async APIs yield periodically during admission, dependency-skip processing,
and completion handling, so ready-heavy batches do not monopolize a local
executor and prevent its cancellation tasks from running. No additional worker
or detached task is created. These yield points cannot preempt a blocking handler.

## Focused regression command

```sh
rch exec -- cargo test --locked -p fcp-host --test batch_async
```

The tests use controlled futures to check real overlap and slot refill, dependency
ordering, failure propagation, stop-and-drain behavior, timeout accounting,
whole-batch rejection, adaptive planning, non-Send borrowing, and drop cleanup.
Timing-based deadline cases are bounded separately from the overlap assertions.
Context regressions additionally cover pre-cancellation and pre-expiration,
partial-response retention, inherited cancellation, competing deadlines, draining
interruption, cancellation inside a handler factory, and ready-heavy fairness.
Dependency-frontier regressions cover fast chains beside blocked roots, fan-in,
diamond graphs and repeated edges, failure propagation before cancellation,
first-error draining across depths, adaptive ready order, the global concurrency
bound, and iterative propagation through 1024 skipped descendants.
A cross-component TCP case runs batch handlers through `MeshRouter::forward` to
two signing peers. Neither peer replies before both authenticated invokes arrive,
so sequential execution cannot pass the bounded barrier. This exercises the mesh
transport, not a provider operation or a newly deployed host HTTP batch route.
