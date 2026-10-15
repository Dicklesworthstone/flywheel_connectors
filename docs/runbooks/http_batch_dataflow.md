# Result-dependent live HTTP batches

The live host batch adapter can bind a successful earlier operation's output
into a later operation's input. This uses the ordinary batch DAG and ordinary
invoke authorization; it does not mint tokens, approve operations, acquire
leases, or retry failed work.

## Request syntax

Inside a member's `request.input`, use a single-key reference object:

```json
{
  "$fcp_batch_ref": {
    "operation": "lookup",
    "pointer": "/result/items/0/id"
  }
}
```

`operation` is the source member's **batch DAG ID**, not its invocation request
ID or connector operation name. The source must be listed explicitly in the
consumer's `depends_on`, must exist, and must use the same exact zone. Declaring
an indirect ancestor is insufficient: also declare the source as a direct
dependency. The existing planner rejects cycles before dispatch.

`pointer` selects from the complete successful batch member `output`, not an
implicitly unwrapped provider result. Use `/result/...` when that output is an
invoke response envelope. The empty pointer selects the whole output. `~0` and
`~1` escape `~` and `/` within object keys. Array indices, empty object keys,
objects, arrays, booleans, numbers, strings and null values are supported.
Values are inserted as JSON values, not interpolated into strings.

For example, the following is a **consumer member fragment**, not a complete
authorized invocation:

```json
{
  "id": "read-item",
  "depends_on": ["lookup"],
  "request": {
    "input": {
      "item_id": {
        "$fcp_batch_ref": {
          "operation": "lookup",
          "pointer": "/result/items/0/id"
        }
      },
      "include_details": true
    }
  }
}
```

Supply all the ordinary invoke fields, including the real capability token,
connector and operation IDs, zone, distinct invocation ID, required idempotency
key, and any applicable lease or approval evidence. The host checks the
**resolved input** through its existing invocation path. A token or approval
bound to the template rather than the resolved request may correctly refuse
the operation; this feature does not retarget or relax that authorization.

The reference wrapper may not contain extra keys. To send marker-shaped JSON
as ordinary literal input, wrap it once:

```json
{
  "$fcp_batch_literal": {
    "$fcp_batch_ref": "literal application data"
  }
}
```

The literal wrapper is removed without interpreting its contents. Resource
limits still apply. Provider output is always inserted literally, including
any marker-shaped objects it contains; it cannot introduce additional reads
or dependencies through recursive template evaluation.

## Information flow and authority

Cross-zone binding is refused. Participating members' supplied provenance must
also have the same origin zone and same-zone chain entries. Cross-zone approval
or declassification is not implemented by this adapter.

Provider-derived input is conservatively marked `HighlyTainted`. Source causal
steps propagate through multiple stages, with a bounded step describing the
source connector operation and its invocation ID. Prior template elevation is
not reused for newly obtained data: the provenance elevation flag and embedded
elevation token are cleared. The submitted capability token, approval tokens,
holder proof, request ID, idempotency key, lease sequence and other authority
fields remain unchanged for ordinary enforcement. No private authority is
copied out of another member's invocation request.

This conservative provenance can prevent a derived input from driving a
privileged operation. That is a refusal, not a reason to strip provenance or
automatically retry with a different token.

## Bounds and failure behavior

The existing result-retention limits remain in force: 1 MiB per encoded provider
result and 16 MiB across retained provider results. The dataflow adapter adds
an independent, cumulative 16 MiB allowance for its cached source outputs and
provenance, plus 1 MiB per substituted input and 16 MiB of cumulative substituted
inputs. These are encoded-byte bounds, **not exact heap or peak-memory bounds**;
the scheduler retains its own response data separately.

Templates are limited to depth 64 and 65,536 visited values, including literal
contents. Each operation can contain at most 128 reference occurrences. A
reference ID is at most 128 bytes and a pointer at most 1,024 bytes. Source
outputs cached for binding have the same depth and value-count bounds.
Provenance is limited to 128 chain steps and 64 KiB of encoded metadata.

Malformed references, missing declarations, forbidden zone flows and invalid
template shapes reject the whole batch before any invocation. A pointer whose
path is absent from an actual successful source output instead produces
`BATCH_INPUT_REFERENCE_MISSING` for that consumer before its invoke handler is
called. Expansion overflow produces `BATCH_INPUT_LIMIT`; excessive provenance
produces `BATCH_INPUT_PROVENANCE_LIMIT`. Descendants of failed members are
skipped by the existing scheduler. Unrelated branches may continue unless the
batch's stop-on-first-error policy or another admission limit stops them.

Failed, interrupted or withheld source outputs never become successful binding
inputs. A source-cache failure stops further admission through the existing
result-delivery failure accounting; it does not turn a known successful source
effect into a failed external action. Already admitted work drains under the
original budget, and known results remain available. There is no automatic
retry and no attempt to undo a provider action.

Planning, resolution, queueing and execution share the original batch deadline.
No per-reference timeout is reset and no detached binding tasks are started.

## Focused verification

Run in the full workspace with its pinned toolchain and existing dependencies:

```bash
rch exec -- cargo test --locked -p fcp-host --test bounded_batch_observation
rch exec -- cargo test --locked -p fcp-host --bin fcp-host http_batch::dataflow_tests
rch exec -- cargo test --locked -p fcp-host --bin fcp-host http_batch::tests
rch exec -- cargo check --locked -p fcp-host --bin fcp-host
```

The new adapter tests use controlled invocation callbacks on the production
adapter; they are not a substitute for authenticated host-binary integration
tests or full workspace verification. No build or test pass is implied by this
runbook.

The fully expanded input also must fit depth 64 and 65,536 visited values.
These checks run before allocating its encoded buffer or parsed JSON tree.
Repeating an individually valid source or nesting it inside a valid template
cannot bypass the combined shape limits. Selected provider values and escaped
literal values remain opaque during this check; marker-shaped data is never
interpreted a second time.
