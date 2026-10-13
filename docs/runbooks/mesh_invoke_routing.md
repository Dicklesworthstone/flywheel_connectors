# Mesh-Backed Invoke Routing

Bridge plan Phase A.2 (`MeshInvokeTransport`). Code: `crates/fcp-mesh/src/invoke_route.rs`
(envelopes, directory, replay guard, routing rules), `crates/fcp-host/src/mesh_routing.rs`
(host configuration and HTTP transport), `crates/fcp-host/src/mesh_routing/discovery.rs`
(bounded authenticated discovery), and `crates/fcp-host/src/mesh_routing/admission.rs`
(outbound resource admission and peer circuit recovery), wired into `fcp-host` at
`/rpc/invoke`, `/rpc/preflight`, `/rpc/introspect/{id}`, and `/rpc/discover`.
Persistent inbound admission: `crates/fcp-host/src/mesh_replay.rs` and
`crates/fcp-host/src/mesh_replay/group_commit.rs`; its bounded worker is in
`crates/fcp-host/src/mesh_routing/inbound.rs`.
Multi-process forwarding coverage: `crates/fcp-host/tests/mesh_invoke_e2e.rs`.
Restart/crash admission coverage: `crates/fcp-host/tests/mesh_replay_restart.rs`.

## What it does

Each `fcp-host` that is given a mesh peer directory can relay requests for connectors it does
not run to a peer that does. `fwc` keeps posting to its own host; the host decides where the
operation executes.

| Request names... | Executes on | `response_metadata.route.truth_source` | `decision` |
|------------------|-------------|----------------------------------------|------------|
| an ordinary non-singleton connector in this host's inventory | this host | `host-backed` | `local_connector` |
| a connector a peer advertises | the HRW-first advertiser | `mesh-backed` | `advertised_peer_forward` |
| a `singleton_writer` connector, with `FCP_HOST_HRW_LEASE_NODES` set on the entry node | the HRW-elected holder | `mesh-backed` | `hrw_holder_forward` |
| a connector nobody advertises | this host (fails `ConnectorNotFound` as before) | — | `no_advertising_peer` |

`fwc invoke` reports `_truth_source: "mesh"` and a top-level `route` object when a peer executed
the call, and `_truth_source: "host"` otherwise.

## Configuration

The node identity, signing key, and peer directory are required together. A partial
configuration makes `fcp-host` refuse to start, so no node silently falls back to host-first.
Timeout and resource ceilings are optional once that configuration is complete.

| Env var | Meaning |
|---------|---------|
| `FCP_HOST_MESH_NODE_ID` | This node's mesh id. Defaults to `FCP_HOST_HRW_LEASE_LOCAL_NODE`. |
| `FCP_HOST_MESH_SIGNING_KEY_FILE` | File holding this node's hex-encoded 32-byte Ed25519 secret key. |
| `FCP_HOST_MESH_PEERS` / `FCP_HOST_MESH_PEERS_FILE` | JSON array of `{ "node_id", "endpoint", "public_key_hex" }`. One shared file can be shipped to every node; each host skips its own entry. |
| `FCP_HOST_MESH_FORWARD_TIMEOUT_MS` | Optional per-forward deadline (default 60000). |
| `FCP_HOST_MESH_FORWARD_MAX_IN_FLIGHT` | Optional router-wide simultaneous-forward ceiling (default 32). |
| `FCP_HOST_MESH_FORWARD_MAX_PER_PEER` | Optional per-peer simultaneous-forward ceiling (default 4; must not exceed the router ceiling). |
| `FCP_HOST_MESH_FORWARD_MAX_REQUEST_BYTES` | Optional aggregate serialized-request-byte ceiling for admitted forwards (default 67108864, or 64 MiB). |
| `FCP_HOST_MESH_FORWARD_MAX_RESPONSE_BYTES` | Optional aggregate wire-reply reservation ceiling (default 536870912, or 512 MiB; minimum 16777216, or 16 MiB). |
| `FCP_HOST_MESH_REPLAY_JOURNAL` | Optional persistent replay journal file. Default: signing-key filename with `.mesh-replay` appended, for example `/state/node.key.mesh-replay`. Parent directory must already exist. |

All ceilings must be positive integers. Empty, malformed, overflowing, zero, or inconsistent
values are startup errors, not a request to disable admission. Limits alone do not silently
turn an incompletely configured mesh router into a host-first deployment. Embedded callers
can use `MeshRouter::with_forward_limits` for explicit limits or `MeshRouter::new` for defaults;
these embedded constructors retain process-local replay state. Persistent embedded hosts
must use `MeshRouter::with_replay_journal` instead. `MeshRouter::from_env` and `from_lookup`
always enable durable replay protection when mesh routing is configured.

Endpoints are bare `http(s)://host:port` base URLs, normally Tailscale addresses.
Owner-signed membership, persistent generation checkpoints, and live file reload are described
in [Mesh membership](mesh_membership.md). That trust mode uses a signed peer source instead
of the raw array above.

## Security model

- A peer's signature authenticates the *relay*, never the operation. The executor runs the
  full local pipeline on every forwarded request: capability token, revocation, zone binding,
  HRW admission, deployment tier, and zone policy. A token the executor does not trust is
  refused there (`403 mesh executor ...`).
- Envelopes (`fcp.mesh.forward.v1`) are domain-separated Ed25519 signatures over
  length-prefixed canonical bytes that cover the method, the exact request JSON, and the
  asserted principal. A preflight cannot be replayed as an invoke.
- Inbound checks, each with its own HTTP status: unknown signer, bad signature, or outside the
  ±30 s freshness window (`401`); addressed to another node (`421`); replayed `(origin, nonce)`
  (`409`); replay cache saturated (`503`, fails closed rather than forgetting a live nonce).
- Environment-configured executors authenticate and sync each accepted nonce before dispatch.
  An executor restart does not erase a still-live nonce from its persistent journal.
- Replies are signed by the executor and bound to the request's origin and nonce, so a reply
  cannot be replayed onto another request or come from a different peer.
- Forwarding is single-hop: a request that arrived over the mesh always executes locally.
- Every relay appends an `invoke.mesh_forwarded` event to the entry node's hash-linked invoke
  audit chain. The executor records its own allow, result, and error events.

## Failure semantics

- Only a failure proving the request was not delivered (local admission refusal, connection
  establishment, or request construction failure) permits trying the next HRW-ranked
  advertiser. Each failed attempt is listed in `route.failed_attempts`.
- `singleton_writer` connectors never fan out: they have exactly one executor. A busy or
  circuit-open holder does not authorize execution on another node.
- A lost reply, post-send connection failure, timeout, invalid signature, malformed reply, or
  unsigned HTTP refusal stops failover. HTTP status alone is not proof of non-execution:
  a proxy can return 5xx after execution, and a 409 replay refusal can mean an earlier delivery
  already executed. The entry node surfaces the ambiguous outcome instead of duplicating a
  non-idempotent operation. Unsigned response bodies are not copied into diagnostics.
- HTTP redirects and implicit HTTP-client retries are disabled. The mesh layer owns delivery
  decisions. A verified executor error is returned as that executor's result, not retried.
- If every advertiser is provably undeliverable or locally refused before sending, the entry
  node returns `503` with the attempts.

## Persistent replay admission and recovery

**Deployment change:** configured mesh hosts now need writable persistent replay storage.
For read-only secret mounts, set `FCP_HOST_MESH_REPLAY_JOURNAL` to a file on a separate
persistent state volume. Do not place it in a temporary directory or an ephemeral container
layer. The `.lock` and `.compact` companion filenames are reserved. Every process using the
same executor identity must use the same journal; do not share the identity across independent
journal copies or rename the signing-key path without preserving the configured journal.

Before the inbound handler can dispatch an operation, the router verifies the envelope,
reserves its `(origin, nonce)`, appends a checksummed record, and calls `sync_all`. Only then
does admission return success. The clock is sampled inside the admission mutex. An append or
sync error latches the guard closed; poisoned state also refuses further admission. Startup
refuses a locked, corrupt, torn, empty-existing, incorrectly scoped, or oversized journal.
There is no automatic reset or volatile fallback. Runtime storage refusal uses the existing
`Malformed` error with `field="replay_journal"`; it does not authorize the entry node to retry.

### Asynchronous admission, isolation, and group commit

The live HTTP handler awaits a dedicated replay worker. It admits at most **33 total jobs**
across the queue and active group, with a fixed **four-job ceiling per authenticated origin**.
The channel holds at most 32 queued jobs. Both limits are reserved atomically before enqueue;
removing a group from the channel does not create extra capacity while its journal work runs.
The separate accounting mutex is never held during disk I/O. Only verified nonce identities
enter the queue, not copies of request bodies or capability tokens.

After acquiring the journal mutex, the worker collects up to **16 already-queued jobs** and
commits their admissible identities with one shared append and `sync_all`. There is no timer
or delay to fill a group: a lone request proceeds immediately. Duplicates are detected both
against durable history and within the group. Scope, freshness, clock rollback, and live-nonce
capacity are checked before staging each identity; ordinary per-job results retain input order.
A group with no admissible identities performs no append or sync.

No successful result is published before the shared sync and in-memory publication complete.
Compaction occurs first when adding the group would exceed the existing disk ceiling, and
retains its separate file/directory sync barriers. The journal format and recovery rules are
unchanged. An uncertain append, sync, or compaction failure refuses the entire group and keeps
admission closed. A crash can consume some unacknowledged nonces or leave a torn journal that
refuses startup; it never authorizes replaying those requests. Group commit is not an atomic
transaction over the connector operations themselves.

The five-second reply deadline is independent of filesystem progress. Queue/total saturation,
peer-slot exhaustion, a stopped worker, poisoned accounting, or journal unavailability is an
unsigned HTTP 503. The queued job owns its slot after caller cancellation or timeout. Success,
error, queue rejection, and channel teardown release its slot before notifying its waiter.
The worker never dispatches an operation for a cancelled handler. These limits cover journal
work, not all host execution or all memory, and do not prove quorum health or fairness across
arbitrarily many enrolled identities. Embedded synchronous admission shares the same journal
and validation rules but remains outside the asynchronous worker's occupancy quotas.

Group-commit and isolation regressions are alongside their implementations. They cover the
shared sync barrier, restart recovery, mixed outcomes, uncertain writes, compaction, expiry,
serial-equivalent admission, bounded burst collection, and cancelled-waiter accounting. These
changes have not yet been compiled, tested, or benchmarked in the delivery environment; no
measured throughput improvement or production-readiness graduation is claimed.

### Journal storage contract

The journal stores domain-separated replay-key hashes and expiry/observation timestamps,
not request JSON, capability tokens, asserted principals, signatures, or response bodies.
It is bound to the executor node ID and freshness window. Nonces remain live through the
inclusive freshness boundary, including future-dated envelopes admitted within clock skew.
A persisted clock high-water mark prevents recovery from resurrecting previously expired
requests after a backward clock jump.

The default capacity is 16,384 live nonces. The append log holds at most 32,768 fixed 80-byte
records plus a 96-byte header. Compaction writes and syncs a complete replacement, atomically
renames it, and syncs its directory; the old journal is not truncated in place. A separate
exclusive file lock remains held across that replacement, preventing another executor from
acquiring the newly replaced data inode as a separate admission owner. A temporary compacted
copy can coexist with the bounded log during replacement.

Storage must provide working file locks, file sync, directory sync, and atomic replacement.
Unix files are created with mode 0600, existing group/other-accessible files are refused, and
final-component symlinks are not followed. The parent directories and filesystem are trusted.
Unsupported platforms/filesystems fail closed; the checked-in persistence tests are Unix-only,
and they do not establish Windows or network-filesystem durability. Checksums detect damaged
records, not deliberate file rollback or a malicious storage administrator. Never remove the
journal or restore an older copy merely to clear a startup failure. Correct the storage/clock
problem while preserving history, or coordinate retirement of the executor identity before
discarding its state.

This is **at-most-once admission of the same signed envelope**, not exactly-once execution.
A crash after the nonce is synced but before connector dispatch may consume a request that
never executes. A crash after an external side effect may leave an unknown outcome. There is
no stored-result replay and no permission to retry with a new nonce. Connector-level durable
idempotency and reconciliation are still required to resolve those cases.

## Outbound admission and peer recovery

Every forward atomically reserves one router slot, one peer slot, its exact serialized request
length, and 16 MiB of wire-reply headroom before network I/O. The reservation is held through
body reading and reply verification. Success, error, panic in future construction, and caller
cancellation all release it. Admission is fail-fast: there is no unbounded queue of waiting
requests, and no synchronous mutex is held across network awaits. A slow peer cannot occupy
more than its per-peer ceiling.

The response budget reserves the full per-reply limit even when the eventual reply is small.
This deliberately decides capacity **before delivery**: running out of aggregate reply allowance
must not cause the router to discard the result of a write it has already sent. A 64 MiB
response budget, for example, admits at most four simultaneous forwards regardless of a higher
router slot limit. The default 512 MiB budget preserves the default 32-forward capacity.
Refusal uses `response_byte_limit` and does not construct the transport future or consume a
recovery-probe slot. Embedded callers configure `MeshForwardLimits::max_response_bytes`; the
environment-variable name is also available as `MeshForwardLimits::RESPONSE_BYTES_ENV`.

These are reservation limits, not process-RSS limits. Decoder copies, HTTP-client buffers,
discovery, and results retained by callers after authentication remain outside this accounting.
Each reply is still independently limited to 16 MiB. `MeshRouter::forward_limits` reports the
active ceilings; `MeshRouter::forward_usage` returns an atomic, redaction-safe snapshot of
in-flight counts, serialized request bytes, and `response_bytes_reserved`, with per-peer counts
in stable order. Poisoned admission state refuses new forwards and returns a snapshot error
rather than inventing free capacity.

Three consecutive transport failures open that peer's circuit for five seconds. A malformed
or unauthenticated reply opens it immediately for thirty seconds. After cooldown, exactly one
new caller is admitted as the recovery probe. Failed probes back off to ten, twenty, then at
most thirty seconds. An authenticated reply closes the circuit and resets backoff, including a
signed operation error: application failure is not transport failure. There are no automatic
replays or synthetic write probes; the single probe is an already-requested forward.

An open circuit changes only admission of later requests. The original timeout, unsigned HTTP
error, or invalid reply is returned unchanged and remains non-retryable. A subsequent request
refused by the circuit has not been sent and may follow the normal routing rule's alternatives.
Resource saturation cannot consume the recovery-probe slot. Cancelling a probe releases both
resources and probe ownership, retaining cooldown without escalating it or claiming recovery.
Ordinary caller cancellation is not counted as a peer failure.

Generation identity fences in-flight observations: a late success cannot close a newer open
circuit, and a late failure cannot poison a completed recovery. Circuit state is local to the
router process and is not a quorum vote or proof of mesh readiness. A fresh advertisement does
not reset it; an existing circuit requires an authenticated invoke reply to recover.

### Circuit history under membership churn

A router retains at most **16,384 peer circuit entries**, even if repeated signed membership
reloads introduce arbitrarily many distinct node IDs. At capacity, a new identity reclaims the
oldest eligible idle entry, with stable node-ID tie-breaking. Healthy closed entries can be
reclaimed immediately. Failure history is eligible only after five minutes without an admitted
forward or completion, and never before its cooldown expires. Refused calls do not refresh
that idle timer. Reclamation is capacity-driven, not a periodic membership or health probe.
An evicted idle peer starts with a fresh circuit if it is subsequently contacted; this is local
history retirement, not authenticated recovery or a statement about membership.

Every outstanding ticket pins the lifetime of its circuit independently of circuit generation.
Opening and recovering a circuit therefore cannot hide older in-flight calls from reclamation.
Live tickets and recovery probes are never evicted. If all entries are protected, new peer
identities fail before transmission with `peer_circuit_capacity`; existing peers still follow
their own circuit rules, including the single recovery probe. No failed request is replayed and
no active peer's failure history is erased merely to make space. A flood of newly introduced
peers can temporarily refuse other new identities; this ceiling does not promise fairness
across arbitrarily many enrolled identities. Reclamation scans at most the fixed capacity and
runs only for a new peer at capacity; established-peer lookup remains logarithmic.

Structured events distinguish `mesh_forward_admission_refused` (peer plus reason, including
`response_byte_limit` and `peer_circuit_capacity`) from `mesh_forward_peer_circuit` (peer, state,
reason, cooldown_ms). Neither event includes request contents, credentials, or unsigned response
bodies. Regression tests alongside admission and circuit code cover response-budget saturation,
concurrent reservations, cancellation, overflow, bounded churn, idle-history retirement, stale
generations, and probe ownership. These new tests have not been run in the delivery environment;
Rust compilation, formatting, Clippy, and the mesh integration suite remain verification gates.

## Discovery under failure and load

Advertisements (`GET /rpc/mesh/advertisement`, signed `fcp.mesh.peer-advertisement.v1`) are
cached for up to 10 seconds, but never beyond their signed freshness window. Every newly
fetched inventory must verify against the requested peer's directory key and node id.

Concurrent callers share one refresh per router, with at most 16 fetches in flight. Each fetch
has a three-second deadline; the whole discovery call has a five-second deadline including
waiting for another refresh. Completed inventories are stored as they arrive. A deadline or
caller cancellation drops outstanding requests and releases the refresh lock; later calls can
resume the missing work without throwing away completed results.

Failed or invalid advertisements are negative-cached for one second to avoid probing a dead
peer on every incoming request. Negative entries never advertise connectors or imply
availability. Results are returned in stable node-id order, regardless of completion order.
Invalidation clears both positive and negative entries and fences results from older in-flight
refreshes. Deadline-limited discovery returns only completed, still-fresh verified inventories;
it does not claim that the catalog is complete. Logs distinguish `mesh_advertisement_unavailable`
from `mesh_discovery_deadline`.

## Not yet covered

- The default deployment is still host-first. The README Mesh-Native row stays `STEADY-STATE
  TARGET (NOT YET OPERATIONAL)` until production evidence exists.
- Owner-signed membership and file reload do not provide gossip or authenticated quorum health.
  Local transport circuits must not be treated as authenticated quorum membership.
- Ordinary locally installed connectors execute locally. Singleton operations follow their
  lease election; general planner-driven placement of local connectors remains outstanding.
