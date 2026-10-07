# Mesh-Backed Invoke Routing

Bridge plan Phase A.2 (`MeshInvokeTransport`). Code: `crates/fcp-mesh/src/invoke_route.rs`
(envelopes, directory, replay guard, routing rules), `crates/fcp-host/src/mesh_routing.rs`
(host configuration and HTTP transport), `crates/fcp-host/src/mesh_routing/discovery.rs`
(bounded authenticated discovery), and `crates/fcp-host/src/mesh_routing/admission.rs`
(outbound resource admission and peer circuit recovery), wired into `fcp-host` at
`/rpc/invoke`, `/rpc/preflight`, `/rpc/introspect/{id}`, and `/rpc/discover`.
Persistent inbound admission: `crates/fcp-host/src/mesh_replay.rs`.
Multi-process forwarding coverage: `crates/fcp-host/tests/mesh_invoke_e2e.rs`.
Restart/crash admission coverage: `crates/fcp-host/tests/mesh_replay_restart.rs`.

## What it does

Each `fcp-host` that is given a mesh peer directory can relay requests for connectors it does
not run to a peer that does. `fwc` keeps posting to its own host; the host decides where the
operation executes.

| Request names... | Executes on | `response_metadata.route.truth_source` | `decision` |
|------------------|-------------|----------------------------------------|------------|
| a connector in this host's inventory | this host | `host-backed` | `local_connector` |
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
| `FCP_HOST_MESH_REPLAY_JOURNAL` | Optional persistent replay journal file. Default: signing-key filename with `.mesh-replay` appended, for example `/state/node.key.mesh-replay`. Parent directory must already exist. |

All ceilings must be positive integers. Empty, malformed, overflowing, zero, or inconsistent
values are startup errors, not a request to disable admission. Limits alone do not silently
turn an incompletely configured mesh router into a host-first deployment. Embedded callers
can use `MeshRouter::with_forward_limits` for explicit limits or `MeshRouter::new` for defaults;
these embedded constructors retain process-local replay state. Persistent embedded hosts
must use `MeshRouter::with_replay_journal` instead. `MeshRouter::from_env` and `from_lookup`
always enable durable replay protection when mesh routing is configured.

Endpoints are bare `http(s)://host:port` base URLs, normally Tailscale addresses.

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

Every forward atomically reserves one router slot, one peer slot, and its exact serialized
request length before network I/O. The reservation is held through body reading and reply
verification. Success, error, panic in future construction, and caller cancellation all release
it. Admission is fail-fast: there is no unbounded queue of waiting requests, and no synchronous
mutex is held across network awaits. A slow peer cannot occupy more than its per-peer ceiling.

The request-byte ceiling does not count returned response bodies or all host memory. Each
response remains independently limited to 16 MiB. `MeshRouter::forward_limits` reports the
active ceilings; `MeshRouter::forward_usage` returns an atomic, redaction-safe snapshot of
in-flight counts and serialized request bytes, with per-peer counts in stable order. Poisoned
admission state refuses new forwards and returns a snapshot error rather than inventing free
capacity.

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
not reset it; the invoke transport must authenticate a reply to recover.

Structured events distinguish `mesh_forward_admission_refused` (peer plus reason) from
`mesh_forward_peer_circuit` (peer, state, reason, cooldown_ms). Neither event includes request
contents, credentials, or unsigned response bodies.

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
- Membership is a static peer file, not gossip. Local transport circuits are not yet fed into
  `MeshQuorumSignals` and must not be treated as authenticated quorum membership.
- A locally installed connector always executes locally. There is no planner-driven placement
  of local connectors onto peers.
