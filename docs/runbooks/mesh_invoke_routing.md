# Mesh-Backed Invoke Routing

Bridge plan Phase A.2 (`MeshInvokeTransport`). Code: `crates/fcp-mesh/src/invoke_route.rs`
(envelopes, directory, replay guard, routing rules) and `crates/fcp-host/src/mesh_routing.rs`
(host configuration, HTTP transport, advertisement cache), wired into `fcp-host` at
`/rpc/invoke`, `/rpc/preflight`, `/rpc/introspect/{id}`, and `/rpc/discover`.
Multi-process proof: `crates/fcp-host/tests/mesh_invoke_e2e.rs`.

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

All of the following are required together. A partial configuration makes `fcp-host` refuse
to start, so no node silently falls back to host-first.

| Env var | Meaning |
|---------|---------|
| `FCP_HOST_MESH_NODE_ID` | This node's mesh id. Defaults to `FCP_HOST_HRW_LEASE_LOCAL_NODE`. |
| `FCP_HOST_MESH_SIGNING_KEY_FILE` | File holding this node's hex-encoded 32-byte Ed25519 secret key. |
| `FCP_HOST_MESH_PEERS` / `FCP_HOST_MESH_PEERS_FILE` | JSON array of `{ "node_id", "endpoint", "public_key_hex" }`. One shared file can be shipped to every node; each host skips its own entry. |
| `FCP_HOST_MESH_FORWARD_TIMEOUT_MS` | Optional per-forward deadline (default 60000). |

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
- Replies are signed by the executor and bound to the request's origin and nonce, so a reply
  cannot be replayed onto another request or come from a different peer.
- Forwarding is single-hop: a request that arrived over the mesh always executes locally.
- Every relay appends an `invoke.mesh_forwarded` event to the entry node's hash-linked invoke
  audit chain. The executor records its own allow, result, and error events.

## Failure semantics

- If a candidate fails before the request could have been delivered (connect refused, or the
  envelope was rejected), the entry node tries the next HRW-ranked advertiser. Each failed
  attempt is listed in `route.failed_attempts`.
- `singleton_writer` connectors never fan out: they have exactly one executor.
- If the outcome is unknown (timeout or broken connection after send), the entry node returns
  `502` and does not retry, because the operation may have executed on the peer.
- If every advertiser is undeliverable, the entry node returns `503` with the attempts.
- Advertisements (`GET /rpc/mesh/advertisement`, signed `fcp.mesh.peer-advertisement.v1`) are
  cached for 10 s. Advertisements that are unreachable or fail verification are skipped and
  logged as `mesh_advertisement_unavailable`.

## Not yet covered

- The default deployment is still host-first. The README Mesh-Native row stays `STEADY-STATE
  TARGET (NOT YET OPERATIONAL)` until production evidence exists.
- Membership is a static peer file, not gossip. Peer health beyond per-request delivery is not
  yet fed into `MeshQuorumSignals`.
- A locally installed connector always executes locally. There is no planner-driven placement
  of local connectors onto peers.
