# Remote signed membership distribution

Bridge-plan Phase A: distribute owner-authorized peer additions, revocations,
key rotations and validity renewals to running hosts without copying each new
membership generation onto every node.

## Configure a publisher

Serve the complete `SignedMeshPeerDirectory` JSON envelope at a stable HTTPS URL.
Keep the signing operation separate from the web server: the publisher needs only
the signed public document, never the owner private key. Publish each replacement
atomically, and increment its generation for every change, including renewal of
`expires_at_ms`. The document must still include each receiving host's own node
ID and actual public key.

Point `FCP_HOST_MESH_PEERS_FILE` at a trusted local JSON descriptor:

```json
{
  "schema_version": "fcp.mesh.directory-source.v1",
  "directory_url": "https://directory.example/mesh/membership.json"
}
```

Continue configuring `FCP_HOST_MESH_ID`, `FCP_HOST_MESH_DIRECTORY_OWNER_KEYS`,
`FCP_HOST_MESH_DIRECTORY_STATE`, node identity/signing key and replay storage as
specified in `mesh_membership.md` and `mesh_invoke_routing.md`. The owner keys are
independently pinned; neither the descriptor nor the downloaded envelope can
appoint a new trust root. The descriptor is supported in the file-backed source,
not in `FCP_HOST_MESH_PEERS`, so the existing supervised reload worker owns the
refresh lifecycle. Ordinary source files containing signed documents or static
peer arrays retain their existing behavior.

A descriptor may be changed atomically to move the configured publisher. Fetched
documents cannot themselves contain another descriptor. HTTP redirects, userinfo,
query strings, fragments, ambient proxies and cookies are not used. URLs require
HTTPS, except literal loopback HTTP for local development and deterministic tests;
`localhost` and non-loopback HTTP addresses are not exceptions. No capability
credentials or signing secrets are transmitted to the publisher.

## Activation and failure semantics

Startup fetches a complete document before verification and checkpoint activation.
The existing file reload worker then reads the descriptor and fetches again on its
one-second polling cadence; a fetch adds up to its three-second deadline. There
is one fetch at a time per worker, not one per incoming invocation. Fetch I/O runs
outside request handlers, and the bridge thread is joined before that refresh
returns. Closing the router stops the owner worker before releasing its persistent
checkpoint lock.

Only HTTP 200 with a bounded UTF-8 signed-envelope document reaches the verifier.
The source descriptor is at most 4 KiB, its URL at most 2 KiB and a fetched envelope
at most 4 MiB. Both declared and chunked body lengths are checked. A partial body,
206, 304, redirect or unsigned error response is not membership evidence. Error
messages do not include URLs, response bodies or credentials.

Owner signature, mesh/local identity, signed expiry, generation and payload
anti-equivocation checks are unchanged. A newer checkpoint is synced before the
new peer view is published. Removing a peer or rotating its key/endpoint fences
its old in-flight authority; replay journals and outbound reservations are not
reset. Loading the same generation never extends its monotonic lifetime.

An unavailable or invalid source fences new mesh work through the existing reload
failure state. A valid document can restore service, but rollback, same-generation
mutation and expired authority cannot. An uncertain checkpoint write remains a
restart-required failure. There is no volatile fallback, automatic reset or
restoration of an older membership merely because the publisher is unavailable.
A restart also requires a reachable, acceptable source; offline bootstrap caching
is not provided by this mode.

## Verification and scope

Tests in `crates/fcp-host/src/mesh_routing/directory/remote/tests.rs` exercise a real
loopback HTTP server, not a provider-service substitute. They cover descriptor and
URL validation, exact-byte preservation, no raw-list downgrade or recursive fetch,
HTTP status/redirect refusal, chunked/truncated/oversized responses, independently
pinned owner verification, live key rotation and revocation, persistent replay
retention, publisher outage/recovery and rollback rejection across restart.

The new Rust code and tests have not been compiled or executed in the delivery
environment. Required checks include:

```sh
rch exec -- cargo test -p fcp-host --lib mesh_routing::directory
rch exec -- cargo test -p fcp-host --test mesh_invoke_e2e
rch exec -- cargo clippy -p fcp-host --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

This is authenticated membership distribution, not consensus, gossip, a quorum
health proof, immediate revocation or a claim that the full mesh-native cutover
is production-proven. The publisher can deny service or withhold a newer signed
generation; it cannot authorize a forged or rolled-back directory. Signed expiry
bounds withheld authority, while the polling cadence bounds ordinary propagation
only when the publisher, network and local storage remain available.
