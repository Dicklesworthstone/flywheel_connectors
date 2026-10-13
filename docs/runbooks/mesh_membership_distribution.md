# Distributing signed mesh membership

`fcp-mesh-directory sync` fetches an owner-signed directory and atomically
installs it at the file already watched by a signed-mode host. `watch` repeats
that authenticated delivery in a long-running process. These deliver validity
renewals, remote-peer additions/removals, and remote-peer key or endpoint changes
without restarting that host. They do not issue membership, appoint owners,
rotate the running host's own signing key, or change the host checkpoint.

## Configure the trust boundary

Use [owner-authorized membership](mesh_membership.md) to issue the signed JSON
offline and configure the host's independent owner root, mesh identity, local
signing key, and persistent checkpoint. Publish only the signed document at a
stable HTTPS URL. Never publish the owner's secret key.

Choose a stable writable source path in an existing trusted directory, for example
`/var/lib/fcp/signed-membership.json`. Use it as `FCP_HOST_MESH_PEERS_FILE`. Reserve
its `.sync-lock` and `.sync-next` companion names for the installer. Run the
installer as the host's OS user; installed sources are mode 0600. This namespace
must be separate from the host checkpoint, its companions, the replay journal,
and all key files. Do not run an unrelated editor or another distribution system
against this path while sync or watch owns it. The filesystem and parent
directories are part of the trusted boundary.

The installer needs only the independently trusted owner public key and this
host's public key, each as 64 hex characters in a bounded regular file. It never
accepts a secret signing key, a provider credential, or an authentication token.
Owner-root changes require an explicit operator-managed transition; a downloaded
signer cannot add itself to the locally pinned trust roots.

## Fetch and install once

```sh
rch exec -- cargo build --locked -p fcp-host --bin fcp-mesh-directory
./target/debug/fcp-mesh-directory sync \
  --url https://membership.example.net/personal-mesh.json \
  --owner-public-key-file /config/mesh-owner.pub \
  --mesh-id personal-mesh \
  --node-id node-a \
  --node-public-key-file /config/node-a.pub \
  --directory /var/lib/fcp/signed-membership.json
```

The source must use HTTPS, except literal loopback HTTP addresses for local
services and tests. DNS names over HTTP, URL credentials, query strings, and
fragments are refused. Requests carry no authorization header. Ambient proxies,
redirects, implicit HTTP retries, and response decompression are disabled. A
10-second deadline covers the request and streamed body; both declared and actual
body size are limited to the signed-directory envelope ceiling (4 MiB).

The JSON result distinguishes `installed` from byte-identical `unchanged` and
reports the accepted generation, previous generation, payload hash, member count,
and expiration. `rollback_checked: false` means first installation: there was no
previous installed document to compare. `host_activation_verified: false` is
intentional. Installation is not proof that a host has accepted the generation,
that every other node has refreshed, or that the mesh-native cutover is complete.
The host performs its own signature, checkpoint, expiration, and replay checks.

## Keep membership synchronized

Run one watcher per destination, normally under the host's service supervisor:

```sh
./target/debug/fcp-mesh-directory watch \
  --url https://membership.example.net/personal-mesh.json \
  --owner-public-key-file /config/mesh-owner.pub \
  --mesh-id personal-mesh \
  --node-id node-a \
  --node-public-key-file /config/node-a.pub \
  --directory /var/lib/fcp/signed-membership.json \
  --interval-secs 30 \
  --max-backoff-secs 300
```

The first attempt starts immediately. Successful `installed` or `unchanged`
results reset the remote-failure count. Consecutive remote failures use the
configured interval, twice that interval, and so on up to the backoff cap. Both
settings accept integer seconds from 1 through 3600; the cap must not be smaller
than the interval. Defaults are 30 and 300 seconds. There is no overlapping fetch
or unbounded request queue. Waits begin after each attempt completes.

When a known installed document has not yet expired, the next wait is shortened
to at most half its remaining wall-clock lifetime, with a one-second floor.
Expired documents return to ordinary bounded backoff rather than a busy loop.
This scheduling is not a renewal guarantee: HTTP latency, unavailable publishers,
filesystem work, and host activation add delay. Neither successful downloads nor
failed attempts extend a signed document's expiration.

The watcher pins its source URL, owner public key, mesh identity, and local public
key at startup. It holds the same installer lock across fetches, writes, and
waits. A second sync or watcher cannot take ownership of that destination. Stop
the watcher before changing local trust or manually replacing its source; restart
with the intended configuration and intact generation history. Owner-key file
changes are not silently adopted by the running process.

Each attempt emits and flushes one `fcp.mesh.directory_watch.v1` JSONL record.
`outcome` is `installed`, `unchanged`, `retrying`, or `fatal`. Records include the
attempt count, consecutive remote failures, next wait, and last known installed
generation and expiration. `installed_expired` compares that last verified
document with the local wall clock; it does not measure host readiness. On fatal
local-state errors the installed metadata is historical, not a claim that the
file remains intact. All records retain `host_activation_verified: false`.
Successful records include the ordinary sync report. URLs, response bodies, and
secret keys are not included. Startup failures go to stderr; output or flush
failure terminates the process rather than continuing without its reports.

Use normal service-manager termination to stop the process. There is no custom
signal handler or claim to drain an in-progress fetch on shutdown. The existing
synced staging file, atomic rename, initialization marker, and retained source
support restart after interruption. Never configure a supervisor to delete those
files as part of restarting the watcher.

## Failure and recovery behavior

Verification covers the independent owner, mesh scope, local key, exact signed
payload bytes, and current validity. The existing signed file is separately
authenticated as generation history, even if expired. An expired file cannot
grant current authority, but it still prevents replacing generation 8 with 7.
An otherwise valid higher generation can renew an expired installation.

The installer rejects generation rollback and different payload bytes at the
same generation. It locks a separate inode across replacement, validates regular
file/link/permission constraints, syncs staged bytes before rename, and syncs the
parent directory. A persistent initialization marker prevents a missing source
from silently becoming a new first installation. An interrupted reserved staging
file can be replaced only after its inode is validated. Corrupt installed data,
unsafe links, missing initialized state, and unsupported filesystem guarantees
fail closed. Installation currently requires Unix filesystem guarantees.

In one-shot sync, a fetch, status, size, signature, validity, or successor rejection
leaves the source unchanged and exits unsuccessfully, unless installation already
reached a potentially ambiguous post-write failure. Watch instead retries remote
failures with bounded backoff, retaining the previous signed file and its
anti-rollback history. It checks that the installed file still matches the last
expected bytes before fetching and again after a remote failure. An unavailable
publisher cannot conceal a deleted or externally replaced local source.

Local corruption, unsafe state, unexpected source changes, runtime initialization,
staging/rename/sync faults, or report-output failure stop the watcher. If an
unsuccessful installation changed the source, the watcher also stops rather than
retrying from stale in-memory history. Inspect the installed signed document and
persistent state before restarting: a failed write may already have taken effect.
Never delete the source, initialization marker, or host checkpoint to bypass a
rollback error. Restoring older filesystem backups is not a safe repair; signed
files and markers assume trusted persistent storage.

An unreachable publisher does not prolong authority. The host continues using
its independently verified directory only until its signed/monotonic deadline,
then refuses new mesh work. Installing a valid successor allows its existing
watcher to recover. Already accepted invokes are not retroactively cancelled.

## Focused regression command

```sh
rch exec -- cargo test --locked -p fcp-host --bin fcp-mesh-directory
```

Continuous-mode regressions include bounded backoff and reset, expiration-aware
polling, expired-history renewal, local corruption and missing state, exclusive
ownership during retries, ambiguous replacement refusal, report-flush failure,
and real HTTP polling through refusal, tampered signatures, successful successor
installation, and an attempted rollback. These are authored test cases, not a
claim of passing execution or deployed host activation.

## Redundant publishers for sync and watch

Both commands accept either the existing single URL or a JSON array of up to four
URLs as the value of `--url`. Quote the array as a single shell argument:

```sh
./target/debug/fcp-mesh-directory watch \
  --url '["https://membership-a.example.net/personal-mesh.json","https://membership-b.example.net/personal-mesh.json"]' \
  --owner-public-key-file /config/mesh-owner.pub \
  --mesh-id personal-mesh \
  --node-id node-a \
  --node-public-key-file /config/node-a.pub \
  --directory /var/lib/fcp/signed-membership.json \
  --interval-secs 30 \
  --max-backoff-secs 300
```

All URLs are validated before network I/O, normalized duplicates are refused, and
the source set remains pinned for the life of the watcher. The ten-second fetch
budget is shared across publishers rather than multiplied by their count. Each
sequential attempt receives a share of the remaining budget, preserving time for
later mirrors when the first is slow or unavailable. Per-response size limits and
all existing transport restrictions still apply. Runtime setup, local verification
and filesystem work are not a hard real-time scheduling guarantee.

Selection is not first-success failover: it chooses the highest generation among
completed, independently owner-authenticated responses. An unavailable publisher,
forged high-generation document or document for another mesh cannot outvote a
valid mirror. Equal authenticated generations must have the same exact payload
hash; conflicting payloads cause the attempt to fail before installation. Identical
payloads use stable source-order selection. Final current-time verification runs
again before returning the selected document to the durable installer.

If the highest authenticated generation is expired, future-dated or no longer
authorizes this node's key, selection fails rather than falling back to an older
mirror that still grants authority. This prevents a revocation observed during
that selection from being concealed by an older successful response. Observations
from rejected selection attempts are not durably stored; the persistent high-water
mark remains the last installed directory, not every rejected document ever seen.
The external watcher does not retroactively revoke the host's currently installed
lease: its existing signed expiration and host enforcement remain authoritative.

This is not publisher quorum or proof of the globally newest generation. An
unreachable publisher may hold a newer document, and publishers can withhold an
update. Signed expiry still bounds retained authority. Installation retains its
own rollback/equivocation checks against durable history, including across restart.
A rejected candidate does not cause source deletion, generation reset or a
permissive unsigned fallback.

Tests in `crates/fcp-host/src/bin/fcp-mesh-directory/sync/sources/tests.rs` cover
source-count/URL bounds, ordering, outages, forged high generations, wrong mesh,
equivocation, observed local revocation, expired/future authority, deadline shares,
local-runtime failure, and real loopback multi-publisher installation with durable
rollback refusal. These tests are authored but have not been executed here.

## Host-integrated remote source alternative

A signed-mode host can fetch directly instead of running an external installer.
Use a separate trusted local descriptor as `FCP_HOST_MESH_PEERS_FILE`:

```json
{
  "schema_version": "fcp.mesh.directory-source.v1",
  "directory_url": "https://directory.example/mesh/membership.json"
}
```

Keep `FCP_HOST_MESH_ID`, `FCP_HOST_MESH_DIRECTORY_OWNER_KEYS`,
`FCP_HOST_MESH_DIRECTORY_STATE`, node signing identity and replay storage configured
as in [mesh membership](mesh_membership.md). The publisher serves only the complete
signed envelope; it never appoints owner roots or provides secret credentials.
Descriptor size is bounded to 4 KiB and its URL to 2 KiB. The URL requires HTTPS
except literal loopback HTTP; credentials, query strings, fragments, whitespace
and redirects are rejected. A remote response cannot name another descriptor or
supply an unsigned peer array. Inline `FCP_HOST_MESH_PEERS` does not interpret
source descriptors.

**Choose one delivery mode per host source path.** Do not run sync/watch against
the descriptor file: the installer expects a signed document as durable generation
history, whereas the descriptor is configuration. Existing deployments that use
signed source files need no migration. The host-integrated descriptor currently
supports one publisher; redundant source sets are provided by sync/watch above.

At startup and on the existing one-second reload cadence, the host resolves the
descriptor and fetches a complete HTTP 200 response. A joined fetch thread keeps
its runtime bridge outside an existing executor; connection and full-fetch
budgets are one and three seconds, respectively. Declared and streamed envelope
size is limited to 4 MiB. No capability credentials, owner secrets, cookies or
ambient proxy configuration are supplied. Errors omit URLs and response bodies.
Request handlers do not perform these source reads. There is no overlapping
fetch within the membership worker.

The fetched bytes go through the same owner-signature, mesh/local identity,
validity and persistent generation checks as a signed file. A new checkpoint is
synced before peer publication. Key rotation, removal and endpoint replacement
preserve existing peer-continuity fencing and do not erase the replay journal.
The same generation cannot extend the original monotonic expiration.

This mode intentionally has stricter availability behavior than the external
watcher: an unavailable or invalid source fences new mesh work when the reload
fails, even before the last directory expires. A valid source can recover it,
but uncertain checkpoint writes require restart. Startup also requires a
reachable acceptable publisher; no offline bootstrap cache is supplied. The
existing external watcher remains the mode for retaining a verified local signed
source through publisher outages, bounded by that document's expiration.

Live-router tests in `crates/fcp-host/src/mesh_routing/directory/remote/tests.rs`
cover independent-owner bootstrap, live rotation/removal, retained replay history,
rollback across restart and publisher failure/recovery. Transport tests exercise
real loopback HTTP, descriptor/URL validation, exact signed bytes, no recursive
or unsigned fallback, status/redirect refusal and bounded/truncated bodies.
Compilation and execution of the new Rust tests remain outstanding:

```sh
rch exec -- cargo test -p fcp-host --lib mesh_routing::directory
rch exec -- cargo test --locked -p fcp-host --bin fcp-mesh-directory
rch exec -- cargo test -p fcp-host --test mesh_invoke_e2e
rch exec -- cargo clippy -p fcp-host --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

Neither delivery mode establishes mesh gossip, authenticated quorum health,
immediate revocation, or production proof of the complete mesh-native cutover.
