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
