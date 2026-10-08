# Distributing signed mesh membership

`fcp-mesh-directory sync` fetches an owner-signed directory and atomically
installs it at the file already watched by a signed-mode host. This delivers
validity renewals, remote-peer additions/removals, and remote-peer key or endpoint
changes without restarting that host. It does not issue membership, appoint
owners, rotate the running host's own signing key, or change the host checkpoint.

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
against this path while sync owns it. The filesystem and parent directories are
part of the trusted boundary.

The installer needs only the independently trusted owner public key and this
host's public key, each as 64 hex characters in a bounded regular file. It never
accepts a secret signing key, a provider credential, or an authentication token.
Owner-root changes require an explicit operator-managed transition; a downloaded
signer cannot add itself to the locally pinned trust roots.

## Fetch and install

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

A fetch, status, size, signature, validity, or successor rejection leaves the
installed source unchanged and exits unsuccessfully. A rename or sync failure is
potentially ambiguous: inspect the installed signed document rather than assuming
nothing changed. Never delete the source, initialization marker, or host
checkpoint to bypass a rollback error. Restoring older filesystem backups is not
a safe repair; signed files and markers assume trusted persistent storage.

An unreachable publisher does not prolong authority. The host continues using
its independently verified directory only until its signed/monotonic deadline,
then refuses new mesh work. Installing a valid successor allows its existing
watcher to recover. Already accepted invokes are not retroactively cancelled.

## Focused regression command

```sh
rch exec -- cargo test --locked -p fcp-host --bin fcp-mesh-directory
```
