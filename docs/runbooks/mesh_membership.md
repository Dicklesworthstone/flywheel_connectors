# Owner-authorized mesh membership

This is an opt-in trust mode for the existing host mesh invoke path. The owner
signs one complete membership document, and each host independently pins the
owner public key and mesh identity. A peer's advertisement cannot appoint a new
trusted peer. File-backed signed documents support live renewal and remote-peer
membership changes. This does not enable automatic distribution, gossip
membership, remote-first placement, or the broader mesh-native cutover.

## Issue a membership generation offline

The `fcp-mesh-directory` binary signs and verifies documents without starting a
host, using provider credentials, or making network requests:

```sh
cargo build --locked -p fcp-host --bin fcp-mesh-directory
./target/debug/fcp-mesh-directory --help
```

Create `membership.json` with this payload shape. Replace the public-key and
clock placeholders; timestamps are Unix milliseconds, not seconds. Include the
local node entry for **every** host that will use the shared document.

```json
{
  "schema_version": "fcp.mesh.peer-directory.v1",
  "mesh_id": "personal-mesh",
  "generation": 1,
  "issued_at_ms": 0,
  "expires_at_ms": 1,
  "peers": [
    {
      "node_id": "node-a",
      "endpoint": "https://node-a.example:8443",
      "public_key_hex": "REPLACE_WITH_NODE_A_64_HEX_PUBLIC_KEY"
    },
    {
      "node_id": "node-b",
      "endpoint": "https://node-b.example:8443",
      "public_key_hex": "REPLACE_WITH_NODE_B_64_HEX_PUBLIC_KEY"
    }
  ]
}
```

The example timestamps are intentionally expired. Set an issuance time near the
current time and a later expiration appropriate for the deployment. The host
allows at most 30 seconds of future issuance skew; expiration is exclusive.

Keep the owner's 32-byte secret in a private, non-symlink, non-hard-linked file,
encoded as 64 hex characters. Do not put the key itself in an argument or an
inline environment variable. The owner secret is not deployed to mesh hosts.
Use a new output filename and shell noclobber to avoid overwriting another file:

```sh
chmod 600 /secure/mesh-owner.key
(set -C; ./target/debug/fcp-mesh-directory sign \
  --owner-key-file /secure/mesh-owner.key \
  --payload membership.json > signed-membership-1.json)
```

The output embeds the exact signed payload bytes. Do not edit `payload_json`
after signing. The signer public key inside the envelope is a selector, not a
trust root. Every host must receive the independently trusted owner public key
through its trusted configuration channel.

Verify for a specific host before installation; this needs only public keys:

```sh
./target/debug/fcp-mesh-directory verify \
  --owner-public-key-file /config/mesh-owner.pub \
  --mesh-id personal-mesh \
  --node-id node-a \
  --node-public-key-file /config/node-a.pub \
  --directory signed-membership-1.json
```

The JSON report explicitly says `rollback_checked: false`: this offline command
checks signature, mesh scope, local-key binding, and validity, but neither reads
nor changes a host's persistent checkpoint. The host makes the rollback decision.

## Activate on a host

Keep the existing node signing key, node id, peer endpoint, and durable replay
configuration from [mesh invoke routing](mesh_invoke_routing.md). Install the
signed envelope at the stable watched pathname and set **all three** membership
options:

```sh
export FCP_HOST_MESH_PEERS_FILE=/config/signed-membership.json
export FCP_HOST_MESH_ID=personal-mesh
export FCP_HOST_MESH_DIRECTORY_OWNER_KEYS='["REPLACE_WITH_OWNER_64_HEX_PUBLIC_KEY"]'
export FCP_HOST_MESH_DIRECTORY_STATE=/var/lib/fcp/node-a.membership
```

Do not also set `FCP_HOST_MESH_PEERS`. The owner-key option accepts 1–32 public
keys to support an explicit overlap during owner-key rotation. It never trusts
an embedded signer that is absent from that list.

The state parent directory must already exist on trusted persistent storage.
The checkpoint, its `.lock` file, and reserved `.next` staging file must use a
unique namespace, distinct from keys, input documents, and replay journals. Keep
that path stable for the lifetime of the node. One active router holds the lock
for its entire lifetime; a second process cannot activate another generation
against the same state, even with a different replay journal.

On Unix, the host rejects non-regular, group/other-accessible, symlink, and
hard-linked state files. Successful activation writes mode-0600 data, syncs it,
atomically replaces the checkpoint, syncs the parent directory, and persists an
initialization marker. Unsupported locking or directory sync fails startup.
Signed-mode persistence currently requires Unix filesystem guarantees.

## Renew, remove a remote peer, or rotate its key

Increment `generation` for every payload change, including expiry renewal,
endpoint changes, member removal, and member-key rotation. With a file-backed
signed source, atomically replace the configured source pathname with the newly
signed complete document. Keep the **same** checkpoint and replay-journal paths.
A dedicated worker checks the source every second, outside the async request
executor. File I/O and scheduling can delay observation; this is not an
instantaneous or mesh-wide revocation guarantee. Distribute each generation to
every host through the trusted configuration channel.

The worker verifies the independent owner roots, mesh identity, validity, local
signing-key binding, and successor generation before touching the checkpoint.
It fences new mesh work during checkpoint commit, then atomically publishes the
complete directory and its validity. Existing routers immediately use the new
snapshot after publication: additions become routing candidates, removals stop
admission, and new peer keys/endpoints replace old ones. Discovery caches bind
both positive and negative entries to the exact peer key and endpoint; old
inventories cannot remain authoritative merely because their local TTL is live.
Replay journals, nonce history, admission limits, and active reservations survive
membership publication unchanged.

Old generations remain rejected even if their signatures and expiry windows are
still valid. Reusing a generation with different payload bytes is rejected as
equivocation. Re-signing identical payload bytes with another independently
trusted owner is allowed during a root-rotation overlap, but cannot reset the
monotonic expiry deadline. A higher valid generation can restore service after
expiration. Inline `FCP_HOST_MESH_PEERS` documents are startup-only and still
require restart to replace. Changes to the host's own signing key, pinned owner
roots, or mesh identity also require restart; every accepted document must still
authorize the running host's actual key.

A missing, unreadable, untrusted, invalid, or rolled-back source fences new mesh
work after observation without advancing the checkpoint. A valid permitted
replacement can recover service. Ambiguous checkpoint failures are different:
once persistence may have changed, the worker stays fenced and requires restart
against trusted storage rather than resuming from stale in-memory state. Shutdown
joins the worker before releasing the checkpoint lock. The structured events
`mesh_membership_reloaded` and `mesh_membership_reload_refused` report activation
or refusal without logging the membership document or secret keys.

Never delete or replace the checkpoint with an older backup to resolve an error.
A missing checkpoint after initialization, corrupt checksum, foreign node/mesh
binding, or recorded clock rollback fails closed. The `.next` file is reserved
for recovery of interrupted checkpoint writes and is never an operator input.
These checks assume trusted storage; checksums do not prevent an attacker with
full filesystem control from rolling back both state and its marker.

## Expiration and request outcomes

A running router enforces both wall-clock expiration and a monotonic deadline.
Once expiry is observed, clock rollback cannot revive that directory. It refuses
new inbound admission and outbound forwarding, withdraws advertised connector
inventory, and stops returning cached peer inventories. It rechecks the exact
membership snapshot after inbound queue/sync waits and after discovery/reply waits.

Requests crossing any published generation change are conservatively refused,
even when the new generation only renews validity. This prevents an in-flight
request from surviving a remove-and-readd sequence unnoticed. A queued inbound
request may consume its nonce without dispatch; the nonce is never rolled back.
Expiration or a generation change before send is `NotDelivered`. After delivery
may have occurred, refusal is `OutcomeUnknown` (or another non-retryable transport
or verification failure), never evidence that another peer may safely execute the
request. Already accepted operations are not retroactively cancelled; reply
signing remains available to report known outcomes. This membership gate does not
replace connector capability, zone, lease, or revocation enforcement.

Leaving all membership options unset retains the existing explicitly trusted
static-directory mode. Setting only some options, passing a raw array in signed
mode, invalid signatures, or persistence failures never silently downgrades.

## Targeted checks

```sh
rch exec -- cargo test --locked -p fcp-mesh --lib peer_manifest
rch exec -- cargo test --locked -p fcp-mesh --lib invoke_route
rch exec -- cargo test --locked -p fcp-host --lib mesh_routing
rch exec -- cargo test --locked -p fcp-host --test mesh_peer_membership
rch exec -- cargo test --locked -p fcp-host --bin fcp-mesh-directory
```

Regression cases cover owner distrust, exact-byte tampering, scope/key binding,
generation rollback and reuse, restart replay protection, persistent corruption
and missing-state handling, unsafe inode rejection, exclusive activation, bounded
input, monotonic expiry, live file renewal/rotation/removal, discovery cache
identity changes, queued admission across revocation, and a delivered forward
whose signed reply crosses a membership change. These are test cases in the
repository, not a claim of successful execution or deployed mesh cutover.
