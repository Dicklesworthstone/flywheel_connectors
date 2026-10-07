# Owner-authorized mesh membership

This is an opt-in trust mode for the existing host mesh invoke path. The owner
signs one complete membership document, and each host independently pins the
owner public key and mesh identity. A peer's advertisement cannot appoint a new
trusted peer. This does not enable gossip membership, hot reload, remote-first
placement, or the broader mesh-native cutover.

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
configuration from [mesh invoke routing](mesh_invoke_routing.md). Replace the raw
peer array with the signed envelope and set **all three** membership options:

```sh
export FCP_HOST_MESH_PEERS_FILE=/config/signed-membership-1.json
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

## Renew, remove a peer, or rotate keys

Increment `generation` for every payload change, including expiry renewal,
endpoint changes, member removal, and member-key rotation. Stop the old host
process, install the newly signed document, and restart with the **same** state
path. No online reload or automatic distribution is implied.

A removed peer's key no longer verifies at the restarted host. Old generations
remain rejected even if their signatures and expiry windows are still valid.
Reusing a generation with different payload bytes is rejected as equivocation.
Re-signing identical payload bytes with another independently trusted owner is
allowed during a root-rotation overlap.

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
inventory, and stops returning cached peer inventories. It rechecks membership
after inbound queue/sync waits and after network discovery/reply waits.

Expiry before send is `NotDelivered`. Expiry after a send is `OutcomeUnknown`,
never evidence that another peer may safely execute the request. Already accepted
operations are not retroactively cancelled; reply signing remains available to
report known outcomes. This membership gate does not replace connector capability,
zone, lease, or revocation enforcement.

Leaving all membership options unset retains the existing explicitly trusted
static-directory mode. Setting only some options, passing a raw array in signed
mode, invalid signatures, or persistence failures never silently downgrades.

## Targeted checks

```sh
rch exec -- cargo test --locked -p fcp-mesh --lib peer_manifest
rch exec -- cargo test --locked -p fcp-host --lib mesh_routing::directory
rch exec -- cargo test --locked -p fcp-host --test mesh_peer_membership
rch exec -- cargo test --locked -p fcp-host --bin fcp-mesh-directory
```

The tests cover owner distrust, exact-byte tampering, scope/key binding,
generation rollback and reuse, restart replay protection, persistent corruption
and missing-state handling, unsafe inode rejection, exclusive activation, bounded
input, monotonic expiry, router refusal, and offline sign/verify round trips.
