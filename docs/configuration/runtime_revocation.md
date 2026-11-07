# Signed revocation feeds for live host authorization

The host can load a continuously renewed, owner-signed revocation snapshot for
each execution zone. It checks the current file during capability admission,
again at connector dispatch, and when authorizing native event and host-egress
requests. Revoking an issuance key or its attesting node rejects every token
below that authority through the existing bounded revocation cascade walker.

Set `FCP_HOST_REVOCATION_CONFIG_FILE` before starting the host:

```json
{
  "zones": [{
    "zone_id": "z:work",
    "owner_public_key_hex": "<64 hexadecimal digits for the trusted zone-owner public key>",
    "snapshot_file": "/run/fcp/revocations/work.json",
    "checkpoint_file": "/var/lib/fcp/revocations/work.json"
  }]
}
```

```bash
export FCP_HOST_REVOCATION_CONFIG_FILE=/etc/fcp/revocation-feeds.json
```

The public key is pinned independently in startup configuration. It is the zone
owner that authorizes the entire issuer-to-node-to-owner chain, not a key supplied
by a request or discovered in the snapshot. The host never needs its private key.
Provide one feed for every zone this host will serve: once configuration is
enabled, requests in an unconfigured zone are refused. One to sixteen unique
zones are supported. Without the environment variable, existing host enforcement
is unchanged; the host does not claim to have a live revocation feed.

All configured paths must be distinct absolute files without `..`. Provision the
source directory for the trusted publisher, and the checkpoint directory on
durable local storage owned by the host user, with mode `0700`. The host creates
the checkpoint and its reserved `.lock` and `.next` companions with mode `0600`.
State files must be private, singly linked Unix regular files; symlinks are
refused. Every ancestor is checked for symlinks and unsafe write access; a
root-owned sticky ancestor such as `/tmp` is allowed. The checkpoint parent must
belong to the host user, with ancestors owned by that user or root. Path aliases
(including hard links and reserved companion aliases) are rejected before any
checkpoint writes. Use real paths where the platform has aliases such as `/var`.
The checkpoint has an exclusive writer lock for the host's lifetime. Protect the
startup configuration from untrusted replacement. This implementation requires
Unix storage semantics.

## Publish a snapshot

Use `fcp_host::RuntimeRevocationSnapshot::sign(&owner)` with the existing FCP
`Ed25519SigningKey`, or run the included publisher:

```bash
cargo run -p fcp-host --example sign_revocation_snapshot -- \
  /secure/zone-owner.seed /secure/work-revocations-payload.json \
  /run/fcp/revocations/work.json
```

`zone-owner.seed` contains the **existing owner's 32 raw secret bytes**, in a
private regular file. Keep it on the trusted publisher, not on the gateway.
Do not generate a different signing key on each renewal. The example prints only
the public key to help provision `owner_public_key_hex`, signs the provided
payload, and publishes the envelope by file sync, atomic rename, and directory
sync. It never invents observations or advances generations for you.

The unsigned payload has this shape; replace the timestamps, key IDs and zone
with real values before signing:

```json
{
  "schema": "fcp.host.revocation-snapshot.v1",
  "zone_id": "z:work",
  "generation": 1,
  "issued_at_ms": 1794000000000,
  "expires_at_ms": 1794000060000,
  "issuance_to_node": [
    [[1,2,3,4,5,6,7,8], [9,10,11,12,13,14,15,16]]
  ],
  "node_to_owner": [
    [[9,10,11,12,13,14,15,16], [17,18,19,20,21,22,23,24]]
  ],
  "tokens": [],
  "keys": [{
    "kid": [1,2,3,4,5,6,7,8],
    "hop": "issuer_key",
    "revoked_at_ms": 1793999999000
  }]
}
```

Key IDs are the eight bytes returned by `Ed25519VerifyingKey::key_id()`; the final
owner ID must derive from the public key pinned in configuration. Use actual
attested issuance and node keys. For a token signed directly by the pinned owner,
an empty chain is sufficient. Unknown issuers and incomplete, ambiguous or
cyclic chains are rejected. Every node edge must terminate at the pinned owner.

Key revocation scopes are `issuer_key`, `node_attestation`, and
`owner_attestation`. Owner revocation also rejects tokens signed directly by that
owner. A direct entry in `tokens` has `token_id` (the ObjectId's 64-character
hexadecimal serialization) and `revoked_at_ms`. Match host token identity: a
32-byte CWT `jti` is the ObjectId directly; any other `jti` is hashed with
`ObjectId::from_unscoped_bytes`; without `jti`, hash the capability's raw COSE
CBOR using that same function. Prefer explicit 32-byte token identifiers.

Renew with a strictly larger positive generation, current Unix-millisecond
issuance time, and an expiry at most 300,000 milliseconds after issuance. A
60-second lifetime with renewal well before expiry is a useful starting point.
Publish all permanent revocations cumulatively, retaining each original or an
earlier revocation timestamp. Future-effective entries are rejected. The host
allows at most five seconds of issuance-clock skew and refuses the snapshot at
its exact expiry. Its clock advances monotonically while running even if the
wall clock moves backwards; a restart also refuses wall time older than the
last persisted observation. Maintain a trustworthy UTC clock across restarts.

The payload is canonical CBOR under domain `fcp.host.revocation-snapshot.v1`,
carried by the existing FCP `SignedEnvelope` with `ClassicalOnly` policy. This
feature explicitly supports the current Ed25519 host mode; it does not claim
post-quantum attestation, automatic mesh discovery or a gossip subscription.

## Failure and recovery behavior

A valid initial snapshot and writable checkpoint are required before the host
starts. Every later check rereads and verifies the current source. Missing,
corrupt, forged, wrong-zone or expired files immediately close this authorization
boundary; a previous successful read is never a fallback. Snapshot and checkpoint
files are bounded to 1 MiB, with at most 4096 cumulative revocations and 1024
historical attestation edges. Configuration is bounded to 64 KiB.

The checkpoint durably records the highest observed authenticated generation,
permanent revocations, and first-observed attestation bindings. An existing
issuance key cannot be reparented away from a revoked node. Rotate to a new
issuance key when changing its attesting authority. Node and issuance key roles
must also remain distinct, including across previously observed snapshots;
reusing a revoked node as a fresh issuance key is rejected. A snapshot may omit old
issuers to stop admitting them, but cannot later reuse their IDs under a
different binding. Revocation removal or a changed binding is a durable refusal;
publish a strictly newer snapshot consistent with all recorded history to recover.

Conflicting signatures for the same generation persist a refusal across restart
and retain the union of all observed permanent revocations. A newer, complete
snapshot can resolve the conflict. An authenticated expired successor still
advances the generation floor, so replacing it with an older healthy snapshot
does not reopen admission. Observed expiry is persisted before refusal so a
restart cannot reverse an already observed expiry by rolling back the clock.
If contradictory histories overflow bounded capacity,
the host persists a terminal refusal requiring explicit operator recovery with
new authority identities. Storage write or sync failures latch refusal until the
service is reopened against repaired, valid state.

On restart, a completed `.next` write is checked against all durable history and
published before any current source can authorize work. Incomplete, corrupt or
weakening staging files refuse startup; a failed rename cannot silently discard
new revocations and restore an older healthy source.

Keep the checkpoint and its `.lock` companion together during backups and
recovery. A missing checkpoint after initialization, a different zone or owner,
or a corrupt checkpoint refuses startup. Its checksum detects accidental
corruption; integrity against an attacker who can rewrite the entire trusted
state directory or restore an older backup requires external durable-state
protection. Never reset these files to clear a revocation.

Reads and signature checks use bounded synchronous local-file operations;
publishing a newly observed generation also synchronizes its checkpoint before
authorizing work. Use trusted local storage. The file-size bounds and Unix
nonblocking flags do not bound delays from a stalled or remote filesystem.
