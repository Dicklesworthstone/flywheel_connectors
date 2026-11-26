# Connector State Externalization Runbook

> Bead: `flywheel_connectors-hr0rr.2.2`

Use this runbook when operating or debugging mesh-native connector state after
local connector state files have become cache-only data and canonical state is
stored through `fcp-store`.

## Runtime Contract

Canonical connector state is a `ConnectorStateRoot` chain in `fcp-store`.
The host may keep local files under the connector state root, but any directory
containing `.fcp-cache-only` is an operator-visible cache and is not the source
of truth.

The expected local cache layout is:

```text
<state-root>/<connector-id>/cache/.fcp-cache-only
<state-root>/<connector-id>/cache/<zone>/.fcp-cache-only
```

Inspect the selected host with an owner credential. The query zone selects the
state or lease being inspected. The bearer authenticates the operator in the
owner zone.

```bash
fwc --host https://node-b.example.invalid connector state explain \
  --connector <id> --zone z:work --admin-token-file ./host-admin.token --json
fwc --host https://node-b.example.invalid connector lease status \
  --connector <id> --zone z:work --admin-token-file ./host-admin.token --json
```

Both commands also accept the bearer from `FCP_HOST_ADMIN_BEARER_TOKEN`.
Use HTTPS, a Unix socket, or literal loopback HTTP. The state report includes
`canonical_storage`, verified canonical state or cache-marker evidence, and the
scope observed by the host. Use `--offline` for local artifacts.

## Runtime Lifecycle and State Handoff

Persisted `disabled` and `uninstalled` intent suppresses runtime launch during
host startup and managed inventory reload. The connector remains visible as a
dormant inventory entry with its admitted manifest and configuration; it is not
advertised as an executable mesh route. An explicit lifecycle `enable` prepares
and configures a runtime before allowing execution. Failed preparation preserves
the disabled authority, and dry-run enable validates configuration without
starting a process.

For a native connector with an admitted `stateless` manifest and `on_demand`
prewarm strategy, `disable` and `uninstall` persist the execution denial, drain
the selected native dispatcher, and confirm that its exact child exited before
reporting `stopped`. `restart` retires that dispatcher before starting its
replacement, including when the old dispatcher was poisoned or already exited.
Previously retained references cannot revive the retired actor. Re-enabling a
runtime retained after an incomplete disable also requires retirement and fresh
preparation. Each transition has a 30-second deadline including transaction
queueing; inspect desired and observed status after a timeout before retrying.

Live stateful handoff, whole warm-pool retirement, and whole WASI-runtime
retirement remain unavailable. A requested disable still persists execution
denial when retirement is unsupported or times out, but returns an error and
does not report the retained runtime as stopped. Stateful restart refuses before
changing intent. Do not treat a disabled dispatch gate as proof of a canonical
state flush or completed ownership transfer. A retained stateful runtime cannot
be re-enabled through this lifecycle path without a supported handoff.

In-place lifecycle `reload` returns an explicit unavailable error. Use managed
configuration preview/apply for supported inventory changes; their existing
state-authority and replacement checks still apply. A failed health probe during
a lifecycle transition is reported as degraded rather than treated as proof of
process exit. Runtime preparation still observes the host's resilience policy;
an open circuit can refuse replacement configuration and leave the connector
disabled until a later retry succeeds.

## Inspect Authenticated Canonical Stores

The host's canonical state explanation, durable lease status, and
flush-before-yield barrier read the writer's existing `fcp-store` data. A store
written with authenticated V2 WAL or snapshot envelopes requires its MAC key
on these read paths as well as its object-ID derivation key. Object and symbol
stores may use different MAC keys; the host never derives either from the
object-ID key or substitutes one store's key for the other.

Every canonical reader also requires independently configured writer authority.
A zone's object-ID key and a store MAC authenticate stored bytes; neither grants
every key named inside those bytes permission to write this connector's state.
The host checks each loaded state writer against the operator's pinned Ed25519
public keys, including when the WAL and snapshot MACs are valid.

Configure keys in the connector's managed inventory **`env` map**. These are
per-connector declarations, not ambient variables read from the host shell:

```json
{
  "env": {
    "FCP_CONNECTOR_STATE": "/srv/fcp/state",
    "FCP_HOST_CONNECTOR_STATE_OBJECT_ID_KEY": "<REDACTED_OBJECT_ID_KEY_64_HEX>",
    "FCP_HOST_CONNECTOR_STATE_OBJECT_MAC_KEY": "<REDACTED_OBJECT_STORE_MAC_KEY_64_HEX>",
    "FCP_HOST_CONNECTOR_STATE_SYMBOL_MAC_KEY": "<REDACTED_SYMBOL_STORE_MAC_KEY_64_HEX>",
    "FCP_HOST_CONNECTOR_STATE_READ_AUTHORITY": "{\"trusted_writer_keys_hex\":[\"<WRITER_PUBLIC_KEY_64_HEX>\"],\"instance_id\":null}"
  }
}
```

The object MAC authenticates
`<state-root>/<sanitized-connector-id>/store/objects`; the symbol MAC
authenticates the sibling `symbols` directory. Each value is exactly 32 bytes
encoded as 64 hexadecimal digits, optionally prefixed with `hex:` or `0x`.
Surrounding whitespace is accepted. The connector-prefixed aliases
`FCP_CONNECTOR_STATE_OBJECT_MAC_KEY` and `FCP_CONNECTOR_STATE_SYMBOL_MAC_KEY`
are also accepted. If both aliases for one store are supplied, they must
decode to the same key. Blank, malformed, and conflicting declarations are
rejected during static inventory validation before preparing a runtime.

`FCP_HOST_CONNECTOR_STATE_READ_AUTHORITY` contains a JSON object of at most
8 KiB. Its `trusted_writer_keys_hex` array must contain 1–64 distinct valid
Ed25519 public keys, each encoded as exactly 64 hexadecimal digits without a
prefix. Repeated keys, invalid or weak keys, unknown fields, and malformed
instance identifiers fail static inventory validation. The public-key roster
may retain both previous and current writers during an explicitly authorized
rotation; the existing monotonic writer-fencing checks still apply.

The optional `instance_id` names the exact persisted state instance. Omission
or `null` selects only instance-unscoped state, and never selects another
instance implicitly. Use the same scope and writer roster as the trusted state
being inspected. These declarations are read from the managed inventory, never
from connector introspection, stored self-signed records, or ambient shell
variables. They are independent of state-transfer grants and do not authorize
activation, replica import, lease issuance, or additional writes.

The MACs must match the keys used by the store's writer. This configuration
does not enable authenticated writes, rotate a key, or migrate existing data.
With a MAC configured, an unauthenticated V1 envelope is refused; with no MAC
configured, an authenticated V2 envelope is refused. An absent declaration
continues to support existing unkeyed stores. The host never retries a failed
authenticated open without its key. Configure an object MAC independently
when only the object store exists; a symbol store is not required for lease
inspection or the yield barrier.

These operations open stores read-only, including while a writer holds its
exclusive lock. They do not repair WAL tails, create snapshots, acquire writer
ownership, or alter the persisted bytes. Wrong or missing keys leave canonical
state unproven, and the yield barrier fails rather than reporting a successful
flush. Missing writer authority or a chain signed by an unpinned writer also
leaves state and lease evidence unproven and refuses the yield barrier. A valid
authority for a different instance reports no matching root; it does not
borrow another instance's head or lease. Canonical-state secret key values are
redacted from inventory mutation responses; configuration snapshots, revision
history, and diffs also redact
MAC and object-ID key fields. A redacted response is not reusable key material.

### Bound Canonical Inspection Work

State explanation, durable lease evidence, and the yield barrier share bounded
observational readers. Each store may consume at most 64 MiB of encoded snapshot
plus WAL input and retain at most 64 MiB of charged live object or symbol state
by default. Historical WAL records count even when their effects are already
checkpointed or idempotent. The reader captures the WAL length at open, so a
live writer cannot extend an inspection indefinitely by continuing to append.

One inspection has a 10-second deadline and a shared allowance of 65,536 object
reads. Root discovery, writer-signature and fork verification, ancestry traversal,
and subsequent lease reads all consume that same allowance. A requested result
limit does not replace full-history authentication. If authentication cannot
finish within the allowance, state remains unproven and yielding the lease is
refused; the host never returns a partially verified chain as authoritative.

For larger operational stores, configure `FCP_HOST_CONNECTOR_STATE_READ_LIMITS`
in the same managed inventory `env` map. It contains JSON of at most 1 KiB;
omitted fields retain their defaults:

```json
{
  "max_recovery_bytes": 134217728,
  "max_live_bytes": 134217728,
  "max_object_reads": 131072,
  "timeout_ms": 20000
}
```

Byte limits apply independently to each object and symbol store. Values must
be positive; the maximum is 1 GiB for each byte limit, 1,000,000 object reads,
and 60,000 milliseconds. Unknown or duplicate fields and invalid values fail
static inventory admission. These limits control observation, not the writer's
storage quota. Increase them deliberately for known store sizes, or compact the
WAL through its owning writer; the observing host never repairs or compacts it.

At most four complete inspections are admitted concurrently. Excess requests
receive an explicit capacity error. Directory metadata checks and disk recovery
run off the asynchronous executor, and an expired or cancelled caller does not free a worker's slot
until its outstanding disk operation actually exits. A stuck filesystem can
therefore occupy a slot after the response deadline, but cannot create an
unbounded queue of replacement workers. Successful recovery preserves the
same read-only, MAC, object-ID, writer-pin, and instance checks described above.

### Inspect a released object writer before handoff

For a singleton writer, POST to
`/rpc/admin/connectors/{connector_id}/lease/flush-before-yield?zone=z%3Awork&require_writer_idle=true`
using the host's owner-admin credentials. The host opens the existing durable
object-store lock file read-only and attempts a shared lock before recovering
the snapshot and WAL. An active object writer, missing lock file, torn WAL or
failed authority check prevents a successful strict observation.

A successful response includes `flush.object_writer_excluded_during_read: true`
alongside the verified root, head and lease sequence, if present. The lock
spans local recovery and canonical ancestry verification and is released by the
time the caller receives the response. It does not establish that a connector
process stopped, that symbol writers drained, that the lease transferred, or
that a writer cannot reopen afterward. Keep the old writer fenced before using
the observed root in a transfer. Requests omitting `require_writer_idle`
continue to inspect a committed prefix alongside an active writer and return
`flush.object_writer_excluded_during_read: false`.

## Retain an Exact Root on Another Host

Singleton state history preserves writer ownership across recovery. A state
signed by a different writer key must carry a strictly newer `lease_seq` than
its predecessor, even when both public keys are trusted. The same writer may
renew a lease without incrementing that token, including replacing the lease
object's content ID. A lower token always fails. The shared rule applies to
live appends, restored canonical roots, snapshot tails, and replica
import/export/inspection; importing a correctly signed history cannot bypass
writer fencing. CRDT state does not use this singleton rule.

`fwc connector state pull` transfers a granted `ConnectorStateRoot`, its
validated state ancestry, and the payload objects referenced by that ancestry
from a configured donor into a recipient's durable, host-owned replica store.
Select the exact root from trusted operator evidence;
the command does not discover `latest` or establish that this root is fresh.
Neither a mesh peer signature nor possession of a grant ID authorizes transfer
without the matching local grant on each host.

Both hosts need mesh routing and a private host listener: loopback TCP or a Unix
socket. Expose remote mesh endpoints through an HTTPS reverse proxy that
preserves this private ingress boundary. Remote configured peer URLs must use
HTTPS; HTTP is accepted only for literal loopback IP addresses in local setups.
DNS names such as `localhost` do not receive that exception, and
`X-Forwarded-*` headers do not establish confidential transport.

### Configure the Donor and Recipient

Set `FCP_HOST_CONNECTOR_STATE_TRANSFER_CONFIG_FILE` to the local JSON
configuration file on each host before startup. The file contains secret zone
key material and must remain operator-controlled. The following examples are
templates: replace every angle-bracket placeholder, including the **future**
RFC 3339 UTC expiry. Each key placeholder stands for exactly 64 hexadecimal
digits (32 bytes); use the existing zone object-ID key and trusted Ed25519
writer public keys. Do not copy redacted values or obtain writer pins from the
peer's transfer response.

Donor `node-a`, exporting only the selected root to `node-b`:

```json
{
  "replica_root": null,
  "stores": [{
    "scope": {
      "connector_id": "slack:chat:v1",
      "zone_id": "z:work",
      "instance_id": "inst-primary"
    },
    "object_id_key_hex": "<REDACTED_ZONE_OBJECT_ID_KEY_64_HEX>",
    "trusted_writer_keys_hex": ["<TRUSTED_WRITER_PUBLIC_KEY_64_HEX>"],
    "source_objects_dir": "/srv/fcp/canonical/slack/objects",
    "source_mac_key_hex": "<REDACTED_SOURCE_MAC_KEY_64_HEX>",
    "source_max_recovery_bytes": 67108864,
    "retain_replica": false,
    "max_store_bytes": 67108864
  }],
  "grants": [{
    "grant_id": "recover-slack-root",
    "direction": "export",
    "peer_node": "node-b",
    "scope": {
      "connector_id": "slack:chat:v1",
      "zone_id": "z:work",
      "instance_id": "inst-primary"
    },
    "root_object_id": "<TRUSTED_ROOT_OBJECT_ID_64_HEX>",
    "expires_at": "<FUTURE_EXPIRY_RFC3339_UTC>",
    "limits": {
      "max_objects": 128,
      "max_canonical_bytes": 1048576,
      "max_wire_bytes": 2097152
    }
  }]
}
```

`source_objects_dir` is an optional absolute path to existing durable objects.
The optional `source_mac_key_hex` must match that source's authenticated
envelopes; omit it or set it to `null` for a source written without a MAC.
The source is captured as a read-only view at startup, without acquiring a
second writer or repairing its WAL. The selected root, all required state
objects, and their referenced payloads must already be present in that captured
view. Missing objects fail
the transfer; subsequent source writes do not refresh the view. Restart the
host to reload source state, grants, expiry, or writer pins.

Donor startup charges the encoded snapshot and WAL together against
`source_max_recovery_bytes`, including historical records. The default is
64 MiB. Set a value from 1 byte through 1 GiB for a larger or smaller source.
During replay the live canonical objects must also fit `max_store_bytes`.
Both limits apply to the entire captured source directory, including objects
outside the granted root. If recovery exceeds either limit, startup refuses
the source. To reduce a long WAL, checkpoint the canonical writer before
restarting the donor. Only set `source_max_recovery_bytes` on stores that
specify a source directory.

Recipient `node-b`, importing the same root only from `node-a`:

```json
{
  "replica_root": "/srv/fcp/retained-state",
  "stores": [{
    "scope": {
      "connector_id": "slack:chat:v1",
      "zone_id": "z:work",
      "instance_id": "inst-primary"
    },
    "object_id_key_hex": "<REDACTED_ZONE_OBJECT_ID_KEY_64_HEX>",
    "trusted_writer_keys_hex": ["<TRUSTED_WRITER_PUBLIC_KEY_64_HEX>"],
    "source_objects_dir": null,
    "source_mac_key_hex": null,
    "retain_replica": true,
    "replica_max_recovery_bytes": 67108864,
    "max_store_bytes": 67108864
  }],
  "grants": [{
    "grant_id": "recover-slack-root",
    "direction": "import",
    "peer_node": "node-a",
    "scope": {
      "connector_id": "slack:chat:v1",
      "zone_id": "z:work",
      "instance_id": "inst-primary"
    },
    "root_object_id": "<TRUSTED_ROOT_OBJECT_ID_64_HEX>",
    "expires_at": "<FUTURE_EXPIRY_RFC3339_UTC>",
    "limits": {
      "max_objects": 128,
      "max_canonical_bytes": 1048576,
      "max_wire_bytes": 2097152
    }
  }]
}
```

Keep the grant ID, scope and root identical across these two configurations;
the direction and peer binding intentionally reverse. Each host enforces its
own expiry and limits. Omit `instance_id` on both hosts and the CLI only for
state that is explicitly instance-unscoped. A store requires at least one
trusted writer pin and a positive `max_store_bytes`. This bounds live objects
during donor and recipient recovery and is the retained store's write quota.
Each grant separately limits the objects and bytes permitted in a transfer.

`retain_replica: true` requires an absolute `replica_root`. The host retains
exclusive store ownership under
`<replica_root>/connector-state-replicas-v1/<scope-digest>/objects`, separate
from live connector state. Replica WAL records use a MAC key derived from the
configured zone object-ID key under the
`fcp.host.connector-state-replica.wal.v1` domain. When no source directory is
configured, explicit export grants can also serve this retained replica,
sharing the same backing store, append lock and cache invalidation state.
No connector process or local installation is required to retain a replica.

On recipient startup, `replica_max_recovery_bytes` limits the combined
encoded snapshot and WAL for each retained store. It defaults to 64 MiB and
accepts a positive byte count. The host verifies the durable envelopes and
object IDs while holding the exclusive writer lock. It may truncate an
incomplete final WAL append only after admitting the full input and validating
the preceding records. If a valid store outgrows its startup budget, raise
`replica_max_recovery_bytes` to cover the two file lengths before restarting.
If its live objects exceed `max_store_bytes`, raise that quota as well.

### Pull the Configured Root

Send the request to the **recipient** host. `--peer` names the configured donor
node, never an arbitrary URL. This example matches the narrower grants above:

```bash
fwc --json --host https://node-b.example.invalid connector state pull \
  --connector slack:chat:v1 \
  --zone z:work \
  --instance inst-primary \
  --peer node-a \
  --grant recover-slack-root \
  --root '<TRUSTED_ROOT_OBJECT_ID_64_HEX>' \
  --max-objects 128 \
  --max-canonical-bytes 1048576 \
  --max-wire-bytes 2097152 \
  --admin-token-file /run/secrets/node-b-admin-token
```

The admin secret belongs to the recipient and can alternatively come from
`FCP_HOST_ADMIN_BEARER_TOKEN`. The CLI sends it to the recipient's protected
owner-zone route, `POST /rpc/admin/connectors/{connector_id}/state/pull`, and
does not forward it to the donor. It follows no redirects and performs no
automatic retries.

CLI defaults are 4096 objects, 4194304 canonical bytes, and 4194304 wire bytes.
All three requested limits must fit both grants, so specify narrower limits
when the grants are smaller. Objects include the root, every state in its
ancestry, and every distinct referenced payload; canonical bytes include
object headers and bodies; wire bytes cover the complete inner JSON export
response. These are separate limits, and JSON encoding can exceed the
canonical byte count.

The client deadline defaults to 30 seconds (`--timeout-ms 30000`, maximum
300000); each host transfer handler has a 60-second deadline. A timeout or
disconnected response leaves publication unconfirmed: an already admitted
durable write can still finish. Grant expiry and continuous peer authority are
checked again before publication admission, but cannot undo that admitted
write.

A successful response reports the exact donor, grant, scope and root, resource
counts, and `replica_only: true`. `replica_root_published: true` means a newer
comparable root was published in the retained replica. `false` means a
duplicate or older comparable root was verified without replacing its current
root; the requested root is not a claim about the replica's current head.
Conflicting branches are rejected.

Payload transfer follows `header.refs` from authenticated signed state objects
and then transitively from their referenced objects. Shared objects count once.
Each object must have a valid zone-keyed content ID in the granted zone;
foreign-zone references, missing dependencies, unrelated extra objects, and
reference paths deeper than 64 payload objects are rejected. Extra references
on the unsigned root cannot expand transfer authority. Encrypted payloads remain
opaque: replication validates and retains their exact bytes without decrypting
them or inferring plaintext state from them.

The recipient validates the entire bundle before changing storage. It retains
payloads and signed state objects before publishing the selected root, using
its own retention policy. A failed or cancelled transfer can leave verified
dependencies behind without publishing a new root. Inspection and export use
the same dependency traversal and resource accounting, so a root with missing
payloads cannot be reported as a complete retained replica.

The operation excludes state lease references, connector snapshots, and other
canonical state histories. It does not discover unreferenced execution results
or receipts, grant lease authority, activate live connector state, resolve
uncertain invocations, or resume execution. Its metadata also makes no
mesh-wide availability or freshness
claim.

## Rollback

Rollback is an operational routing choice, not a data deletion operation.

1. Keep `FCP_TRUTH_PRECEDENCE_DEFAULT=v1` or unset the variable so the host uses
   the host-first path.
2. Run:

   ```bash
   fwc connector state explain --connector <id> --json
   ```

3. Confirm `canonical_storage` is `local` or `both` before relying on local
   files for incident recovery.
4. Do not remove mesh objects, cache directories, or `.fcp-cache-only` markers
   during rollback. They are evidence and recovery inputs.

If rollback is needed because a mesh write path is unhealthy, leave the
`fcp-store` object chain intact and switch reads to the host-first cache path
until canonical mesh reads are healthy again.

## Recovery

1. Capture current state:

   ```bash
   fwc connector state explain --connector <id> --json
   ```

   Preserve `schema_version`, `canonical_storage`, `local_cache_present`,
   `local_cache_path`, `local_cache_marker_present`, `cache_marker.present`,
   `last_canonical_seq`, and any `warnings`.

2. If `canonical_storage` is `mesh`, inspect the latest root and snapshot with
   the host or fcp-store diagnostic surface that owns the deployment. The
   recovered head sequence must be at least the last committed sequence that the
   connector acknowledged.

3. If `canonical_storage` is `local`, treat the local path as host-first
   canonical only until the host writes cache markers and proves fcp-store
   replication. Do not edit the file while a connector process is running.

4. If both cache and mesh are unavailable, fail closed. The caller should see a
   typed `ConnectorStateError::StorageUnavailable` or host-level
   connector-state unavailable error rather than stale state.

5. After recovery, run the explain command again and compare
   `last_canonical_seq` and cache marker evidence against the incident snapshot.

## Common Failures

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `canonical_storage = "local"` with no `.fcp-cache-only` marker. | The host has not migrated this connector's state directory to cache-only semantics. | Keep using the host-first path and do not claim mesh-native state recovery for this connector yet. |
| `local_cache_marker_present = false` or `zone.local_cache_marker_present = false` but the path is under `<connector-id>/cache`. | Host cache directory creation was interrupted or the operator inspected a manually created path. | Re-run the host startup path that prepares connector state directories; do not hand-create authority markers in production. |
| `ConnectorStateError::StorageUnavailable`. | The fcp-store object layer is unreachable, missing the referenced object, or failed a storage operation. | Keep local cache reads read-only, restore object-store availability, then re-run `fwc connector state explain --connector <id> --json`. |
| `ConnectorStateError::MalformedState`. | A stored object has invalid canonical CBOR, mismatched connector or zone identity, invalid prev-pointer, or a body/header content-id mismatch. | Quarantine the bad object through the object-store recovery process and restore from the latest valid `ConnectorStateSnapshot`. |
| `ConnectorStateError::SnapshotUnavailable`. | The root references a missing head, no state head exists, or a newly emitted snapshot cannot be reloaded. | Stop compaction, inspect root refs, and restore the latest valid snapshot before resuming writes. |
| `ConnectorStateError::SubscribeUnavailable`. | The change stream lagged or the publisher closed, so a host cache may not have observed all updates. | Drop the local cache view and force the next read through canonical fcp-store before accepting connector output. |

## Verification

For a focused runbook-facing check after changing this surface:

```bash
rch exec -- cargo fmt -p fwc -p fcp-store -- --check
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-connector-state-runbook-rch CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p fwc connector_state_explain --bin fwc -- --nocapture
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-connector-state-runbook-rch CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p fcp-store connector_state --lib -- --nocapture
```

When host cache invalidation changes, add the host E2E lane required by the bead:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-connector-state-host-e2e-rch CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p fcp-host connector_state --tests -- --nocapture
```

Use `git diff --check -- docs/runbooks/connector_state_externalization.md` for
the documentation-only slice.

## Redacted Log Examples

```json
{"event_type":"fcp.connector_state.read","bead_id":"flywheel_connectors-hr0rr.2.2","actor":"host","redaction_scope":"public","correlation_id":"state-read-20260510T130000Z","timestamp":"2026-05-10T13:00:00.000Z","connector_id":"github","zone_id":"z:work","operation":"read","result":"hit","latency_seconds":0.0008,"metric_name":"fcp_connector_state_latency_seconds"}
```

```json
{"event_type":"fcp.connector_state.fall_through","bead_id":"flywheel_connectors-hr0rr.2.2","actor":"host","redaction_scope":"public","correlation_id":"state-read-20260510T130001Z","timestamp":"2026-05-10T13:00:01.000Z","connector_id":"github","zone_id":"z:work","local_cache_marker_present":true,"cache_result":"miss","canonical_storage":"mesh","result":"fcp-store-read","metric_name":"fcp_connector_state_fall_through_total"}
```

```json
{"event_type":"fcp.connector_state.snapshot","bead_id":"flywheel_connectors-hr0rr.2.2","actor":"host","redaction_scope":"public","correlation_id":"state-snapshot-20260510T130002Z","timestamp":"2026-05-10T13:00:02.000Z","connector_id":"github","zone_id":"z:work","operation":"snapshot","result":"emitted","covers_seq":1000,"snapshot_reason":"entry-threshold","metric_name":"fcp_connector_state_latency_seconds"}
```

Do not log state CBOR, capability tokens, connector credentials, raw local file
contents, principal private data, or provider response bodies. When an
identifier would expose sensitive data, log a SHA-256 value with a `_hash`
suffix instead.
