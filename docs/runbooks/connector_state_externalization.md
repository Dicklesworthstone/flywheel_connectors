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

Use `fwc connector state explain --connector <id> --json` before treating any
state file as authoritative. The command reports `schema_version: "1.0.0"`,
`canonical_storage`, cache marker evidence, and any live-host downgrade or
offline-inspection warnings.

## Retain an Exact Root on Another Host

`fwc connector state pull` transfers a granted `ConnectorStateRoot` and its
validated state ancestry from a configured donor into a recipient's durable,
host-owned replica store. Select the exact root from trusted operator evidence;
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
second writer or repairing its WAL. The selected root and all required state
objects must already be present in that captured view. Missing objects fail
the transfer; subsequent source writes do not refresh the view. Restart the
host to reload source state, grants, expiry, or writer pins.

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
trusted writer pin and a positive `max_store_bytes`; this is the retained
store's write quota, independent of the transfer budgets.

`retain_replica: true` requires an absolute `replica_root`. The host retains
exclusive store ownership under
`<replica_root>/connector-state-replicas-v1/<scope-digest>/objects`, separate
from live connector state. Replica WAL records use a MAC key derived from the
configured zone object-ID key under the
`fcp.host.connector-state-replica.wal.v1` domain. When no source directory is
configured, explicit export grants can also serve this retained replica,
sharing the same backing store, append lock and cache invalidation state.
No connector process or local installation is required to retain a replica.

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
when the grants are smaller. Objects include the root; canonical bytes include
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

This operation transfers root/state-object ancestry only. It does not transfer
connector snapshots, lease authority, execution results or operation receipts,
activate live connector state, resolve uncertain invocations, or resume
execution. Its metadata also makes no mesh-wide availability or freshness
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
