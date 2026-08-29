# Multi-Node Failover Runbook

> Bead: `flywheel_connectors-hr0rr.2.4`

Use this runbook when validating the deterministic A.4 three-node failover
proof, reading replay artifacts from a failing run, or extending the proof from
the local control-plane harness to host-backed mesh peers.

## Proof Command

The focused CI lane is intentionally narrow and avoids the connector feature
fan-out:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env TMPDIR=/Volumes/trj-data/tmp \
  CARGO_INCREMENTAL=0 \
  CARGO_TARGET_DIR=/Volumes/trj-data/tmp/fcp-hr0rr-a4-local-mesh-target \
  cargo test -j 1 -p fcp-e2e --no-default-features --test multi_node_failover -- --nocapture
```

For the reusable testkit harness compile/lint proof:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env TMPDIR=/Volumes/trj-data/tmp \
  CARGO_INCREMENTAL=0 \
  CARGO_TARGET_DIR=/Volumes/trj-data/tmp/fcp-hr0rr-a4-local-mesh-target \
  cargo clippy -j 1 -p fcp-testkit --lib --no-deps -- -D warnings
```

For the current host-backed handoff seam:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env TMPDIR=/Volumes/trj-data/tmp \
  CARGO_INCREMENTAL=0 \
  CARGO_TARGET_DIR=/Volumes/trj-data/tmp/fcp-hr0rr-a4-host-replay-target \
  cargo test -j 1 -p fcp-host --test lease_handoff_e2e \
    leader_departure_flushes_state_reselects_holder_and_fences_stale_writes -- --nocapture
```

`RCH_REQUIRE_REMOTE=1` must be applied to `rch` itself, before `rch exec`.
Do not move it after `--`, where it would only affect the remote Cargo process.
An accepted proof transcript must show an `[RCH] remote ...` banner. If `rch`
prints `[RCH] local ...` or refuses with no admissible worker, stop and record
that as proof infrastructure blockage instead of counting the Cargo result.

## Current Proof Surface

`fcp_testkit::local_mesh::LocalMeshHarness` is a deterministic in-process
control-plane harness. It builds three real `MeshNode` values with in-memory
object/symbol stores, deterministic node signing keys, the mesh HRW
lease-holder selector, signed `OperationReceipt` records, and redaction-safe
replay bundles. It does not start real `fcp-host` processes, use a real
Tailscale network, or prove cross-machine production failover yet.

Treat this as the CI-runnable substrate for A.4, not as final mesh-native
graduation evidence.

The E2E test runs 100 seeds across these `LocalChaosMode` values:

| Mode | What it proves |
| --- | --- |
| `network_partition_then_heal` | The isolated holder loses write authority and the majority elects one replacement holder. |
| `kill_leader_mid_write` | A reissued in-flight write is idempotent after holder replacement. |
| `kill_follower_mid_read` | Follower loss and recovery do not change the active holder's exactly-once receipts. |

`crates/fcp-host/tests/lease_handoff_e2e.rs` is the current host-backed seam.
It launches real `fcp-host` binaries for a three-node HRW singleton-writer
handoff, proves the departing holder flushes canonical state before yielding,
proves the replacement holder fences stale writes, and records a redacted
`host_failover_replay.jsonl` timeline in the test tempdir.

## Evidence Expectations

Each run produces an in-memory `LocalReplayBundle` with:

- `manifest` with scenario ID, seed, chaos mode, node count, and result.
- `events` with hashed node IDs, role transitions, handoff targets, positive
  transition durations, and monotonically increasing logical time.
- `node_snapshots` for all three nodes.
- `node_timelines` with per-node snapshots at t0, chaos, heal, and end.
- `invariants` with active-holder liveness, final online-node count, orphaned
  active lease count, orphaned connector-state count, and invalid receipt
  signature count.
- `hashes` for final state, receipt state, and transition state.

The test asserts that repeating the same seed and chaos mode yields the same
final state hash when the 0..99 seed matrix is traversed forward and in
reverse, that idempotent retry paths leave exactly one receipt with zero
duplicate receipts, that the active holder is online after recovery, that
receipt signatures verify against the executing node key, that no orphaned
connector-state receipt remains, that the manifest result is `pass`, and that
the JSONL event stream does not contain raw node IDs.

The forward 100-seed x 3-mode matrix also writes one replay bundle per scenario
under a persistent temp artifact root named
`fcp-multi-node-failover-replay-<pid>-<nanos>-matrix_forward`. The reverse
matrix replays the same scenarios without writing a second artifact tree; it is
only used to prove traversal-order independence.

The reusable testkit also has targeted failure-injection coverage for the
invariant reporter itself: one test tampers with an `OperationReceipt`
signature and requires `invalid_receipt_signature_count` plus
`orphaned_connector_state_count` to increment; another marks the active holder
offline and requires `orphaned_active_lease_count` to increment while
`all_nodes_online_at_end` flips false. These tests make the invariant fields a
real backstop instead of only a clean-path assertion.

The local harness pins the other refinement failure categories with focused
tests as well: zero-node harness construction fails as a typed configuration
error, malformed receipt state is re-signed and still counted as orphaned
connector state, receipt executor/signature mismatches are counted as invalid
authorization evidence, and a restarted same-seed harness reforms the same
final state, receipt hash, and transition hash from zero local receipts.

## Replay Bundle Layout

`LocalReplayBundle::write_to_dir` runs the shared
`redacted_replay_bundle` scan before writing and then emits this layout:

```text
<replay-root>/
  manifest.json
  events.jsonl
  hashes.json
  invariants.json
  per_node_snapshots/
    node_<index>_<node_hash_prefix>/
      state_at_t0.cbor
      state_at_chaos.cbor
      state_at_heal.cbor
      state_at_end.cbor
```

`manifest.json` records `schema_version`, `scenario_id`, `seed_index`,
`chaos_mode`, `node_count`, and `result`.

`events.jsonl` is the chronological role-transition stream. Each line contains
`node_id_hash`, `prior_role`, `new_role`, `lease_handoff_target_hash`,
`transition_duration_ms`, and logical time. Raw node IDs are intentionally not
written.

`hashes.json` contains:

- `final_state_hash`
- `per_node_state_hashes` with one `{node_id_hash, state_hash}` record per
  final node snapshot
- `receipt_hash`
- `transition_hash`

`invariants.json` contains:

- `active_holder_hash`
- `online_node_count`
- `all_nodes_online_at_end`
- `orphaned_active_lease_count`
- `orphaned_connector_state_count`
- `invalid_receipt_signature_count`

Each snapshot file is canonical CBOR for `fcp.testkit:LocalNodeSnapshot@1.0.0`
using the `fcp-cbor` schema-hash-prefixed serializer.

Use `fcp_testkit::redacted_replay_bundle::verify_written_replay_bundle` to
validate a saved replay root before attaching it to a bug report or comparing
it against another run. The helper decodes `manifest.json`, `events.jsonl`,
`hashes.json`, `invariants.json`, and every per-node CBOR snapshot, then fails
if any artifact contains raw harness node labels or credential-like markers
(`authorization`, `bearer`, `cookie`, `password`, `secret`, `token`), empty
node hashes, non-64-hex hash fields, missing transition events, a non-green invariant
summary, or a node/timeline/hash count mismatch.

## Golden Matrix

The smoke test pins every scenario's `final_state_hash` against a checked-in
golden matrix at
`crates/fcp-e2e/golden/multi_node_failover/matrix.json`
(schema `fcp.multi-node-failover-matrix/v1`, one `seed_<n>_<chaos_mode>` entry
per scenario). The matrix proves the harness is deterministic across commits:
any code change that alters failover behavior changes at least one hash and
fails the test.

Regenerate only after confirming the new behavior is intentional and the
forward/reverse traversal check still passes:

```bash
cargo test -p fcp-e2e --no-default-features --test multi_node_failover -- \
  --ignored generate_multi_node_failover_golden_matrix
```

The generator runs the full 100-seed x 3-mode matrix twice (forward and
reverse) and refuses to write goldens if the two traversals disagree, so a
non-deterministic harness can never produce a green-looking matrix. Review the
resulting diff: every changed line is a scenario whose failover behavior moved.

## Host Handoff Replay

`lease_handoff_e2e.rs` writes:

```text
<host-test-tempdir>/
  host_failover_replay.jsonl
```

Each line has `schema_version`, `phase`, optional `local_node_hash`, and a
phase-specific payload. The current phases are:

- `initial_candidate_set`
- `initial_holder_admitted`
- `departing_holder_flushed_before_yield`
- `replacement_holder_admitted`
- `stale_write_fenced_after_handoff`
- `canonical_state_exposed_after_handoff`
- `invariant_summary`

The host replay contract treats `local_node_hash` as null only for the global
`initial_candidate_set` phase. Every node-specific phase must carry a 64-hex
`local_node_hash`, and payload fields that identify nodes must use 64-hex hash
values: `eligible_node_hashes`, `expected_holder_hash`, refusal
`node_id_hash` entries, `departed_node_hash`, and `remaining_node_hashes`.
Refusal payloads also assert the typed `not_selected_coordinator` predicate so
the replay proves non-holders were rejected for the expected HRW reason.

This replay is intentionally smaller than the local `LocalReplayBundle`
because it records observable HTTP/binary-test evidence rather than in-memory
per-node snapshots. It is useful when the host handoff test fails after a
departure, replacement election, stale write, or state-explain regression.
The final `invariant_summary` phase makes the written replay self-verifying:
it records the initial and post-departure candidate/refusal counts, durable and
replacement fencing tokens, replacement-holder change, stale-write fencing,
canonical-state replay, and quorum satisfaction predicates asserted by the
test.

The writer renders and redaction-checks the JSONL before creating the artifact
directory. Raw `node-a`/`node-b`/`node-c` labels and obvious credential-like
strings fail the preflight instead of leaving a partial replay on disk.

## Reading A Failure

1. Extract the failing `seed_index` and `chaos_mode` from the test failure or
   `scenario_id`.
2. Locate the scenario replay directory under the `matrix_forward` artifact
   root. Directory names are the scenario IDs, for example
   `seed_42_kill_leader_mid_write`.
3. Inspect `events.jsonl` first. The last transition before divergence usually
   shows whether the failure came from partition handling, leader handoff, or
   recovery.
4. Compare `state_at_t0.cbor`, `state_at_chaos.cbor`, `state_at_heal.cbor`,
   and `state_at_end.cbor` for the same node directory. Decode them with
   `CanonicalSerializer::deserialize::<LocalNodeSnapshot>` and the
   `fcp.testkit:LocalNodeSnapshot@1.0.0` schema.
5. Compare `hashes.json` against the checked-in golden matrix
   (`crates/fcp-e2e/golden/multi_node_failover/matrix.json`). The smoke test
   asserts every scenario's `final_state_hash` equals its golden entry; the
   `per_node_state_hashes` array identifies which final node snapshot diverged
   first when the whole-state hash changes. If the drift is an intentional
   behavior change, regenerate the matrix (see "Golden Matrix" below) and
   review the diff before committing.
6. Inspect `invariants.json` when the final state hash is stable but failover
   acceptance still fails. Non-zero orphan counts or invalid signatures identify
   whether the issue is active-holder liveness, connector-state reachability, or
   receipt authenticity.
7. For host-backed handoff failures, inspect `host_failover_replay.jsonl`.
   The first missing phase identifies whether the break happened before holder
   admission, during flush-before-yield, during replacement admission, while
   fencing stale writes, or while exposing canonical state after handoff.

## Common Failures

| Symptom | Likely cause | Next step |
|---------|--------------|-----------|
| `final_state_hash` differs between two runs. | A decision path used process order, wall-clock time, or non-seeded randomness. | Search the failing mode for non-`ChaCha20Rng` decisions and add the value to `events.jsonl`. |
| Forward and reverse seed matrices differ. | A scenario leaked state across iterations or consumed non-local scheduler/process state. | Re-run the failing seed/mode pair alone and compare its replay bundle against the matrix run. |
| Matrix artifact count is not 300. | The forward matrix did not write one replay bundle per seed/mode scenario. | Check the `matrix_forward` artifact root and the `write_to_dir` error for the missing scenario. |
| `receipt_count` is greater than one. | Idempotency key handling allowed a retry to create a second receipt. | Inspect `events.jsonl` around the handoff and confirm only the current holder called `execute_once`. |
| `duplicate_receipt_count` is non-zero. | The same idempotency key was inserted under multiple receipt records. | Compare `receipt_hash` across reruns and inspect holder promotion order. |
| Replay logical time is not monotonic. | A transition writer used wall-clock/process order or reset the local logical clock. | Inspect `events.jsonl` around the first non-increasing `logical_time_ms` and keep transition timing derived from the seeded harness. |
| `orphaned_active_lease_count` is non-zero. | The selected singleton holder is offline or not in holder role after recovery. | Inspect the final node snapshots and the last holder promotion/recovery transition in `events.jsonl`. |
| `orphaned_connector_state_count` is non-zero. | A receipt lost its request ref, outcome object, idempotency key, node binding, or signature validity. | Compare `receipt_hash` with `per_node_state_hashes` and verify the executing node key for the failing seed. |
| `invalid_receipt_signature_count` is non-zero. | The `OperationReceipt` signature no longer verifies against the executing node's deterministic signing key. | Reproduce the seed and inspect holder changes before `execute_once`. |
| Host replay phase order changes. | The real `fcp-host` handoff test no longer matches the documented replay contract. | Inspect `host_failover_replay.jsonl` and update the runbook only if the new phase is intentional and has assertions. |
| Host replay node hash contract fails. | A host replay phase omitted `local_node_hash`, emitted a non-hex node hash, or leaked node identity into a payload. | Keep global phases hash-free, require 64-hex hashes on node-specific phases, and store node sets in `*_hashes` arrays. |
| Host replay refusal predicate is false. | A non-holder was refused for an unexpected reason or the typed HRW rejection was lost. | Inspect the process spawn error and preserve `NotSelectedCoordinator` as the redacted `not_selected_coordinator` predicate. |
| Host `invariant_summary` contains a false predicate. | The real host handoff lost candidate/refusal, fencing, canonical-state, or quorum evidence. | Compare the preceding replay phases against the failed invariant field before changing test expectations. |
| Redaction assertion fails. | A replay field contains raw node IDs or credential-like text. | Store hashed identifiers with `_hash` suffixes and keep credentials out of replay payloads. |
| Snapshot CBOR fails to deserialize. | The snapshot schema changed without updating the replay writer or test. | Update the schema version and keep old fixture decoding explicit if old artifacts must remain readable. |
| Raw `mesh-harness-node-` appears in an artifact. | Redaction regressed. | Hash the identifier before adding it to manifests, events, or snapshots. |
| `host_failover_replay.jsonl` refuses to write. | Host replay preflight found raw node labels or credential-like strings. | Replace raw host labels with `hash_node_label` and keep credential material out of replay payloads. |
| Test compiles connector dependencies. | The command missed `--no-default-features`. | Re-run the focused E2E command above. |

## Redaction Contract

Replay bundles may contain public hashes, role names, durations, logical time,
and deterministic scenario IDs. They must not contain:

- raw node names
- private signing keys
- bearer tokens
- cookies
- connector credentials

Fields that identify a node or handoff target use a `_hash` suffix. Keep that
convention for future host-backed replay artifacts so operators can compare
timelines without leaking deployment identifiers. Every replay hash field must
be lowercase 64-hex, including event node hashes, handoff target hashes,
snapshot node hashes, per-node state hashes, active-holder hashes,
`final_state_hash`, `receipt_hash`, and `transition_hash`.

The ProofGraph flight-recorder adapter follows the same node-redaction rule:
`MeshFailoverFlightRecord` rejects participating nodes, primary-before/after
nodes, and event node references unless they are lowercase 64-hex hashes.
Its JSONL projection emits `node_id_hash`, not raw node labels, so evidence
bundles can be attached to proof graphs without exposing host inventory names.

## Graduation Path

This harness is the reusable deterministic substrate for the full A.4 proof.
The full closeout should add a host-backed variant that exercises real
`fcp-host` and `fcp-mesh` state transfer while preserving the same seed matrix,
chaos modes, replay-bundle shape, and redaction checks.

This local harness landing is not enough to unignore
`v2_cutover_mechanism_fwc_mesh_explain_availability_returns_mesh_backed`.
That deferred cutover gate is operator-facing: `fwc mesh explain-availability`
must consume live per-zone mesh inventory and return `mesh-backed` truth for at
least one placed connector. Keep the distinction explicit so local deterministic
failover proof is not mistaken for the final `fwc` availability proof.

Likewise, a live `fwc mesh explain-availability --host` payload can be
`mesh-backed` when the host recorded artifact placement policy, but that is
still not enough to green the `mesh-inventory-placement` cutover gate. That gate
needs live replica telemetry: `placement.has_mesh_replica=true` and
`placement.replica_count` meeting the target for the placed connector set.
`fwc mesh cutover-gates --host` only treats a direct host snapshot as live gate
telemetry when the host payload advertises `schema_version:
fcp-host-cutover-gates/v1`; a missing or older schema stays `skip` with
`direct-cutover-telemetry-invalid` instead of green-lighting cutover from a
stale or foreign route.
The same fail-closed rule applies when the host snapshot's top-level
`overall_status` contradicts the individual gate records; operators should fix
the host telemetry route rather than trusting a locally recomputed green result.
