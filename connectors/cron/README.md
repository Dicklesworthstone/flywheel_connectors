# Cron Connector V3 Contract

> **Status**: runtime contract documented; manifest/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below

## Purpose

This document fixes the operator-facing contract for `fcp.cron`. The connector exposes the scheduling surface implemented in this crate: schedule creation, schedule listing, schedule deletion, manual trigger recording, and execution-history listing.

The connector is intentionally a bounded in-process scheduler catalog. It is not a durable distributed cron service, job runner, operation dispatcher, workflow engine, calendar service, or external queue.

## Current Runtime Snapshot

The current crate exposes these operations:

- `cron.schedules.list`
- `cron.schedules.create`
- `cron.schedules.delete`
- `cron.trigger`
- `cron.executions.list`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-cron`.
- Runtime `BaseConnector` ID is `cron`.
- Manifest connector ID is `fcp.cron`.
- Manifest interface hash is all zeroes.
- Runtime manifest proof computes a SHA-256 hash over `manifest.toml`.
- Runtime configuration accepts a typed provisioning policy under `state_store` and `clock`.
- Default state store backend is `memory`.
- Default `max_schedules` is `10000`.
- Default `max_executions` is `100000`.
- Default `persist_to_disk` is `false`.
- `persist_to_disk = true` is rejected with an in-memory-only error.
- Configured `max_schedules` must be in `1..=100000`.
- Configured `max_executions` must be in `1..=1000000`.
- Creating a schedule at capacity returns `ResourceExhausted`. Deleting a schedule frees its slot.
- Execution history retains the newest `max_executions` records across all schedules. A smaller history limit takes effect immediately. Reconfiguration rejects a schedule limit below the current schedule count and preserves the previous policy and history on failure.
- Default clock source is `system_utc`.
- Default timezone is `UTC`.
- Default `max_clock_skew_seconds` is `30`; configured values above `300` are rejected.
- Timezone is normalized to uppercase and must be `UTC`.
- `configure` marks the connector configured.
- `handshake` requires prior configuration, installs a `CapabilityVerifier`, and returns the runtime manifest hash.
- `invoke` requires the connector to be configured and handshaken through `base.check_ready()`.
- `invoke` uses the `operation_id` request field, not `operation`.
- `invoke` currently does not read or verify a `capability_token`.
- `simulate` checks only whether `operation_id` is present in the runtime operation inventory.
- `cron.schedules.create` validates minutes (0–59), hours (0–23), days of month (1–31), months (1–12), and weekdays (0–7, Sunday at either end). Fields accept comma-separated values, ascending ranges, wildcards, and positive steps on ranges and wildcards. Months and weekdays also accept three-letter English names regardless of case.
- `cron.schedules.create` rejects duplicate schedule names.
- `cron.schedules.create` generates `sched_<uuid>` IDs and stores schedules in process memory.
- `cron.schedules.delete` removes the schedule record and returns `{}`.
- `cron.trigger` verifies that the schedule exists, generates an `exec_<uuid>` record, stores status `triggered`, and returns the execution ID.
- `cron.trigger` does not dispatch or invoke the stored `target_operation`.
- `cron.executions.list` returns most recent execution records first.
- `cron.executions.list` defaults to limit `50` and caps requested limits at `100`.
- `handle_shutdown()` clears configured and handshaken base flags but leaves in-memory schedules, executions, and verifier state in the object.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest interface hash is `blake3-256:fcp.interface.v2:` followed by zeroes, while runtime handshake reports a SHA-256 hash over `manifest.toml`.
- Manifest state hints say schedules, last-run timestamps, and execution history are stored, but runtime configuration rejects disk persistence and keeps schedule/execution data in process memory.
- Handshake installs a `CapabilityVerifier`, but `handle_invoke` and `handle_simulate` do not verify capability tokens.
- Runtime request shape uses `operation_id`; many other connectors use `operation`.
- Runtime `simulate` checks operation existence only; it does not validate input, configured state, handshake state, or capability grants.
- Manifest marks schedule create/trigger as policy approval and schedule delete as interactive approval, but runtime introspection sets `requires_approval = None` for every Cron operation.
- `cron.trigger` currently records a local execution only; it does not invoke `target_operation`.
- `target_operation` is stored as provided and is not resolved, invoked, or capability-checked.
- `handle_shutdown()` does not clear schedule/execution vectors or verifier state.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should decide whether Cron is a durable scheduler or a process-local catalog, align manifest proof, add capability-token enforcement, reconcile approval metadata, validate target operations, and implement or rename the non-dispatching trigger path.

## First-Slice Scope

The current Cron README slice documents the existing runtime surface:

- provisioning policy parsing and validation
- in-memory schedule and execution catalogs
- schedule list/create/delete operations
- manual trigger record creation
- execution-history filtering and limits
- readiness, doctor, health, self-check, introspection, simulation, and shutdown behavior
- runtime/manifest drift that operators must not infer past

## Auth And Scope Boundary

- Authentication mechanisms: none in this crate slice.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Required manifest capability is `storage.state`.
- Optional manifest capabilities are `network.dns`, `network.egress`, `cron.executions.read`, `cron.schedules.write`, and `cron.schedules.read`.
- Forbidden manifest capabilities are `system.exec`, `network.listen`, `media.upload`, and `media.download`.
- Runtime capability metadata:
  - `cron.schedules.read` gates schedule listing in introspection metadata.
  - `cron.schedules.write` gates create, delete, and trigger in introspection metadata.
  - `cron.executions.read` gates execution listing in introspection metadata.
- Runtime invoke does not currently enforce those capabilities with a token check.
- Cron data can include operation IDs, static payloads, schedule names, trigger times, and execution history. Treat live output as work-zone operational data.

## Network And Runtime Invariants

- Runtime operations do not perform provider egress in this slice.
- Manifest operation network constraints use placeholder local host `localhost.localdomain`.
- Manifest operation port is `443`.
- Manifest operation policy denies tailnet ranges but does not deny localhost, private ranges, or IP literals.
- Manifest operation policy does not require SNI or host canonicalization.
- Manifest connect timeout is `5000 ms`.
- Manifest total timeout is `10000 ms` for schedule list/create/delete and execution list.
- Manifest total timeout is `30000 ms` for manual trigger.
- Manifest maximum response bytes are `1048576` for schedule write/list and trigger, and `10485760` for execution listing.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `120000 ms` wall-clock timeout, read-only `/usr` and `/lib`, writable `$CONNECTOR_STATE`, no exec, and no ptrace.
- The connector does not open inbound sockets.
- The connector does not spawn or execute scheduled target operations.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `cron.schedules.read` | List configured in-memory schedules. |
| `cron.schedules.write` | Create schedules, delete schedules, and record manual triggers. |
| `cron.executions.read` | List in-memory execution records. |
| `storage.state` | Manifest-required state capability; runtime state is currently process-local. |

## Operation Inventory

| Operation | Runtime shape | Capability metadata | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|---------------|---------------------|------------|-----------|-------------|-----------|
| `cron.schedules.list` | local read | `cron.schedules.read` | `Safe` | `Low` | `Strict` | Returns all configured schedules, including disabled schedules. |
| `cron.schedules.create` | local write | `cron.schedules.write` | `Risky` | `Medium` | `Strict` | Adds an in-memory schedule with `name`, `expression`, `target_operation`, optional `payload`, and optional `enabled`. |
| `cron.schedules.delete` | local write | `cron.schedules.write` | `Dangerous` | `High` | `Strict` | Removes one schedule by `schedule_id`. |
| `cron.trigger` | local write | `cron.schedules.write` | `Risky` | `Medium` | `None` | Appends an execution record with status `triggered`; it does not dispatch the target operation. |
| `cron.executions.list` | local read | `cron.executions.read` | `Safe` | `Low` | `Strict` | Lists execution records, optionally filtered by `schedule_id`, most recent first. |

## Resource URIs

Runtime invoke does not currently perform capability-token verification, so there are no runtime resource URI bindings for Cron operations in this slice.

Schedule IDs, execution IDs, target operation IDs, payloads, and schedule names are not currently represented as resource URIs in a bound token check.

## Explicit Non-Goals

The current implementation does not include:

- durable schedule storage across process restarts
- disk-backed state, migrations, or recovery
- actual periodic clock polling or timer execution
- dispatch of `target_operation` through the gateway or another connector
- distributed leader election, shard placement, or mesh-wide singleton enforcement
- retry policy, backoff policy, failure classification, or completion status transitions
- cron timezone support beyond UTC
- full cron grammar validation
- inbound webhooks or external event triggers

These are excluded on purpose:

- Scheduling creates side effects only after a dispatch contract exists.
- Durable scheduler semantics need clear lease, fencing, replay, and state migration contracts.
- Target-operation dispatch needs capability enforcement and audit boundaries before it can be safe.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configured and handshaken state
- session ID and runtime manifest hash
- provisioning policy values for state store and clock
- current in-memory schedule and execution counts
- request and error counters
- operation metadata with capability, risk, safety tier, idempotency, schemas, and hints
- simulation allow/deny based on operation inventory only

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, default configuration, custom provisioning, rejected disk persistence, rejected non-UTC clock policy, handshake before configure, shutdown, self-check, doctor, and introspection behavior
- schedule create/list/delete behavior, duplicate-name rejection, basic expression rejection, and not-found errors
- manual trigger record creation and schedule existence checks
- execution-list filtering, default limit, maximum limit cap, and reverse chronological ordering
- request-shape errors for missing or unknown `operation_id`
- drift-sensitive assertions for operation count and metadata

## Source Notes

- `connectors/cron/src/connector.rs` defines provisioning policy parsing, lifecycle handlers, health, doctor, self-check, introspection, simulation, operation dispatch, in-memory schedule state, and execution state.
- `connectors/cron/src/types.rs` defines schedule and execution records plus the current basic cron-expression validator.
- `connectors/cron/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/cron/src/main.rs` maps FCP methods to connector handlers.
- `connectors/cron/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, capability families, and rate-limit pools.
- `connectors/cron/tests/integration.rs` covers deterministic runtime behavior and contract assertions.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/cron_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation inventory and policy metadata
- lifecycle, provisioning, health, doctor, self-check, shutdown, and simulation behavior
- local schedule and execution catalog behavior
- basic expression validation and request-shape errors
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use this connector as a local schedule catalog unless and until a dispatch contract is implemented.
- Do not assume persisted state survives process restart or shutdown.
- Do not assume `cron.trigger` invokes the schedule's `target_operation`.

**Redaction rules**:

- Redact schedule names when sensitive, target operation IDs that reveal private workflow topology, static payloads, execution IDs, schedule IDs, timestamps when sensitive, and provider-style error bodies if future dispatch is added.
- Verification output should use operation IDs, counts, status classes, request-shape summaries, and limit behavior rather than full payload bodies.

**Common remediation**:

- If configuration fails, keep `state_store.backend = "memory"`, `persist_to_disk = false`, `clock.source = "system_utc"`, and `clock.timezone = "UTC"`.
- If schedule creation fails, provide all required fields: `name`, `expression`, and `target_operation`.
- If expression validation rejects input, check the five field ranges, list separators, and step values. For example, `*/15 9-17 * * MON-FRI` is valid.
- If duplicate-name rejection fires, list schedules and choose a unique schedule name.
- If trigger fails, verify the schedule ID exists; schedule names are not accepted for trigger/delete.
- If execution listing returns fewer records than expected, check `schedule_id` filtering and the `100` record limit cap.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-cron-readme cargo check -p fcp-cron --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-cron-readme cargo test -p fcp-cron --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-cron-readme cargo clippy -p fcp-cron --all-targets --no-deps -- -D warnings`
- `ubs connectors/cron/README.md`
