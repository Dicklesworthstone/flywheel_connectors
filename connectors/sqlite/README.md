# SQLite Connector V3 Contract

> **Status**: native host protocol with signed session authority and bounded local SQL execution
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **SQLite transactions**: https://www.sqlite.org/lang_transaction.html
> **SQLite PRAGMA reference**: https://www.sqlite.org/pragma.html
> **SQLite authorizer API**: https://www.sqlite.org/c3ref/set_authorizer.html
> **SQLite VACUUM reference**: https://www.sqlite.org/lang_vacuum.html

## Purpose

This document fixes the operator-facing contract for `fcp.sqlite`. The connector currently exposes a local SQLite database surface implemented in this crate: read-only queries, mutating statements, schema inspection, query-plan inspection, one active transaction, batch execution, health checks, allowlisted pragmas, and vacuum.

The connector is intentionally a bounded local-database bridge. It is not a general SQL proxy, multi-database attachment layer, migration runner, replication client, backup/restore tool, virtual-table host, extension loader, network database driver, or durable database-management service.

## Current Runtime Snapshot

The current crate exposes these operations:

- `sqlite.query`
- `sqlite.execute`
- `sqlite.explain`
- `sqlite.schema.tables`
- `sqlite.schema.columns`
- `sqlite.transaction.begin`
- `sqlite.transaction.commit`
- `sqlite.transaction.rollback`
- `sqlite.batch`
- `sqlite.health`
- `sqlite.vacuum`
- `sqlite.pragma`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-sqlite`.
- Runtime, manifest, handshake, health, and invocation connector ID is `fcp.sqlite`.
- The manifest declares a native executable. The shared JSONL transport bounds request frames to 16 MiB, keeps outer RPC IDs separate from invocation IDs, and exits after flushing a successful shutdown acknowledgment.
- The embedded manifest and its interface hash are validated before configuration can activate the connection. Operation schemas and policy metadata come from that manifest.
- Configuration requires `database_path` or its alias `path`.
- `database_path` is trimmed and rejected when missing or blank.
- `:memory:` is accepted and opens an in-memory database.
- `file:` URI paths are rejected even though the rusqlite open flags include `SQLITE_OPEN_URI`.
- Paths containing a parent-directory component `..` are rejected.
- `read_only` defaults to `false`.
- `create_if_missing` defaults to `!read_only`.
- `busy_timeout_ms` defaults to `5000`, must fit a positive signed 32-bit millisecond count, and is shortened when the invocation deadline is nearer.
- `enable_wal` defaults to `true`.
- `enforce_foreign_keys` defaults to `true`.
- File-backed read-only mode opens the database with read-only flags.
- File-backed writable mode opens the database read/write and optionally create.
- Writable connections enable foreign-key enforcement when configured.
- Writable file-backed connections request WAL mode when configured and warn if WAL is unavailable.
- Runtime opens no network connections.
- `invoke` requires a typed `InvokeRequest` with `type`, nonempty `id`, canonical `connector_id`, `zone_id`, `operation`, object `input`, and `capability_token`. Legacy `operation_id` envelopes are rejected.
- `StandaloneSession` verifies the host signature, expiration, operation, negotiated capability, actual instance, private zone, resource constraints, and signed idempotency-key scope before SQL execution. It atomically charges signed call and request/response-byte budgets; failures do not refund admissions.
- The host remains responsible for approval, revocation, holder-proof, provenance, and lease enforcement before using this private channel. Caller-supplied unsigned approval metadata does not grant permission.
- `simulate` validates the same session authority, operation/input schema, resource scope, and transaction prerequisites without executing SQL or spending a signed call. It does not promise that a SQL statement will compile or succeed against the current schema.
- Every configuration attempt first revokes the old instance and closes its connection, including attempts that fail validation. A fresh configuration requires a new handshake.
- `handshake` accepts FCP protocol `2.0` or `2.0.0`, binds to `z:private`, and grants only requested capabilities declared by operations. Each attempt revokes old authority; any active transaction is rolled back before a replacement session can begin. Caller-selected instance IDs never override the actual rotated instance.
- `health` returns a typed `HealthSnapshot`. Local configuration plus an established session makes it ready; `details` includes the actual instance, zone, session, request counters, and transaction-active flag. Database probes remain in `doctor`, `self_check`, and the authorized `sqlite.health` operation.
- `doctor()` checks configuration, client state, database probe, filesystem readiness, WAL preconditions, and handshake state.
- `self_check()` is `ok` only after configuration, session establishment, filesystem readiness, and a successful health probe.
- Shutdown, EOF, and transport failure clear connection and authority and roll back uncommitted transactions. Committed file-backed data remains in SQLite; in-memory data ends with its connection.

## Scope And Remaining Limits

The runtime preserves these boundaries:

- Runtime introspection derives operation descriptions, schemas, capabilities, risk, safety, idempotency, approval mode, rate limits, and AI hints from `manifest.toml`.
- Manifest marks `sqlite.execute`, `sqlite.batch`, and `sqlite.vacuum` as requiring interactive approval. Runtime metadata exposes that intent for host admission.
- Manifest says singleton-writer state stores configured database path and transaction state. Runtime keeps configuration, session, and active transaction state in process memory only.
- Runtime serializes native requests and permits one active transaction per instance. Callers must pass the matching `txn_id` while a transaction is open. Active transactions do not migrate or survive a session replacement.
- Runtime rejects `txn_id` when no transaction is active and rejects missing or mismatched `txn_id` while one is active.
- `sqlite.health` is an authorized invoke operation that reports the active transaction ID and probes the database; lifecycle `health` exposes only local session readiness.
- `sqlite.pragma` is read-only and allowlisted, despite SQLite PRAGMA generally including both query and mutation forms.
- Runtime path policy rejects `..` components but does not create a durable sandbox boundary by itself; filesystem containment still depends on host/sandbox policy.
- There is no dedicated tracked verification shell script for this connector.

Durable transaction migration, per-table SQL authorization, and multi-connection concurrency remain outside the current surface. Host filesystem sandbox policy must contain the configured database and its journal files.

## First-Slice Scope

The current SQLite README slice documents the existing runtime surface:

- local file and in-memory database configuration
- read-only query, mutating execute, explain, schema inspection, transaction, batch, health, vacuum, and pragma operations
- SQLite authorizer policy for denying dangerous SQL actions
- connector-local transaction state and batch savepoint behavior
- lifecycle, health, doctor, self-check, simulation, introspection, and shutdown behavior
- native host sessions, signed capability budgets, and fail-closed lifecycle transitions
- deterministic connector tests, actual executable protocol transcripts, and direct proof commands

## Auth And Scope Boundary

- Provider authentication is filesystem authority; the native control channel additionally requires host-signed, instance-bound capabilities.
- Home and session zone: `z:private`. Other handshake zones are refused.
- Runtime capability metadata:
  - `sqlite.read`
  - `sqlite.write`
  - `sqlite.admin`
- Every operation requires the resource URI `sqlite:database`, meaning the database configured for this exact instance. This does not promise per-table SQL isolation. Calls with `txn_id` additionally require `sqlite:transaction:<txn_id>`; these URIs are derived from the validated request.
- Capability tokens must target the actual `instance_id` returned in handshake and health, and must use a negotiated capability. Missing, forged, stale-instance, wrong-operation, wrong-zone, or out-of-scope tokens are denied before dispatch.
- Approval and higher-level policy checks are enforced by the host. The connector should run only on its private supervised control channel.
- The connector persists committed file-backed SQLite data and journal files. It does not separately persist SQL history, input/output payloads, session keys, capability tokens, or request counters.
- SQLite databases can contain private, work, or credential-adjacent data. Treat live query output according to the configured file path and host zone.

## Runtime And Storage Invariants

- The connector opens exactly one SQLite connection for the configured connector instance.
- `:memory:` creates an in-memory database tied to the process lifetime.
- File-backed databases are opened through rusqlite with URI support enabled, while `file:` URI input is rejected by configuration policy.
- Read-only mode prevents `sqlite.execute`, `sqlite.batch`, transaction writes, `sqlite.vacuum`, and other mutating SQL through the client policy.
- Writable mode may create the database file when `create_if_missing = true`.
- Each invocation uses the shorter of the caller's `deadline_ms` and the 30-second connector ceiling. SQLite VM progress checks interrupt execution cooperatively, and the lock-wait timeout is clamped to the remaining budget before each statement. A lock wait that begins later inside a statement can overrun that budget; a final deadline check after response validation refuses late success. These checks bound synchronous SQL work without promising hard real-time preemption.
- Results are limited to 10,000 rows and 8 MiB of encoded JSON, narrowed by the signed response allowance. Exceeding a limit returns an error without releasing a partial result. SQLite cell/row bytes are capped at 8 MiB and SQL text at 1 MiB before those allocations can grow without bound.
- `PRAGMA foreign_keys = ON` is applied for writable connections when configured.
- `PRAGMA journal_mode = WAL` is requested for writable file-backed connections when configured.
- The authorizer denies attach, detach, virtual table creation/drop, load extension, direct transaction control, unsafe savepoints, and non-allowlisted pragma access.
- The connector's batch operation uses internal savepoint `fcp_sqlite_batch` and rolls back the full batch on error.
- Result blobs are returned as objects with `$blob_base64`.
- JSON null maps to SQLite NULL, booleans map to integers, integers map to integers, floats map to reals, strings map to text, and arrays/objects are serialized as JSON text.
- Requests, including rejected requests, increment local request counters; errors increment the error counter. Signed call budgets are charged only after schema/scope validation and before execution.
- No native listener, network socket, replication stream, or cross-process coordinator is opened by this connector.

## Operation Inventory

| Operation | Runtime behavior | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|------------------|------------|------------|-----------|-------------|----------------|
| `sqlite.query` | Run read-only SQL and return rows | `sqlite.read` | `Safe` | `Low` | `Strict` | `sql`; optional `params`, `txn_id` |
| `sqlite.execute` | Run one mutating or DDL statement | `sqlite.write` | `Risky` | `Medium` | `None` | `sql`; optional `params`, `txn_id` |
| `sqlite.explain` | Run `EXPLAIN QUERY PLAN` for read-only SQL | `sqlite.read` | `Safe` | `Low` | `Strict` | `sql`; optional `params`, `txn_id` |
| `sqlite.schema.tables` | List main user tables excluding `sqlite_%` | `sqlite.read` | `Safe` | `Low` | `Strict` | none |
| `sqlite.schema.columns` | Read `pragma_table_xinfo` for one table | `sqlite.read` | `Safe` | `Low` | `Strict` | `table` |
| `sqlite.transaction.begin` | Begin `deferred`, `immediate`, or `exclusive` transaction | `sqlite.write` | `Safe` | `Low` | `None` | optional `mode` |
| `sqlite.transaction.commit` | Commit the active transaction | `sqlite.write` | `Safe` | `Low` | `BestEffort` | `txn_id` |
| `sqlite.transaction.rollback` | Roll back the active transaction | `sqlite.write` | `Safe` | `Low` | `BestEffort` | `txn_id` |
| `sqlite.batch` | Run nonempty statement list under savepoint | `sqlite.write` | `Risky` | `Medium` | `None` | `statements` |
| `sqlite.health` | Return database health and active transaction ID | `sqlite.read` | `Safe` | `Low` | `Strict` | none |
| `sqlite.vacuum` | Run `VACUUM` outside transactions | `sqlite.admin` | `Risky` | `Medium` | `Strict` | none |
| `sqlite.pragma` | Run an allowlisted read-only pragma | `sqlite.read` | `Safe` | `Low` | `Strict` | `name`; optional `argument` |

## PRAGMA Allowlist

`sqlite.pragma` is limited to these names:

- `application_id`
- `auto_vacuum`
- `cache_size`
- `compile_options`
- `encoding`
- `foreign_keys`
- `freelist_count`
- `journal_mode`
- `locking_mode`
- `mmap_size`
- `page_count`
- `page_size`
- `schema_version`
- `synchronous`
- `temp_store`
- `user_version`
- `wal_autocheckpoint`

## Explicit Non-Goals

The current implementation does not include:

- remote database access, SQL-over-HTTP, TCP database routing, connection pooling, or cross-process transaction coordination
- multiple simultaneous SQLite connections per connector instance
- arbitrary attach/detach, extension loading, virtual table management, custom SQL functions, collations, authorizer plugins, or user-defined aggregates
- backup, restore, online backup API exposure, replication, change feeds, session extension, migration planning, or schema diffing
- full PRAGMA proxying, writable pragma mutation, arbitrary transaction SQL, or user-controlled savepoints
- durable query cache, result pagination cursors, streaming row output, large BLOB streaming, or output redaction
- provider-level credential management, file picker integration, durable connector state, or host filesystem sandbox setup

These are excluded on purpose:

- Local SQL mutation can destroy private or work data quickly.
- Arbitrary SQL/admin proxying would bypass the connector's typed capability model.
- SQLite file access is a filesystem authority surface and must remain visibly bounded by host policy.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configured/unconfigured state, client presence, session ID, request counters, and error counters
- database probe readiness through `SELECT 1`
- filesystem readiness and WAL precondition guidance
- transaction model metadata with `single_active_transaction`
- local database-only compliance metadata with `network_required = false`
- simulation allow/deny for readiness, operation/input contracts, signed authority, resources, and transaction prerequisites
- typed SQLite/FCP error mapping for configuration, path policy, read-only violations, denied SQL actions, transaction mismatches, missing input, rusqlite errors, and serialization errors

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, health, doctor, self-check, introspection, simulation, shutdown, and counters
- file-backed and in-memory databases
- query, execute, explain, schema, transaction, batch, health, vacuum, and pragma operations
- read-only enforcement and denied SQL categories
- transaction ID matching, active transaction exclusion, and vacuum rejection during transactions
- JSON parameter mapping, result mapping, missing input, unknown operation, and error conversion
- signature, instance, zone, grant, operation, and resource denials before effects; signed call/byte/key budgets; simulation without effects or charges
- session replacement rollback, rejected configuration revocation, real subprocess request/result correlation, shutdown exit, and EOF rollback

## Source Notes

- `connectors/sqlite/src/connector.rs` defines configuration parsing, lifecycle handlers, manifest-derived operation catalog, introspection, simulation, and invoke dispatch.
- `connectors/sqlite/src/client.rs` defines rusqlite connection setup, authorizer policy, SQL classification, transaction state helpers, schema helpers, pragma handling, batch behavior, health probes, and value conversion.
- `connectors/sqlite/src/types.rs` defines runtime request/response and introspection shapes.
- `connectors/sqlite/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/sqlite/manifest.toml` defines the manifest operation catalog, sandbox boundary, zone policy, approval intent, and state intent.
- `connectors/sqlite/tests/integration.rs` contains the runtime contract proof surface.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/sqlite/README.md
ubs connectors/sqlite/README.md
LC_ALL=C rg -n '[^ -~]' connectors/sqlite/README.md
rg -n '\bmaster\b' connectors/sqlite/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-sqlite
rch exec -- cargo check -p fcp-sqlite --all-targets
rch exec -- cargo clippy -p fcp-sqlite --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Prefer read-only mode for inspection workloads and only enable write mode for controlled mutation.
- Grant only the required read, write, or admin capability and bind it to the negotiated instance and database resource. Route mutations through host approval policy.
- Do not point this connector at broad or user-writable filesystem locations without a host sandbox policy.
- Use `:memory:` only for tests or ephemeral sessions.
- Keep long-running transactions short; the runtime permits only one active transaction per connector instance.
- Use `simulate` for local admission checks. It does not execute or compile SQL, reserve a later invocation, or replace host approval and revocation checks.
