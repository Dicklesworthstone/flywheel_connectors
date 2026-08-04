# SQLite Connector V3 Contract

> **Status**: runtime contract documented; runtime operation metadata derives from manifest
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
- Runtime `BaseConnector` ID is `sqlite`.
- Manifest connector ID and handshake connector ID are `fcp.sqlite`.
- Manifest interface hash is `blake3-256:fcp.interface.v2:0133b7c75dee87ffe347dcda9891710ebc43f66092c02c42d72b2b1dfcb5e4ae`.
- Configuration requires `database_path` or its alias `path`.
- `database_path` is trimmed and rejected when missing or blank.
- `:memory:` is accepted and opens an in-memory database.
- `file:` URI paths are rejected even though the rusqlite open flags include `SQLITE_OPEN_URI`.
- Paths containing a parent-directory component `..` are rejected.
- `read_only` defaults to `false`.
- `create_if_missing` defaults to `!read_only`.
- `busy_timeout_ms` defaults to `5000` and must be greater than zero.
- `enable_wal` defaults to `true`.
- `enforce_foreign_keys` defaults to `true`.
- File-backed read-only mode opens the database with read-only flags.
- File-backed writable mode opens the database read/write and optionally create.
- Writable connections enable foreign-key enforcement when configured.
- Writable file-backed connections request WAL mode when configured and warn if WAL is unavailable.
- Runtime opens no network connections.
- Runtime `invoke` uses `operation_id`, not `operation`.
- Runtime `invoke` checks connector readiness but does not verify `capability_token`.
- Runtime does not verify approval tokens for `sqlite.execute`, `sqlite.batch`, or `sqlite.vacuum`.
- `simulate` only checks whether `operation_id` is present in the local operation inventory.
- `handle_configure()` creates a fresh SQLite client, clears session and transaction state, sets configured, and clears handshaken state.
- `handle_handshake()` requires configuration and a client, accepts an optional `session_id`, and returns `sqlite.read`, `sqlite.write`, and `sqlite.admin` capability strings.
- `health()` reports healthy only when a session ID exists and the probe query succeeds.
- `doctor()` checks configuration, client state, database probe, filesystem readiness, WAL preconditions, and handshake state.
- `self_check()` is `ok` only after configuration, session establishment, filesystem readiness, and a successful health probe.
- `handle_shutdown()` clears client, config, session, active transaction, and base lifecycle flags, but request/error counters remain in memory.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Runtime introspection derives operation descriptions, schemas, capabilities, risk, safety, idempotency, approval mode, rate limits, and AI hints from `manifest.toml`.
- Manifest marks `sqlite.execute`, `sqlite.batch`, and `sqlite.vacuum` as requiring interactive approval, and runtime operation metadata now exposes that approval intent. Invoke still checks no approval token.
- Runtime does not verify capability tokens even though the connector is a local database mutation surface.
- Manifest says singleton-writer state stores configured database path and transaction state. Runtime keeps configuration, session, and active transaction state in process memory only.
- Runtime uses one connector-wide active transaction. Concurrent callers share that state and must pass the matching `txn_id` while a transaction is open.
- Runtime rejects `txn_id` when no transaction is active and rejects missing or mismatched `txn_id` while one is active.
- `sqlite.health` is an invoke operation that reports the active transaction ID, while lifecycle `health()` reports session/probe readiness.
- `health()` exposes `handshaken` as `session_id.is_some()`, not directly from the base handshaken flag.
- `sqlite.pragma` is read-only and allowlisted, despite SQLite PRAGMA generally including both query and mutation forms.
- Runtime path policy rejects `..` components but does not create a durable sandbox boundary by itself; filesystem containment still depends on host/sandbox policy.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should add bound capability-token verification, add approval-token verification for mutating/admin operations, decide whether SQLite state should be durable outside process memory, document or redesign the single-active-transaction model for concurrency, and add a tracked verification bundle.

## First-Slice Scope

The current SQLite README slice documents the existing runtime surface:

- local file and in-memory database configuration
- read-only query, mutating execute, explain, schema inspection, transaction, batch, health, vacuum, and pragma operations
- SQLite authorizer policy for denying dangerous SQL actions
- connector-local transaction state and batch savepoint behavior
- lifecycle, health, doctor, self-check, simulation, introspection, and shutdown behavior
- remaining capability-token and approval-token enforcement gaps
- deterministic connector tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanism: none at the provider layer; local database access is governed by connector configuration, capability metadata, and host policy.
- Home zone: local private/work data, depending on the configured database path.
- Runtime capability metadata:
  - `sqlite.read`
  - `sqlite.write`
  - `sqlite.admin`
- Handshake returns capability strings but does not install a verifier.
- Invoke does not reject missing, malformed, wrong-operation, or wrong-capability tokens.
- Write/admin operations do not verify approval tokens at runtime.
- The connector does not persist SQL statements, parameters, result rows, database contents, database paths, provider errors, or request counters outside process memory.
- SQLite databases can contain private, work, or credential-adjacent data. Treat live query output according to the configured file path and host zone.

## Runtime And Storage Invariants

- The connector opens exactly one SQLite connection for the configured connector instance.
- `:memory:` creates an in-memory database tied to the process lifetime.
- File-backed databases are opened through rusqlite with URI support enabled, while `file:` URI input is rejected by configuration policy.
- Read-only mode prevents `sqlite.execute`, `sqlite.batch`, transaction writes, `sqlite.vacuum`, and other mutating SQL through the client policy.
- Writable mode may create the database file when `create_if_missing = true`.
- `busy_timeout_ms` is applied to the connection.
- `PRAGMA foreign_keys = ON` is applied for writable connections when configured.
- `PRAGMA journal_mode = WAL` is requested for writable file-backed connections when configured.
- The authorizer denies attach, detach, virtual table creation/drop, load extension, direct transaction control, unsafe savepoints, and non-allowlisted pragma access.
- The connector's batch operation uses internal savepoint `fcp_sqlite_batch` and rolls back the full batch on error.
- Result blobs are returned as objects with `$blob_base64`.
- JSON null maps to SQLite NULL, booleans map to integers, integers map to integers, floats map to reals, strings map to text, and arrays/objects are serialized as JSON text.
- Request counters increment before dispatch; error counters increment on typed SQLite connector errors.
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
- simulation allow/deny for known versus unknown operation IDs only
- typed SQLite/FCP error mapping for configuration, path policy, read-only violations, denied SQL actions, transaction mismatches, missing input, rusqlite errors, and serialization errors

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, health, doctor, self-check, introspection, simulation, shutdown, and counters
- file-backed and in-memory databases
- query, execute, explain, schema, transaction, batch, health, vacuum, and pragma operations
- read-only enforcement and denied SQL categories
- transaction ID matching, active transaction exclusion, and vacuum rejection during transactions
- JSON parameter mapping, result mapping, missing input, unknown operation, and error conversion

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
- Treat `sqlite.execute`, `sqlite.batch`, `sqlite.transaction.*`, `sqlite.vacuum`, and `sqlite.pragma` as high-review operations until capability and approval verification are implemented.
- Do not point this connector at broad or user-writable filesystem locations without a host sandbox policy.
- Use `:memory:` only for tests or ephemeral sessions.
- Keep long-running transactions short; the runtime permits only one active transaction per connector instance.
- Do not rely on `simulate()` as an authorization check; it only validates operation existence.
