# PostgreSQL Connector V3 Contract

> **Status**: PROVEN runtime contract documented with HTTP-facade and capability-token drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/postgresql_connector_verification.sh`
> **Supabase Data API upstream**: https://supabase.com/docs/guides/api
> **PostgREST RPC upstream**: https://postgrest.org/en/latest/references/api/functions.html

## Purpose

This document fixes the operator-facing contract for `fcp.postgresql`. Despite the connector name, the current implementation is not a native PostgreSQL wire-protocol client. It is an HTTP client for a Supabase/PostgREST-compatible REST facade that exposes SQL-like RPC endpoints.

The connector is intentionally a bounded database HTTP-facade bridge. It is not a direct TCP PostgreSQL driver, migration runner, schema migration planner, connection pooler, row-level-security manager, Supabase project-management client, SQL proxy server, replication client, logical decoding client, or durable transaction coordinator.

## Current Runtime Snapshot

The current crate exposes these operations:

- `pg.query`
- `pg.execute`
- `pg.explain`
- `pg.schema.tables`
- `pg.schema.columns`
- `pg.schema.indexes`
- `pg.transaction.begin`
- `pg.transaction.commit`
- `pg.transaction.rollback`
- `pg.batch`
- `pg.prepared`
- `pg.health`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-postgresql`.
- Runtime `BaseConnector` ID is `postgresql`.
- Manifest and handshake connector ID are `fcp.postgresql`.
- Connector version is `0.1.0`.
- Configuration requires exactly one auth source:
  - `api_key`
  - `credential_id`
- `credential_id` must be a valid UUID.
- Default base URL is the placeholder `https://db.example.com`.
- `api_key` mode sends `Authorization: Bearer <key>`.
- `credential_id` mode sends `X-FCP-Credential-Id: <uuid>`.
- Runtime base URL policy accepts arbitrary HTTPS hosts and loopback HTTP(S) for tests.
- Runtime base URL policy rejects empty URLs, invalid URLs, non-HTTP(S) schemes, nonlocal HTTP, missing host, userinfo, query strings, and fragments.
- Runtime reqwest timeout is `30 seconds`.
- Runtime request context timeout is `30 seconds`.
- Runtime contains an `HttpRetryConfig` with `max_retries = 2`, but current request methods send requests directly and do not use a retry loop.
- Runtime `invoke` uses `operation_id`, not `operation`.
- Runtime `invoke` checks only connector readiness, operation identity, local input extraction, and client initialization before dispatch.
- Runtime does not verify `capability_token`.
- Runtime does not verify approval tokens for write operations.
- `simulate` validates operation identity, required input shape, base readiness, and client presence, but does not validate caller authority or approval state.
- `handle_shutdown()` shuts down the client runtime, clears client/config state, and resets configured/handshaken flags.
- `handle_shutdown()` does not clear the stored `session_id` string.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- The connector name says PostgreSQL, but runtime requires an HTTP facade under `/rest/v1/...`; it does not open a PostgreSQL TCP connection or speak the native wire protocol.
- Supabase documents an auto-generated PostgREST API at `https://<project_ref>.supabase.co/rest/v1/`. Runtime instead expects custom RPC-style endpoints such as `/rest/v1/rpc/query`, `/rest/v1/rpc/transaction`, `/rest/v1/rpc/batch`, and `/rest/v1/rpc/prepared`.
- PostgREST exposes PostgreSQL functions under `/rpc/<function>` and accepts JSON arguments. Runtime assumes specific function names and JSON contracts that must exist on the configured facade.
- Manifest network constraints use placeholder `*.example.com` hosts. Runtime accepts arbitrary HTTPS hosts and loopback HTTP(S) for tests.
- Manifest `interface_hash` is all zeros.
- Manifest marks `pg.execute`, `pg.batch`, and `pg.prepared` as policy-gated. Runtime introspection exposes every operation with `requires_approval = None`, and invoke checks no approval token.
- Runtime handshake returns operation IDs in the `capabilities` array rather than capability IDs such as `pg.read` and `pg.write`.
- Runtime `self_check` reports `ok` whenever config exists and does not call the live `/rest/v1/health` endpoint.
- Runtime `doctor` checks only local configuration, client initialization, and handshake state; it does not perform a live provider probe.
- Runtime keeps request/error counters in memory only.
- The tracked verifier script is deliberately fail-closed: missing `rch` workers or Docker/testcontainer prerequisites are reported as infra-blocked, not as a green connector proof.

A follow-up parity bead should decide whether this connector remains a custom PostgREST/Supabase HTTP facade or becomes a native PostgreSQL driver, replace placeholder manifest network constraints, install bound capability-token verification, enforce approval-token semantics for write operations, align handshake capabilities with actual capability IDs, and add broader deterministic endpoint-shape coverage beyond the transaction harness.

## First-Slice Scope

The current PostgreSQL README slice documents the existing runtime surface:

- direct API-key and host credential-reference configuration
- HTTP facade endpoint contract and placeholder default URL
- read, write, explain, schema, transaction, batch, prepared, and health operations
- retry, timeout, provider error, readiness, doctor, health, self-check, simulate, introspect, invoke, and shutdown behavior
- runtime/manifest drift around protocol naming, endpoint policy, approvals, capability-token verification, handshake capabilities, interface hash, and live readiness
- testcontainer transaction proof and direct proof commands

## Auth And Zone Boundary

- Authentication mechanisms: bearer API key or host credential reference.
- Runtime does not implement Supabase auth flows, JWT minting, service-role key rotation, database role management, row-level-security policy setup, password auth, TLS client certificates, SCRAM, IAM auth, or connector-local credential vaulting.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Capability families:
  - `pg.read`
  - `pg.write`
- The connector does not persist API keys, credential IDs beyond configuration metadata, SQL statements, parameter values, query results, schema results, transaction IDs, prepared statement names, provider responses, provider error bodies, request counters, or error counters outside process memory.
- SQL statements and result rows can contain production data, secrets, credentials, emails, customer records, tokens, audit records, and business-sensitive state. Treat live reads and writes as work-zone or private-zone data based on the configured database.

## Network And Runtime Invariants

- Default runtime base URL: `https://db.example.com`.
- Runtime HTTP endpoints:
  - `POST /rest/v1/rpc/query` for `pg.query`
  - `POST /rest/v1/rpc/query` with `"mode": "execute"` for `pg.execute`
  - `POST /rest/v1/rpc/explain`
  - `GET /rest/v1/schema/tables`
  - `GET /rest/v1/schema/columns?table=...`
  - `GET /rest/v1/schema/indexes?table=...`
  - `POST /rest/v1/rpc/transaction` with action `begin`, `commit`, or `rollback`
  - `POST /rest/v1/rpc/batch`
  - `POST /rest/v1/rpc/prepared`
  - `GET /rest/v1/health`
- Runtime request timeout: `30 seconds`.
- Runtime auth:
  - `api_key` uses bearer auth.
  - `credential_id` uses `X-FCP-Credential-Id`.
- Runtime sends JSON requests with `Content-Type: application/json` and expects JSON responses.
- Runtime percent-encodes schema/table query parameters for schema endpoints.
- Runtime maps successful empty bodies to `{}`.
- Runtime maps JSON success bodies containing an `"error"` string to query errors.
- Runtime maps 401 to auth errors, 403 to permission-denied errors, 409 to constraint violations, 429 to rate-limit errors, 408 to timeout errors, and other non-success statuses to provider API errors.
- Runtime reads `Retry-After` on 429 and defaults to 60000 ms when absent.
- Manifest live-operation policy requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, and currently allows only `*.example.com` on port 443.
- Sandbox profile is `strict`, with `512 MB` memory, `75%` CPU, `300000 ms` wall-clock timeout, read-only `/usr` and `/lib`, writable `$CONNECTOR_STATE`, no exec, and no ptrace.
- The connector does not open inbound sockets.

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|----------------|------------|------------|-----------|-------------|----------------|
| `pg.query` | `POST /rest/v1/rpc/query` | `pg.read` | `Safe` | `Low` | `Strict` | `sql`; optional `params`, `timeout_ms`. |
| `pg.execute` | `POST /rest/v1/rpc/query` with `mode=execute` | `pg.write` | `Risky` | `Medium` | `None` | `sql`; optional `params`. |
| `pg.explain` | `POST /rest/v1/rpc/explain` | `pg.read` | `Safe` | `Low` | `Strict` | `sql`; optional `params`. |
| `pg.schema.tables` | `GET /rest/v1/schema/tables` | `pg.read` | `Safe` | `Low` | `Strict` | None; optional `schema`. |
| `pg.schema.columns` | `GET /rest/v1/schema/columns?table=...` | `pg.read` | `Safe` | `Low` | `Strict` | `table`. |
| `pg.schema.indexes` | `GET /rest/v1/schema/indexes?table=...` | `pg.read` | `Safe` | `Low` | `Strict` | `table`. |
| `pg.transaction.begin` | `POST /rest/v1/rpc/transaction` | `pg.write` | `Safe` | `Low` | `None` | None; optional `isolation_level`. |
| `pg.transaction.commit` | `POST /rest/v1/rpc/transaction` | `pg.write` | `Safe` | `Low` | `BestEffort` | `txn_id`. |
| `pg.transaction.rollback` | `POST /rest/v1/rpc/transaction` | `pg.write` | `Safe` | `Low` | `BestEffort` | `txn_id`. |
| `pg.batch` | `POST /rest/v1/rpc/batch` | `pg.write` | `Risky` | `Medium` | `None` | non-empty `statements`; optional `params`. |
| `pg.prepared` | `POST /rest/v1/rpc/prepared` | `pg.write` | `Risky` | `Medium` | `BestEffort` | `name`; optional `params`. |
| `pg.health` | `GET /rest/v1/health` | `pg.read` | `Safe` | `Low` | `Strict` | None. |

## Explicit Non-Goals

The current implementation does not include:

- native PostgreSQL TCP, TLS, SCRAM, password, certificate, IAM, Unix-socket, or connection-string handling
- direct table CRUD through ordinary PostgREST table routes
- automatic SQL parsing, statement allowlists, read-only enforcement, migration planning, schema diffing, or destructive-statement detection
- row-level-security policy management, grants, roles, extensions, triggers, replication, logical decoding, LISTEN/NOTIFY, or advisory locks
- Supabase project creation, API-key lookup, Edge Functions, Realtime, Storage, Auth, Management API, or dashboard automation
- durable transaction sessions inside this connector; transaction state belongs to the configured HTTP facade
- connector-local storage of SQL history, result caches, prepared statement definitions, schema metadata, or transaction IDs
- direct FCP capability-token or approval-token verification at connector invoke time

These are excluded on purpose:

- SQL execution can mutate or destroy production data.
- Schema introspection can reveal sensitive table and column names.
- A safe native PostgreSQL connector needs a different connection, pooling, transaction, and policy model than this HTTP facade.
- Write operations need host-mediated approval and capability enforcement before they should be considered production-safe.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration, client, and handshake state
- in-memory request/error counters
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- local simulation input validation and readiness checks
- provider error mapping for auth, permission, constraint, rate-limit, timeout, API, JSON, and transport errors

The deterministic evidence is currently split:

- Inline client tests cover URL encoding, auth redaction, and default/custom URL behavior.
- Inline connector tests cover base URL validation and lifecycle behavior.
- `connectors/postgresql/tests/transaction_integration.rs` is feature-gated behind `integration-testcontainer` and uses a real PostgreSQL testcontainer plus a minimal Axum PostgREST-style shim for `/rest/v1/rpc/transaction`.
- The transaction integration harness proves begin/commit/rollback visibility, rollback discard behavior, multiple open transaction sessions, and invalid transaction ID handling.

## Source Notes

- `connectors/postgresql/src/connector.rs` defines configuration parsing, lifecycle handlers, diagnostics, introspection, simulation, invoke dispatch, operation IDs, and base URL policy.
- `connectors/postgresql/src/client.rs` defines the HTTP facade request construction, auth headers, timeout configuration, schema parameter encoding, transaction endpoints, and provider error mapping.
- `connectors/postgresql/src/types.rs` defines provider error envelope shapes.
- `connectors/postgresql/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/postgresql/manifest.toml` defines the operation catalog, placeholder network constraints, sandbox boundary, zone policy, rate-limit pools, and AI hints.
- `connectors/postgresql/tests/transaction_integration.rs` covers real transaction behavior through a testcontainer-backed shim.
- `scripts/e2e/postgresql_connector_verification.sh` bundles the redaction-safe manifest, docs, Cargo, and testcontainer proof lane for reruns.

## Verification Bundle

The closeout surface is the verifier, crate-local test suite, and fail-closed
`fwc proof run` evidence for Cargo-backed `rch` proof commands. The verifier
writes proof-governor artifacts under `${OUT_ROOT}/proof`. Only
`accepted_remote_proof` rows in `*.rch_remote_proof.jsonl` are green closeout
evidence for Cargo-backed steps. `refused_local_fallback`, `infra_blocked`,
`remote_command_failed`, `failed_closed`, `not_proof`, or a missing proof row
keep the batch bead open. `format_check` is a source-state check, not accepted
remote Cargo proof.

Run these after changing this connector contract:

```bash
scripts/e2e/postgresql_connector_verification.sh
PROOF_GOVERNOR=1 scripts/e2e/postgresql_connector_verification.sh
FWC_BIN=/path/to/current/target/debug/fwc PROOF_GOVERNOR=1 scripts/e2e/postgresql_connector_verification.sh
git diff --check -- connectors/postgresql/README.md
ubs connectors/postgresql/README.md
LC_ALL=C rg -n '[^ -~]' connectors/postgresql/README.md
rg -n '\bmaster\b' connectors/postgresql/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-postgresql
rch exec -- cargo check -p fcp-postgresql --all-targets
rch exec -- cargo clippy -p fcp-postgresql --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

For the Docker-backed transaction lane, use the feature-gated test explicitly:

```bash
rch exec -- cargo test -p fcp-postgresql --features integration-testcontainer --test transaction_integration
```

Set `POSTGRESQL_RUN_TESTCONTAINER=0` only for a metadata/docs smoke of the verifier shape when Docker is unavailable. That mode is not local non-mock acceptance evidence.

## Operator Guidance

Rerun commands are listed in the verification bundle above. Use the tracked verifier for the full redaction-safe proof lane, and use the individual `rch` commands only when narrowing a specific failing step.

- Configure an explicit `base_url`; the default `https://db.example.com` is a placeholder.
- Verify the configured facade implements the expected custom RPC endpoints before diagnosing connector code.
- Do not assume ordinary Supabase table CRUD routes satisfy this connector's `/rpc/query`, `/rpc/transaction`, `/rpc/batch`, or `/rpc/prepared` contract.
- Use parameter arrays instead of interpolating caller input into SQL strings.
- Treat `pg.execute`, `pg.batch`, `pg.prepared`, and transaction commit as side-effecting operations even though runtime approval checks are absent.
- Do not rely on `self_check` as a live database proof; use `pg.health` or a provider-side health endpoint through invoke.
- Do not rely on capability-token or approval-token enforcement until runtime verification is implemented.
- Redact API keys, credential IDs where needed, SQL containing secrets or customer data, parameter values, query results, schema names where sensitive, transaction IDs, provider payloads, and provider error bodies in shared logs.
