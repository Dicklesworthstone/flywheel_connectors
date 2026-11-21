# Asana Connector V3 Contract

> **Status**: all 10 runtime operations declared in the validated manifest
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Contract repair**: `flywheel_connectors-asana-contract-zyoy5`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://developers.asana.com/docs/quick-start
> **Auth upstream**: https://developers.asana.com/docs/authentication

## Purpose

This document fixes the operator-facing contract for `fcp.asana`. The connector exposes the current Asana REST API surface implemented in this crate: workspace listing, project listing and retrieval, task listing, task retrieval, task creation, task update, task deletion, section listing, and workspace task search.

The connector is intentionally a work-zone project-management bridge. It is not an OAuth app installer, webhook receiver, portfolio client, attachment bridge, reporting warehouse, or full Asana admin API client.

## Current Runtime Snapshot

The current runtime exposes these operations:

- `asana.workspaces.list`
- `asana.projects.list`
- `asana.projects.get`
- `asana.tasks.list`
- `asana.tasks.get`
- `asana.tasks.create`
- `asana.tasks.update`
- `asana.tasks.delete`
- `asana.sections.list`
- `asana.tasks.search`

Important runtime truths the contract preserves:

- Configuration requires exactly one of `access_token` or `credential_id`.
- `access_token` mode sends `Authorization: Bearer ...`.
- `credential_id` mode sends `X-FCP-Credential-Id`.
- Credential IDs must be valid UUIDs.
- Access tokens are trimmed and redacted in debug output.
- Default base URL is `https://app.asana.com/api/1.0`.
- Direct access-token mode accepts only `https://app.asana.com`, `https://api.asana.com`, or loopback test origins.
- Credential-id mode accepts any HTTPS host, plus loopback test origins, after rejecting userinfo, query strings, and fragments.
- Base URLs are trimmed of trailing slashes after validation.
- Reconfiguration clears handshake state.
- The HTTP client uses a 30 second timeout and user agent `fcp-asana/0.1.0 (FCP connector)`.
- A shared retry config with `max_retries = 2` is constructed, but current direct request helpers do not route provider calls through the retry loop.
- Path GIDs are rejected when empty, slash-bearing, backslash-bearing, path-traversing, URL-active, encoded slash/backslash-bearing, NUL-bearing, or control-character-bearing.
- `asana.tasks.search` percent-encodes query text for the `text` parameter.
- 401, 403, 404, 429 with `Retry-After`, and generic API errors are mapped into connector error classes.
- `health` is local connector state, not a live provider probe.
- `self_check` reports local provisioning readiness and does not call Asana.

## Manifest And Runtime Contract

`manifest.toml` declares all 10 operations exposed by dispatch and introspection,
including their input and output schemas, capability requirements, risk, safety,
and idempotency. Project retrieval, task retrieval, section listing, and task
search therefore participate in host admission and discovery alongside the
other operations. Every operation has a rate-limit pool and the same bounded
Asana egress policy. `asana.sections.read` is declared in both the manifest and
the handshake.

Identifier fields follow the runtime contract:

- `asana.projects.list` and `asana.tasks.search` require `workspace_gid`.
- `asana.projects.get`, `asana.tasks.list`, and `asana.sections.list` require `project_gid`.
- `asana.tasks.get`, `asana.tasks.update`, and `asana.tasks.delete` require `task_gid`.
- `asana.tasks.create` retains the provider field `workspace`, plus `name`; it forwards those fields inside the Asana `data` envelope.
- `asana.tasks.search` also requires a string `query`.

Task deletion is `Dangerous` / `High`, requires interactive approval in the
manifest, and has idempotency `None`; the host must not treat it as a strictly
replayable operation. Creation remains policy-gated and non-idempotent, while
updates remain policy-gated and `Strict`.

The existing integration suite checks the complete introspection/manifest
contract, rejects obsolete identifier names before dispatch, and exercises all
10 manifest examples against a loopback Asana fixture with the host's real
input and output validators. These checks cover contract consistency; live
provider verification remains a separate operator step.

## First-Slice Scope

The first Asana README slice documents the existing runtime surface:

- workspace listing through `GET /workspaces`
- project listing through `GET /workspaces/{workspace_gid}/projects`
- project retrieval through `GET /projects/{project_gid}`
- task listing through `GET /projects/{project_gid}/tasks`
- task retrieval through `GET /tasks/{task_gid}`
- task creation through `POST /tasks` with `{ "data": input }`
- task update through `PUT /tasks/{task_gid}` with `task_gid` removed from the body
- task deletion through `DELETE /tasks/{task_gid}`
- section listing through `GET /projects/{project_gid}/sections`
- workspace task search through `GET /workspaces/{workspace_gid}/tasks/search?text=...`
- direct personal access token auth and host credential reference auth
- base URL, path segment, lifecycle, doctor, self-check, introspection, simulation, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanisms: Asana personal access token or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Capability surface:
  - `asana.workspaces.read` gates workspace listing.
  - `asana.projects.read` gates project listing and project retrieval.
  - `asana.tasks.read` gates task listing, task retrieval, and task search.
  - `asana.tasks.write` gates task creation and task update.
  - `asana.tasks.delete` gates task deletion.
  - `asana.sections.read` gates section listing.
- The connector does not persist workspaces, projects, sections, tasks, access tokens, credential IDs, or search results beyond process memory.
- Credential-id mode forwards a host credential reference header; host-side credential materialization remains outside this connector.
- Actions made through a personal access token are attributed by Asana to the token owner.

## Network And Runtime Invariants

- Production base URL: `https://app.asana.com/api/1.0`.
- Alternate accepted production host: `api.asana.com`.
- Production port: `443`.
- TLS and SNI are required for live direct-token traffic.
- Manifest provider network policy allows `app.asana.com`, denies localhost, private ranges, tailnet ranges, and IP literals, and sets port `443`.
- Runtime loopback provider API overrides are test-only.
- Runtime request timeout: `30_000 ms`.
- Manifest operation total timeout: `30_000 ms`.
- Maximum response bytes are `10_485_760` for read/list operations and `1_048_576` for write/delete operations.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open a listener and does not implement FCP subscriptions.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `asana.workspaces.read` | List accessible Asana workspaces. |
| `asana.projects.read` | List projects in a workspace and retrieve one project. |
| `asana.tasks.read` | List, retrieve, and search tasks. |
| `asana.tasks.write` | Create and update tasks. |
| `asana.tasks.delete` | Delete tasks. |
| `asana.sections.read` | List project sections. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `asana.workspaces.list` | `GET /workspaces` | `asana.workspaces.read` | `Safe` | `Low` | `Strict` | Lists accessible workspaces and organizations. |
| `asana.projects.list` | `GET /workspaces/{workspace_gid}/projects` | `asana.projects.read` | `Safe` | `Low` | `Strict` | Lists projects under one workspace. |
| `asana.projects.get` | `GET /projects/{project_gid}` | `asana.projects.read` | `Safe` | `Low` | `Strict` | Reads one project record. |
| `asana.tasks.list` | `GET /projects/{project_gid}/tasks` | `asana.tasks.read` | `Safe` | `Low` | `Strict` | Lists top-level project tasks. |
| `asana.tasks.get` | `GET /tasks/{task_gid}` | `asana.tasks.read` | `Safe` | `Low` | `Strict` | Reads one task record. |
| `asana.tasks.create` | `POST /tasks` | `asana.tasks.write` | `Risky` | `Medium` | `None` | Creates a task in Asana. |
| `asana.tasks.update` | `PUT /tasks/{task_gid}` | `asana.tasks.write` | `Risky` | `Medium` | `Strict` | Updates an existing task. |
| `asana.tasks.delete` | `DELETE /tasks/{task_gid}` | `asana.tasks.delete` | `Dangerous` | `High` | `None` | Deletes a task and can remove associated subtasks. |
| `asana.sections.list` | `GET /projects/{project_gid}/sections` | `asana.sections.read` | `Safe` | `Low` | `Strict` | Lists sections in one project. |
| `asana.tasks.search` | `GET /workspaces/{workspace_gid}/tasks/search?text=...` | `asana.tasks.read` | `Safe` | `Low` | `Strict` | Searches tasks in a workspace by text. |

## Explicit Non-Goals

The current implementation does not include:

- OAuth authorization flow, token refresh, or app installation management
- service account provisioning or admin-console APIs
- webhooks, events, stories, comments, attachments, portfolios, goals, teams, users, custom fields, dependencies, or project templates
- durable task cache, local search index, or reporting warehouse
- inbound public callback endpoints
- automatic project/section assignment helpers beyond passthrough create/update bodies
- connector-local credential vaulting
- public-zone invocation

These are excluded on purpose:

- The useful first slice is a bounded work-zone task/project bridge.
- Create, update, and delete operations mutate real Asana data and must remain capability and policy gated.
- Full OAuth, webhook, and admin APIs need separate security and state contracts.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, request counters, and error counters
- auth mode as personal access token or credential ID
- base URL policy status and local client readiness
- degraded self-check for credential-id mode because egress proxy injection is required
- runtime operation metadata, schemas, capability IDs, risk levels, safety tiers, and idempotency
- simulation support for known operation names

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- lifecycle health, handshake, reconfigure, shutdown, self-check, doctor, and introspection
- complete manifest/introspection schema and authority parity, interface-hash validation, and provider execution of all manifest examples
- bearer auth header behavior
- workspace listing, project listing, project retrieval, task listing, task retrieval, task creation, task update, task deletion, section listing, and task search
- required-field validation for all operation families
- path-segment rejection for URL-active and traversal characters
- 401, 403, 404, 429 with `Retry-After`, and 500 provider error paths
- unknown-operation and simulation behavior
- request/error counters
- configuration parsing, token trimming, credential ID validation, base URL validation, and auth redaction

## Source Notes

- `connectors/asana/src/connector.rs` defines configuration parsing, auth mode selection, base URL policy, lifecycle handlers, operation dispatch, diagnostics, simulation, operation metadata, provisioning recipe metadata, and capability contract tests.
- `connectors/asana/src/client.rs` defines Asana REST calls, bearer/credential headers, default base URL, request timeout, path-segment validation, query encoding, response parsing, and provider error mapping.
- `connectors/asana/src/types.rs` defines provider error response parsing.
- `connectors/asana/manifest.toml` defines the current manifest operation catalog, network constraints, sandbox boundary, zone policy, rate-limit pools, and operation AI hints.
- `connectors/asana/tests/integration.rs` covers manifest/runtime parity, host schema validation, deterministic WireMock operation behavior, lifecycle diagnostics, error handling, simulation, and counters.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/asana_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation contract tests
- deterministic WireMock Asana API coverage
- auth, base URL, workspace, project, task, section, search, error, lifecycle, simulation, provisioning, and introspection tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use an Asana personal access token for direct live verification.
- Use `credential_id` only when an egress proxy can materialize the secret at request time.
- Use WireMock loopback fixtures for routine proof.
- Use a dedicated test workspace and project for live mutation tests.

**Dedicated environment**:

- Create synthetic test tasks only.
- Avoid live delete tests against production workspaces.
- Keep user, workspace, project, section, and task IDs out of routine logs when they can reveal private work structure.
- Treat task names, notes, search queries, and provider error bodies as sensitive work data.

**Redaction rules**:

- Redact access tokens, credential IDs where needed, workspace GIDs when sensitive, project GIDs when sensitive, task GIDs when sensitive, task names and notes when sensitive, search query text, provider payloads, and provider error bodies.
- Verification output should use operation names, endpoint paths, auth mode, result counts, status/error classes, and local readiness status.

**Common remediation**:

- If `health` reports `unconfigured`, configure with exactly one of `access_token` or `credential_id`.
- If configuration fails, make sure `credential_id` is a UUID and that `access_token` is not supplied at the same time.
- If `doctor` reports the handshake check as degraded, call `handshake` after configuration.
- If provider calls fail with 401 or 403, check token scope and the Asana user's workspace permissions.
- If task search returns 402, confirm the user/workspace has access to Asana's premium search endpoint.
- If `asana.projects.list`, `asana.tasks.list`, or `asana.tasks.delete` rejects inputs, use runtime field names: `workspace_gid`, `project_gid`, and `task_gid`.
- If live egress fails from a sandbox, reconcile runtime host policy with the manifest host allow-list before widening the connector.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-asana-e2e cargo check -p fcp-asana --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-asana-e2e cargo test -p fcp-asana --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-asana-e2e cargo clippy -p fcp-asana --all-targets --no-deps -- -D warnings`
