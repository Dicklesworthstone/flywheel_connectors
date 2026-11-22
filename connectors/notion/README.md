# Notion Connector V3 Contract

> **Status**: runtime contract documented; Notion data-source drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Notion API upstream**: https://developers.notion.com/reference/intro
> **Notion versioning upstream**: https://developers.notion.com/reference/versioning
> **Notion data sources upstream**: https://developers.notion.com/reference/data-source
> **Notion search upstream**: https://developers.notion.com/reference/post-search
> **Notion block append upstream**: https://developers.notion.com/reference/patch-block-children

## Purpose

This document fixes the operator-facing contract for `fcp.notion`. The connector exposes the Notion workspace surface implemented in this crate: pages, databases, blocks, search, and comments through the Notion REST API.

The connector is intentionally a bounded workspace bridge. It is not a full Notion administration client, OAuth setup flow, webhook listener, durable replay engine, file-upload client, user-directory synchronizer, template manager, data-source parity layer, or Notion SDK wrapper.

## Current Runtime Snapshot

The current crate exposes these operations:

- `notion.create_page`
- `notion.get_page`
- `notion.update_page`
- `notion.delete_page`
- `notion.get_database`
- `notion.create_database`
- `notion.update_database`
- `notion.query_database`
- `notion.search`
- `notion.get_block`
- `notion.update_block`
- `notion.delete_block`
- `notion.get_block_children`
- `notion.append_blocks`
- `notion.add_comment`
- `notion.list_comments`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-notion`.
- Manifest and connector ID are `fcp.notion`.
- Manifest version is `0.1.0`.
- Manifest format is `wasi`.
- Configuration requires exactly one auth source:
  - `token`
  - `credential_id`
- Direct token mode sends `Authorization: Bearer <token>`.
- `credential_id` mode sends `X-FCP-Credential-ID` and expects host egress policy to inject real secret material.
- `credential_id` must be a valid UUID.
- Default runtime API URL is `https://api.notion.com/v1`.
- Direct token mode accepts only `https://api.notion.com` or loopback test URLs.
- `credential_id` mode accepts custom absolute URLs with a host and no userinfo, query string, or fragment.
- Default `Notion-Version` is `2026-03-11`.
- `notion_version` may come from config, `FCP_NOTION_API_VERSION`, or the default.
- `notion_version` validation checks date shape only. It does not verify that Notion released that version.
- Runtime request timeout is 30 seconds.
- Runtime request-context timeout is 30 seconds.
- The client uses the shared retry loop with `max_retries = 2`.
- `health()` returns a canonical `HealthSnapshot` with the real instance ID, configured/handshaken state, zone, session, uptime, and counters. Readiness requires configuration and a successful handshake. It does not perform a live Notion probe.
- `doctor()` performs local configuration and credential-injection checks only. It does not call Notion.
- `self_check()` performs a live `POST /search` probe only in direct-token mode.
- `credential_id` self-check reports degraded `credential_injection_required` and skips a live probe.
- Runtime `invoke` requires a complete `InvokeRequest`: `type: "invoke"`, a nonempty string `id`, `connector_id: "fcp.notion"`, `zone_id`, `operation`, `input`, and a bound `capability_token`.
- Runtime input and output schemas, operation metadata, and approval modes come from the bundled manifest. Input is checked before admission; successful output is checked before release.
- Runtime `invoke` verifies the negotiated capability class, signed operation, connector, zone, actual instance, and input-derived resource scopes. Shared session admission enforces signed call and complete FCP-message byte budgets and idempotency-key scope.
- Runtime `simulate` checks configuration, handshake, operation, input schema, signed token, resource scopes, and current call allowance without provider I/O or consuming a call. It is a local authorization preview; host approval, revocation, holder proof, lease enforcement, and provider availability remain separate responsibilities.
- Every configure or handshake attempt revokes previous authority and rotates its instance binding, including rejected attempts. Reconfiguration clears previous credentials before validating replacements.
- Runtime `shutdown()` clears configuration, client, session authority, and readiness, and returns `{ "status": "shutdown" }`.

### Native host transport

The binary accepts bounded JSONL RPC frames with `method` and `params`, using the shared 16 MiB request limit. It validates supplied JSON-RPC versions and transport IDs, recovers after malformed frames, and closes the stream after an oversized frame. Successful shutdown is flushed before exit, even if the host keeps stdin open; later buffered work is not dispatched.

Handshake accepts protocol `2.0` or `2.0.0`, grants only deduplicated capability classes used by manifest operations, and returns the actual `instance_id`. Tokens must be signed after negotiation and bound to that returned instance. The manifest's forbidden `z:public` zone is rejected. A configured workspace remains bound to its first negotiated zone until reconfiguration; a rejected attempt to change zones also revokes the previous session.

An invoke reply contains a canonical `InvokeResponse` inside the RPC `result`. Its `id` is the invocation ID from `params.id`; the outer RPC `id` is independently preserved. The complete FCP response has a 16 MiB local cap and must also fit a token's remaining signed byte allowance. An unknown or oversized outcome retains its admission charge and is not a retry permit.

## Runtime API Adapter

The runtime uses these request shapes:

| Operation | Runtime request | Required input | Output handling |
|-----------|-----------------|----------------|-----------------|
| `notion.create_page` | `POST /pages` | `parent`, `properties` | Returns `{ "page": ... }`. |
| `notion.get_page` | `GET /pages/{page_id}` | `page_id` | Returns `{ "page": ... }`. |
| `notion.update_page` | `PATCH /pages/{page_id}` with `{ "properties": ... }` | `page_id`, `properties` | Returns `{ "page": ... }`. |
| `notion.delete_page` | `PATCH /pages/{page_id}` with `{ "archived": true }` | `page_id` | Soft archives the page and returns `{ "page": ... }`. |
| `notion.get_database` | `GET /databases/{database_id}` | `database_id` | Returns `{ "database": ... }`. |
| `notion.create_database` | `POST /databases` | `parent`, `title`, `properties` | Returns `{ "database": ... }`. |
| `notion.update_database` | `PATCH /databases/{database_id}` | `database_id` | Forwards optional `title`, `properties`, and `description`. |
| `notion.query_database` | `POST /databases/{database_id}/query` | `database_id` | Returns `results`, `has_more`, and `next_cursor`. |
| `notion.search` | `POST /search` | none | Returns redacted `results`, pagination fields, result count, sensitivity, provenance, and taint metadata. |
| `notion.get_block` | `GET /blocks/{block_id}` | `block_id` | Returns `{ "block": ... }`. |
| `notion.update_block` | `PATCH /blocks/{block_id}` | `block_id` | Removes `block_id` from the input and sends all remaining fields. |
| `notion.delete_block` | `PATCH /blocks/{block_id}` with `{ "archived": true }` | `block_id` | Soft archives the block and returns `{ "block": ... }`. |
| `notion.get_block_children` | `GET /blocks/{block_id}/children` | `block_id` | Returns `results`, `has_more`, and `next_cursor`. Runtime does not accept `start_cursor` here. |
| `notion.append_blocks` | `PATCH /blocks/{block_id}/children` | `block_id`, `children` | Sends `{ "children": ... }` and returns `results`. |
| `notion.add_comment` | `POST /comments` | `parent`, `rich_text` | Returns `{ "comment": ... }`. |
| `notion.list_comments` | `GET /comments?block_id={block_id}` | `block_id` | Returns `results`, `has_more`, and `next_cursor`. Runtime does not accept `start_cursor` here. |

Identifier and cursor handling is deliberately restrictive:

- Page, database, block, and comment IDs reject empty strings, slashes, backslashes, query markers, fragments, ampersands, equals signs, percent signs, spaces, tabs, newlines, and null bytes.
- Accepted ID path segments are percent encoded before being placed into request paths.
- Pagination cursors reject empty strings, control characters, and values longer than 512 bytes.
- `query_database` accepts an optional safe `start_cursor`.
- `search` accepts optional `query`, `filter`, and safe `start_cursor`.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Current Notion docs describe the API base URL as `https://api.notion.com` and require a `Notion-Version` header on REST API requests. Runtime appends `/v1` in its base URL and sends `Notion-Version: 2026-03-11`.
- Current Notion docs introduce the data-source object and data-source query APIs after the database/data-source split. Runtime still exposes database-centric operations and calls `/databases/{database_id}/query`.
- Current Notion docs describe cursor values as opaque. Runtime validates cursor byte length and control characters before forwarding them.
- Current Notion docs describe append-block limits, including a maximum of 100 block children in one request. Runtime documents this in hints but does not enforce the 100-child limit before sending.
- Manifest rate-limit pools exist for read, write, delete, and search at 3 requests per 1000 ms with burst 3. Runtime introspection reports no rate-limit metadata.
- Manifest event capabilities advertise streaming support with no replay and a 50-event minimum buffer. Runtime does not expose subscribe or unsubscribe handlers in the stdio entrypoint.
- There is no dedicated tracked verification shell script for this connector.

Remaining provider parity work includes database/data-source endpoint naming, rate-limit pool reporting, append child-count enforcement, and event delivery. The native session continues to use the existing FCP 2 JSONL handshake; this change is not a transport-version migration.

## First-Slice Scope

The current Notion README slice documents the existing runtime surface:

- token and credential-id configuration
- API URL and Notion API version handling
- Notion page, database, block, search, and comment operations
- lifecycle, doctor, health, self-check, simulate, introspect, invoke, and shutdown behavior
- provider error mapping, retry behavior, timeout behavior, redaction, ID validation, and cursor validation
- runtime/manifest/provider-doc drift around data sources, schemas, approvals, rate limits, events, simulation, and lifecycle reset
- deterministic WireMock integration tests

## Auth And Zone Boundary

- Authentication mechanisms: direct Notion integration token or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability families:
  - `notion.read`
  - `notion.write`
  - `notion.delete`
  - `notion.search`
- Manifest required capabilities are `network.dns`, `network.egress`, `network.tls.sni`, and `storage.state`.
- Optional manifest capability `media.download` is declared but not mapped to an operation in this runtime.
- The connector does not intentionally persist integration tokens, credential IDs beyond configuration metadata, provider payloads, provider error bodies, search results, pages, databases, blocks, comments, request counters, or error counters outside process memory.
- Notion payloads can contain private workspace documents, page properties, databases, comments, user metadata, and email addresses. Treat live output as work-zone sensitive data unless the host supplies a stricter zone policy.
- Runtime search redacts person emails in `people` properties and user objects under `created_by` and `last_edited_by`.

## Network And Runtime Invariants

- Default runtime API URL: `https://api.notion.com/v1`.
- Direct token mode production host policy accepts `https://api.notion.com`.
- Loopback URLs are accepted for deterministic tests in direct token mode.
- `credential_id` mode allows custom absolute URLs after basic URL shape validation.
- Manifest operation network policy allows `api.notion.com` on port `443`, requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, caps redirects at zero, and caps response sizes by operation.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120000 ms` wall-clock timeout, no exec, no ptrace, read-only `/usr` and `/lib`, and writable `$CONNECTOR_STATE`.
- The connector does not open inbound sockets.
- Provider 401 and 403 map to unauthorized.
- Provider 404 maps to resource not found.
- Provider 429 is retryable and honors `Retry-After` seconds, defaulting to 60 seconds when absent.
- Provider 5xx responses are retryable external errors.
- Other provider errors are terminal external API errors with truncated response bodies.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `notion.read` | Read pages, databases, blocks, block children, comments, and database query results. |
| `notion.write` | Create or update pages, databases, blocks, block children, and comments. |
| `notion.delete` | Archive pages and blocks. |
| `notion.search` | Search across Notion objects shared with the integration. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `notion.create_page` | `POST /pages` | `notion.write` | `Risky` | `Medium` | `None` | Creates workspace content. |
| `notion.get_page` | `GET /pages/{page_id}` | `notion.read` | `Safe` | `Low` | `Strict` | Reads page properties. |
| `notion.update_page` | `PATCH /pages/{page_id}` | `notion.write` | `Risky` | `Medium` | `Strict` | Mutates page properties. |
| `notion.delete_page` | `PATCH /pages/{page_id}` archive body | `notion.delete` | `Risky` | `High` | `Strict` | Archives a page. |
| `notion.get_database` | `GET /databases/{database_id}` | `notion.read` | `Safe` | `Low` | `Strict` | Reads database metadata. |
| `notion.create_database` | `POST /databases` | `notion.write` | `Risky` | `Medium` | `None` | Creates database schema. |
| `notion.update_database` | `PATCH /databases/{database_id}` | `notion.write` | `Risky` | `Medium` | `Strict` | Mutates database metadata or schema fields. |
| `notion.query_database` | `POST /databases/{database_id}/query` | `notion.read` | `Safe` | `Low` | `Strict` | Reads rows from a database-like source. |
| `notion.search` | `POST /search` | `notion.search` | `Safe` | `Medium` | `Strict` | Searches shared workspace objects and adds sensitivity metadata. |
| `notion.get_block` | `GET /blocks/{block_id}` | `notion.read` | `Safe` | `Low` | `Strict` | Reads block metadata/content. |
| `notion.update_block` | `PATCH /blocks/{block_id}` | `notion.write` | `Risky` | `Medium` | `Strict` | Mutates a block. |
| `notion.delete_block` | `PATCH /blocks/{block_id}` archive body | `notion.delete` | `Risky` | `High` | `Strict` | Archives a block. |
| `notion.get_block_children` | `GET /blocks/{block_id}/children` | `notion.read` | `Safe` | `Low` | `Strict` | Reads first-level child blocks. |
| `notion.append_blocks` | `PATCH /blocks/{block_id}/children` | `notion.write` | `Risky` | `Medium` | `None` | Appends content under a block. |
| `notion.add_comment` | `POST /comments` | `notion.write` | `Risky` | `Medium` | `None` | Adds a page or block comment. |
| `notion.list_comments` | `GET /comments?block_id=...` | `notion.read` | `Safe` | `Low` | `Strict` | Reads comment threads attached to a block. |

## Resource URIs

Runtime derives resource bindings from the actual validated input for both simulation and invocation. Signed allow/deny constraints apply to these scopes:

| Operation family | Resource URI shape |
|------------------|------------------------------|
| Pages | `notion://page/{page_id}` |
| Databases and database queries | `notion://database/{database_id}` |
| Blocks, block children, appends, and comment listing | `notion://block/{block_id}` |
| Page/database creation and comment creation | The selected parent page, database, discussion (`notion://discussion/{discussion_id}`), or workspace (`notion://workspace`) |
| Workspace search | `notion://workspace/search` |

Each creation parent must identify exactly one resource. UUID IDs are normalized to lowercase, hyphenated form for authorization, so compact or uppercase aliases cannot evade a resource deny; path segments use the same validation and encoding rules as HTTP dispatch. Search covers the currently configured integration's workspace visibility. Configuration changes revoke all prior instance-bound tokens.

## Explicit Non-Goals

The current implementation does not include:

- Notion OAuth setup, token refresh, connection creation, capability provisioning, or workspace installation flows
- webhooks, subscription delivery, durable replay, event acknowledgement, or changed-object sync
- file uploads, file downloads, user directory enumeration, custom emoji management, views, templates, public-page publishing, workspace administration, or database/data-source migration tooling
- recursive block tree traversal, rich pagination helpers for block children or comments, or provider-side page-size controls outside current query/search paths
- data-source endpoint parity, `filter_properties`, view query APIs, or Notion SDK compatibility behavior
- durable storage of Notion pages, databases, comments, blocks, credentials, provider responses, or provider error bodies

These are excluded on purpose:

- Notion workspaces frequently contain private docs and comments. Reads and writes need explicit zone and capability boundaries before expanding the surface.
- Notion's database/data-source API model is moving. Endpoint parity should be deliberate rather than hidden behind broad compatibility shims.
- Write and delete operations mutate human-authored workspace content and need stronger approval/simulation parity before production promotion.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, `introspect()`, `invoke()`, and `shutdown()` are part of the public closeout contract. They surface:

- local configuration, client, request, and error counter state
- auth mode, API URL, and effective Notion version
- local network-constraint target checks
- credential-injection requirement for credential-id mode
- direct-token self-check through a live `POST /search` probe
- operation metadata and input/output schemas derived from the embedded manifest
- local simulation with the same input and authorization checks as invocation
- typed provider/FCP error mapping
- search redaction behavior for email-bearing person and user fields

The deterministic integration evidence is anchored on connector-local tests covering:

- error taxonomy for 401, 403, 404, 429, and 5xx responses
- token redaction and Bearer auth headers
- page, database, block, search, and comment request paths
- connector invoke dispatch for every declared operation
- capability-token verification and wrong-capability rejection
- missing required fields and unknown operation rejection
- search sensitivity metadata and person/user email redaction
- custom API URLs, credential-id mode, Notion version override, doctor, self-check, and manifest hash stability
- lifecycle revocation on successful and failed configuration/handshake attempts, forbidden zones, and workspace zone binding
- the shipped binary's real HTTP request, typed health and invoke envelopes, non-consuming simulation, signed call/byte budgets, malformed frames, oversized frames, and shutdown termination

## Source Notes

- `connectors/notion/src/connector.rs` defines configuration parsing, lifecycle handlers, diagnostics, introspection, simulation, invoke dispatch, operation validation, capability verification, search redaction, and shutdown behavior.
- `connectors/notion/src/client.rs` defines Notion HTTP request construction, auth headers, retry dispatch, timeout settings, endpoint paths, ID/cursor validation, response parsing, and provider error handling.
- `connectors/notion/src/types.rs` defines Notion response shapes for pages, databases, blocks, comments, rich text, pagination, and API errors.
- `connectors/notion/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/notion/src/limits.rs` defines Notion-facing limits used in hints.
- `connectors/notion/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, event capabilities, and rate-limit pools.
- `connectors/notion/tests/integration.rs` contains deterministic HTTP behavior and connector-level behavior.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/notion/README.md
LC_ALL=C rg -n '[^ -~]' connectors/notion/README.md
rg -n '\bmaster\b' connectors/notion/README.md
ubs connectors/notion/README.md
```

Cargo/rch is not required for this README-only contract. If source code changes are made, run the relevant connector tests and the workspace verification lane described in the repository `AGENTS.md`.
