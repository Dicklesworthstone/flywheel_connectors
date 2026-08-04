# Coda Connector V3 Contract

> **Status**: PROVEN runtime contract documented with remote Coda verifier proof
> **Bead**: `flywheel_connectors-j05nu.5.3.1`
> **Unblocks**: `flywheel_connectors-j05nu.5.3.2`
> **Primary upstream**: https://coda.io/developers/apis/v1
> **Verification script**: `scripts/e2e/coda_connector_verification.sh`
> **Proof bundle**: `/Users/jemanuel/projects/flywheel_connectors/.codex-targets/coda-verification/20260607T113953Z/evidence/summary.json` (`sha256:451acca5f8300bf9aec6f3d96b8128b45f2d406335da728fac8e18855883f37c`, `overall_status=failed` only because the manifest lane was run before the capability/interface-hash refresh; `cargo_check`, `format_check`, `health_guidance`, `doctor_guidance`, `self_check`, `retryable_self_check`, `pagination_evidence`, `dangerous_delete_evidence`, `compliance`, `integration_suite`, `crate_suite`, and `clippy` all passed remotely)
> **Supplemental manifest proof**: `/Users/jemanuel/projects/flywheel_connectors/.codex-targets/coda-verification/20260607T1506Z/logs/manifest_check_after_promotion.log` (`sha256:7a643c25e4bf14580e57c6ea102c97816d220611f162473b46295931b8f004d6`, `rch` job `29871232832767237` on `vmi1149989`, `changed=false`, exit 0)
> **Supplemental gauntlet proof**: `/Users/jemanuel/projects/flywheel_connectors/.codex-targets/coda-verification/20260607T1506Z/evidence/coda_gauntlet_after_promotion.jsonl` (`sha256:5ba860e94073969e8d5a530e779bf74d2474de01b510b0382cb18dd13eb91794`, all 12 checks passed)

## Purpose

This document pins down the first implementation slice for `fcp.coda` so the follow-on runtime bead has a stable contract instead of inventing scope while coding.

The connector targets Coda's REST API at `https://coda.io/apis/v1` and treats Coda as a request-response SaaS surface with asynchronous document mutations.

## Current Runtime Snapshot

The current crate already exposes these operations:

- `coda.account.whoami`
- `coda.docs.list`
- `coda.docs.get`
- `coda.pages.list`
- `coda.pages.get`
- `coda.tables.list`
- `coda.tables.get`
- `coda.columns.list`
- `coda.rows.list`
- `coda.rows.get`
- `coda.rows.upsert`
- `coda.rows.delete`
- `coda.formulas.list`
- `coda.formulas.get`
- `coda.controls.list`
- `coda.controls.get`
- `coda.mutations.get_status`
- `coda.health`

Important implementation truths that this contract must preserve:

- Configuration is `workspace_id` plus `api_token`, with optional `allowed_doc_ids`, retry tuning, base URL override, request timeout, mutation poll interval, and mutation deadline.
- The current first slice is bearer-token only. `credential_id` is not part of the implemented config surface yet.
- The connector binds to exactly one workspace and rejects docs outside that workspace.
- `allowed_doc_ids` is an optional second narrowing pass on top of workspace scope.
- Row writes are asynchronous from the provider's perspective: the connector consumes `requestId` and polls `mutationStatus` until completion or timeout.
- `health` and `self_check` are both grounded in `whoami` reachability plus workspace-boundary validation.
- `manifest.toml` is expected to declare the same `coda.io` network boundary and first-slice rate-limit pools described below, so the contract is mechanically enforceable instead of being README-only guidance.

## First-Slice Scope

The first implementation slice is intentionally narrow:

- Read account identity and token scope via `whoami`.
- Enumerate docs inside one configured workspace boundary.
- Read doc, page, table, column, row, formula, and control metadata.
- Read individual rows and formula values.
- Support controlled row upsert and row delete flows.
- Track document mutations through Coda `requestId` and `mutationStatus`.
- Expose a safe health probe backed by token reachability and workspace-boundary validation.

The connector is `operational` and `stateless`.

## Auth And Scope Boundary

- Authentication is Bearer-token only.
- The token represents a single Coda user and exposes a primary workspace through `GET /whoami`.
- The connector instance binds to exactly one configured `workspace_id`.
- Per-operation `doc_id` input is allowed, but the connector MUST reject docs whose returned `workspaceId` does not match the configured workspace boundary.
- Optional `allowed_doc_ids` narrowing is permitted for higher-trust deployments, but the default contract is workspace-scoped rather than single-doc-scoped.
- `credential_id` is explicitly out of scope for the current first slice; the implemented runtime only accepts a bearer API token.
- Stable IDs are the contract surface: `docId`, `pageId`, `tableId`, `rowId`, `columnId`, `formulaId`, and `controlId`.
- Name-based lookups are a fallback only for safe read operations. They are forbidden for destructive operations because Coda documents that names are fragile and can resolve ambiguously.

## Network And Runtime Invariants

- Base API host: `coda.io`
- Base path: `/apis/v1`
- Port: `443`
- TLS + SNI required for live Coda traffic
- `deny_localhost = true`
- `deny_private_ranges = true`
- No redirects to other hosts
- Published rate limits currently include reads at `100 requests / 6 seconds`, general writes at `10 requests / 6 seconds`, doc-content writes at `5 requests / 10 seconds`, and doc listing at `4 requests / 6 seconds`.
- Writes MUST treat HTTP `202 Accepted` as queued work, not completion.
- Every mutation path MUST poll `GET /mutationStatus/{requestId}` until completion or timeout.
- `rows.upsert` is only valid for base tables, not views.
- `X-Coda-Doc-Version: latest` is optional caller-controlled behavior, not the default, because Coda may return `400` when the latest snapshot is unavailable.

For deterministic connector-local verification, the runtime also allows an explicit `http://localhost` or `http://127.0.0.1` base URL override so integration tests can drive a mock Coda API without live credentials. That override is for test harnesses only; live operator guidance still assumes `https://coda.io/apis/v1`.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `coda.account.read` | Token identity, workspace, and token-scope inspection |
| `coda.docs.read` | Doc, page, and high-level metadata discovery |
| `coda.tables.read` | Table and column discovery |
| `coda.rows.read` | Row listing and point lookup |
| `coda.rows.write` | Row upsert and deletion |
| `coda.formulas.read` | Formula discovery and value reads |
| `coda.controls.read` | Control discovery and inspection |
| `coda.mutations.read` | Poll queued mutation status |

## Operation Inventory

| Operation | Endpoint | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------|------------|------------|-----------|-------------|-----------|
| `coda.account.whoami` | `GET /whoami` | `coda.account.read` | `Safe` | `Low` | `Strict` | Read-only auth and workspace probe used during configure, doctor, self-check, and health. |
| `coda.docs.list` | `GET /docs` | `coda.docs.read` | `Safe` | `Low` | `Strict` | Read-only workspace doc discovery. |
| `coda.docs.get` | `GET /docs/{docId}` | `coda.docs.read` | `Safe` | `Low` | `Strict` | Read-only doc metadata, including folder, workspace, and publication state. |
| `coda.pages.list` | `GET /docs/{docId}/pages` | `coda.docs.read` | `Safe` | `Low` | `Strict` | Structural discovery inside a doc. |
| `coda.pages.get` | `GET /docs/{docId}/pages/{pageId}` | `coda.docs.read` | `Safe` | `Low` | `Strict` | Read-only page metadata and layout context. |
| `coda.tables.list` | `GET /docs/{docId}/tables` | `coda.tables.read` | `Safe` | `Low` | `Strict` | Read-only table discovery. |
| `coda.tables.get` | `GET /docs/{docId}/tables/{tableId}` | `coda.tables.read` | `Safe` | `Low` | `Strict` | Read-only table metadata including row counts and view/base-table distinctions. |
| `coda.columns.list` | `GET /docs/{docId}/tables/{tableId}/columns` | `coda.tables.read` | `Safe` | `Low` | `Strict` | Read-only schema discovery required before robust row writes. |
| `coda.rows.list` | `GET /docs/{docId}/tables/{tableId}/rows` | `coda.rows.read` | `Safe` | `Low` | `Strict` | Read-only row listing, filtering, and sync-style enumeration. |
| `coda.rows.get` | `GET /docs/{docId}/tables/{tableId}/rows/{rowId}` | `coda.rows.read` | `Safe` | `Low` | `Strict` | Read-only point lookup for a stable row identifier. |
| `coda.rows.upsert` | `POST /docs/{docId}/tables/{tableId}/rows` | `coda.rows.write` | `Risky` | `Medium` | `BestEffort` | Side-effecting row insertion/update with no provider-side idempotency key; connector should prefer `keyColumns` and receipt tracking, but exact-once is not guaranteed by Coda. |
| `coda.rows.delete` | `DELETE /docs/{docId}/tables/{tableId}/rows` with `rowIds` request body | `coda.rows.write` | `Dangerous` | `High` | `Strict` | Destructive row deletion. The connector currently requires one or more stable row IDs, sends them as a batch body, and polls `mutationStatus` before returning. |
| `coda.formulas.list` | `GET /docs/{docId}/formulas` | `coda.formulas.read` | `Safe` | `Low` | `Strict` | Read-only discovery of named formulas. |
| `coda.formulas.get` | `GET /docs/{docId}/formulas/{formulaId}` | `coda.formulas.read` | `Safe` | `Low` | `Strict` | Read-only formula value inspection. |
| `coda.controls.list` | `GET /docs/{docId}/controls` | `coda.controls.read` | `Safe` | `Low` | `Strict` | Read-only discovery of controls exposed in the doc. |
| `coda.controls.get` | `GET /docs/{docId}/controls/{controlId}` | `coda.controls.read` | `Safe` | `Low` | `Strict` | Read-only control inspection. |
| `coda.mutations.get_status` | `GET /mutationStatus/{requestId}` | `coda.mutations.read` | `Safe` | `Low` | `Strict` | Polls queued mutation completion and warnings after any async write. |
| `coda.health` | `GET /whoami` via connector health/self-check path | `coda.account.read` | `Safe` | `Low` | `Strict` | Safe readiness probe for token reachability and workspace-boundary validation. |

## Explicit Non-Goals

The first implementation slice does not include these surfaces:

- `docs.create`, `docs.update`, and `docs.delete`
- folder CRUD
- ACL and permission management
- publish and unpublish flows
- page create, update, delete, export, and content mutation
- name-based destructive row deletion
- push-button execution
- automations, analytics, Packs, or browser-link resolution
- multi-workspace aggregation from a single connector instance

These are excluded on purpose:

- Doc and ACL mutations expand the trust boundary from data edits into workspace governance.
- Destructive row deletes are supported only through explicit stable row IDs. Name-based destructive deletes remain out of scope because names are ambiguous and fragile.
- Button execution is too broad because Coda documents that a button may perform arbitrary actions elsewhere in the doc, including Pack actions.
- Analytics, publishing, and automation surfaces are useful, but they are orthogonal to the minimal document-and-table workflow this connector needs first.

## Implementation Notes For `flywheel_connectors-j05nu.5.3.2`

- `self_check()` should call `whoami` and surface token validity, token scope (`scoped`), and workspace mismatch failures explicitly.
- Config should include `workspace_id`, `api_token`, optional `allowed_doc_ids`, `base_url`, bounded request timeout, mutation poll interval, mutation deadline, and retry policy tuning.
- Keep the first slice bearer-token only. Secretless `credential_id` support is a future expansion, not part of the current contract.
- Error mapping must preserve Coda `401`, `403`, `404`, `429`, and `400` cases distinctly.
- Write paths should treat `202` as `accepted_for_processing`, then poll `mutationStatus` until completion, timeout, or warning.
- `health` should remain a safe `whoami`-backed probe that reports workspace-boundary context rather than inventing a separate provider endpoint.
- Reads should prefer stable IDs and should not silently downgrade to name-based destructive behavior.
- Row upsert support should document that multiple rows may be updated when `keyColumns` match more than one record.
- Tests should cover snapshot-staleness behavior, rate limits, async mutation polling, workspace-boundary rejection, and name-resolution ambiguity rejection.

## Readiness And Verification

The follow-on closeout bead for this connector is `flywheel_connectors-j05nu.5.3.3`. Verification artifacts should be reproducible without reopening planning notes.

- Replayable verification bundle: `scripts/e2e/coda_connector_verification.sh`
- Artifact root: `artifacts/e2e/coda_connector/<timestamp>`
- Manifest verification command: `RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=1 rch exec -- cargo run -q -p fwc -- manifest fix connectors/coda/manifest.toml --check --json`
- Focused cargo checks:
  - `RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=1 rch exec -- cargo check -p fcp-coda --all-targets`
  - `RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=1 rch exec -- cargo test -p fcp-coda --test integration -- --nocapture`
  - `RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=1 rch exec -- cargo test -p fcp-coda -- --nocapture`
  - `RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=1 rch exec -- cargo clippy -p fcp-coda --all-targets -- -D warnings`

Operator guidance for verification:

- Prefer a disposable Coda workspace and doc set, or a localhost mock server, before exercising write paths.
- Keep one connector instance bound to one `workspace_id`; if `allowed_doc_ids` is set, every verification doc must be inside that explicit narrowing list.
- Redact API tokens, Authorization headers, request IDs, login IDs, workspace IDs, doc IDs, row IDs, browser links, and copied request logs before sharing artifacts.
- Treat `coda.rows.upsert` and `coda.rows.delete` as live mutations unless the verification bundle is pointed at a mock server.
- Common remediation:
  - `not_configured`: configure `workspace_id`, `api_token`, timeout, retry, and mutation polling settings, then rerun `self_check`.
  - `coda_auth_rejected`: replace the API token and confirm `GET /whoami` succeeds.
  - `workspace_mismatch`: align `workspace_id` with the workspace returned by `GET /whoami` or swap to the correct token.
  - `doc_allowlist_violation`: add the target doc to `allowed_doc_ids` or verify against an already-allowed doc.
  - `self_check_retryable`: wait for Coda to recover or increase timeout / retry settings before rerunning the verification bundle.
  - `network_constraints_invalid`: use `https://coda.io/apis/v1` for live verification or an explicit localhost override for deterministic tests.

## Source Notes

This contract is grounded in the current connector implementation plus Coda's official API reference:

- `connectors/coda/src/connector.rs` defines the current operation inventory, capability mapping, idempotency classes, health/self-check contract, and workspace-scope enforcement.
- `connectors/coda/src/client.rs` defines the concrete endpoint shapes, including batch row deletion via `DELETE .../rows` with a `rowIds` JSON body and explicit `mutationStatus` polling helpers.
- `connectors/coda/manifest.toml` defines the current manifest-declared risk, safety, and idempotency semantics that the README contract must match.

- The API root is `https://coda.io/apis/v1`.
- Coda exposes docs, pages, tables, rows, formulas, controls, `whoami`, and `mutationStatus` as first-class endpoints.
- Coda publishes rate limits for reads, writes, doc-content writes, and doc listing.
- Mutating endpoints return `202` with a `requestId`, and completion is checked through `GET /mutationStatus/{requestId}`.
- `rows.upsert` supports `keyColumns`, updates multiple matching rows, and only works on base tables.

## Verification Bundle

The readiness closeout for the current connector surface is anchored on `scripts/e2e/coda_connector_verification.sh`.
It writes replayable artifacts under `artifacts/e2e/coda_connector/<timestamp>` and is intended to be rerun through `rch`-offloaded Cargo commands plus a crate-local `cargo fmt` check.

The verification bundle captures:

- manifest validation for `connectors/coda/manifest.toml`
- `cargo check -p fcp-coda --all-targets`
- formatting verification for the Coda crate
- targeted readiness evidence for `health`, `doctor`, `self_check`, docs pagination/scope filtering, destructive row deletion, and typed introspection compliance
- the full Coda integration suite and full crate test suite
- `cargo clippy -p fcp-coda --all-targets -- -D warnings`

## Operator Guidance

Prerequisites:
- Use a disposable workspace or copied fixture docs with at least one base table and stable row IDs before running verification.
- Configure a dedicated bearer API token for that workspace and keep `workspace_id` aligned with the workspace returned by `whoami`.
- Keep `allowed_doc_ids` either empty or pinned to the fixture docs you intend to exercise so pagination and mutation evidence stay deterministic.

Dedicated environment:
- Never point the verification bundle at a shared production workspace. `coda.rows.delete` is destructive, and both write paths rely on asynchronous mutation completion rather than reversible drafts.

Redaction rules:
- Redact `api_token`, Authorization headers, workspace IDs, doc IDs, row IDs, browser links, login IDs, and copied request payloads before sharing logs.
- Treat table names, formula/control values, row contents, and doc metadata as potentially sensitive workspace data.
- If artifacts leave the local machine, replace live fixture identifiers with sanitized stand-ins first.

Common remediation:
- If `configure` rejects `base_url`, use `https://coda.io/apis/v1` for live runs or a localhost mock endpoint that preserves the same `/apis/v1` path prefix.
- If `self_check` reports `workspace_mismatch`, align `workspace_id` with the workspace returned by `whoami` for the chosen token or rotate to the correct token.
- If docs or row mutations fail due to scope, either add the fixture doc to `allowed_doc_ids` or rerun against a doc in the configured workspace boundary.
- If verification hits 429s, respect the backoff window, lower concurrency, and rerun once the provider bucket recovers.

Rerun commands:
- `scripts/e2e/coda_connector_verification.sh`
- `RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=1 rch exec -- cargo run -q -p fwc -- manifest fix connectors/coda/manifest.toml --check --json`
- `cargo fmt --manifest-path connectors/coda/Cargo.toml --check`
- `RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=1 rch exec -- cargo check -p fcp-coda --all-targets`
- `RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=1 rch exec -- cargo test -p fcp-coda --test integration -- --nocapture`
- `RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=1 rch exec -- cargo test -p fcp-coda`
- `RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=1 rch exec -- cargo clippy -p fcp-coda --all-targets -- -D warnings`
