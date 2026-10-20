# Confluence Connector V3 Contract

> **Status**: PROVEN (2026-10-20; 12/12 graduation gauntlet, verifier + unit/integration/local_non_mock suites verified)
> **Bead**: `flywheel_connectors-j05nu.5.2.1`
> **Verification script**: `scripts/e2e/confluence_connector_verification.sh`
> **Unblocks**: `flywheel_connectors-j05nu.5.2.2`
> **Primary upstreams**:
> - https://developer.atlassian.com/cloud/confluence/using-the-rest-api/
> - https://developer.atlassian.com/cloud/confluence/rest/v2/api-group-space/
> - https://developer.atlassian.com/cloud/confluence/rest/v2/api-group-page/
> - https://developer.atlassian.com/cloud/confluence/rest/v1/api-group-search/
> - https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/

## Purpose

This document fixes the first implementation slice for `fcp.confluence` so the follow-on implementation bead can converge on a stable contract instead of inheriting the parent feature's over-broad scope.

The connector is a request-response knowledge-platform surface for Atlassian Confluence Cloud. The intended first slice is space discovery, page CRUD, CQL-backed search, and a narrow health/readiness probe. Attachments, comments, permissions, and OAuth flows are explicitly deferred.

## Current Runtime Snapshot

The current connector code already exposes these operations:

- `confluence.spaces.list`
- `confluence.spaces.get`
- `confluence.pages.list`
- `confluence.pages.get`
- `confluence.pages.create`
- `confluence.pages.update`
- `confluence.pages.delete`
- `confluence.search`
- `confluence.health`

The current implementation is materially ahead of the manifest:

- Runtime exposes nine operations.
- `manifest.toml` currently declares only `spaces_list`, `pages_create`, and `pages_delete`.
- The client currently uses the legacy `/wiki/rest/api/...` family for spaces, pages, and search.

That drift is the main follow-on implementation problem for `flywheel_connectors-j05nu.5.2.2`.

## First-Slice Scope

The first Confluence slice is intentionally narrow:

- List spaces visible to the authenticated tenant user.
- Get space details for a known `space_key`.
- List pages within a known space.
- Get a page by `page_id`, including storage body and version metadata.
- Create a page in a known space.
- Update a page with explicit version control.
- Delete a page by `page_id`.
- Search content with CQL.
- Run a simple health probe against the tenant API.

The public operation shape should stay stable around `space_key` and `page_id` even if the underlying provider calls are reconciled from v1 endpoints toward the documented Cloud v2 surfaces.

## Provider API Split

The current Atlassian Cloud docs are mixed rather than purely v2:

- Spaces are documented in v2 under `/wiki/api/v2/spaces`.
- Pages are documented in v2 under `/wiki/api/v2/pages`.
- Search remains documented under the v1 `/wiki/rest/api/search` surface.
- Atlassian also documents v2 groups for attachments, comments, and space permissions, but those groups are outside this first slice.

That means the first-slice contract is:

- Spaces and pages are conceptually aligned to the current Cloud v2 model.
- Search remains a v1 API dependency.
- The existing all-v1 implementation is acceptable as an intermediate state, but `flywheel_connectors-j05nu.5.2.2` must either reconcile toward this mixed provider contract or document any intentional v1 holdovers explicitly.

## Auth And Scope Boundary

- The first slice is tenant-scoped to one Confluence Cloud site, configured as `base_url` plus `email` and `api_token`.
- The intended production `base_url` shape is `https://<tenant>.atlassian.net/wiki`.
- The current connector authenticates with HTTP Basic auth using `email:api_token`, base64-encoded into the `Authorization` header.
- Atlassian Support currently recommends scoped API tokens for stronger least-privilege, but scoped tokens must be used via `https://api.atlassian.com/ex/confluence/{cloudId}` rather than the tenant-local `/wiki` host. The current connector does not implement that mode.
- OAuth2 is not part of the first slice, even though the parent feature bead mentions it.
- The connector instance is tenant-scoped, not space-scoped. Space restriction happens through call parameters such as `space_key`, not through a connector-level allowlist.
- The implementation currently tolerates an empty token as a secretless proxy-injection mode. That is an implementation detail, not a stable public auth contract yet.
- Atlassian Support now sets new API tokens to expire within 1 to 365 days, with a one-year default. Operator guidance must treat token rotation as normal rather than exceptional.

## Network And Runtime Invariants

- Production host family: `*.atlassian.net`
- Expected path prefix: `/wiki`
- Ports: `443`
- TLS + SNI required
- `deny_localhost = true`
- `deny_private_ranges = true`
- `deny_tailnet_ranges = true`
- `deny_ip_literals = true`
- No cross-host redirects
- Request timeout default: `30_000 ms`
- `doctor()` currently allows `localhost` and `127.0.0.1` as test overrides, but that is test-only behavior and not part of the live-ready contract
- Search, spaces, and pages all share the same tenant host boundary in the first slice

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `confluence.spaces.read` | Discover and inspect spaces visible to the authenticated principal |
| `confluence.pages.read` | List, inspect, and search page content |
| `confluence.pages.write` | Create, update, and delete pages in spaces where the principal has write authority |

For the first slice, delete remains under `confluence.pages.write` to match the current runtime. That capability grouping is acceptable short term, but the dangerous delete path still requires explicit approval semantics.

## Operation Inventory

| Operation | Provider endpoint target | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|--------------------------|------------|------------|-----------|-------------|-----------|
| `confluence.spaces.list` | `GET /wiki/api/v2/spaces` or equivalent tenant-local v1 listing during transition | `confluence.spaces.read` | `Safe` | `Low` | `None` | Read-only space discovery inside one tenant. |
| `confluence.spaces.get` | `GET /wiki/api/v2/spaces?keys=...` or equivalent key lookup | `confluence.spaces.read` | `Safe` | `Low` | `None` | Read-only inspection of one known space boundary. |
| `confluence.pages.list` | `GET /wiki/api/v2/spaces/{id}/pages` or equivalent transitional listing | `confluence.pages.read` | `Safe` | `Low` | `None` | Read-only enumeration of pages inside a known space. |
| `confluence.pages.get` | `GET /wiki/api/v2/pages/{id}` or equivalent tenant-local content lookup | `confluence.pages.read` | `Safe` | `Low` | `None` | Read-only page retrieval including body and version metadata. |
| `confluence.pages.create` | `POST /wiki/api/v2/pages` or equivalent transitional content create | `confluence.pages.write` | `Risky` | `Medium` | `BestEffort` | Page creation mutates knowledge state and duplicate retries can create ambiguous results. |
| `confluence.pages.update` | `PUT /wiki/api/v2/pages/{id}` or equivalent transitional content update | `confluence.pages.write` | `Risky` | `Medium` | `BestEffort` | Updates require explicit version coordination and retries can fail after partial success due to version drift. |
| `confluence.pages.delete` | `DELETE /wiki/api/v2/pages/{id}` or equivalent transitional delete | `confluence.pages.write` | `Dangerous` | `High` | `BestEffort` | Delete is a real destructive mutation. Atlassian documents trash and purge semantics, so the connector must not describe it as a guaranteed hard delete unless purge support is implemented explicitly. |
| `confluence.search` | `GET /wiki/rest/api/search` | `confluence.pages.read` | `Safe` | `Low` | `None` | CQL-backed read-only search across content visible to the principal. |
| `confluence.health` | Lightweight authenticated tenant probe | `confluence.spaces.read` | `Safe` | `Low` | `Strict` | Deterministic reachability and auth check used for configure, doctor, and self-check. |

## Explicit Non-Goals

The first implementation slice does not include these provider surfaces:

- attachments list, upload, download, or metadata flows
- comments list, create, update, or delete
- content restrictions, page permissions, or space permissions as standalone operations
- space creation, archival, role assignment, or administration
- labels, properties, blog posts, whiteboards, databases, folders, or other broader Confluence content families
- OAuth2, Atlassian app auth, or scoped-token access through `api.atlassian.com/ex/confluence/{cloudId}`
- webhook ingestion or any long-lived streaming behavior

These are excluded on purpose:

- The current code does not implement them.
- The parent feature bead currently overstates the first slice relative to the live crate.
- Stabilizing truthful spaces/pages/search behavior is higher value than widening into admin or collaboration surfaces prematurely.

## Implementation Notes For `flywheel_connectors-j05nu.5.2.2`

- Reconcile manifest and runtime so every exposed operation is declared truthfully with typed schemas and network constraints.
- Decide explicitly whether spaces/pages stay on the current v1 implementation surface for now or migrate to the documented v2 endpoints during the implementation bead. Search should remain on v1 unless Atlassian moves that surface.
- Keep the public operation inputs stable unless there is a strong reason to break them. In particular, `space_key` is a useful operator-facing input even if the underlying provider call becomes id-based.
- Fix the current semantic drift around delete. The code and manifest should not imply irreversible purge semantics unless purge is implemented explicitly.
- Revisit idempotency metadata. `pages.create` and `pages.update` are currently modeled too strongly for real provider behavior.
- `doctor()` and `self_check()` should report tenant host validity, `/wiki` path expectations, unsupported auth modes, and token-expiry rotation expectations clearly.
- Tests should cover path sanitization, Basic auth construction, `401` unauthorized, `429 Retry-After`, pagination, version-conflict handling, and delete behavior.

## Live Sandbox Verification

Verification script: `scripts/e2e/confluence_connector_verification.sh`

The gated live suite uses `FCP_LIVE_SANDBOX=1` plus `CONFLUENCE_SANDBOX_BASE_URL`, `CONFLUENCE_SANDBOX_EMAIL`, `CONFLUENCE_SANDBOX_API_TOKEN`, `CONFLUENCE_SANDBOX_SPACE_KEY`, and `FCP_SANDBOX_RUN_NAMESPACE`. It performs read-only space and page listings and emits redaction-safe `CONFLUENCE_LIVE_SANDBOX_JSONL` evidence.

Focused rerun command:

```bash
rch exec -- cargo test -p fcp-confluence --test live_verification -- --nocapture
```

## Source Notes

This contract is grounded in Atlassian's current official documentation:

- The "Using the REST API" guide still documents tenant-local Basic auth using Atlassian email plus API token and shows `/wiki/rest/api/search` examples.
- The current Cloud reference documents spaces and pages under REST API v2.
- The current Cloud reference documents search under the v1 `/wiki/rest/api/search` family.
- Atlassian Support documents scoped API tokens, token expiry windows, and the requirement to use `api.atlassian.com/ex/confluence/{cloudId}` for scoped-token calls.
- The Confluence Cloud reference also documents attachment, comment, and space-permission groups, which confirms those are real provider surfaces but not part of this first implementation slice.

## Operation Inventory

See the operation list above (`spaces_list`, `spaces_get`, `pages_list`, `pages_get`, `pages_create`, `pages_update`, `pages_delete`, `search`, `health`).

## Operator Guidance

Prerequisites:
- Use the deterministic loopback/WireMock harness for local verification; never log raw Atlassian API tokens or unredacted page bodies.

Rerun commands:
- `bash scripts/e2e/confluence_connector_verification.sh`
- `rch exec -- cargo test -p fcp-confluence --test local_non_mock -- --nocapture`
- `rch exec -- cargo test -p fcp-confluence --test integration -- --nocapture`
- `rch exec -- cargo clippy -p fcp-confluence --all-targets -- -D warnings`
