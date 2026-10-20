# Roam Connector V3 Contract

> **Status**: PROVEN (2026-10-20; 12/12 graduation gauntlet, verifier + unit/integration/local_non_mock suites verified)
> **Bead**: `flywheel_connectors-j05nu.12.6`
> **Connector**: `fcp.roam`
> **Verification script**: `scripts/e2e/roam_connector_verification.sh`

## Purpose

This document defines the V3 retrofit surface for the existing Roam connector. The connector is a graph-scoped knowledge-base adapter for listing pages, reading page content, listing blocks, and creating blocks in a single Roam graph.

## Current Runtime Snapshot

The current crate exposes these operations:

- `roam.pages.list`
- `roam.pages.get`
- `roam.blocks.list`
- `roam.blocks.create`

Important runtime truths:

- Authentication is either a direct Roam bearer token or a secretless `credential_id` that depends on host-side injection.
- The default base URL is `https://api.roamresearch.com/api/graph`.
- `graph_name` defaults to `default` when not supplied.
- The connector is graph-scoped. It does not attempt multi-graph orchestration, account administration, or streaming updates.

## Scope Boundary

This retrofit keeps the connector intentionally narrow:

- List pages in the configured graph.
- Look up a page by title.
- List blocks on a page.
- Create a block beneath an existing page UID.
- Prove readiness and operator guidance through health, doctor, self-check, and introspection evidence.

Explicit non-goals for this slice:

- graph settings or account management
- template, extension, or export workflows
- full block-tree mutation APIs beyond simple block creation
- streaming subscriptions or webhook-style delivery

## Auth And Zone Expectations

- Home zone is `z:private`.
- Required capabilities cover DNS and connector state storage, with network egress enabled when live API access is needed.
- `credential_id` mode is supported for host-managed secret injection, but live verification remains degraded until concrete secret material is injected.

## Network And Runtime Invariants

- Production host: `api.roamresearch.com`
- HTTPS required for non-local targets
- Localhost overrides are allowed only for deterministic bridge-style fixtures
- The connector operates on exactly one configured graph at a time

## Readiness And Verification

Verification is replayed through:

```bash
scripts/e2e/roam_connector_verification.sh
```

Artifacts land under:

```text
artifacts/e2e/roam_connector/<timestamp>
```

The readiness contract should surface these operator truths:

- whether the configured base URL satisfies Roam host policy
- whether concrete secret material is available or the connector is still waiting for credential injection
- whether a live `roam.pages.list` probe succeeds against the configured graph
- that the connector is intentionally limited to page/block graph access rather than broader Roam account workflows

## Operation Inventory

See the runtime operations above (`roam.pages.list`, `roam.pages.get`, `roam.blocks.list`, `roam.blocks.create`).

## Operator Guidance

Prerequisites:
- Use the deterministic local loopback harness or `WireMock` server for verification; never log raw Roam bearer tokens.

Rerun commands:
- `bash scripts/e2e/roam_connector_verification.sh`
- `rch exec -- cargo test -p fcp-roam --test local_non_mock -- --nocapture`
- `rch exec -- cargo test -p fcp-roam --test integration -- --nocapture`
- `rch exec -- cargo clippy -p fcp-roam --all-targets -- -D warnings`
