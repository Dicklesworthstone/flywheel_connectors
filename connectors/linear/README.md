# Linear Connector V3 Contract

> **Status**: runtime contract documented with API-key header and manifest-policy drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Linear GraphQL upstream**: https://linear.app/developers/graphql
> **Linear OAuth upstream**: https://linear.app/developers/oauth-2-0-authentication
> **Linear webhooks upstream**: https://linear.app/developers/webhooks

## Purpose

This document fixes the operator-facing contract for `fcp.linear`. The connector exposes the Linear surfaces implemented in this crate: issue creation, issue reads and updates, issue search, team, cycle, project, and comment reads/writes, deterministic Beads-to-Linear sync planning, and pre-verified webhook payload processing.

The connector is intentionally a bounded Linear issue-tracking bridge. It is not a full Linear SDK, GraphQL pass-through client, workspace administration client, OAuth app installer, webhook listener, customer-management client, document client, initiative client, notification client, or durable issue-sync daemon.

## Current Runtime Snapshot

The current crate exposes these operations:

- `linear.create_issue`
- `linear.get_issue`
- `linear.update_issue`
- `linear.search_issues`
- `linear.list_teams`
- `linear.list_cycles`
- `linear.add_comment`
- `linear.list_projects`
- `linear.plan_sync`
- `linear.process_webhook`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-linear`.
- Runtime `BaseConnector` ID is `linear`.
- Manifest connector ID is `fcp.linear`.
- Manifest version is `0.1.0`.
- Configuration requires exactly one auth source:
  - `api_key`
  - `credential_id`
- `credential_id` must be a valid UUID.
- Direct `api_key` mode sends `Authorization: Bearer <key>`.
- `credential_id` mode sends no auth header; it assumes host or egress-proxy credential injection.
- Default GraphQL URL is `https://api.linear.app/graphql`.
- Direct `api_key` mode accepts only `https://api.linear.app` or local loopback test URLs.
- `credential_id` mode accepts any parseable absolute URL after rejecting userinfo, query strings, fragments, and missing hosts.
- Runtime reqwest timeout is `30 seconds`.
- Runtime request-context timeout is `30 seconds`.
- Runtime retry config sets `max_retries = 2` and routes GraphQL execution through the shared retry loop.
- `health_check` performs `query { viewer { id } }`.
- `self_check` performs the live viewer query only for direct-auth mode; credential-id mode reports `credential_injection_required`.
- `health` reports only local client configuration and request metrics, not live provider reachability.
- `doctor` checks configuration, client initialization, API URL, auth mode, a string-based host policy, and credential-injection status.
- `handshake` constructs a `CapabilityVerifier`, records a new session, grants requested capabilities back, and returns a SHA-256 hash of the bundled `manifest.toml`.
- `invoke` expects `operation`, `input`, and `capability_token`.
- `invoke` verifies a bound FCP capability token against the operation capability and operation-specific resource URIs before dispatching.
- `simulate` deserializes `SimulateRequest` and returns allowed without checking operation ID, configured state, handshake state, capability tokens, or approval policy.
- `handle_shutdown` calls the client runtime shutdown hook but does not clear client/config/verifier/session state or reset configured/handshaken flags.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Linear's current GraphQL docs distinguish OAuth bearer tokens from personal API keys. OAuth tokens are passed as `Authorization: Bearer <ACCESS_TOKEN>`, while personal API keys are documented as `Authorization: <API_KEY>`. Runtime direct `api_key` mode always sends a bearer header.
- Linear OAuth apps were migrated to refresh-token behavior on April 1, 2026, and access tokens are short-lived. Runtime does not implement OAuth, token refresh, revocation, migration, client credentials, PKCE, or actor authorization.
- Runtime `BaseConnector` ID is `linear`, while the manifest connector ID is `fcp.linear`.
- Runtime `simulate` is permissive and does not mirror invoke's capability-token verification.
- Runtime operation metadata sets `requires_approval = None` in introspection, while the manifest marks create, update, and comment creation as policy-gated.
- Manifest rate-limit operation pools map `linear.process_webhook` to `linear.read`, while runtime introspection and token verification use `linear.process_webhook`.
- Manifest gives `linear.plan_sync` network constraints for `api.linear.app`, but runtime `plan_sync` is local-only and does not call Linear.
- Runtime event caps say streaming is available, but the connector has no inbound listener and only processes webhook payloads forwarded by fcp-host.
- Runtime direct `api_key` URL policy is pinned to `api.linear.app`, while credential-id mode can configure arbitrary parsed absolute URLs.
- Runtime doctor host policy uses substring matching for `api.linear.app`, so self-check or configure-time validation is the stronger endpoint-policy source.
- Runtime `health` can report healthy for a configured client before handshake and without a live provider check.
- Runtime shutdown does not reset lifecycle state.

A follow-up parity bead should decide whether direct auth is an OAuth token or a personal API key, align the header accordingly, implement or explicitly exclude OAuth refresh behavior, make simulation deny by the same policy family as invoke, align approval metadata, map `linear.process_webhook` to its own rate-limit pool, and tighten credential-id endpoint policy.

## First-Slice Scope

The current Linear README slice documents the existing runtime surface:

- direct-key and credential-id configuration
- GraphQL issue, team, cycle, project, and comment operations
- deterministic Beads/Linear sync planning
- forwarded webhook processing with signature-validation flag, timestamp skew checks, and delivery replay protection
- retry, timeout, provider error, readiness, doctor, health, self-check, simulate, introspect, invoke, and shutdown behavior
- runtime/manifest drift around auth headers, approval metadata, endpoint policy, event streaming, rate-limit pools, and simulation
- mock-only GraphQL and connector integration tests

### Webhook Replay Protection

The host must verify `Linear-Signature` against the raw request body before
forwarding parsed JSON with `signature_validated = true`. The connector checks
the signed `payload.webhookTimestamp` in milliseconds against an inclusive
60-second skew window, as specified by the
[Linear webhook security guidance](https://linear.app/developers/webhooks).

Replay admission atomically checks both the forwarded `Linear-Delivery` UUID
and a SHA-256 fingerprint of the complete, canonically ordered payload. Changing
the unsigned delivery header or JSON object key order cannot admit the same
payload again. Distinct updates with a shared `webhookId` remain admissible.

The in-memory cache retains at most 10,000 fixed-size receipts. Each receipt
remains for at least 120,001 milliseconds of local monotonic time and until its
signed timestamp has expired. Verification time never moves backward, so a
wall-clock rollback cannot revive an expired delivery; clock stalls preserve
still-valid receipts. Capacity exhaustion returns `ResourceExhausted` without
evicting active protection, and rejected duplicates do not extend retention.
This protection is local to the connector process and is not durable across
restarts.

## Auth And Zone Boundary

- Authentication mechanisms: direct `api_key` value or host credential reference.
- Official Linear docs support personal API keys and OAuth2 access tokens for the GraphQL API.
- Runtime does not implement OAuth app creation, authorization redirects, PKCE, actor authorization, token exchange, token refresh, token revocation, client credentials, app mention/assignment scopes, or connector-local credential vaulting.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Runtime handshake grants whatever capabilities are requested by the host after constructing its verifier.
- The connector does not persist issues, comments, projects, teams, cycles, OAuth tokens, API keys, credential IDs beyond configuration metadata, provider payloads, provider error bodies, webhook payloads, webhook delivery IDs beyond the in-memory replay cache, or Beads sync plans.
- Linear issue data can include private project names, incident details, customer references, code snippets, and internal planning. Treat live reads and writes as work-zone data.

## Network And Runtime Invariants

- Default runtime host: `api.linear.app`.
- Default runtime path: `/graphql`.
- Runtime request construction posts all provider operations to the configured GraphQL URL.
- Runtime direct API-key mode allows `https://api.linear.app` plus local loopback test hosts.
- Runtime credential-id mode currently accepts arbitrary parsed absolute URLs after URL component checks.
- Runtime rejects configured URLs with userinfo, query strings, fragments, or no host.
- Runtime reqwest timeout: `30 seconds`.
- Runtime request-context timeout: `30 seconds`.
- Runtime retry loop retries transport timeouts/connect errors, 429 responses within retry budget, and 5xx GraphQL HTTP responses.
- Manifest live-operation network policy requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, and allows only `api.linear.app` on port 443.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120000 ms` wall-clock timeout, no exec, no ptrace, read-only `/usr` and `/lib`, and writable `$CONNECTOR_STATE`.
- The connector does not open inbound sockets.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `linear.read` | Read issues, teams, cycles, projects, and sync-planning input. |
| `linear.write` | Create or update issues and add issue comments. |
| `linear.process_webhook` | Process pre-verified Linear webhook payloads forwarded by fcp-host. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `linear.create_issue` | GraphQL `issueCreate` | `linear.write` | `Risky` | `Medium` | `None` | Creates a Linear issue in a team. |
| `linear.get_issue` | GraphQL `issue(id:)` | `linear.read` | `Safe` | `Low` | `Strict` | Reads one Linear issue by UUID or accepted Linear issue ID value. |
| `linear.update_issue` | GraphQL `issueUpdate` | `linear.write` | `Risky` | `Medium` | `Strict` | Updates title, state ID, or description. |
| `linear.search_issues` | GraphQL `searchIssues` | `linear.read` | `Safe` | `Low` | `Strict` | Runs a text search and returns parsed issue nodes. |
| `linear.list_teams` | GraphQL `teams` | `linear.read` | `Safe` | `Low` | `Strict` | Reads workspace teams. |
| `linear.list_cycles` | GraphQL `team(id).cycles` | `linear.read` | `Safe` | `Low` | `Strict` | Reads cycles for one team. |
| `linear.add_comment` | GraphQL `commentCreate` | `linear.write` | `Risky` | `Medium` | `None` | Adds an issue comment and can notify subscribers. |
| `linear.list_projects` | GraphQL `projects` | `linear.read` | `Safe` | `Low` | `Strict` | Reads active workspace projects from the runtime query. |
| `linear.plan_sync` | Local snapshot comparison | `linear.read` | `Safe` | `Low` | `Strict` | Produces a deterministic Beads/Linear sync intent without provider egress. |
| `linear.process_webhook` | Local forwarded payload processing | `linear.process_webhook` | `Safe` | `Low` | `Strict` | Processes a host-verified webhook envelope, enforces replay window, and returns an event object. |

## Explicit Non-Goals

The current implementation does not include:

- OAuth app lifecycle, PKCE flow, token exchange, token refresh, client credentials, actor authorization, token revocation, or app scopes
- arbitrary GraphQL query execution, attachments, documents, initiatives, customers, customer requests, roadmaps, views, favorites, labels management, workflow-state listing, comments update/delete, user management, or workspace admin APIs
- webhook subscription creation, inbound HTTP listener, Linear signature verification over raw bodies, source-IP validation, persistent event streams, event replay, or host-managed ack handling
- durable Linear/Beads synchronization, issue-link storage, conflict resolution writes, or background polling
- Linear TypeScript SDK parity or schema-introspection cache

These are excluded on purpose:

- Linear writes can create notifications and mutate project execution state.
- Webhook signature verification requires raw request bodies and belongs at the fcp-host ingress boundary before parsed JSON is forwarded.
- OAuth and actor authorization need a first-class credential lifecycle before broad agent deployment.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration and local client state
- auth mode as direct key or credential ID
- credential-injection requirement for credential-id mode
- live viewer-query self-check for direct-auth mode
- request and error counters through base metrics
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- webhook event topics for issue, comment, project, and cycle create/update/remove families
- provider error mapping for unauthorized, not-found, rate-limit, retryable server errors, GraphQL errors, JSON errors, and transport errors

The deterministic integration evidence is anchored on connector-local tests covering:

- GraphQL success paths for issue reads/writes, search, team/cycle/project reads, and comments
- provider 401, 403, 429, 500, GraphQL errors in 200 responses, empty data, not-found, retry-after, and redaction
- connector-level invoke paths with generated capability tokens
- plan-sync update and conflict planning
- webhook signature-validation flag, timestamp replay window, duplicate delivery rejection, and scoped resource URI checks
- configuration validation for auth exclusivity, credential IDs, unsafe URL components, direct host policy, local test URLs, and manifest operation inventory

## Source Notes

- `connectors/linear/src/connector.rs` defines configuration parsing, lifecycle handlers, diagnostics, handshake, capability verification, introspection, simulation, invoke dispatch, sync planning, webhook processing, and resource URI derivation.
- `connectors/linear/src/client.rs` defines Linear GraphQL request construction, auth headers, retry dispatch, response parsing, provider error handling, and health checks.
- `connectors/linear/src/types.rs` defines GraphQL envelopes, issue/team/cycle/project/comment models, webhook payloads, and Beads sync snapshot/intent types.
- `connectors/linear/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/linear/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, event caps, rate-limit pools, and AI hints.
- `connectors/linear/tests/integration.rs` covers deterministic HTTP behavior and connector-level behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/linear_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation inventory and policy metadata
- deterministic WireMock GraphQL coverage
- auth, provider error, retry, lifecycle, simulation, introspection, self-check, doctor, and capability-token coverage
- webhook replay under timestamp reordering, changed delivery IDs, concurrent
  admission, capacity exhaustion, and clock stalls/rollback, plus timestamp,
  signature-validation, and resource-scope behavior
- sync-planning behavior without provider egress
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use WireMock fixtures for routine verification.
- Use a disposable Linear workspace for live mutation proof.
- Prefer OAuth access-token semantics for live direct-auth checks until the direct `api_key` header behavior is reconciled with current Linear docs.

**Dedicated environment**:

- Keep live issues, projects, teams, comments, and webhook payloads synthetic.
- Use explicit team UUIDs for issue creation.
- Use explicit state UUIDs for status updates.
- Forward webhook payloads only after fcp-host verifies `Linear-Signature` over the raw body and preserves `Linear-Delivery`.

**Redaction rules**:

- Redact API keys, OAuth tokens, credential IDs where needed, issue titles/descriptions when sensitive, comment bodies, project names, team names, actor emails, webhook payloads, provider error bodies, and request URLs containing custom test hosts.
- Verification output should use operation IDs, endpoint classes, resource URI classes, HTTP status classes, retry decisions, and synthetic Linear IDs.

**Common remediation**:

- If configuration fails, provide exactly one of `api_key` or `credential_id`.
- If direct auth fails against live Linear, check whether the provided value is an OAuth access token or a personal API key and reconcile the header behavior.
- If self-check reports `credential_injection_required`, use direct auth or wire host-side injection.
- If issue creation fails, use the team UUID returned by `linear.list_teams`, not only the team key.
- If issue update fails, use a workflow state UUID, not a state display name.
- If `linear.plan_sync` rejects input, include `planned_at` and at least one `bead` or `linear` snapshot.
- If webhook processing rejects a payload, confirm `signature_validated = true`, a UUID `delivery_id`, a fresh `payload.webhookTimestamp`, and an allowed capability-token resource scope.
- If `simulate` allows an operation but policy should deny it, remember that current simulation is permissive and invoke is the enforcing path.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-linear-readme cargo check -p fcp-linear --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-linear-readme cargo test -p fcp-linear --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-linear-readme cargo clippy -p fcp-linear --all-targets --no-deps -- -D warnings`
- `ubs connectors/linear/README.md`
