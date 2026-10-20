# Calendly Connector V3 Contract

> **Status**: PROVEN (2026-10-20; 12/12 graduation gauntlet, verifier + unit/integration/local_non_mock suites verified)
> **Bead**: `flywheel_connectors-j05nu.5.4.3`
> **Parent**: `flywheel_connectors-j05nu.5.4`
> **Verification script**: `scripts/e2e/calendly_connector_verification.sh`
> **Primary upstream**: https://developer.calendly.com/

## Purpose

This document fixes the first implementation slice for `fcp.calendly` so follow-on work can build on a stable contract instead of treating Calendly like a generic REST API.
It is the authoritative readiness and operator-facing artifact for the current connector surface.

The connector is a request-response scheduling connector for one authenticated Calendly principal boundary.
It exposes user, event, invitee, event-type, availability, scheduling-link, and cancellation workflows through FCP capabilities and a host-verified capability token boundary.

## Current Runtime Snapshot

The current crate exposes these operations:

- `calendly.events.list`
- `calendly.events.get`
- `calendly.event_types.list`
- `calendly.invitees.list`
- `calendly.scheduling_links.create`
- `calendly.events.cancel`
- `calendly.user.get`
- `calendly.availability.list`
- `calendly.health`

Important runtime truths that the contract must preserve:

- Configuration is `access_token`, optional `base_url`, retry policy, and bounded `request_timeout_ms`.
- The live production host is `https://api.calendly.com`; non-HTTPS hosts are rejected unless the host is `localhost`, `127.0.0.1`, or `*.localhost` for deterministic mock-server tests.
- The connector defaults user-scoped reads to the authenticated principal via `GET /users/me` when `user_uri` is omitted.
- A blank `access_token` is treated as a secretless proxy-injection mode and should not be interpreted as proof of live PAT-based connectivity.
- Event UUID path inputs are sanitized to reject traversal, slashes, null bytes, and ambiguous path segments.
- `health` and `self_check` are contract-bearing surfaces: they expose verification script paths, artifact-root hints, provisioning state, operator guidance, manifest hashes, and auth-boundary details.
- The runtime is explicitly non-streaming; all workflows are bounded request-response calls.

## First-Slice Scope

The first Calendly slice is intentionally narrow:

- read the authenticated user identity and provider-visible organization boundary
- list and inspect scheduled events
- list event types
- list invitees for one scheduled event
- list one user's availability schedules
- create scheduling links for a visible event type
- cancel a scheduled event with an optional reason
- run readiness, doctor, health, and self-check probes that preserve operator-facing verification evidence

The connector is scoped to scheduling workflows, not to every Calendly surface.

## Auth And Scope Boundary

- The connector authenticates with a bearer personal access token or an egress proxy that injects credentials.
- One connector instance is bound to one authenticated provider-visible principal boundary.
- The token may expose user-scoped and organization-visible resources, but every `user_uri` and `owner_uri` still has to resolve to a resource that same principal can legitimately see.
- `calendly.events.read` gates event, invitee, and event-type inspection.
- `calendly.events.write` gates event cancellation.
- `calendly.scheduling.read` gates availability inspection.
- `calendly.scheduling.write` gates scheduling-link creation.
- `calendly.user.read` gates current-user reads and health probing.
- There is no cross-account aggregation, webhook ingest, or cross-connector fanout in the current slice.

## Network And Runtime Invariants

- Production base API host: `api.calendly.com`
- Production port: `443`
- TLS + SNI required for live traffic
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and redirects for live operations
- Localhost HTTP overrides are test-only and exist solely for deterministic integration verification
- Default request timeout: `30_000 ms`
- Retry policy is explicit and surfaced in readiness output
- Runtime advertises no replay or streaming event support

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `calendly.events.read` | List scheduled events, fetch one event, list event types, and inspect invitees |
| `calendly.events.write` | Cancel a scheduled event |
| `calendly.scheduling.read` | List availability schedules for a visible user |
| `calendly.scheduling.write` | Create a scheduling link for a visible event type |
| `calendly.user.read` | Read the authenticated user profile and run readiness probes |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `calendly.events.list` | `GET /scheduled_events?user=...` | `calendly.events.read` | `Safe` | `Low` | `None` | Read-only event enumeration within one principal boundary. |
| `calendly.events.get` | `GET /scheduled_events/{event_uuid}` | `calendly.events.read` | `Safe` | `Low` | `None` | Read-only point lookup for one scheduled event UUID. |
| `calendly.event_types.list` | `GET /event_types?user=...` | `calendly.events.read` | `Safe` | `Low` | `None` | Read-only inspection of scheduling surfaces visible to the token. |
| `calendly.invitees.list` | `GET /scheduled_events/{event_uuid}/invitees` | `calendly.events.read` | `Safe` | `Low` | `None` | Read-only invitee inspection for one event. |
| `calendly.scheduling_links.create` | `POST /scheduling_links` | `calendly.scheduling.write` | `Risky` | `Medium` | `Strict` | Creates a shareable scheduling surface with real downstream booking effects. |
| `calendly.events.cancel` | `POST /scheduled_events/{event_uuid}/cancellation` | `calendly.events.write` | `Risky` | `Medium` | `Strict` | Cancels a real event and can notify real invitees. |
| `calendly.user.get` | `GET /users/me` | `calendly.user.read` | `Safe` | `Low` | `None` | Deterministic point read of the authenticated principal identity. |
| `calendly.availability.list` | `GET /user_availability_schedules?user=...` | `calendly.scheduling.read` | `Safe` | `Low` | `None` | Read-only availability inspection inside the principal boundary. |
| `calendly.health` | `GET /users/me` | `calendly.user.read` | `Safe` | `Low` | `Strict` | Deterministic auth and reachability probe used for readiness. |

## Explicit Non-Goals

The first implementation slice does not include these provider surfaces:

- routing forms, embed widgets, and booking-page customization
- webhook ingest and push delivery
- organization-wide admin APIs and cross-account aggregation
- round-robin pools, availability overrides, and advanced schedule mutation
- invitee mutation flows beyond cancellation side effects driven by `events.cancel`
- analytics, reporting, audit history, and provider-side event streaming

These are excluded on purpose:

- The valuable first slice is deterministic scheduling inspection plus two meaningful mutation workflows.
- Broadening into embed, admin, or webhook behavior would blur the connector boundary from "scheduling operator surface" into "entire Calendly platform runtime."
- The current implementation does not model those workflows honestly yet.

## Readiness And Verification Surface

`doctor()`, `health()`, and `self_check()` are part of the public closeout contract, not incidental diagnostics.
They must continue to surface:

- configuration, client, runtime, and handshake state
- manifest hash and verification script path
- artifact root hint for replayable evidence
- provisioning details including auth mode, timeout, retry policy, authenticated identity probe, and risky mutation inventory
- operator guidance including prerequisites, dedicated environments, redaction rules, remediation, and rerun commands
- contract details that restate auth boundary, service inventory, and explicit non-goals

The deterministic integration evidence is anchored on localhost mock-server runs for:

- unconfigured health guidance
- unconfigured doctor guidance
- successful self-check with authenticated identity evidence
- retryable self-check degradation
- scheduling-link creation evidence
- scheduled-event cancellation evidence
- introspection compliance evidence

## Source Notes

This contract is grounded in the current connector implementation and manifest:

- `connectors/calendly/src/client.rs` defines request construction, retry handling, error mapping, path sanitization, and the `GET /users/me` readiness probe.
- `connectors/calendly/src/connector.rs` defines the FCP operation inventory, capability boundary, readiness output shape, operator guidance, and risky mutation semantics.
- `connectors/calendly/manifest.toml` defines the production network allowlist and sandbox boundary for the current slice.

## Verification Bundle

The closeout bundle is anchored on `scripts/e2e/calendly_connector_verification.sh`.
It writes replayable artifacts under `artifacts/e2e/calendly_connector/<timestamp>` and runs through `rch`-offloaded Cargo commands so validation does not contend with local multi-agent sessions.

The bundle captures:

- manifest validation for `connectors/calendly/manifest.toml`
- `cargo check -p fcp-calendly --all-targets`
- formatting verification for the Calendly crate
- targeted readiness evidence for `health`, `doctor`, `self_check`, retryable degradation, and both risky scheduling mutations
- typed introspection compliance evidence
- the Calendly integration suite and full crate test suite
- `cargo clippy -p fcp-calendly --all-targets -- -D warnings`

## Operator Guidance

Prerequisites:
- Use a disposable Calendly account, test organization, or localhost mock server before running the verification bundle.
- Keep the connector bound to one authenticated user or organization boundary and confirm that every `user_uri` or `owner_uri` you pass is visible to that token.
- Treat scheduling-link creation and scheduled-event cancellation as live mutations that can affect real invitees unless you are using a localhost mock override.
- For the gated sandbox live suite, set `FCP_LIVE_SANDBOX=1`, `CALENDLY_SANDBOX_TOKEN`, `CALENDLY_SANDBOX_ORG_URI`, `CALENDLY_SANDBOX_EVENT_TYPE_URI`, and `FCP_SANDBOX_RUN_NAMESPACE`. `CALENDLY_SANDBOX_BASE_URL` defaults to `https://api.calendly.com`.

Dedicated environment:
- Prefer a disposable Calendly workspace or a localhost mock server. Do not run verification against a live production scheduling surface unless the resulting links, events, and invitee notifications are acceptable.

Redaction rules:
- Redact access tokens, `Authorization` headers, proxy-injection hints, and copied request logs before sharing evidence.
- Treat user URIs, organization URIs, scheduling URLs, invitee email addresses, event UUIDs, and location join URLs as sensitive operational data.
- If verification uses a real Calendly account, sanitize organization names, booking pages, and invitee metadata in archived artifacts.

Common remediation:
- If `health` or `self_check` reports `not_configured`, set `access_token`, `base_url`, timeout, and retry settings, then rerun `self_check`.
- If `self_check` reports `credential_injection_required`, run behind the configured egress proxy or switch to a direct PAT for deterministic live probes.
- If `self_check` reports `calendly_auth_rejected`, replace the PAT or proxy-injected credential, confirm the token still has access to the intended resources, and rerun the verification script.
- If `self_check` reports `self_check_retryable`, increase timeout or retry settings, wait for the upstream to recover, and rerun verification.
- If `doctor` reports `network_constraints_invalid`, use `api.calendly.com` for live verification or a localhost override for deterministic mock tests.
- If availability, events, or scheduling-link workflows reject a `user_uri` or `owner_uri`, rerun `calendly.user.get` or `self_check` first and then restrict inputs to resources visible to that same authenticated principal.

Rerun commands:
- `scripts/e2e/calendly_connector_verification.sh`
- `fwc manifest fix connectors/calendly/manifest.toml --check --json`
- `rch exec -- cargo fmt --manifest-path connectors/calendly/Cargo.toml --check`
- `rch exec -- cargo check -p fcp-calendly --all-targets`
- `rch exec -- cargo test -p fcp-calendly --test live_verification -- --nocapture`
- `rch exec -- cargo test -p fcp-calendly --test integration -- --nocapture`
- `rch exec -- cargo test -p fcp-calendly -- --nocapture`
- `rch exec -- cargo clippy -p fcp-calendly --all-targets -- -D warnings`
