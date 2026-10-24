# Google Calendar Connector V3 Contract

> **Status**: PROVEN runtime contract documented with manifest/runtime drift called out
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/google_calendar_connector_verification.sh`
> **Calendar API upstream**: https://developers.google.com/workspace/calendar/api/v3/reference
> **Events upstream**: https://developers.google.com/workspace/calendar/api/v3/reference/events
> **Partial updates upstream**: https://developers.google.com/workspace/calendar/api/v3/reference/events/patch
> **Event IDs and duplicate recovery upstream**: https://developers.google.com/workspace/calendar/api/guides/create-events
> **Freebusy upstream**: https://developers.google.com/workspace/calendar/api/v3/reference/freebusy/query

## Purpose

This document fixes the operator-facing contract for `fcp.google-calendar`. The connector exposes the Google Calendar API surface implemented in this crate: calendar listing and lookup, event CRUD, natural-language quick add, free/busy lookup, recurring-event instance listing, and incremental event sync.

The connector is intentionally a bounded calendar bridge. It is not a full Google Workspace client, Calendar settings manager, ACL manager, channel watcher, push-notification receiver, Meet provisioning client, task client, contact client, or long-running calendar warehouse.

## Current Runtime Snapshot

The current crate exposes these operations:

- `gcal.list_calendars`
- `gcal.get_calendar`
- `gcal.list_events`
- `gcal.get_event`
- `gcal.create_event`
- `gcal.update_event`
- `gcal.delete_event`
- `gcal.quick_add`
- `gcal.freebusy`
- `gcal.list_event_instances`
- `gcal.sync_events`

Important runtime truths the contract preserves:

- Configuration defaults `service_selector` to `calendar` and requires that it resolves to `calendar:v3`.
- Configuration requires exactly one Google auth source accepted by the shared Google discovery auth layer.
- Supported auth inputs include direct bearer token fields accepted by the shared layer, `credential_id`, and `oauth_refresh`.
- Direct bearer-token mode sends the Google Authorization header through `GoogleRestExecutor`.
- `credential_id` mode is secretless; self-check reports `credential_injection_required` because the egress proxy must inject credentials.
- Default base URL is `https://www.googleapis.com/calendar/v3`.
- Public base URLs must use HTTPS, must target exact host `www.googleapis.com`, and must not contain userinfo, query strings, or fragments.
- `localhost`, `127.0.0.1`, and `::1` are accepted with HTTP or HTTPS for deterministic loopback tests.
- Required scopes come from the embedded Google provisioning bundle. Callers may provide explicit `required_scopes`, or provide `scope_triggers`, but not both.
- Runtime request timeout is 30 seconds.
- The client uses the shared retry loop with three retries, 1000 ms initial delay, 60 second max delay, and jitter.
- Event updates use sparse `PATCH` requests: omitted fields, attendees, recurrence, reminders, and conference data are preserved. An explicit `attendees: []` removes all attendees; empty strings clear text fields. Malformed supplied fields and empty updates are rejected before any provider call.
- Event creation accepts an optional `event_id` containing 5–1024 lowercase letters `a`–`v` or digits `0`–`9`. With an ID, retry attempts reuse the same payload and a private request fingerprint; a duplicate is recovered only when the existing active event has the same ID and fingerprint. Reuse the same ID and input to recover a creation, and use `gcal.update_event` to change it.
- Without `event_id`, event creation retains fail-closed retry behavior. Ambiguous unkeyed writes and quick-add results return nonretryable errors so an outer invocation cannot silently create another event. Requests rejected before transmission or rate-limited without execution retain their safe retry behavior.
- Calendar IDs, event IDs, query values, quick-add text, sync tokens, and page tokens are percent-encoded before provider calls.
- Provider 401, 404, 429 with `Retry-After`, retryable transport/5xx classes, malformed JSON, and API error bodies map into typed connector and FCP errors.
- Handshake installs a `CapabilityVerifier`.
- `invoke` resolves the requested operation's capability from runtime introspection and verifies a bound capability token before provider execution.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Runtime `BaseConnector` ID is `google-calendar`, while the manifest connector ID is `fcp.google-calendar`.
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.
- Manifest `event_caps.streaming = true`, but runtime handshake reports `streaming = false`, runtime introspection has no events, and no watch/channel flow is implemented.
- Runtime `simulate` returns allowed for any syntactically valid `SimulateRequest`; it does not validate operation inventory, readiness, input schema, capability, or capability token.
- Manifest output names for list/delete operations drift from runtime output names. Runtime `list_events` returns `events`, `next_page_token`, and `summary`; runtime `delete_event` returns `status: deleted`.
- Runtime `handle_shutdown` shuts down the client runtime but does not clear config, client, verifier, session, or configured/handshaken flags.
- The dedicated tracked verification shell script is `scripts/e2e/google_calendar_connector_verification.sh`.

A follow-up parity bead should align simulation, manifest/runtime event capability, output schemas, interface proof, and shutdown state reset.

## First-Slice Scope

The current Google Calendar README slice documents the existing runtime surface:

- Google bearer-token, credential-reference, and OAuth refresh auth selection through the shared Google layer
- Calendar service selection and scope-trigger handling
- Calendar base URL policy and loopback test allowance
- calendar list/get, event list/get/create/update/delete, quick add, freebusy, recurring instances, and incremental sync
- bound capability-token verification during invoke
- provider error mapping, retry behavior, redaction posture, and health behavior
- lifecycle, doctor, health, self-check, introspection, simulation, invoke, and shutdown surfaces
- deterministic WireMock tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: Google bearer token, host credential reference, or OAuth refresh material through the shared Google discovery auth layer.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability surface:
  - `gcal.read` gates calendar lookup, event reads, freebusy, recurring instances, and sync.
  - `gcal.write` gates event creation, event update, and quick add.
  - `gcal.delete` gates event deletion.
- Manifest capability surface uses the same three capability names.
- The connector does not persist calendars, events, attendees, email addresses, tokens, credential IDs, provider payloads, or provider error bodies beyond process memory.
- Read operations can still expose private calendar metadata, attendee information, locations, descriptions, and availability. Treat all live reads as private or work-zone data.

## Network And Runtime Invariants

- Production host: `www.googleapis.com`.
- Production API prefix: `/calendar/v3`.
- Production port: `443`.
- TLS and SNI are required by the manifest for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback base URLs are test-only.
- Runtime request timeout: `30 seconds`.
- Manifest network constraints use `10_000 ms` connect timeout and either `30_000 ms` or `60_000 ms` total timeout depending on operation.
- Manifest maximum response bytes are `1_048_576`, `5_242_880`, or `10_485_760` depending on operation size.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not implement Calendar channels, watch renewal, webhook receiving, or streaming replay.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `gcal.read` | Read calendars, events, availability, recurring instances, and incremental sync pages. |
| `gcal.write` | Create or update events, including quick-add parsing. |
| `gcal.delete` | Delete events from a calendar. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `gcal.list_calendars` | `GET /users/me/calendarList` | `gcal.read` | `Safe` | `Low` | `Strict` | Lists calendars visible to the authenticated principal. |
| `gcal.get_calendar` | `GET /users/me/calendarList/{calendar_id}` | `gcal.read` | `Safe` | `Low` | `Strict` | Reads one calendar-list entry. |
| `gcal.list_events` | `GET /calendars/{calendar_id}/events` | `gcal.read` | `Safe` | `Low` | `Strict` | Reads event pages for one calendar and optional time window. |
| `gcal.get_event` | `GET /calendars/{calendar_id}/events/{event_id}` | `gcal.read` | `Safe` | `Low` | `Strict` | Reads one event by provider ID. |
| `gcal.create_event` | `POST /calendars/{calendar_id}/events` | `gcal.write` | `Risky` | `Medium` | `None` | Creates an event; optional `event_id` enables provider-keyed retry and duplicate recovery. |
| `gcal.update_event` | `PATCH /calendars/{calendar_id}/events/{event_id}` | `gcal.write` | `Risky` | `Medium` | `BestEffort` | Changes only supplied fields; explicit arrays replace the corresponding arrays. |
| `gcal.delete_event` | `DELETE /calendars/{calendar_id}/events/{event_id}` | `gcal.delete` | `Risky` | `High` | `None` | Deletes an event or recurring event series/instance. |
| `gcal.quick_add` | `POST /calendars/{calendar_id}/events/quickAdd?text={text}` | `gcal.write` | `Risky` | `Medium` | `None` | Lets Google parse natural-language event text into an event. |
| `gcal.freebusy` | `POST /freeBusy` | `gcal.read` | `Safe` | `Low` | `Strict` | Reads busy blocks for requested calendars. |
| `gcal.list_event_instances` | `GET /calendars/{calendar_id}/events/{event_id}/instances` | `gcal.read` | `Safe` | `Low` | `Strict` | Lists concrete instances of a recurring event. |
| `gcal.sync_events` | `GET /calendars/{calendar_id}/events?syncToken={token}` | `gcal.read` | `Safe` | `Low` | `Strict` | Reads incremental event changes using a provider sync token. |

## Explicit Non-Goals

The current implementation does not include:

- Calendar ACLs, calendar create/update/delete, settings, colors, channels, watches, or push notifications
- event import, move, arbitrary resource patching, attachments, conference-data creation, Meet creation, reminders, extended properties, or event type controls
- OAuth consent setup, Calendar API enablement, service-account/domain-wide delegation provisioning, or Google Workspace tenant onboarding
- durable event caches, sync-token storage, event warehouse export, alerting, deduped watch replay, or long-running pagination jobs
- recurring-rule authoring beyond passing event fields currently represented in the local `Event` type
- connector-local credential vaulting

These are excluded on purpose:

- Calendar data routinely contains private attendees, locations, descriptions, and availability.
- Provider watch/channel behavior needs lease, renewal, callback, and replay contracts that are separate from this request-response slice.
- Full event authoring is a larger compatibility surface than the current typed runtime supports.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, client state, auth mode, base URL, service identity, required scopes, and request counters
- operation metadata with capability, risk, safety tier, idempotency, schemas, and AI hints
- bound capability-token verification during `invoke`
- current simulation behavior, which is permissive
- provider-backed self-check through `users/me/calendarList?maxResults=1` when credentials are materialized
- degraded self-check for secretless credential references
- redacted auth labels and typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- calendar list/get, event list/get/create/delete, quick add, freebusy, recurring instances, and calendar lookup
- 401, 404, 429, retryable transport/server classes, JSON errors, and FCP error mapping
- base URL validation, localhost loopback allowance, redaction, credential-reference configuration, and self-check behavior
- invoke rejection for wrong capability, unknown operation, missing fields, and pre-provider capability verification

## Source Notes

- `connectors/google-calendar/src/connector.rs` defines configuration parsing, base URL policy, scope selection, lifecycle handlers, introspection, simulation, capability-token verification, and invoke dispatch.
- `connectors/google-calendar/src/client.rs` defines Calendar paths, Google auth application, retry dispatch, timeout, health probe, request metrics, percent-encoding, and provider error mapping.
- `connectors/google-calendar/src/types.rs` defines calendar, event, and freebusy request/response shapes.
- `connectors/google-calendar/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/google-calendar/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, event caps, and rate-limit pools.
- `connectors/google-calendar/tests/integration.rs` covers deterministic HTTP behavior and runtime invoke coverage.

## Verification Bundle

The dedicated tracked verification bundle is `scripts/e2e/google_calendar_connector_verification.sh`. It writes a redaction-safe artifact tree under `artifacts/e2e/google-calendar/<run-id>` by default and records the gauntlet output, manifest check, connector-local Cargo proof logs, extracted `local_non_mock` JSONL, environment metadata, replay command, and summary status.

Promotion evidence:

- Pre-promotion verifier run `sagestork-pre-20260604T153143Z` wrote its summary to `/tmp/fcp-google-calendar-e2e/sagestork-pre-20260604T153143Z/summary.json` (`sha256:fc9db13a7d0d70e5982ed6dae2695bc2c8ad46c89658b5653515e0dd6ebe8776`). The run passed `cargo_check`, `format_check`, `integration_suite`, `local_non_mock`, `local_non_mock_jsonl`, and `clippy`; it remained non-green only because README/manifest promotion metadata and the manifest `interface_hash` update were still pending.
- Extracted local non-mock evidence is `/tmp/fcp-google-calendar-e2e/sagestork-pre-20260604T153143Z/evidence/local_non_mock.jsonl` (`sha256:5546317526fefad2d076c34d39626d678d4706abeec25f2f6812ce866324e2d2`). It records redaction-safe acceptance for `gcal.list_calendars`, `self_check`, `gcal.create_event`, and pre-egress wrong-capability denial.
- Remote proof summaries are recorded for `cargo_check` on `vmi1156319`, plus `integration_suite`, `local_non_mock`, and `clippy` on `vmi1153651`.

The verification surface captures:

- runtime operation inventory and policy metadata
- deterministic WireMock coverage for Calendar API paths
- auth, endpoint policy, provider error, lifecycle, simulation, and introspection tests
- formatting, check, test, and clippy proof through `rch`
- extracted local non-mock acceptance records for `gcal.list_calendars`, `self_check`, `gcal.create_event`, and pre-egress wrong-capability denial
- redaction checks for Calendar access tokens, loopback endpoints, attendee email addresses, fixture event IDs, event summaries, event descriptions, live credential markers, and provider error-body markers
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a Google Workspace or Google account test calendar for live verification.
- Prefer credential-reference mode when host policy should own Google secret material.
- Use loopback WireMock fixtures for routine proof.

**Dedicated environment**:

- Keep test calendars separate from personal and production calendars.
- Use `primary` only in controlled fixtures; prefer explicit calendar IDs in shared environments.
- Use historical time windows for stable list/freebusy proof.
- Treat quick-add text as provider-interpreted input and avoid ambiguous dates in live checks.

**Redaction rules**:

- Redact access tokens, credential IDs where needed, calendar IDs when sensitive, event IDs, attendee emails, organizer/creator identities, descriptions, locations, provider payloads, provider error bodies, and endpoint URLs when they reveal tenant topology.
- Verification output should use operation IDs, endpoint shapes, auth mode, host class, result counts, status/error classes, retry decisions, and payload-shape summaries.

**Common remediation**:

- If configuration fails, provide exactly one Google auth source and a service selector that resolves to `calendar:v3`.
- If live checks are degraded with `credential_injection_required`, inject host credentials before running the probe.
- If `create_event` fails validation, pass `start` and `end` as RFC3339 strings in the current runtime contract.
- If `update_event` clears data, include every field that must survive the provider `PUT`.
- If recurring instances are missing, verify the event ID is a recurring event series and the time window covers expected occurrences.
- If sync fails, do not mix `sync_token` with time filters; restart from a full sync when Google rejects an expired sync token.

**Rerun commands**:

- `RUN_ID=manual-google-calendar OUT_ROOT=/tmp/fcp-google-calendar-e2e/manual-google-calendar scripts/e2e/google_calendar_connector_verification.sh`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-calendar-readme cargo check -p fcp-google-calendar --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-calendar-readme cargo test -p fcp-google-calendar --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-calendar-readme cargo clippy -p fcp-google-calendar --all-targets --no-deps -- -D warnings`
- `ubs connectors/google-calendar/README.md scripts/e2e/google_calendar_connector_verification.sh`
