# Google People Connector V3 Contract

> **Status**: PROVEN runtime contract documented with manifest/runtime drift called out
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/google_people_connector_verification.sh`
> **People API upstream**: https://developers.google.com/people/api/rest
> **People connections upstream**: https://developers.google.com/people/api/rest/v1/people.connections
> **People search contacts upstream**: https://developers.google.com/people/api/rest/v1/people/searchContacts
> **Other contacts upstream**: https://developers.google.com/people/api/rest/v1/otherContacts
> **Contact groups upstream**: https://developers.google.com/people/api/rest/v1/contactGroups

## Purpose

This document fixes the operator-facing contract for `fcp.google-people`. The connector exposes the Google People API surface implemented in this crate: contact listing, person lookup, contact search, other-contact listing, Workspace directory search, contact-group listing, contact creation, contact update, and contact deletion.

The connector is intentionally a bounded contacts bridge. It is not a full Workspace directory administrator, contact-group membership manager, profile reader, batch mutation client, sync-token warehouse, photo manager, or CRM importer.

## Current Runtime Snapshot

The current crate exposes these operations:

- `people.list_connections`
- `people.get_person`
- `people.search_contacts`
- `people.list_other_contacts`
- `people.search_directory_people`
- `people.list_contact_groups`
- `people.create_contact`
- `people.update_contact`
- `people.delete_contact`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-google-people`.
- Runtime `BaseConnector` ID is `google-people`.
- Configuration requires a `service_selector` that resolves to `people:v1`; the default selector is `people`.
- Configuration requires exactly one Google auth source accepted by `GoogleAuthSelection`.
- Required scopes can be supplied explicitly through `required_scopes`, or selected through `scope_triggers`, but not both.
- If scopes are not supplied, runtime defaults to `https://www.googleapis.com/auth/contacts.readonly`.
- Direct bearer-token mode sends the Google Authorization header through `GoogleRestExecutor`.
- `credential_id` mode is secretless and reports `credential_injection_required` for self-check.
- Default base URL is `https://people.googleapis.com/v1`.
- Public base URLs must use HTTPS, must target exact host `people.googleapis.com`, and must not contain userinfo, query strings, or fragments.
- `localhost`, `127.0.0.1`, and `::1` are accepted with HTTP or HTTPS for deterministic loopback tests.
- Runtime request timeout is 30 seconds.
- The client uses the shared retry loop with `max_retries = 3`, `initial_delay_ms = 1000`, `max_delay_ms = 60000`, and jitter enabled.
- Runtime operation capabilities are resolved through the embedded Google policy catalog.
- Runtime `invoke` requires `capability_token` and verifies a bound token before provider execution.
- Runtime `simulate` validates operation inventory, selected inputs, configured state, handshaken state, and bound capability token before returning an allowed result.
- Field masks are explicit: reads accept `person_fields` or `group_fields`, and updates accept `update_person_fields` or derive it from non-empty mutable fields.
- `people.update_contact` requires `person.etag` and rejects mismatch between `resource_name` and `person.resourceName`.
- `people.get_person` intentionally rejects `people/me`; callers must request a concrete contact or directory resource.
- `self_check()` probes `contactGroups.list` with `groupFields=name&pageSize=1` when direct credentials are materialized.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest connector ID is `fcp.google-people`, while runtime `BaseConnector` ID is `google-people`.
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.
- Runtime capability-token verification currently uses an empty resource URI list for People operations. Capabilities are operation-bound but not resource-bound to a contact, directory person, group, or search corpus.
- Manifest input schema for `people.update_contact` does not express the runtime `person.etag` requirement or the runtime `resource_name` versus `person.resourceName` consistency check.
- Runtime `handle_shutdown` calls client shutdown, but it does not clear config, client, verifier, session, configured flags, or handshaken flags.
- The dedicated tracked verification shell script is `scripts/e2e/google_people_connector_verification.sh`.

A follow-up parity bead should add resource URI binding, align manifest schemas with runtime update-contact validation, and reset lifecycle state consistently on shutdown.

## First-Slice Scope

The current Google People README slice documents the existing runtime surface:

- Google bearer-token, credential-reference, and OAuth refresh auth selection through the shared Google layer
- People service selection, required-scope selection, and scope-trigger handling
- People API base URL policy and loopback test allowance
- contact, other-contact, directory, contact-group, create, update, and delete operations
- bound capability-token verification during both `invoke` and `simulate`
- provider error mapping, retry behavior, field-mask behavior, redaction posture, and health behavior
- lifecycle, doctor, health, self-check, introspection, simulation, invoke, and shutdown surfaces
- deterministic WireMock tests, local non-mock JSONL, and direct proof commands
- the tracked verifier bundle that ties gauntlet, manifest, Cargo, local non-mock JSONL, redaction, and replay evidence together

## Auth And Scope Boundary

- Authentication mechanisms: Google bearer token, host credential reference, or OAuth refresh material through the shared Google auth layer.
- Home zone: `z:private`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zones: `z:private` and `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability surface:
  - `people.contacts.read` gates personal contact listing and contact search.
  - `people.profile.read` gates `people.get_person`.
  - `people.other_contacts.read` gates other-contact listing.
  - `people.directory.read` gates Workspace directory search.
  - `people.contact_groups.read` gates contact-group listing.
  - `people.contacts.write` gates contact create and update.
  - `people.contacts.delete` gates contact deletion.
- Manifest operation entries use those capability names, but the manifest optional capability list is currently empty.
- The connector does not persist contacts, directory people, contact groups, email addresses, phone numbers, access tokens, credential IDs, provider payloads, or provider error bodies beyond process memory.
- People API data can contain private contact names, email addresses, phone numbers, organizations, addresses, notes, birthdays, and profile metadata. Treat all live reads and writes as private or work-zone data.

## Network And Runtime Invariants

- Production host: `people.googleapis.com`.
- Production API prefix: `/v1`.
- Production port: `443`.
- TLS and SNI are required by the manifest for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback base URLs are test-only.
- Runtime request timeout: `30 seconds`.
- Manifest network constraints use `10_000 ms` connect timeout and `30_000 ms` total timeout.
- Manifest maximum response bytes are `2_097_152` or `4_194_304` for read operations and `1_048_576` for mutations.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `30_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets.
- Runtime handshake event caps report no streaming and no replay.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `people.contacts.read` | Read or search the authenticated user's contacts. |
| `people.profile.read` | Read a concrete People person resource by resource name. |
| `people.other_contacts.read` | Read Google-suggested other contacts. |
| `people.directory.read` | Search Workspace directory people. |
| `people.contact_groups.read` | Read contact-group metadata. |
| `people.contacts.write` | Create and update contacts. |
| `people.contacts.delete` | Delete contacts. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `people.list_connections` | `GET /v1/people/me/connections` | `people.contacts.read` | `Safe` | `Medium` | `Strict` | Lists the authenticated user's contacts with an explicit field mask. |
| `people.get_person` | `GET /v1/{resource_name}` | `people.profile.read` | `Safe` | `Medium` | `Strict` | Reads one concrete contact or directory person resource. |
| `people.search_contacts` | `GET /v1/people:searchContacts` | `people.contacts.read` | `Safe` | `Medium` | `Strict` | Searches the authenticated user's contacts. |
| `people.list_other_contacts` | `GET /v1/otherContacts` | `people.other_contacts.read` | `Safe` | `Medium` | `Strict` | Lists Google-suggested other contacts. |
| `people.search_directory_people` | `GET /v1/people:searchDirectoryPeople` | `people.directory.read` | `Safe` | `Medium` | `Strict` | Searches Workspace directory people. |
| `people.list_contact_groups` | `GET /v1/contactGroups` | `people.contact_groups.read` | `Safe` | `Medium` | `Strict` | Lists contact-group metadata. |
| `people.create_contact` | `POST /v1/people:createContact` | `people.contacts.write` | `Risky` | `High` | `None` | Creates a durable contact entry. |
| `people.update_contact` | `PATCH /v1/{resource_name}:updateContact` | `people.contacts.write` | `Risky` | `High` | `BestEffort` | Updates a contact with explicit field-mask and etag semantics. |
| `people.delete_contact` | `DELETE /v1/{resource_name}:deleteContact` | `people.contacts.delete` | `Dangerous` | `Critical` | `Strict` | Deletes a contact after interactive approval. |

## Field-Mask Contract

The runtime keeps People field exposure explicit:

- `people.list_connections`, `people.get_person`, `people.search_contacts`, `people.list_other_contacts`, and `people.search_directory_people` accept `person_fields`.
- `people.list_contact_groups` accepts `group_fields`.
- `people.update_contact` accepts `update_person_fields` as a string, CSV string, or array of strings.
- If `update_person_fields` is omitted, the connector derives it from non-empty mutable top-level fields in `person`.
- `people.update_contact` requires `person.etag` to preserve People API concurrency semantics.
- Empty field lists, non-string field entries, and empty update masks are rejected before provider execution.

## Explicit Non-Goals

The current implementation does not include:

- `people/me` self-profile reads, batch create/update/delete, batch get, photo update, or contact-group membership mutation
- other-contact search, copy-other-contact-to-contacts, contact-group create/update/delete, or directory sync
- People change tokens, durable contact caches, deduplicated sync stores, contact merge, or CRM import/export
- OAuth consent setup, People API enablement, service-account/domain-wide delegation provisioning, or Google Workspace tenant onboarding
- connector-local credential vaulting

These are excluded on purpose:

- Contact data is high-sensitivity personal data.
- People API field masks determine privacy exposure and must remain explicit.
- Mutations require concurrency and approval semantics that should not be hidden behind broad helper operations.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, auth mode, base URL, service identity, required scopes, and request counters
- operation metadata with capability, risk, safety tier, idempotency, schemas, and AI hints
- bound capability-token verification during `invoke`
- simulation denial for unknown operation, invalid input, unconfigured connector, missing handshake, and bound capability-token mismatch
- secretless credential-injection requirements
- provider-backed self-check through `contactGroups.list` when direct credentials are available
- local health and doctor diagnostics
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- contact listing, person lookup, contact search, other contacts, directory search, contact groups, create, update, and delete behavior
- field-mask query construction and update-contact etag validation
- base URL validation, localhost loopback allowance, auth redaction, credential-reference configuration, and self-check behavior
- provider 401, 403, 404, 409, 429, retryable transport/server classes, malformed JSON, and FCP error mapping
- invoke rejection for wrong capability, unknown operation, missing fields, and pre-provider capability verification

## Source Notes

- `connectors/google-people/src/connector.rs` defines configuration parsing, base URL policy, scope selection, lifecycle handlers, introspection, simulation, capability-token verification, policy-backed capability mapping, field-mask validation, and invoke dispatch.
- `connectors/google-people/src/client.rs` defines People paths, Google auth application, retry dispatch, timeout, health probe, request metrics, resource-name validation, query construction, and provider error mapping.
- `connectors/google-people/src/types.rs` defines contact, group, doctor, and response shapes.
- `connectors/google-people/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/google-people/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and operation-level capability declarations.
- `connectors/google-people/tests/integration.rs` covers deterministic HTTP behavior and runtime invoke coverage.

## Verification Bundle

The dedicated tracked verifier is `scripts/e2e/google_people_connector_verification.sh`. It writes a replayable artifact bundle with logs, redaction-checked local non-mock JSONL, gauntlet evidence, manifest drift evidence, and a summary JSON.

The verification surface captures:

- runtime operation inventory and policy metadata
- deterministic WireMock coverage for People API paths
- auth, endpoint policy, provider error, lifecycle, simulation, and introspection tests
- formatting, check, test, and clippy proof through `rch`
- redaction-safe local non-mock JSONL for `people.list_connections`, `self_check`, `people.create_contact`, and wrong-capability denial
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a Google Workspace or Google account test tenant with People API access enabled for live verification.
- Prefer credential-reference mode when host policy should own Google secret material.
- Use loopback WireMock fixtures for routine proof.

**Dedicated environment**:

- Keep test contacts separate from personal and production contacts.
- Use disposable contacts for create, update, and delete proof.
- Use narrow `person_fields` and `group_fields` for live reads.
- Treat directory search results as work-zone data even when only names and email addresses are requested.

**Redaction rules**:

- Redact access tokens, credential IDs where needed, resource names, contact names, email addresses, phone numbers, organizations, notes, birthdays, addresses, contact-group names, provider payloads, provider error bodies, and endpoint URLs when they reveal tenant topology.
- Verification output should use operation IDs, endpoint shapes, auth mode, host class, result counts, status/error classes, retry decisions, and payload-shape summaries.

**Common remediation**:

- If configuration fails, provide exactly one Google auth source and a service selector that resolves to `people:v1`.
- If scope resolution fails, provide either `required_scopes` or `scope_triggers`, not both.
- If a read returns too much data, narrow `person_fields` or `group_fields`.
- If `people.get_person` rejects `people/me`, request a concrete `people/{id}` resource.
- If `people.update_contact` fails validation, include `person.etag` and either explicit `update_person_fields` or at least one non-empty mutable field.
- If provider returns 403, treat it as an auth/permission failure rather than a retryable transport error.

**Rerun commands**:

- `RUN_ID=google-people-rerun-$(date -u +%Y%m%dT%H%M%SZ) bash -lc 'OUT_ROOT=/tmp/fcp-google-people-e2e/$RUN_ID RCH_FORCE_REMOTE=1 RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 scripts/e2e/google_people_connector_verification.sh'`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-people-readme cargo check -p fcp-google-people --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-people-readme cargo test -p fcp-google-people --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-people-readme cargo clippy -p fcp-google-people --all-targets --no-deps -- -D warnings`
- `ubs connectors/google-people/README.md`
