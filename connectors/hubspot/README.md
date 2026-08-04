# HubSpot Connector V3 Contract

> **Status**: runtime contract documented with CRM versioning and capability-enforcement drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **HubSpot auth upstream**: https://developers.hubspot.com/docs/apps/legacy-apps/authentication/intro-to-auth
> **HubSpot usage limits upstream**: https://developers.hubspot.com/docs/developer-tooling/platform/usage-guidelines
> **HubSpot contacts upstream**: https://developers.hubspot.com/docs/api-reference/crm-contacts-v3/guide
> **HubSpot companies upstream**: https://developers.hubspot.com/docs/api-reference/crm-companies-v3/guide
> **HubSpot deals upstream**: https://developers.hubspot.com/docs/api-reference/legacy/crm/objects/deals/guide
> **HubSpot associations upstream**: https://developers.hubspot.com/docs/api-reference/latest/crm/associations/overview
> **HubSpot events upstream**: https://developers.hubspot.com/docs/api-reference/latest/events/guide

## Purpose

This document fixes the operator-facing contract for `fcp.hubspot`. The connector exposes the HubSpot CRM and event surfaces implemented in this crate: contacts, companies, deals, search, associations, pipelines, local pipeline metrics, a legacy analytics report call, and event occurrence polling.

The connector is intentionally a bounded HubSpot CRM bridge. It is not a full HubSpot platform SDK, app marketplace manager, webhook receiver, marketing automation authoring tool, CMS client, email analytics client, contact-list manager, property-schema manager, file manager, data warehouse sync, or durable CRM index.

## Current Runtime Snapshot

The current crate exposes these operations:

- `hubspot.contacts.list`
- `hubspot.contacts.get`
- `hubspot.contacts.create`
- `hubspot.contacts.update`
- `hubspot.contacts.delete`
- `hubspot.companies.list`
- `hubspot.companies.get`
- `hubspot.companies.create`
- `hubspot.companies.update`
- `hubspot.contacts.search`
- `hubspot.companies.search`
- `hubspot.association.get`
- `hubspot.deals.list`
- `hubspot.deals.create`
- `hubspot.deals.get`
- `hubspot.deals.update`
- `hubspot.deals.search`
- `hubspot.deals.set_stage`
- `hubspot.deals.associate`
- `hubspot.pipelines.list`
- `hubspot.analytics.report`
- `hubspot.pipeline.metrics`
- `hubspot.pipeline.stage_metrics`
- `hubspot.events.stream`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-hubspot`.
- Runtime `BaseConnector` ID is `hubspot`.
- Manifest connector ID is `fcp.hubspot`.
- Configuration accepts exactly one of:
  - `access_token`
  - `credential_id`
- `access_token` mode sends `Authorization: Bearer <token>`.
- `credential_id` must be a valid UUID and sends `X-FCP-Credential-Id: <uuid>`.
- Default base URL is `https://api.hubapi.com`.
- Direct-token base URLs must pass runtime policy: `api.hubapi.com`, `api.hubspot.com`, or localhost/loopback test hosts, with HTTPS required except for local tests.
- Credential-id base URLs reject userinfo, query strings, and fragments and require HTTPS unless targeting local tests; they may point at an arbitrary secure egress-proxy host.
- Runtime HTTP timeout is `30 seconds`.
- Runtime stores a `HttpRetryConfig` with `max_retries = 3`, but normal HTTP requests are currently direct reqwest sends and do not run a retry loop.
- Provider error bodies are truncated to 2048 bytes before API errors are surfaced.
- HTTP 401 maps to unauthorized, 403 maps to forbidden, 404 maps to not-found, and 429 maps to rate-limited with `Retry-After` support.
- Path segments are percent-encoded before object IDs and object types are inserted into CRM paths.
- Query parameter values are percent-encoded for list and event calls.
- `health` reports local configured/handshaken state plus request and error counters.
- `doctor` checks local configuration, client initialization, and handshake only.
- `self_check` checks local provisioning readiness and credential-injection requirements; direct-token mode does not currently perform a provider-backed live probe.
- Runtime exposes a provisioning recipe for OAuth2 Authorization Code with PKCE plus a webhook registration step, but the CLI lifecycle does not execute that recipe automatically.
- `handle_shutdown` shuts down the client runtime, clears config/client state, and resets configured and handshaken flags.
- `invoke` only checks the connector ready state and operation ID. It does not require or verify an FCP capability token in this checkout.
- `simulate` only checks whether an operation ID is known. It does not check configured state, handshake state, approval policy, or capability tokens.
- Runtime operation metadata is derived from the strict manifest, including schemas, capabilities, risk, safety, idempotency, approval, AI hints, and rate-limit metadata.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Runtime does not verify bound capability tokens for either `invoke` or `simulate`; capability families are advertised but not mechanically enforced at this connector boundary.
- Runtime uses legacy HubSpot CRM v3/v4 paths such as `/crm/v3/objects/contacts`, `/crm/v3/objects/deals/search`, and `/crm/v4/objects/.../associations/...`. Current HubSpot docs also expose newer date-versioned API paths for some CRM operations.
- Runtime `hubspot.contacts.delete` sends `DELETE /crm/v3/objects/contacts/{contact_id}` and returns `{ "deleted": true }`; HubSpot documentation treats this as archiving a contact record.
- Runtime `hubspot.events.stream` is not a streaming or webhook receiver. It polls `GET /events/v3/events` and returns the provider response under `events`.
- Manifest describes webhook subscription state and streaming archetype, while runtime has no inbound webhook listener, HMAC verifier, subscription manager, or event replay.
- Runtime `hubspot.analytics.report` posts to `/analytics/v2/reports`; this is covered by tests but is less aligned with current HubSpot event/reporting guides than the CRM object paths.
- Runtime direct HTTP requests do not currently use the stored retry configuration.
- Runtime direct-token base URL validation is stricter than many older tests expected, while credential-id mode intentionally allows secure proxy origins.
- `configure` returns `{}` and does not surface the provisioning-readiness payload that `self_check` calculates.
- `doctor` does not include base URL policy or auth-mode diagnostics, while `self_check` does.

A follow-up parity bead should add capability-token verification, decide whether to move to HubSpot's latest date-versioned CRM paths, clarify delete/archive wording in API results, either implement real webhook receiving or rename the event operation as polling, reconcile `analytics.report` with current HubSpot reporting APIs, and route direct HTTP requests through the shared retry policy.

## First-Slice Scope

The current HubSpot README slice documents the existing runtime surface:

- private-app/OAuth access-token and credential-id configuration
- CRM contact, company, deal, search, association, pipeline, analytics, pipeline-metric, and event occurrence operations
- local path/query sanitization and base URL policy behavior
- local provisioning recipe, doctor, health, self-check, simulate, introspect, invoke, and shutdown surfaces
- provider error mapping and rate-limit response handling
- remaining runtime drift around capability-token verification, CRM API versioning, analytics/reporting, and event streaming
- mock-only WireMock integration tests

## Auth And Zone Boundary

- Authentication mechanisms: HubSpot OAuth/private-app bearer token or host credential reference.
- Official HubSpot docs describe OAuth and private app access tokens as bearer tokens in the `Authorization` header.
- Runtime does not implement OAuth browser authorization, OAuth token exchange, token refresh, private app creation, token rotation, marketplace installation, or connector-local credential vaulting.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime handshake advertises:
  - `hubspot.contacts.read`
  - `hubspot.contacts.write`
  - `hubspot.contacts.delete`
  - `hubspot.companies.read`
  - `hubspot.companies.write`
  - `hubspot.deals.read`
  - `hubspot.deals.write`
  - `hubspot.pipelines.read`
  - `hubspot.analytics.read`
  - `hubspot.events.read`
  - `hubspot.associations.read`
  - `hubspot.associations.write`
- Manifest optional capabilities also include `media.download`, but current runtime does not download media.
- The connector does not persist contacts, companies, deals, pipelines, events, analytics output, tokens, credential IDs beyond configuration metadata, provider payloads, provider error bodies, webhook subscriptions, or CRM sync cursors.
- HubSpot CRM data can include personal data, sales opportunities, account records, pipeline values, and customer interaction timelines. Treat all live reads and writes as work-zone data.

## Network And Runtime Invariants

- Default runtime host: `api.hubapi.com`.
- Alternate direct-token runtime host: `api.hubspot.com`.
- Runtime direct-token policy requires HTTPS except for localhost/loopback tests.
- Runtime credential-id policy requires HTTPS or localhost/loopback tests and rejects userinfo, query strings, and fragments.
- Runtime request construction appends endpoint paths to `base_url`.
- Runtime reqwest timeout: `30 seconds`.
- Runtime request-context timeout: `30 seconds`.
- Runtime has direct get/post/patch/put/delete helpers that send one HTTP request each.
- Runtime does not open inbound sockets and does not implement HubSpot webhook receiving.
- Manifest live-operation network policy requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, and allows `api.hubapi.com` and `api.hubspot.com` on port 443.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120_000 ms` wall-clock timeout, no exec, and no ptrace.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `hubspot.contacts.read` | List, get, and search contacts. |
| `hubspot.contacts.write` | Create and update contacts. |
| `hubspot.contacts.delete` | Archive/delete contacts. |
| `hubspot.companies.read` | List, get, and search companies. |
| `hubspot.companies.write` | Create and update companies. |
| `hubspot.deals.read` | List, get, and search deals. |
| `hubspot.deals.write` | Create, update, and move deals between stages. |
| `hubspot.associations.read` | Read CRM associations. |
| `hubspot.associations.write` | Create deal-to-object associations. |
| `hubspot.pipelines.read` | Read CRM pipelines. |
| `hubspot.analytics.read` | Read or derive analytics and pipeline metrics. |
| `hubspot.events.read` | Poll event occurrences linked to CRM records. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `hubspot.contacts.list` | `GET /crm/v3/objects/contacts` | `hubspot.contacts.read` | `Safe` | `Low` | `Strict` | Reads paginated contact records. |
| `hubspot.contacts.get` | `GET /crm/v3/objects/contacts/{contact_id}` | `hubspot.contacts.read` | `Safe` | `Low` | `Strict` | Reads one contact record. |
| `hubspot.contacts.create` | `POST /crm/v3/objects/contacts` | `hubspot.contacts.write` | `Risky` | `Medium` | `None` | Creates a contact. |
| `hubspot.contacts.update` | `PATCH /crm/v3/objects/contacts/{contact_id}` | `hubspot.contacts.write` | `Risky` | `Medium` | `Strict` | Updates contact properties. |
| `hubspot.contacts.delete` | `DELETE /crm/v3/objects/contacts/{contact_id}` | `hubspot.contacts.delete` | `Dangerous` | `High` | `Strict` | Archives/deletes a contact record. |
| `hubspot.companies.list` | `GET /crm/v3/objects/companies` | `hubspot.companies.read` | `Safe` | `Low` | `Strict` | Reads paginated company records. |
| `hubspot.companies.get` | `GET /crm/v3/objects/companies/{company_id}` | `hubspot.companies.read` | `Safe` | `Low` | `Strict` | Reads one company record. |
| `hubspot.companies.create` | `POST /crm/v3/objects/companies` | `hubspot.companies.write` | `Risky` | `Medium` | `None` | Creates a company. |
| `hubspot.companies.update` | `PATCH /crm/v3/objects/companies/{company_id}` | `hubspot.companies.write` | `Risky` | `Medium` | `Strict` | Updates company properties. |
| `hubspot.contacts.search` | `POST /crm/v3/objects/contacts/search` | `hubspot.contacts.read` | `Safe` | `Low` | `Strict` | Searches contacts using HubSpot filter groups or query. |
| `hubspot.companies.search` | `POST /crm/v3/objects/companies/search` | `hubspot.companies.read` | `Safe` | `Low` | `Strict` | Searches companies using HubSpot filter groups or query. |
| `hubspot.association.get` | `GET /crm/v4/objects/{from_type}/{from_id}/associations/{to_type}` | `hubspot.associations.read` | `Safe` | `Low` | `Strict` | Reads associations from one CRM object to another object type. |
| `hubspot.deals.list` | `GET /crm/v3/objects/deals` | `hubspot.deals.read` | `Safe` | `Low` | `Strict` | Reads paginated deal records. |
| `hubspot.deals.create` | `POST /crm/v3/objects/deals` | `hubspot.deals.write` | `Risky` | `Medium` | `None` | Creates a deal, optionally with associations. |
| `hubspot.deals.get` | `GET /crm/v3/objects/deals/{deal_id}` | `hubspot.deals.read` | `Safe` | `Low` | `Strict` | Reads one deal record. |
| `hubspot.deals.update` | `PATCH /crm/v3/objects/deals/{deal_id}` | `hubspot.deals.write` | `Risky` | `Medium` | `Strict` | Updates deal properties. |
| `hubspot.deals.search` | `POST /crm/v3/objects/deals/search` | `hubspot.deals.read` | `Safe` | `Low` | `Strict` | Searches deals using HubSpot filter groups or query. |
| `hubspot.deals.set_stage` | `PATCH /crm/v3/objects/deals/{deal_id}` | `hubspot.deals.write` | `Risky` | `Medium` | `Strict` | Updates deal stage and optionally pipeline. |
| `hubspot.deals.associate` | `PUT /crm/v4/objects/deals/{deal_id}/associations/{to_type}/{to_id}` | `hubspot.associations.write` | `Risky` | `Medium` | `None` | Creates a HubSpot-defined association between a deal and another object. |
| `hubspot.pipelines.list` | `GET /crm/v3/pipelines/{object_type}` | `hubspot.pipelines.read` | `Safe` | `Low` | `Strict` | Reads pipeline definitions for an object type. |
| `hubspot.analytics.report` | `POST /analytics/v2/reports` | `hubspot.analytics.read` | `Safe` | `Low` | `Strict` | Calls the runtime's legacy/custom analytics report endpoint. |
| `hubspot.pipeline.metrics` | `POST /crm/v3/objects/deals/search` plus local aggregation | `hubspot.analytics.read` | `Safe` | `Low` | `Strict` | Aggregates deal count, total value, and stage counts for a pipeline. |
| `hubspot.pipeline.stage_metrics` | `POST /crm/v3/objects/deals/search` plus local aggregation | `hubspot.analytics.read` | `Safe` | `Low` | `Strict` | Aggregates deal count and total value for one pipeline stage. |
| `hubspot.events.stream` | `GET /events/v3/events` | `hubspot.events.read` | `Safe` | `Low` | `Strict` | Polls event occurrences; not a persistent stream. |

## Explicit Non-Goals

The current implementation does not include:

- OAuth authorization execution, OAuth token exchange, refresh-token handling, private app management, or token rotation
- webhook receiving, HMAC verification, webhook subscription lifecycle, replay, durable event cursors, or event acknowledgement
- HubSpot CMS, marketing email, lists, workflows, owners, properties, imports, exports, tickets, line items, products, invoices, quotes, tasks, notes, calls, meetings, or files
- batch CRM create/update/read/delete operations
- schema/property management or association label management
- long-running data sync, deduplication, warehouse loading, or bidirectional CRM reconciliation
- direct FCP capability-token verification at connector invoke time

These are excluded on purpose:

- HubSpot CRM data can include customer personal data, sales pipeline value, account metadata, and interaction history.
- CRM writes and deletes are provider-visible changes and need approval/capability enforcement before broad automation.
- Webhook receiving requires an inbound listener and signature verification boundary that this connector does not expose.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration and local client state
- request and error counters
- auth mode as bearer token or credential ID
- local base URL policy status through self-check provisioning details
- credential-injection requirement for credential-id mode
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- a provisioning recipe for OAuth2 Authorization Code with PKCE and webhook registration metadata

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle health, configure, handshake, shutdown, doctor, self-check, introspection, and simulate
- WireMock coverage for contacts, companies, deals, pipelines, analytics report, and event occurrence polling
- provider 401 and 429 error mapping
- missing required fields for representative write and analytics operations
- request/error counters
- operation inventory, manifest capability parity, contacts-delete capability separation, provisioning recipe serialization, base URL policy, and URL smuggling regressions

## Source Notes

- `connectors/hubspot/src/connector.rs` defines configuration parsing, lifecycle handlers, diagnostics, provisioning recipe, introspection, simulation, invoke dispatch, operation metadata, and base URL policy.
- `connectors/hubspot/src/client.rs` defines HubSpot HTTP request construction, auth headers, path/query encoding, CRM paths, analytics/event paths, response parsing, and provider error handling.
- `connectors/hubspot/src/types.rs` defines CRM object, pagination, pipeline, webhook-event, and provider-error shapes.
- `connectors/hubspot/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, event caps, rate limits, and AI hints.
- `connectors/hubspot/tests/integration.rs` covers deterministic HTTP behavior and lifecycle behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/hubspot_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation inventory and policy metadata
- deterministic WireMock coverage for HubSpot REST paths
- auth, provider error, lifecycle, simulation, introspection, self-check, and doctor coverage
- base URL policy and path/query encoding regression coverage
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use WireMock fixtures for routine verification.
- Use a disposable HubSpot sandbox or development account for live checks.
- Prefer credential-id mode only when the host or egress proxy is ready to inject HubSpot auth.

**Dedicated environment**:

- Keep live creates, updates, deletes, associations, and deal-stage changes confined to disposable contacts, companies, deals, and pipelines.
- Never archive contacts or mutate production deals without explicit operator approval.
- Use synthetic CRM object IDs, property names, property values, event filters, pipeline IDs, stage IDs, and association type IDs in logs and transcripts.

**Redaction rules**:

- Redact access tokens, credential IDs where needed, contact IDs, email addresses, names, company domains, deal names, amounts, pipeline/stage identifiers, event payloads, provider payloads, provider error bodies, and local paths.
- Verification output should use operation IDs, endpoint shapes, host classes, status/error classes, retry decisions, and synthetic HubSpot resource identifiers.

**Common remediation**:

- If configuration fails, provide exactly one of `access_token` or `credential_id`.
- If direct-token configuration rejects a custom host, use `https://api.hubapi.com`, `https://api.hubspot.com`, or credential-id mode with a secure egress-proxy base URL.
- If self-check reports `credential_injection_required`, use direct-token mode or wire host-side injection.
- If list/search operations return missing fields, pass the `properties` array explicitly.
- If create/update operations fail, verify required HubSpot internal property names and object-specific validation rules.
- If rate limits occur, respect the provider `Retry-After` value and account/app rate limits.
- If an operation succeeds in `simulate` but should be denied by policy, remember that current simulation only checks operation IDs.
- If event work needs push semantics, this connector currently polls event occurrences; use a separate webhook receiver design.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-hubspot-readme cargo check -p fcp-hubspot --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-hubspot-readme cargo test -p fcp-hubspot --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-hubspot-readme cargo clippy -p fcp-hubspot --all-targets --no-deps -- -D warnings`
- `ubs connectors/hubspot/README.md`
