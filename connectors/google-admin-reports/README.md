# Google Admin Reports Connector V3 Contract

> **Status**: PROVEN runtime contract documented; manifest/runtime identity drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/google_admin_reports_connector_verification.sh`
> **Reports overview**: https://developers.google.com/workspace/admin/reports/v1/get-start/overview
> **Activities upstream**: https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list
> **User usage upstream**: https://developers.google.com/workspace/admin/reports/reference/rest/v1/userUsageReport/get
> **Customer usage upstream**: https://developers.google.com/workspace/admin/reports/reference/rest/v1/customerUsageReports/get
> **Entity usage upstream**: https://developers.google.com/workspace/admin/reports/reference/rest/v1/entityUsageReports/get

## Purpose

This document fixes the operator-facing contract for `fcp.google-admin-reports`. The connector exposes the Google Workspace Admin SDK Reports API surface implemented in this crate: audit activity listing, per-user usage reports, customer-wide usage reports, and entity-level usage reports.

The connector is intentionally a bounded domain-admin reporting bridge. It is not a Directory API client, Gmail audit parser, Drive Activity API client, Vault client, alert-center client, Admin console automation tool, report warehouse, push-notification watcher, or Google Workspace provisioning tool.

## Current Runtime Snapshot

The current crate exposes these operations:

- `admin.list_activities`
- `admin.list_user_usage`
- `admin.list_customer_usage`
- `admin.list_entity_usage`

Important runtime truths the contract preserves:

- Configuration defaults `service_selector` to `admin-reports` and requires that it resolves to `admin:reports_v1`.
- Configuration requires exactly one Google auth source accepted by the shared Google discovery auth layer.
- Direct bearer-token mode sends the Google Authorization header through `GoogleRestExecutor`.
- `credential_id` mode is secretless; configuration succeeds with `configured_pending_token_materialization` and self-check reports `credential_injection_required`.
- Default base URL is `https://admin.googleapis.com/admin/reports/v1`.
- Public base URLs must use HTTPS, must target exact host `admin.googleapis.com`, and must not contain userinfo, query strings, or fragments.
- `localhost`, `127.0.0.1`, and `::1` are accepted with HTTP or HTTPS for deterministic loopback tests.
- Default required scope is `https://www.googleapis.com/auth/admin.reports.audit.readonly`.
- `scope_triggers` can add `https://www.googleapis.com/auth/admin.reports.usage.readonly`; callers may instead provide an explicit `required_scopes` list, but not both.
- The client uses the shared retry loop with two retries, 500 ms initial delay, 30 second max delay, and jitter.
- Runtime request timeout is 30 seconds.
- Activity, usage, and entity identifiers are URL encoded when placed into provider paths.
- Provider 401/403, 404, 429 with `Retry-After`, retryable transport/5xx classes, malformed JSON, and API error bodies map into typed connector and FCP errors.
- Handshake installs a `CapabilityVerifier`.
- `simulate` and `invoke` validate operation IDs, required inputs, resource URIs, and bound capability tokens.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest connector ID is `fcp.google-admin-reports`, while runtime `BaseConnector` and requests use `google-admin-reports`.
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.
- Manifest `interface_hash` is still `pending`.
- Manifest optional capabilities are empty even though operation entries and runtime introspection use `admin.reports.audit.read` and `admin.reports.usage.read`.
- Manifest input schema for `admin.list_activities` requires only `application_name`, while runtime requires both `user_key` and `application_name`.
- Manifest input schema for `admin.list_entity_usage` omits `entity_key`, while runtime requires `entity_type`, `entity_key`, and `date`.
- Runtime `handle_shutdown` shuts down the client runtime but does not clear config, client, verifier, session, or configured/handshaken flags.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should align connector IDs, interface hash, optional capabilities, required input schemas, and shutdown state semantics.

## First-Slice Scope

The current Google Admin Reports README slice documents the existing runtime surface:

- Google bearer-token and secretless credential-reference configuration
- Admin Reports service selection and scope-trigger handling
- Admin Reports base URL policy
- activity listing through `activities.list`
- user, customer, and entity usage report reads
- bound capability-token verification in both `simulate` and `invoke`
- provider error mapping, retry behavior, redaction posture, and health behavior
- lifecycle, doctor, health, self-check, introspection, simulation, invoke, and shutdown surfaces
- deterministic WireMock tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: Google bearer token or host credential reference through the shared Google discovery auth layer.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability surface:
  - `admin.reports.audit.read` gates `admin.list_activities`.
  - `admin.reports.usage.read` gates user, customer, and entity usage reports.
- Required Google scopes:
  - `https://www.googleapis.com/auth/admin.reports.audit.readonly` for activity reports.
  - `https://www.googleapis.com/auth/admin.reports.usage.readonly` for usage reports.
- The connector does not persist report rows, actors, email addresses, IP addresses, customer IDs, group IDs, org-unit IDs, access tokens, credential IDs, provider payloads, or provider error bodies beyond process memory.
- All four operations are read-only but policy-sensitive because Admin Reports is domain-wide and can expose organization activity, user behavior, IP addresses, and app usage.

## Network And Runtime Invariants

- Production host: `admin.googleapis.com`.
- Production API prefix: `/admin/reports/v1`.
- Production port: `443`.
- TLS and SNI are required by the manifest for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback base URLs are test-only.
- Runtime request timeout: `30 seconds`.
- Manifest network constraints use `10_000 ms` connect timeout and `30_000 ms` total timeout.
- Manifest maximum response bytes are `10_485_760` for all four operations.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not implement Admin Reports watches or streaming.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `admin.reports.audit.read` | Read Google Workspace audit activity events. |
| `admin.reports.usage.read` | Read user, customer, and entity usage reports. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `admin.list_activities` | `GET /activity/users/{user_key}/applications/{application_name}` | `admin.reports.audit.read` | `Safe` | `High` | `Strict` | Reads domain audit events for one Workspace application. |
| `admin.list_user_usage` | `GET /usage/users/{user_key}/dates/{date}` | `admin.reports.usage.read` | `Safe` | `High` | `Strict` | Reads per-user usage metrics for a report date. |
| `admin.list_customer_usage` | `GET /usage/dates/{date}` | `admin.reports.usage.read` | `Safe` | `High` | `Strict` | Reads aggregate tenant usage metrics for a report date. |
| `admin.list_entity_usage` | `GET /usage/{entity_type}/{entity_key}/dates/{date}` | `admin.reports.usage.read` | `Safe` | `High` | `Strict` | Reads entity-specific usage metrics for niche Admin Reports surfaces. |

## Explicit Non-Goals

The current implementation does not include:

- `activities.watch`, channels, push notifications, or webhook receiving
- Directory API users, groups, org units, roles, customers, devices, or tokens
- Admin Reports parameter catalogs, report schema discovery, event-type appendix parsing, or report normalization beyond serde structs
- Gmail audit export, Drive Activity API, Calendar logs, Meet quality tooling, Vault, Alert Center, Chrome management, or security investigation APIs
- OAuth consent, domain-wide delegation setup, service-account provisioning, Admin SDK enablement, or tenant onboarding automation
- durable report storage, report replay, warehouse export, SIEM forwarding, or long-running pagination jobs
- connector-local credential vaulting

These are excluded on purpose:

- Admin Reports is an admin-only surface and should stay narrow and auditable.
- Report payloads can expose employee activity, account identifiers, IP addresses, and tenant-level metrics.
- Push/watch handling needs lease, replay, and channel-expiration contracts that are separate from this read-only slice.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, client state, handshake state, auth mode, base URL, service identity, and required scopes
- policy-backed operation metadata with capability, risk, safety tier, idempotency, schemas, and AI hints
- `simulate` denial for unconfigured, unhandshaken, missing-input, unknown-operation, and capability-token mismatch cases
- bound capability-token verification for invoke
- self-check through a lightweight `admin.list_activities` probe against the `admin` application with `maxResults = 1`
- degraded self-check for secretless credential references
- redacted auth labels and request/error metrics

The deterministic integration evidence is anchored on connector-local tests covering:

- activity, user usage, customer usage, entity usage, pagination, query parameters, and auth headers
- self-check and health behavior
- 401, 429 with retry-after, malformed JSON, timeout, cancellation, and FCP error mapping
- operation catalog, manifest presence, network constraints, and redaction
- base URL policy, service selector validation, scope defaults, and usage-trigger scope escalation
- `simulate` denial and allow paths with bound capability tokens
- invoke rejection before handshake and unknown-operation simulation denial

## Source Notes

- `connectors/google-admin-reports/src/connector.rs` defines configuration parsing, base URL policy, scope selection, lifecycle handlers, operation metadata, capability-token verification, simulation, and invoke dispatch.
- `connectors/google-admin-reports/src/client.rs` defines Admin Reports paths, Google auth application, retry dispatch, timeout, health probe, request metrics, and error mapping.
- `connectors/google-admin-reports/src/types.rs` defines Admin Reports activity and usage response types.
- `connectors/google-admin-reports/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/google-admin-reports/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and rate-limit pool.
- `connectors/google-admin-reports/tests/integration.rs` covers deterministic HTTP behavior, manifest/runtime contract checks, and redaction.

## Verification Bundle

The tracked verification bundle is `scripts/e2e/google_admin_reports_connector_verification.sh`. It runs the graduation gauntlet, manifest check, crate-local compilation, formatting, integration suite, `local_non_mock` loopback acceptance suite, JSONL redaction/evidence checks, and clippy through `rch`.

The verification surface captures:

- runtime operation inventory and policy metadata
- deterministic WireMock coverage for all four operations
- auth, endpoint policy, provider error, lifecycle, simulation, and introspection tests
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a Google Workspace test tenant for live verification.
- Use delegated admin credentials with only the needed Admin Reports readonly scopes.
- Prefer credential-reference mode when host policy should own Google secret material.
- Use WireMock loopback fixtures for routine proof.

**Dedicated environment**:

- Keep test queries bounded by application, date range, user key, group, and org unit.
- Do not run broad tenant-wide report reads against production without explicit approval.
- Expect usage reports to lag the current date; use historical report dates.
- Treat `all` user-key reads as domain-wide access.

**Redaction rules**:

- Redact access tokens, credential IDs where needed, user keys, actor emails, IP addresses, customer IDs, org-unit IDs, group IDs, report parameters when sensitive, provider payloads, provider error bodies, and endpoint URLs when they reveal tenant topology.
- Verification output should use operation IDs, endpoint shapes, auth mode, host class, result counts, status/error classes, retry decisions, and payload-shape summaries.

**Common remediation**:

- If configuration fails, provide exactly one Google auth source and a service selector that resolves to `admin:reports_v1`.
- If usage reports are denied, add the usage-report scope trigger or explicit `admin.reports.usage.readonly` scope.
- If live checks are degraded with `credential_injection_required`, inject host credentials before running the probe.
- If activity input fails validation, pass both `user_key` and `application_name`.
- If entity usage input fails validation, pass `entity_type`, `entity_key`, and `date`.
- If provider returns no report rows, verify tenant audit retention, app name, report date, filters, and Admin SDK Reports API access.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-admin-reports-readme cargo check -p fcp-google-admin-reports --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-admin-reports-readme cargo test -p fcp-google-admin-reports --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-admin-reports-readme cargo clippy -p fcp-google-admin-reports --all-targets --no-deps -- -D warnings`
