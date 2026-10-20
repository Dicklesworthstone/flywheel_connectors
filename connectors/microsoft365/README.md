# Microsoft 365 Outlook/Exchange V3 Contract

> **Status**: PROVEN (2026-10-20; 12/12 graduation gauntlet, verifier + unit/integration/local_non_mock suites verified)
> **Bead**: `flywheel_connectors-j05nu.7.1`
> **Unblocks**: `flywheel_connectors-j05nu.7.2`
> **Verification script**: `scripts/e2e/microsoft365_connector_verification.sh`
> **Primary upstream**: Microsoft Graph v1.0 at `https://graph.microsoft.com/v1.0`

## Purpose

This document pins down the Outlook / Exchange first slice currently implemented inside `fcp.microsoft365`. The follow-on runtime bead should converge on this contract rather than inventing a separate `fcp.outlook` surface or widening scope beyond what the connector already supports truthfully.

In this document, "Exchange" means Exchange Online and Outlook workloads exposed through Microsoft Graph. It does not mean EWS, IMAP/SMTP, or on-prem Exchange administration.

## Current Runtime Snapshot

The current crate already exposes the first-slice Outlook/Exchange operations inside a broader Microsoft 365 connector:

- Mail: `m365.mail.list_messages`, `m365.mail.get_message`, `m365.mail.search_messages`, `m365.mail.list_threads`, `m365.mail.send_message`, `m365.mail.create_draft`, `m365.mail.reply_message`, `m365.mail.forward_message`, `m365.mail.list_attachments`, and `m365.mail.add_attachment`
- Calendar: `m365.calendar.list_events`, `m365.calendar.get_event`, `m365.calendar.create_event`, `m365.calendar.update_event`, `m365.calendar.delete_event`, and `m365.calendar.get_freebusy`
- Adjacent but broader-than-this-contract surfaces also exist: `m365.subscriptions.create`, `m365.subscriptions.renew`, `m365.subscriptions.delete`, `m365.notifications.ingest`, and `m365.delta.sync`

Important runtime truths that the contract must preserve:

- `m365.mail.list_threads` is a synthetic summary built by grouping `list_messages` results on `conversationId`; there is no dedicated thread API client path.
- `folder_id` is only a routing selector on mail list/thread operations. There is no standalone folder discovery or folder CRUD operation yet.
- When `folder_id` is omitted, mail reads currently route to `/{user_scope}/messages`; the connector does not inject an explicit inbox folder.
- `m365.calendar.list_events` uses `/{user_scope}/calendarView` only when both `start_datetime` and `end_datetime` are provided. Otherwise it falls back to `/{user_scope}/events`.
- The first Outlook/Exchange slice stays at primary-calendar scope. Non-primary `calendar_id` routing is intentionally out of the public contract until the runtime and client support it end to end.
- Mailbox rules are not currently implemented at all.

## First-Slice Scope

The first Outlook/Exchange slice is intentionally narrow:

- Read mailbox messages for one routed mailbox scope.
- Read individual messages by stable `message_id`.
- Search mailbox content with Graph full-text semantics.
- Produce thread summaries by grouping messages on Graph `conversationId`.
- Create drafts, send mail, reply, and forward.
- Inspect attachments and add attachments to existing draft/message records.
- Read the primary calendar, create/update/delete events, and query free/busy.
- Surface truthful health, doctor, and self-check readiness for the chosen auth mode.

The first slice is mailbox-oriented rather than admin-oriented. It is not a general Microsoft 365 governance connector.

## Service Inventory

| Surface | Status in first slice | Notes |
|---------|-----------------------|-------|
| Messages | In scope | Full mail read/search plus send, draft, reply, forward, and attachment flows are implemented. |
| Folders | Selector-only | `folder_id` can narrow `list_messages` and `list_threads`, but there is no folder list/get/create/update/delete surface. |
| Search | In scope | `m365.mail.search_messages` uses Microsoft Graph `$search` with `ConsistencyLevel: eventual`. |
| Rules | Out of scope | No inbox rule or message rule operations exist today. |
| Calendar | In scope | Primary-calendar event list/get/create/update/delete plus free/busy are implemented. |
| Subscriptions, notification ingress, and delta | Deferred from this contract | The broader connector owns Graph subscription creation/renewal/deletion, host-forwarded notification validation/deduplication, and delta-sync handoff; they are not part of the Outlook/Exchange first-slice contract being stabilized here. |

## Auth And Scope Boundary

- A connector instance binds to exactly one configured auth source: `access_token`, `credential_id`, or `app_credentials`.
- `access_token` and `app_credentials` are the only modes where the connector can locally parse JWT claims and verify `required_permissions`.
- `credential_id` is a valid deployment mode, but readiness remains degraded until the egress proxy injects the actual credential material.
- `app_credentials` default to the Microsoft Graph client-credentials scope `https://graph.microsoft.com/.default`.
- The network boundary is Microsoft Graph plus Microsoft Entra auth: API traffic defaults to `https://graph.microsoft.com/v1.0`, and token exchange defaults to `https://login.microsoftonline.com`.
- Tenant scope is determined by the presented token or client credentials. The connector does not try to aggregate across multiple tenants in one instance.
- Mailbox scope is routed per operation through `user_id`.
- `user_id = "me"` maps to `/me/...`.
- Any other `user_id` maps to `/users/{user_id}/...` after path-safety validation.
- Cross-mailbox access is therefore only possible when the caller's delegated or application permissions already authorize it inside the same tenant boundary.
- `required_permissions` is a narrowing contract, not an expansion mechanism. If configured, the connector must reject tokens that do not advertise those claims.

## Tier B Live Sandbox Verification

The connector's gated sandbox proof is `rch exec -- cargo test -p fcp-microsoft365 --test live_verification -- --nocapture`. It is skipped unless `FCP_LIVE_SANDBOX=1` and the Microsoft 365 sandbox environment is complete.

Required live inputs:

- `MICROSOFT365_SANDBOX_TENANT_ID`
- `MICROSOFT365_SANDBOX_CLIENT_ID`
- `MICROSOFT365_SANDBOX_CLIENT_SECRET`
- `MICROSOFT365_SANDBOX_USER_ID`
- `FCP_SANDBOX_RUN_NAMESPACE`

Optional endpoint overrides default to `https://graph.microsoft.com/v1.0` and `https://login.microsoftonline.com` through `MICROSOFT365_SANDBOX_API_URL` and `MICROSOFT365_SANDBOX_AUTH_URL`.

Use a dedicated Microsoft 365 developer/test tenant, a sandbox app registration with `Files.ReadWrite.All` application permission and admin consent, and a disposable OneDrive-enabled user. The proof intentionally uses the broader connector's file operations, not mail/calendar delivery, so it can perform a reversible `upload_file` -> `list_items` -> `delete_item` -> post-delete `get_item` lifecycle without sending mail or calendar invitations. It also performs an invalid client-secret configure attempt as the auth-denial path.

The live test emits `MICROSOFT365_LIVE_SANDBOX_JSONL` evidence with the command, git revision when provided through `FCP_LIVE_GIT_REVISION`, sandbox class, call ceiling, cleanup result, hashed user/file/item identifiers, and skip/failure reason. It never logs tenant id, client id, client secret, user id, file path, item id, provider resource ids, or raw provider error bodies.

## Network And Runtime Invariants

- Base API host: `graph.microsoft.com`
- Default API root: `https://graph.microsoft.com/v1.0`
- Auth host: `login.microsoftonline.com`
- `m365.notifications.ingest` is a host-forwarded local ingress path. It validates Graph webhook payloads, updates connector state, and returns acknowledgements without opening Graph or Entra network connections.
- Port: `443`
- TLS + SNI required
- `deny_localhost = true`
- `deny_private_ranges = true`
- `deny_tailnet_ranges = true`
- `deny_ip_literals = true`
- Request defaults are bounded: `connect_timeout_ms = 10_000`, `total_timeout_ms = 30_000`
- Host canonicalization is required, and the live contract should not depend on alternate hosts or open redirects

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `m365.mail.read` | Mailbox reads, search, thread summaries, and attachment inspection |
| `m365.mail.write` | Draft creation and attachment mutation prior to send |
| `m365.mail.send` | Real outbound mail actions such as send, reply, and forward |
| `m365.calendar.read` | Event reads and free/busy schedule inspection |
| `m365.calendar.write` | Event creation, update, and deletion |

## Operation Inventory

| Operation | Provider endpoint target | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|--------------------------|------------|------------|-----------|-------------|-----------|
| `m365.mail.list_messages` | `GET /{user_scope}/messages` or `GET /{user_scope}/mailFolders/{folder_id}/messages` | `m365.mail.read` | `Safe` | `Low` | `Strict` | Read-only mailbox enumeration with optional folder narrowing and OData filter support. |
| `m365.mail.get_message` | `GET /{user_scope}/messages/{message_id}` | `m365.mail.read` | `Safe` | `Low` | `Strict` | Deterministic point read of one mailbox message. |
| `m365.mail.search_messages` | `GET /{user_scope}/messages?$search=...` | `m365.mail.read` | `Safe` | `Low` | `Strict` | Read-only full-text search over one routed mailbox scope. |
| `m365.mail.list_threads` | `GET /{user_scope}/messages` or `GET /{user_scope}/mailFolders/{folder_id}/messages`, then local grouping on `conversationId` | `m365.mail.read` | `Safe` | `Low` | `Strict` | The connector synthesizes thread summaries from message reads; there is no native separate thread resource in the current client. |
| `m365.mail.list_attachments` | `GET /{user_scope}/messages/{message_id}/attachments` | `m365.mail.read` | `Safe` | `Low` | `Strict` | Read-only attachment metadata inspection. |
| `m365.mail.create_draft` | `POST /{user_scope}/messages` | `m365.mail.write` | `Risky` | `Medium` | `None` | Creates a mailbox object with side effects but avoids delivery. Retries can duplicate drafts. |
| `m365.mail.add_attachment` | `POST /{user_scope}/messages/{message_id}/attachments` | `m365.mail.write` | `Risky` | `Medium` | `None` | Mutates draft/message state and can duplicate attachments on retry. |
| `m365.mail.send_message` | `POST /{user_scope}/sendMail` | `m365.mail.send` | `Dangerous` | `High` | `None` | Real outbound delivery. Duplicate retries can send duplicate mail. |
| `m365.mail.reply_message` | `POST /{user_scope}/messages/{message_id}/reply` | `m365.mail.send` | `Dangerous` | `High` | `None` | Real outbound reply that inherits recipient context from the existing thread. |
| `m365.mail.forward_message` | `POST /{user_scope}/messages/{message_id}/forward` | `m365.mail.send` | `Dangerous` | `High` | `None` | Real outbound forwarding with new recipients and potential sensitive-content exposure. |
| `m365.calendar.list_events` | `GET /{user_scope}/events` or `GET /{user_scope}/calendarView?startDateTime=...&endDateTime=...` | `m365.calendar.read` | `Safe` | `Low` | `Strict` | Read-only event enumeration on the primary calendar; bounded date ranges opt into Graph `calendarView`. |
| `m365.calendar.get_event` | `GET /{user_scope}/events/{event_id}` | `m365.calendar.read` | `Safe` | `Low` | `Strict` | Deterministic point read of one calendar event. |
| `m365.calendar.get_freebusy` | `POST /me/calendar/getSchedule` | `m365.calendar.read` | `Safe` | `Low` | `Strict` | Read-only schedule inspection for one or more addresses. |
| `m365.calendar.create_event` | `POST /{user_scope}/events` | `m365.calendar.write` | `Risky` | `Medium` | `None` | Creates a new event and may emit attendee invitations. |
| `m365.calendar.update_event` | `PATCH /{user_scope}/events/{event_id}` | `m365.calendar.write` | `Risky` | `Medium` | `BestEffort` | Partial updates mutate existing event state and retries may race provider-side changes. |
| `m365.calendar.delete_event` | `DELETE /{user_scope}/events/{event_id}` | `m365.calendar.write` | `Dangerous` | `High` | `Strict` | Destructive event removal and may send cancellation notices. |

## Explicit Non-Goals

The first Outlook/Exchange slice does not include these surfaces:

- standalone folder enumeration or folder CRUD
- inbox rules, message rules, transport rules, or mailbox automation policies
- contacts, people, tasks, notes, files, Teams, SharePoint, or broader Microsoft 365 productivity surfaces
- EWS, IMAP, POP, SMTP, or on-prem Exchange administration
- mailbox delegation provisioning, tenant administration, or compliance/governance APIs
- multi-tenant aggregation inside one connector instance
- a new dedicated `fcp.outlook` crate or identifier in this bead
- Microsoft Graph webhook notification ingress in the legacy `fcp.outlook` connector; ownership stays in `fcp.microsoft365` so subscription state, `clientState` validation, replay suppression, and delta handoff share one state file

These are excluded on purpose:

- The current connector does not implement them.
- The valuable first slice is mailbox interaction and calendar workflow, not tenant governance.
- Inventing a separate connector ID before the current `fcp.microsoft365` surface is stabilized would create naming churn without improving capability isolation.

## Implementation Notes For `flywheel_connectors-j05nu.7.2`

- Keep the contract anchored to the existing `fcp.microsoft365` connector unless there is an explicit parent-level decision to split crates and identifiers.
- Keep the first-slice calendar contract truthful: do not advertise `calendar_id` until non-primary calendar routing is implemented end to end.
- Reconcile the mail-folder story. The contract should not describe `folder_id` as a full folder service when the runtime only treats it as an optional path selector.
- Make mailbox-wide versus folder-scoped message listing explicit. The current runtime does not hardcode `inbox` when `folder_id` is absent.
- Preserve the degraded readiness model for `credential_id` deployments and make operator guidance explicit in health, doctor, and self-check outputs.
- Keep `required_permissions` surfaced in configure, health, doctor, and self-check so operators can see whether the permission boundary is explicit or implicit.
- Tests should cover `/me` versus `/users/{id}` routing, folder selector sanitization, `$search` header requirements, thread grouping semantics, `calendarView` switching, free/busy payload shape, and retry-sensitive dangerous operations such as send, reply, forward, and delete.

## Source Notes

This contract is grounded in the current connector implementation and manifest, not an aspirational future design:

- `connectors/microsoft365/src/client.rs` defines the actual Graph paths for messages, attachments, replies, forwards, `calendarView`, events, and `getSchedule`.
- `connectors/microsoft365/src/connector.rs` defines the auth modes, readiness behavior, and the exposed `OperationInfo` safety/risk/idempotency metadata.
- `connectors/microsoft365/manifest.toml` already declares the same mail/calendar capability families and network constraints used by the runtime.

## Operator Guidance

**Prerequisites**:

- Use a dedicated Microsoft 365 developer or test tenant for live verification.
- Use an app registration or delegated token whose consent scope matches the operation family being verified.
- Keep `credential_id` deployments behind the host credential injection layer; direct connector logs must never contain access tokens, tenant IDs, client secrets, user IDs, message IDs, file paths, or provider error bodies.
- Use the local non-mock test for loopback request-shape acceptance before running the live sandbox verifier.

**Verification surface**:

- `connectors/microsoft365/tests/local_non_mock.rs` drives real loopback HTTP through the connector for mailbox read and send request construction.
- `connectors/microsoft365/tests/live_verification.rs` is the gated Tier B sandbox proof and is skipped unless `FCP_LIVE_SANDBOX=1` plus the Microsoft 365 sandbox environment is complete.
- `scripts/e2e/microsoft365_connector_verification.sh` is the operator closeout script. It writes redaction-safe evidence under `artifacts/e2e/microsoft365_connector/<run-id>` and requires `rch` proof for Cargo lanes.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-microsoft365-readme cargo test -p fcp-microsoft365 --test local_non_mock -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-microsoft365-readme cargo test -p fcp-microsoft365 --test integration -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-microsoft365-readme cargo clippy -p fcp-microsoft365 --all-targets -- -D warnings`
- `scripts/e2e/microsoft365_connector_verification.sh --run-id <redacted-run-id>`
