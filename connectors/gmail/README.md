# Gmail Connector V3 Contract

> **Status**: PROVEN
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/gmail_connector_verification.sh`
> **Gmail REST upstream**: https://developers.google.com/workspace/gmail/api/reference/rest
> **Messages upstream**: https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages
> **Attachment reads upstream**: https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages.attachments/get
> **Messages send upstream**: https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/send
> **History upstream**: https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.history/list
> **Threads upstream**: https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.threads
> **Drafts upstream**: https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.drafts
> **Labels upstream**: https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.labels

## Purpose

This document fixes the operator-facing contract for `fcp.gmail`. The connector exposes the Gmail API surface implemented in this crate: messages, attachment retrieval, mailbox listing, history sync, labels, threads, drafts, and sending.

The connector is intentionally a bounded mailbox bridge. It is not a Google Workspace admin connector, contact connector, Calendar connector, watch-channel manager, mailbox backup system, or general MIME processing toolkit.

## Current Runtime Snapshot

The current crate exposes these operations:

- `gmail.send_message`
- `gmail.get_message`
- `gmail.get_attachment`
- `gmail.list_messages`
- `gmail.sync_history`
- `gmail.modify_message`
- `gmail.trash_message`
- `gmail.get_thread`
- `gmail.list_labels`
- `gmail.get_draft`
- `gmail.create_draft`
- `gmail.send_draft`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-gmail`.
- Runtime `BaseConnector` ID is `gmail`.
- Manifest connector ID is `fcp.gmail`.
- The manifest declares a native binary. History checkpoints require operating-system file locks; unsupported locking fails closed rather than weakening writer fencing.
- The connector configure boundary accepts a secretless `credential_id`; raw bearer tokens and OAuth refresh secrets are rejected there. The low-level client and shared auth substrate retain bearer/OAuth support for host materialization and internal tests.
- `credential_id` mode is secretless and returns `configured_pending_token_materialization`.
- `oauth_refresh` mode can materialize granted scopes and lets `doctor()`/`self_check()` detect scope-limited operation coverage.
- Configuration accepts either explicit `required_scopes` or `scope_triggers`; both together are rejected.
- Default base URL is `https://gmail.googleapis.com/gmail/v1`.
- Public base URLs must use HTTPS and target `googleapis.com` or a `googleapis.com` subdomain.
- `localhost`, `127.0.0.1`, and `::1` are accepted with HTTP or HTTPS for deterministic loopback tests.
- All base URLs reject userinfo, query strings, and fragments.
- Runtime request timeout is 30 seconds.
- The client uses the shared retry loop with `max_retries = 3`, `initial_delay_ms = 1000`, and `max_delay_ms = 60000`.
- The client retries retryable Google REST errors; 401 and 403 map to Unauthorized, and 429 maps to RateLimited with retry guidance.
- Message IDs, thread IDs, and draft IDs used in URL path segments are validated to reject empty strings, slashes, backslashes, traversal, and encoded slash/backslash variants.
- Attachment reads validate and percent-encode both IDs as individual URL path segments; message IDs are limited to 128 bytes and attachment IDs to 4096 bytes.
- `gmail.get_attachment` checks canonical URL-safe base64 and decoded size, with a caller-controlled `max_bytes` ceiling up to 16 MiB. Malformed or oversized replies never return partial file contents.
- The native connector identity is `fcp.gmail`. A protocol `2.0` or `2.0.0` handshake negotiates only manifest-declared capabilities through the shared SDK session authority. An empty requested capability list grants nothing, and manifest-forbidden zones are rejected.
- Each handshake returns a fresh actual `instance_id`, also reported in `health().details.instance_id`. Bind capability tokens to that returned identity; a host's requested instance is a preference and cannot revive old tokens. Reconfigure before rebinding the mailbox to another zone.
- `invoke` requires the complete FCP `InvokeRequest`, including its type, inner request ID, connector ID, zone ID, operation, input, and signed capability token. Admission verifies the negotiated grant and actual resource URIs, charges signed call and FCP-message byte allowances, and enforces any signed idempotency-key restriction before provider execution. Complete invocation responses are capped at 32 MiB.
- `simulate` verifies the same target, zone, operation, resources, and remaining call allowance without spending a provider invocation. Host revocation, approval, holder-proof, and lease checks remain host responsibilities.
- `gmail.sync_history` persists the caller-acknowledged history boundary and requires `lease_seq` as a singleton-writer fencing token. Fetching a batch never acknowledges it; `latest_history_id` becomes the next input only after the caller has processed the complete result.
- `health()` returns a canonical `HealthSnapshot`. Native readiness requires configuration and a valid handshake; `details` contains the actual instance, lifecycle flags, negotiated zone, auth/scope diagnostics, and request metrics. Secretless credential references can be natively ready while provider materialization remains separately reported as pending.
- `doctor()` and `self_check()` probe Gmail reachability through `list_labels()` when credentials are materialized, and degrade for `credential_id` mode.
- Every configure attempt invalidates prior authority before resolving replacement credentials. Failed handshakes also revoke prior authority. Shutdown invalidates the session, stops the client runtime, and clears stored configuration and lifecycle state.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.
- Manifest `gmail.list_messages` input schema mentions `label_ids`, but runtime input validation and client dispatch use `query`, `max_results`, and `page_token`.
- Manifest AI hints mention `gmail.search_messages` and `gmail.modify_labels`, but neither operation exists in runtime dispatch.
- Runtime introspection marks `gmail.trash_message` idempotency as `BestEffort`; manifest marks it `strict`.
- Runtime base URL policy accepts any `googleapis.com` subdomain, while manifest operation allowlists name `gmail.googleapis.com` and `www.googleapis.com`.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should align list-message schema, idempotency metadata, base URL policy wording, and manifest hints. Native event streaming is not advertised; mailbox history remains available through the acknowledged `gmail.sync_history` operation.

## First-Slice Scope

The current Gmail README slice documents the existing runtime surface:

- shared Google bearer-token, credential-reference, and OAuth refresh auth selection
- Gmail API base URL policy and loopback test allowance
- message send/read/list/modify/trash, thread read, label list, draft read/create/send, and history sync operations
- bound capability-token verification during both `invoke` and `simulate`
- consumer-acknowledged history checkpoints, restart replay, bounded pagination, and singleton-writer fencing
- provider error mapping, retry behavior, redaction posture, doctor behavior, health behavior, and shutdown behavior
- deterministic WireMock tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: Google bearer token, host credential reference, or OAuth refresh material through the shared Google auth layer.
- Home zone: `z:private`.
- Allowed source zones: `z:owner` and `z:private`.
- Allowed target zone: `z:private`.
- Forbidden zones: `z:public` and `z:work`.
- Runtime capability surface:
  - `gmail.read` gates message and attachment reads, message listing, thread reads, and label listing.
  - `gmail.history.read` gates restart-safe mailbox history sync.
  - `gmail.write` gates label modification and draft read/create.
  - `gmail.send` gates sending new messages and sending drafts.
  - `gmail.delete` gates moving messages to trash.
- The connector does not persist messages, labels, threads, drafts, access tokens, credential IDs, provider payloads, or provider error bodies beyond process memory.
- The exception is the `gmail.sync_history` cursor state file, which stores the acknowledged history ID, cursor version, a scope fingerprint, lease sequence, optional lease object ID, and update timestamp. The scope fingerprint binds the credential reference, provider base URL, and normalized history filters without persisting raw credential material or history payloads.
- Gmail data can include personal email contents, recipients, subject lines, labels, snippets, thread context, draft content, and mailbox metadata. Treat all live reads and writes as private-zone data.

## Network And Runtime Invariants

- Production host: `gmail.googleapis.com`.
- Production API prefix: `/gmail/v1`.
- Production port: `443`.
- TLS and SNI are required by the manifest for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback base URLs are test-only.
- Runtime request timeout: `30 seconds`.
- Manifest connect timeout is `10000 ms` for Gmail operations.
- Manifest total timeout is `30000 ms` for most operations and `60000 ms` for list/history operations.
- Manifest maximum response bytes range from `1048576` to `22435160`. The attachment allowance includes base64 expansion of 16 MiB plus 64 KiB of JSON envelope overhead; a smaller requested `max_bytes` also lowers its streaming response bound.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120000 ms` wall-clock timeout, read-only `/usr` and `/lib`, writable `$CONNECTOR_STATE`, no exec, and no ptrace.
- The connector does not open inbound sockets.
- The connector does not implement Gmail watch channels, Pub/Sub, replay streaming, or webhook ingress.

## History Sync And Consumer Acknowledgement

`gmail.sync_history` returns every page in a bounded history traversal. It keeps a durable checkpoint of what the caller says it has already processed. This separates receiving a provider response from acknowledging that the consumer has safely handled its records.

Use the operation as follows:

1. Start with a history ID obtained from an already completed mailbox sync. Supply that value as `start_history_id`, together with the current `lease_seq` and optional `lease_object_id`.
2. Process the entire returned `history` batch durably. `latest_history_id` is a candidate for the next request; the response's `acknowledged_history_id` shows the checkpoint actually persisted.
3. After processing succeeds, pass the prior `latest_history_id` as the next `start_history_id`. That explicit boundary acknowledges the processed range and allows the checkpoint to advance.
4. If the response or processing outcome is uncertain, retry with the original `start_history_id`, or omit it to resume from the last acknowledged checkpoint. Repeated history records are expected, including after restart; deduplicate by provider history identity as needed.

For example:

| Request or result | Meaning |
|---|---|
| Input `{"start_history_id":"100","lease_seq":7}` | The caller has processed changes through `100`. |
| Result includes `latest_history_id: "400"`, `acknowledged_history_id: "100"` | Changes after `100` were fetched; `400` has not been acknowledged. |
| Retry input `{"lease_seq":7}` | Fetch again from the durable `100` boundary. |
| Next input `{"start_history_id":"400","lease_seq":7}` after processing | Acknowledge the completed range and fetch changes after `400`. |

An explicit older cursor is honored for replay. It does not move a version-2 checkpoint backward. `dedup_applied` remains present for compatibility and is always `false`; the connector never substitutes a newer checkpoint for an explicitly requested older start. A retry can include newer mailbox changes, so callers must not assume an identical cached response.

Each cursor file belongs to one credential reference, provider base URL, and normalized `history_types` filter. A different scope is rejected before provider execution and must use a separate cursor file with its own known-consumed starting boundary. Use separate files for independent consumers as well. Rotating a credential reference does not prove that the mailbox identity is unchanged; migrate that consumer explicitly to a separate checkpoint. With no filter, all history types are requested. Supported explicit values are `messageAdded`, `messageDeleted`, `labelAdded`, and `labelRemoved`.

### Existing Cursor Files

Older unversioned files stored the newest fetched ID, which does not establish that a caller received or processed those changes. They cannot be resumed implicitly. Supply the last history ID the consumer knows it processed, using a current lease. This migrates the checkpoint to `cursor_version = 2`, even when the acknowledged boundary is below the old fetched value, and preserves stale-writer fencing. Unknown cursor versions are rejected. Keep the same checkpoint and lease identity when retrying an uncertain migration.

The on-disk field `next_history_id` is retained for compatibility; in version 2 it means the acknowledged resume boundary. The connector serializes checkpoint updates through a persistent sibling lock file, rechecks the latest lease and scope under that lock, and publishes the new state with an atomic, synced file replacement. A late response from an older lease cannot overwrite a newer writer's checkpoint. Lock contention produces a conflict that can be retried with the same acknowledgement boundary.

### Completion And Limits

`max_results` is a page size from 1 through 500. A sync is limited to 100 provider pages and 8 MiB of serialized history records; each provider response also has an 8 MiB plus 64 KiB streaming body limit. Pagination cycles, malformed cursors, oversized replies, provider errors, and unfinished traversals fail without offering a partial batch as completed progress. The checkpoint is updated only after a complete valid traversal, and only to the caller's acknowledged boundary.

Gmail returns changes after the requested history ID, and history IDs are increasing but noncontiguous. Use the ID returned from the completed traversal; do not calculate a successor. [Google's history API contract](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.history/list) permits storing the returned history ID after the final page. This connector additionally waits for the caller to confirm consumption before recording that progress.

Provider retention still limits recovery. If Gmail returns `404` because a history ID has expired, [perform a full sync](https://developers.google.com/workspace/gmail/api/guides/sync) and resume from its known-consumed boundary. The connector does not silently jump to a newer cursor or fabricate the missing history.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `gmail.read` | Read messages and attachments, list messages, read threads, and list labels visible to the authenticated mailbox principal. |
| `gmail.history.read` | Incrementally fetch mailbox history while preserving cursor fencing. |
| `gmail.write` | Modify message labels and read/create drafts. |
| `gmail.send` | Send new messages and send saved drafts. |
| `gmail.delete` | Move messages to trash. |
| `media.download` | Manifest optional capability; not used by runtime capability verification in this slice. |
| `media.upload` | Manifest optional capability; not used by runtime capability verification in this slice. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `gmail.send_message` | `POST /gmail/v1/users/me/messages/send` | `gmail.send` | `Dangerous` | `High` | `None` | Sends a new email from raw MIME or structured fields. |
| `gmail.get_message` | `GET /gmail/v1/users/me/messages/{message_id}` | `gmail.read` | `Safe` | `Low` | `Strict` | Reads one Gmail message by message ID. |
| `gmail.get_attachment` | `GET /gmail/v1/users/me/messages/{message_id}/attachments/{attachment_id}` | `gmail.read` | `Safe` | `Low` | `Strict` | Retrieves a separate MIME body with validated base64url data and a decoded-byte limit. |
| `gmail.list_messages` | `GET /gmail/v1/users/me/messages?q={query}&maxResults={max_results}&pageToken={page_token}` | `gmail.read` | `Safe` | `Low` | `Strict` | Lists or searches message IDs visible to the mailbox principal. |
| `gmail.sync_history` | `GET /gmail/v1/users/me/history?startHistoryId={history_id}` | `gmail.history.read` | `Safe` | `Low` | `Strict` | Fetches complete bounded history batches and persists only caller-acknowledged progress. |
| `gmail.modify_message` | `POST /gmail/v1/users/me/messages/{message_id}/modify` | `gmail.write` | `Risky` | `Medium` | `BestEffort` | Adds or removes label IDs on one message. |
| `gmail.trash_message` | `POST /gmail/v1/users/me/messages/{message_id}/trash` | `gmail.delete` | `Risky` | `Medium` | `Strict` manifest; `BestEffort` introspection | Moves one message to trash. |
| `gmail.get_thread` | `GET /gmail/v1/users/me/threads/{thread_id}` | `gmail.read` | `Safe` | `Low` | `Strict` | Reads a Gmail thread by thread ID. |
| `gmail.list_labels` | `GET /gmail/v1/users/me/labels` | `gmail.read` | `Safe` | `Low` | `Strict` | Lists system and user labels. |
| `gmail.get_draft` | `GET /gmail/v1/users/me/drafts/{draft_id}` | `gmail.write` | `Risky` | `Medium` | `Strict` | Reads one saved draft. |
| `gmail.create_draft` | `POST /gmail/v1/users/me/drafts` | `gmail.write` | `Risky` | `Medium` | `None` | Creates an unsent draft from raw MIME or structured fields. |
| `gmail.send_draft` | `POST /gmail/v1/users/me/drafts/send` | `gmail.send` | `Dangerous` | `High` | `None` | Sends a saved draft and consumes it. |

## Resource URIs

Runtime capability-token verification binds operations to these resource URI shapes:

| Operation | Resource URI |
|-----------|--------------|
| `gmail.send_message` | `gmail:messages:send` |
| `gmail.get_message` | `gmail:message:{message_id}` |
| `gmail.get_attachment` | `gmail:message:{percent_encoded_message_id}:attachment:{percent_encoded_attachment_id}` |
| `gmail.modify_message` | `gmail:message:{message_id}` |
| `gmail.trash_message` | `gmail:message:{message_id}` |
| `gmail.list_messages` | `gmail:messages` |
| `gmail.sync_history` | `gmail:history` |
| `gmail.get_thread` | `gmail:thread:{thread_id}` |
| `gmail.list_labels` | `gmail:labels` |
| `gmail.get_draft` | `gmail:draft:{draft_id}` |
| `gmail.send_draft` | `gmail:draft:{draft_id}` |
| `gmail.create_draft` | `gmail:drafts:create` |

## Attachment Retrieval

Read a message with `gmail.get_message` or `gmail.get_thread`, then inspect its MIME parts. A part with `body.attachmentId` has a separate body that can be fetched with `gmail.get_attachment`. Pass the containing message ID and that exact attachment ID; a MIME `partId` or filename is not an attachment ID. Parts whose bytes are already in `body.data` do not need a separate fetch.

```json
{
  "message_id": "18d1234abc567890",
  "attachment_id": "ANGjdJ-example",
  "max_bytes": 1048576
}
```

The result is `{"attachment":{"size":5,"data":"SGVsbG8"}}`: `size` counts decoded bytes, and `data` uses Gmail's URL-safe base64 alphabet, with or without canonical padding. Decode it to recover the original binary bytes. Both response fields are required and the declared size must match the decoded contents. A zero-byte attachment is valid; `max_bytes: 0` permits only an empty attachment. The default and hard decoded limit is `16777216` bytes (16 MiB).

The provider requires `gmail.readonly`, `gmail.modify`, or `https://mail.google.com/`; metadata-only scope cannot retrieve attachment contents. Capability authorization binds both IDs, so a grant for one attachment cannot read another attachment or another message. The client sends an authenticated GET with no request body, refuses redirects, and retries only safe read failures. Response bounds apply while reading the network body, before JSON/base64 decoding, including oversized error responses. Attachment validation errors contain no provider payload.

## Explicit Non-Goals

The current implementation does not include:

- Gmail watch channels, Pub/Sub setup, webhook ingress, replay streams, or mailbox event fanout
- attachment upload, separate attachment downloads above 16 MiB, MIME tree normalization, inline image extraction, or message body rendering
- label create/update/delete, thread modify/trash, message untrash, message delete, batch modify, batch delete, import, insert, or SMTP-like sending
- filters, settings, delegates, forwarding addresses, vacation settings, send-as aliases, signatures, or profile management
- multi-mailbox delegation, domain-wide delegation provisioning, service account setup, Admin SDK integration, Contacts/People API integration, or Calendar integration
- durable message store, search index, mailbox export, backup, or retention-policy engine

These are excluded on purpose:

- Gmail contains private user data and live sends are side-effecting.
- History sync uses caller acknowledgements and singleton-writer fencing; provider-retention recovery and full mailbox synchronization remain caller responsibilities.
- Attachment reads have an explicit size/encoding contract; MIME rendering and attachment upload still need their own media contracts.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, auth mode, base URL, history cursor path, required scopes, granted scopes, and request metrics
- credential-reference degraded state when host token injection is required
- scope-limited operation inventory when OAuth refresh grants are authoritative but insufficient
- provider-backed readiness through `list_labels()` when credentials are materialized
- operation metadata with capability, risk, safety tier, idempotency, approval mode, schemas, and hints
- bound capability-token verification during `invoke`
- simulation denial for unknown operation, invalid input, unconfigured connector, missing handshake, and bound capability-token mismatch
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- local non-mock loopback acceptance for production `handle_invoke()` paths across `gmail.list_labels`, `gmail.get_message`, and `gmail.send_message`
- lifecycle, configuration, base URL policy, loopback allowance, introspection, simulation, doctor, self-check, and shutdown behavior
- message get/list/send/modify/trash, thread get, label list, draft get/create/send, and history sync through deterministic HTTP fixtures
- attachment HTTP fixtures cover exact binary contents, required response fields, base64url and size validation, encoded IDs, bounded bodies, provider refusals, safe read retries, redirect refusal, and message/attachment-specific capability authority
- acknowledged cursor persistence, lost-response replay, explicit older-cursor replay, legacy migration, scope isolation, bounded pagination, and `lease_seq` fencing
- invoke rejection for unknown operation, missing token, missing input, wrong capability, and pre-provider capability verification
- provider 401, 403, 404, 429, 500 classes and FCP error mapping
- shared Google discovery/provisioning overlap for list, send, and history metadata

## Source Notes

- `connectors/gmail/src/connector.rs` defines configuration parsing, base URL policy, scope resolution, lifecycle handlers, introspection, simulation, capability-token verification, resource URI binding, history cursor state, and invoke dispatch.
- `connectors/gmail/src/client.rs` defines Gmail paths, Google auth execution, retry dispatch, timeout, request metrics, path-segment validation, provider response decoding, and provider error mapping.
- `connectors/gmail/src/types.rs` defines message, thread, label, draft, history, and list response shapes.
- `connectors/gmail/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/gmail/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, event caps, and rate-limit pools.
- `connectors/gmail/tests/integration.rs`, `connectors/gmail/tests/conformance_contract.rs`, and `connectors/gmail/tests/migration_acceptance.rs` cover deterministic runtime behavior and contract assertions.

## Verification Bundle

The dedicated tracked verification bundle is `scripts/e2e/gmail_connector_verification.sh`. The closeout surface is the crate-local test suite plus fail-closed `fwc proof run` evidence for Cargo-backed `rch` proof commands.

The verification surface captures:

- runtime operation inventory and policy metadata
- deterministic WireMock coverage for Gmail API paths
- deterministic local loopback coverage for the `local_non_mock` acceptance suite
- shared Google auth, endpoint policy, provider error, lifecycle, simulation, history cursor, and introspection tests
- formatting as a source-state check, plus test and clippy proof through `fwc proof run` / `rch`
- UBS on changed files before commit

The verifier writes proof-governor artifacts under `${OUT_ROOT}/proof`. Only `accepted_remote_proof` rows in `*.rch_remote_proof.jsonl` are green closeout evidence for Cargo-backed steps. `refused_local_fallback`, `infra_blocked`, `remote_command_failed`, `failed_closed`, `not_proof`, or a missing proof row keep the batch bead open. The wrapper normalizes stale proof-runner output for `[RCH] remote required; refusing local fallback` to `refused_local_fallback` so local-fallback refusal is not mistaken for a Gmail code failure.

## Operator Guidance

**Prerequisites**:

- Use a Gmail test account or Workspace test tenant for live proof.
- Prefer credential-reference mode when host policy should own Google secret material.
- Use loopback WireMock fixtures for routine proof.
- For OAuth refresh proof, request only the Gmail scopes needed for the operation family under test.

**Dedicated environment**:

- Keep live test messages, drafts, labels, and trash operations separate from personal or production mailboxes.
- Do not run send proof against real recipients unless the side effect is intentional and approved.
- Use a dedicated history cursor path for each proof run to avoid cross-run cursor contamination.

**Redaction rules**:

- Redact access tokens, refresh tokens, credential IDs where needed, client IDs/secrets, email addresses, message IDs, thread IDs, draft IDs, subject lines, snippets, body text, headers, label names, history IDs, cursor paths when sensitive, provider payloads, provider error bodies, and endpoint URLs that reveal tenant topology.
- Verification output should use operation IDs, endpoint shapes, auth mode, host class, result counts, status/error classes, retry decisions, and payload-shape summaries.

**Common remediation**:

- If configuration fails, provide exactly one Google auth source and do not mix `required_scopes` with `scope_triggers`.
- If `credential_id` self-check degrades, materialize host credentials through the egress proxy before invoking provider operations.
- If OAuth refresh self-check reports `scope_limited`, request the missing Gmail scopes or avoid the operations listed in the report.
- If `gmail.sync_history` conflicts, inspect `lease_seq`, `lease_object_id`, checkpoint scope, and cursor version. Retry an uncertain result from the same acknowledged boundary; supply a known-consumed start for legacy migration, and use a separate cursor path for a different credential or history filter.
- If `gmail.list_messages` filters do not behave as expected, use runtime `query` syntax rather than manifest-only `label_ids`.
- If provider returns 403, treat it as an auth/scope/permission failure rather than a retryable transport error.
- If an attachment read exceeds `max_bytes`, raise the caller limit only if appropriate, up to 16 MiB; larger attachments require another retrieval path. Missing or malformed attachment fields are errors, never fabricated empty files.

**Rerun commands**:

- `scripts/e2e/gmail_connector_verification.sh`
- `PROOF_GOVERNOR=1 scripts/e2e/gmail_connector_verification.sh`
- `FWC_BIN=/path/to/current/target/debug/fwc PROOF_GOVERNOR=1 scripts/e2e/gmail_connector_verification.sh` when the installed `fwc` binary does not yet include `proof run`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-gmail-readme cargo test -p fcp-gmail --test local_non_mock -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-gmail-readme cargo check -p fcp-gmail --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-gmail-readme cargo test -p fcp-gmail --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-gmail-readme cargo clippy -p fcp-gmail --all-targets --no-deps -- -D warnings`
- `ubs connectors/gmail/README.md`
