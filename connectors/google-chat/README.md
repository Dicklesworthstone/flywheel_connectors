# Google Chat Connector V3 Contract

> **Status**: PROVEN runtime contract documented; capability-enforcement drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/google_chat_connector_verification.sh`
> **Chat API upstream**: https://developers.google.com/workspace/chat/api/reference/rest
> **Messages upstream**: https://developers.google.com/workspace/chat/api/reference/rest/v1/spaces.messages
> **Media upload upstream**: https://developers.google.com/workspace/chat/upload-media-attachments
> **Interaction events upstream**: https://developers.google.com/workspace/chat/receive-respond-interactions

## Purpose

This document fixes the operator-facing contract for `fcp.google_chat`. The connector exposes the Google Chat API surface implemented in this crate: spaces, messages, threaded replies, media attachment send, message reads, reactions, memberships, and host-forwarded Chat interaction events.

The connector is intentionally a bounded Chat bridge. It is not a full Workspace admin client, Chat app provisioning tool, incoming webhook creator, direct listener, push server, card/dialog renderer, space management client, custom emoji client, import-mode client, user read-state client, or organization-wide Chat search client.

## Current Runtime Snapshot

The current crate exposes these operations:

- `chat.ingest_webhook`
- `chat.list_spaces`
- `chat.get_space`
- `chat.send_message`
- `chat.reply_message`
- `chat.send_media_message`
- `chat.list_messages`
- `chat.get_message`
- `chat.add_reaction`
- `chat.list_members`

Important runtime truths the contract preserves:

- Configuration accepts auth either at the top level or under `auth`.
- Configuration requires exactly one Google auth source accepted by the shared Google discovery auth layer.
- Direct bearer-token mode sends the Google Authorization header through `reqwest`.
- `credential_id` mode is secretless and sends the shared `X-FCP-Credential-ID` header for host/egress credential materialization.
- Default base URL is `https://chat.googleapis.com/v1`.
- Public base URLs must use HTTPS, must target exact host `chat.googleapis.com`, and must not contain userinfo, query strings, or fragments.
- `localhost`, `127.0.0.1`, and `::1` are accepted with HTTP or HTTPS for deterministic loopback tests.
- The upload base URL is derived from the API base URL when the base ends with `/v1`; otherwise it falls back to `https://chat.googleapis.com/upload/v1`.
- `request_timeout_ms` defaults to `30_000` and must be between 1 and `30_000`.
- Resource names reject path traversal, query strings, fragments, encoded slashes, encoded backslashes, and leading slashes.
- Media sends decode base64 locally, reject empty media, cap decoded bytes at 20 MiB by default, validate filename/content type, upload first, then send the message with a redacted upload token.
- Outbound `chat.send_message`, `chat.reply_message`, and `chat.send_media_message` run through chat-coordination checks before provider execution.
- Host-forwarded webhook ingress does not open a listener. The FCP host must accept the request and call `chat.ingest_webhook`.
- Webhook ingress supports authorization-header bearer material and Workspace Add-on `authorizationEventObject.systemIdToken` material.
- Webhook token comparison is constant-time and all token material is redacted from summaries/evidence.
- Webhook ingress validates POST, JSON content type, body size, pre-auth body size, body read timeout, replay keys, sender rate, inbound policy, and dispatch outcome.
- Runtime introspection exposes event topic `chat.webhook.message` with replay-capable event caps.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest connector ID is `fcp.google_chat`, runtime `BaseConnector` ID is `google-chat`, and package/binary names use `fcp-google-chat`.
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.
- Manifest `interface_hash` is all zeroes.
- Manifest optional capabilities are empty even though operations and runtime introspection use `chat.read`, `chat.write`, and `chat.webhook`.
- Runtime `handle_invoke_internal` does not parse or verify `capability_token` for any operation. Capability-token verification currently exists in `simulate`, not `invoke`.
- Runtime `chat.ingest_webhook` requires a configured `ChatClient` even though the operation itself performs no provider egress.
- `ChatClient` stores an `HttpRetryConfig`, but request helpers currently perform one `reqwest` send per call and do not run the shared retry loop.
- Runtime `handle_shutdown` clears the client but leaves webhook config, inbound policy, verifier, session, and base configured/handshaken flags in place.
- Runtime `health` and `self_check` only report local client/configured state; they do not probe Google Chat.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should make `invoke` enforce bound capability tokens, populate manifest capabilities and interface hash, align connector ID spelling, decide whether webhook ingest should require outbound auth, wire retry behavior or remove the unused retry config, and reset lifecycle state on shutdown.

## First-Slice Scope

The current Google Chat README slice documents the existing runtime surface:

- Google bearer-token and secretless credential-reference auth selection
- Chat API base URL policy and upload URL derivation
- spaces, messages, replies, media attachments, reactions, memberships, and host-forwarded webhook ingest
- chat coordination for outbound sends
- simulation-time capability-token verification and invoke-time enforcement gap
- provider error mapping, timeout behavior, redaction posture, and webhook guardrails
- lifecycle, doctor, health, self-check, introspection, simulation, invoke, and shutdown surfaces
- deterministic WireMock tests, conformance-contract tests, and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: Google bearer token, host credential reference, or other shared Google auth material accepted by `GoogleAuthSelection`.
- Home zone: `z:work`.
- Allowed source zones: `z:owner` and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability surface:
  - `chat.read` gates spaces, messages, and memberships reads.
  - `chat.write` gates outbound messages, threaded replies, media messages, and reactions.
  - `chat.webhook` gates host-forwarded webhook simulation metadata.
- Current invoke path does not enforce those capabilities. Host policy must not treat invoke as capability-verified until the follow-up fix lands.
- The connector does not persist spaces, messages, media, membership records, sender IDs, access tokens, credential IDs, webhook tokens, provider payloads, or provider error bodies beyond process memory.
- Chat data can contain private user text, attachments, thread identifiers, space names, display names, and email addresses. Treat all live reads and webhook payloads as private or work-zone data.

## Network And Runtime Invariants

- Production host: `chat.googleapis.com`.
- Production API prefix: `/v1`.
- Production upload prefix: `/upload/v1`.
- Production port: `443`.
- TLS and SNI are required by the manifest for live provider egress.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live provider operations.
- Runtime loopback base URLs are test-only.
- Runtime request timeout defaults to `30_000 ms`.
- Manifest network constraints use `10_000 ms` connect timeout and either `30_000 ms` or `60_000 ms` total timeout.
- Manifest maximum response bytes are `1_048_576`, `5_242_880`, or `10_485_760` depending on operation size.
- `chat.ingest_webhook` has empty provider egress allow-lists in the manifest because the host forwards the request into the connector.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `30_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `chat.read` | Read spaces, messages, and memberships visible to the authenticated principal. |
| `chat.write` | Send messages, replies, media attachments, and reactions. |
| `chat.webhook` | Process host-forwarded Google Chat interaction events. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `chat.ingest_webhook` | host-forwarded request only | `chat.webhook` | `Safe` | `Low` | `Strict` | Normalizes a Chat interaction event after host ingress. |
| `chat.list_spaces` | `GET /v1/spaces` | `chat.read` | `Safe` | `Low` | `Strict` | Lists spaces visible to the authenticated user/app. |
| `chat.get_space` | `GET /v1/{space_name}` | `chat.read` | `Safe` | `Low` | `Strict` | Reads one space resource. |
| `chat.send_message` | `POST /v1/{space_name}/messages` | `chat.write` | `Risky` | `Medium` | `None` | Sends a new top-level message. |
| `chat.reply_message` | `POST /v1/{space_name}/messages?messageReplyOption=...` | `chat.write` | `Risky` | `Medium` | `None` | Sends a threaded reply by thread name or thread key. |
| `chat.send_media_message` | `POST /upload/v1/{space_name}/attachments:upload`, then `POST /v1/{space_name}/messages` | `chat.write` | `Risky` | `Medium` | `None` | Uploads bounded media and attaches it to a message. |
| `chat.list_messages` | `GET /v1/{space_name}/messages` | `chat.read` | `Safe` | `Low` | `Strict` | Lists messages in a space. |
| `chat.get_message` | `GET /v1/{message_name}` | `chat.read` | `Safe` | `Low` | `Strict` | Reads one message resource. |
| `chat.add_reaction` | `POST /v1/{message_name}/reactions` | `chat.write` | `Risky` | `Medium` | `None` | Adds a Unicode emoji reaction. |
| `chat.list_members` | `GET /v1/{space_name}/members` | `chat.read` | `Safe` | `Low` | `Strict` | Lists memberships in a space. |

## Host-Forwarded Webhook Contract

`chat.ingest_webhook` is a host-forwarded ingress operation. It accepts:

- `method`, defaulting to `POST`
- `headers`, including `Authorization: Bearer ...` and `Content-Type: application/json`
- `body`, either a raw JSON string or parsed JSON object
- `body_size_bytes` and `body_read_elapsed_ms` measured by the host
- `delivery_id` and `source_id` for redacted receipt metadata
- `command_authorized`, `require_mention`, `mention_text`, and `dispatch_outcome`

Default webhook policy values:

- `enabled = false`
- `max_body_bytes = 65536`
- `preauth_max_body_bytes = 16384`
- `body_timeout_ms = 3000`
- `auth_failure_limit_per_minute = 10`
- `sender_limit_per_minute = 60`
- `replay_ttl_secs = 86400`
- `replay_max_entries = 1000`

Default inbound policy values:

- direct-message policy: `pairing`
- group policy: `allowlist`
- require mention: `true`
- default mention text: `@flywheel`

Webhook output is intentionally a redacted receipt. It reports accept/drop status, event emission, reason codes, auth source, replay decision, policy decision, ingress limits, and normalized event shape without exposing bearer tokens or raw message bodies.

## Chat Coordination

Outbound send operations call the shared chat-coordination layer before provider execution:

- default backend: `in_memory`
- configurable backends: `in_memory`, `agent_mail`, and `mesh_gossip`
- configurable `ttl_seconds`, `fail_open`, `allowlist_channels`, and `dm_mode`
- configurable DM modes: `skip` and `treat_as_thread`

When coordination denies a send, the provider call is not executed. Successful outputs include coordination audit records.

## Explicit Non-Goals

The current implementation does not include:

- direct network listeners, Chat app registration, incoming webhook creation, OAuth consent setup, or Google Cloud project enablement
- card builders, dialogs, slash command routing, app home, private messages, accessory widgets, or custom emoji operations
- space create/update/delete/search/setup, membership create/update/delete, message update/delete, reaction delete/list, attachment metadata get, media download, space event list/get, or user read-state APIs
- Drive-backed attachment handling, file download, resumable upload, or uploads over 20 MiB
- durable replay storage, durable thread ownership, event queue persistence, or webhook delivery retries beyond host-dispatch outcome signaling
- connector-local credential vaulting

These are excluded on purpose:

- Chat messages and attachments contain high-sensitivity human communication.
- Inbound event handling belongs behind host-controlled request-region ingress.
- Broader Chat app behavior needs app registration, slash-command, card, dialog, and policy contracts that are separate from this connector slice.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration and client state
- webhook config summaries with token material redacted
- inbound policy summaries with IDs redacted
- operation metadata with capability, risk, safety tier, idempotency, schemas, and AI hints
- event topic `chat.webhook.message` and replay-capable event caps
- simulation denial for unknown operation, unconfigured connector, missing handshake, and bound capability-token mismatch
- current invoke capability-enforcement gap
- local-only self-check for configured state

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, auth redaction, health, doctor, self-check, and shutdown behavior
- bound-token simulation denial for wrong zone or instance
- loopback REST calls for spaces, sends, replies, and webhook ingest
- provider 401, 429, malformed payloads, timeout, and FCP error mapping
- webhook policy, replay, guardrails, token redaction, Add-on payload normalization, and redacted JSONL evidence
- manifest/runtime operation catalog parity, network constraints, and error taxonomy
- media upload ordering, max-byte validation, upload-token redaction, and coordination denial before upload

## Source Notes

- `connectors/google-chat/src/connector.rs` defines configuration parsing, base URL policy, lifecycle handlers, webhook ingress, chat coordination, introspection, simulation, and invoke dispatch.
- `connectors/google-chat/src/client.rs` defines Chat paths, auth header application, request timeout, upload URL derivation, media upload body construction, resource-name validation, and provider error mapping.
- `connectors/google-chat/src/types.rs` defines spaces, messages, users, memberships, reactions, attachments, and Chat event payloads.
- `connectors/google-chat/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/google-chat/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, webhook event caps, and rate-limit pools.
- `connectors/google-chat/tests/integration.rs` covers deterministic HTTP behavior, webhook behavior, redaction, coordination, and simulation.
- `connectors/google-chat/tests/conformance_contract.rs` covers manifest/runtime operation parity and network constraints.

## Verification Bundle

The tracked verification bundle is `scripts/e2e/google_chat_connector_verification.sh`. It runs the graduation gauntlet, manifest check, crate-local compilation, formatting, integration/conformance suites, `local_non_mock` loopback acceptance suite, JSONL redaction/evidence checks, and clippy through `rch`.

The verification surface captures:

- runtime operation inventory and policy metadata
- deterministic WireMock coverage for Chat API paths
- host-forwarded webhook guardrails and redaction
- auth, endpoint policy, provider error, lifecycle, simulation, and introspection tests
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a Google Workspace test space for live verification.
- Prefer credential-reference mode when host policy should own Google secret material.
- Use host-forwarded loopback fixtures for webhook proof.
- Do not expose webhook bearer tokens in logs, bead notes, or evidence artifacts.

**Dedicated environment**:

- Keep Chat app test spaces separate from production rooms.
- Use stable resource names such as `spaces/...` and `spaces/.../messages/...`, not display names.
- Use `REPLY_MESSAGE_OR_FAIL` when policy must surface missing-thread errors.
- Use `REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD` only when starting a new thread is acceptable.
- Keep media fixtures small and non-sensitive.

**Redaction rules**:

- Redact access tokens, credential IDs where needed, webhook bearer tokens, space names when sensitive, message names, thread keys, user IDs, display names, emails, message text, attachment content, upload tokens, provider payloads, provider error bodies, and endpoint URLs when they reveal tenant topology.
- Verification output should use operation IDs, endpoint shapes, auth mode, host class, result counts, status/error classes, policy decisions, replay decisions, and payload-shape summaries.

**Common remediation**:

- If configuration fails, provide exactly one Google auth source.
- If live provider calls fail with 403, verify the Chat API scopes and app/user authorization mode for the target operation.
- If webhook ingress returns `webhook_disabled`, enable `webhook.enabled` and provide at least one bearer token.
- If webhook ingress returns `preauth_payload_too_large`, lower the host-forwarded body size before token extraction or use header bearer auth.
- If a group message is accepted but not dispatched, check group policy, allow-lists, mention requirements, and disabled spaces.
- If media send fails before upload, verify base64, decoded size, filename, and content type.
- Until invoke capability enforcement is fixed, run sends only behind host policy that verifies operation, capability, approval, and target zone before calling `invoke`.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-chat-readme cargo check -p fcp-google-chat --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-chat-readme cargo test -p fcp-google-chat --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-chat-readme cargo clippy -p fcp-google-chat --all-targets --no-deps -- -D warnings`
- `ubs connectors/google-chat/README.md`
