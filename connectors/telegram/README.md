# Telegram Connector V3 Contract

> **Status**: PROVEN runtime contract documented; no-live-credential Bot API/webhook loopback proof tracked
> **Bead**: `flywheel_connectors-6n7.2`
> **Parent**: `flywheel_connectors-6n7`
> **Verification script**: `scripts/e2e/telegram_connector_verification.sh`
> **Telegram Bot API upstream**: https://core.telegram.org/bots/api

## Purpose

This document fixes the operator-facing contract for `fcp.telegram`. The connector exposes the Telegram Bot API surface implemented in this crate: text send, media send, file metadata lookup, callback-query acknowledgement, chat actions, message reactions, webhook registration management, long-polling event intake, and host-forwarded webhook update ingestion.

The connector is intentionally a bounded bot API bridge. It is not a Telegram client session, MTProto client, bot-management console, payment processor, chat-admin tool, inline-query engine, custom-certificate uploader, or full Bot API wrapper.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `telegram.send_message`
- `telegram.send_media`
- `telegram.get_file`
- `telegram.answer_callback_query`
- `telegram.send_chat_action`
- `telegram.set_message_reaction`
- `telegram.set_webhook`
- `telegram.delete_webhook`
- `telegram.get_webhook_info`
- `telegram.ingest_webhook_update`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-telegram`.
- Manifest ID is `fcp.telegram`.
- `BaseConnector` runtime ID is `fcp.telegram`.
- Manifest version is `0.1.0`.
- Manifest format is `wasi`.
- Manifest schema version is `2.1`.
- Manifest protocol features include `streaming`.
- Configuration requires exactly one auth source:
  - `credential`
  - `credential_id`
- Direct credential mode expects a Telegram bot token in `<bot_id>:<secret>` form and validates it with `getMe` during configure.
- `credential_id` must be a valid UUID.
- `credential_id` mode is accepted, but no bot token is materialized in the current runtime; configure returns `configured_pending_token_materialization`.
- `credential_id` mode cannot complete handshake validation, health live checks, or self-check live probes until host egress credential injection materializes a token.
- Default base URL is `https://api.telegram.org`.
- Runtime base URL policy accepts `api.telegram.org` and loopback hosts for tests.
- Runtime rejects base URLs with userinfo, path, query, or fragment components.
- Runtime rejects non-local `http`.
- `poll_timeout` defaults to 30 seconds and must be between 1 and 50 seconds.
- `allowed_updates` defaults to the crate-local known update list when omitted.
- Inbound policy defaults to deny before event emission.
- Inbound policy modes are `deny`, `open`, and `allowlist`.
- Allowlist policy can constrain sender user IDs, chat IDs, and topic resource URIs.
- Webhook ingestion requires configured `webhook_secret_token` and a matching forwarded `secret_token` input.
- Handshake requires `zone_dir` for polling cursor and singleton-writer lease persistence.
- Handshake verifies the bot with `getMe`, installs a bound `CapabilityVerifier`, starts the polling loop, and returns streaming event caps.
- Runtime `invoke` uses the JSON field `operation`, not `operation_id`.
- Runtime `invoke` requires `capability_token` and verifies a bound capability token against operation ID, capability ID, instance ID, zone, and resource URIs.
- Runtime `simulate` also validates known operation, input shape, config/handshake state, and a bound capability token.
- Runtime `subscribe` confirms requested topics and reports `replay_supported: false`.
- Runtime `shutdown()` stops polling, shuts down the client runtime, clears config/client/verifier/session/zone state, clears webhook replay cache, and clears base configured/handshaken flags.

## Runtime API Adapter

The runtime uses these request shapes under `{base_url}`:

| Operation | Runtime request | Required input | Output handling |
|-----------|-----------------|----------------|-----------------|
| `telegram.send_message` | `POST /bot{token}/sendMessage` | `chat_id`, `text` | Returns first message ID, all produced message IDs, chunk count, and chat ID after provider success. |
| `telegram.send_media` | `POST /bot{token}/sendPhoto`, `sendDocument`, `sendAudio`, `sendVideo`, or `sendVoice` | `chat_id`, `media_type`, `media` | Dispatches by `media_type`; returns message ID and chat ID after provider success. |
| `telegram.get_file` | `GET /bot{token}/getFile?file_id=...` | `file_id` | Returns Telegram file metadata and locally constructs a file download URL when `file_path` is present. |
| `telegram.answer_callback_query` | `POST /bot{token}/answerCallbackQuery` | `callback_query_id` | Returns `{ "success": true }` after provider success. |
| `telegram.send_chat_action` | `POST /bot{token}/sendChatAction` | `chat_id`, `action` | Returns `{ "success": true }` after provider success. |
| `telegram.set_message_reaction` | `POST /bot{token}/setMessageReaction` | `chat_id`, `message_id` | Returns `{ "success": true }` after provider success. |
| `telegram.set_webhook` | `POST /bot{token}/setWebhook` | `url` | Registers a public HTTPS webhook URL using the configured `webhook_secret_token` and returns success without echoing the secret. |
| `telegram.delete_webhook` | `POST /bot{token}/deleteWebhook` | none | Deletes the current webhook registration, optionally dropping pending updates. |
| `telegram.get_webhook_info` | `GET /bot{token}/getWebhookInfo` | none | Returns Telegram webhook URL, certificate flag, pending update count, and optional delivery diagnostics. |
| `telegram.ingest_webhook_update` | no connector-owned egress | `payload`, `secret_token` | Validates raw Update JSON, required forwarded secret, inbound policy, duplicate update IDs, and emits an event when allowed. |

Input and event handling:

- `telegram.send_message` splits long text into bounded 4096 UTF-16-code-unit Telegram chunks, preserving `message_thread_id` on every chunk and applying `reply_to_message_id` only to the first chunk.
- `telegram.send_message` and `telegram.send_media` claim chat ownership before Bot API sends. Duplicate active owners return `FcpError::Unauthorized` code `4090` before provider HTTP, and successful sends include redaction-safe `coordination` audit records.
- `telegram.send_media` validates the 1024 character caption limit.
- `telegram.send_media` accepts media types `photo`, `document`, `audio`, `video`, and `voice`.
- `telegram.send_chat_action` accepts Telegram Bot API chat-action enum values such as `typing`, `upload_photo`, and `upload_document`.
- `telegram.set_message_reaction` accepts at most one non-paid reaction, matching Telegram's bot restriction; omit `reaction` or pass an empty array to clear the bot's reaction.
- `telegram.set_webhook` accepts only public HTTPS webhook URLs, optional fixed IP address, optional max connections from `1` to `100`, optional allowed update filter, and optional `drop_pending_updates`.
- `telegram.set_webhook` takes its `secret_token` from connector configuration, so invocation payloads do not carry secret material.
- `telegram.delete_webhook` and `telegram.get_webhook_info` use the configured bot credential and do not require `webhook_secret_token`.
- `chat_id` can be a numeric ID, `@username`, some `t.me` links, or a bare username that can be normalized.
- Invite links are rejected as chat IDs.
- `message_thread_id` is accepted for message and media sends and is included in resource URI binding.
- Optional `chat_coordination` config supports `enabled`, `ttl_seconds`, `fail_open`, `allowlist_channels`, `backend`, and `dm_mode`; the connector defaults to the in-memory backend for deterministic local proof.
- `get_file` percent-encodes `file_path` and rejects empty, absolute, empty-segment, dot, and dot-dot path forms before constructing a download URL.
- Long polling uses `getUpdates` with offset, limit `100`, configured poll timeout, and normalized allowed updates.
- Polling persists `telegram_poll_cursor.json` and `telegram_poll_lease.json` under `zone_dir`.
- Polling uses a singleton-writer lease so a second live instance with the same zone state cannot poll concurrently.
- Webhook ingestion uses a bounded in-memory duplicate cache keyed by Telegram `update_id`.
- Event topics are `telegram.message.new`, `telegram.message.edited`, `telegram.channel_post.new`, `telegram.channel_post.edited`, and `telegram.callback_query`.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Telegram documents `getUpdates` and outgoing webhooks as mutually exclusive update-receive modes. The runtime always starts long polling during handshake when direct-token mode is available, even though it also exposes a host-forwarded webhook ingest operation.
- Telegram currently documents more update kinds than the crate-local `KNOWN_ALLOWED_UPDATES` list covers, including newer boost, paid-media, and managed-bot update kinds.
- Telegram documents local Bot API servers as supporting local file paths and other local-network behavior. Runtime allows local base URLs for tests, while manifest operation network constraints deny localhost for production egress operations.
- Manifest `interface_hash` is still the all-zero placeholder value.
- Runtime handshake response uses a SHA-256 manifest string hash, not the manifest's `blake3-256` placeholder.
- Handshake grants every requested capability ID. It does not filter requested capabilities against the Telegram manifest.
- Manifest marks `telegram.send_message` and `telegram.send_media` as policy-approved operations. Runtime introspection reports no approval requirement and `invoke` does not verify approval tokens.
- Runtime capability-token enforcement is wired and bound for both `invoke` and `simulate`.
- `get_file` uses a manual HTTP path rather than the retry helper used by the generic request method.
- The client retry helper retries selected HTTP/connect/timeout/provider errors with `max_retries = 2`; manifest rate-limit pools are documented but not enforced locally.
- Runtime setWebhook support does not upload custom TLS certificates or multipart files.
- Runtime `subscribe` confirms topics but does not filter them against the advertised Telegram event catalog.
- Event replay is not supported.
- The tracked no-live-credential verifier exercises a local Bot API loopback plus host-forwarded webhook ingest, but the connector still does not open an inbound webhook listener itself; inbound HTTP remains a host responsibility.

A follow-up parity bead should reconcile Telegram's current update taxonomy, decide whether polling and host-forwarded webhook modes should be mutually exclusive at runtime, add custom-certificate handling if needed, filter handshake grants, expose approval metadata, enforce rate-limit pools, and replace the placeholder interface hash.

## First-Slice Scope

The current Telegram README slice documents the existing runtime surface:

- bot-token and credential-ID configuration
- base URL, poll timeout, allowed updates, webhook secret, and inbound policy configuration
- text send, media send, file lookup, callback acknowledgement, chat action, message reaction, webhook management, and webhook ingest operations
- long-polling state, singleton-writer lease, event emission, duplicate suppression, and shutdown behavior
- lifecycle, doctor, health, self-check, simulate, introspect, invoke, subscribe, and shutdown behavior
- provider error handling, retry behavior, local path safety, and message/caption limits
- runtime/manifest/provider-doc drift around update taxonomy, approval tokens, grant filtering, rate limits, and interface hashes
- deterministic WireMock, connector-suite tests, connector-local `local_non_mock` coverage, and the no-live-credential loopback JSONL verifier

## Auth And Zone Boundary

- Authentication mechanisms: direct Telegram bot token or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability families:
  - `telegram.send`
  - `telegram.read`
  - `telegram.webhook`
- Manifest required capabilities are `network.dns`, `network.egress`, `network.tls.sni`, and `storage.state`.
- Manifest forbids `system.exec` and `network.listen`.
- The connector intentionally persists only polling cursor and lease state under `zone_dir`.
- The connector does not intentionally persist bot tokens, webhook secret tokens, provider payloads, message text, request counters, or event payloads outside process memory.
- Telegram payloads can contain user IDs, chat IDs, usernames, messages, captions, files, callback query data, channel posts, and topic IDs. Treat live output as work-zone or private-zone sensitive data unless the host supplies a stricter zone policy.

## Network And Runtime Invariants

- Default runtime base URL: `https://api.telegram.org`.
- Direct-token requests embed the bot token in Telegram Bot API paths.
- `credential_id` mode is accepted during configure but blocked before live Telegram calls in the current runtime.
- Runtime base URL policy accepts `https://api.telegram.org` and loopback hosts for tests.
- Runtime base URL policy rejects non-local `http` and unknown hosts.
- Runtime client timeout is 60 seconds.
- Runtime request-context timeout is 60 seconds.
- Long-poll requests set request timeout to `poll_timeout + 10` seconds.
- Manifest egress operations allow `api.telegram.org` on port `443`, require TLS/SNI, deny localhost, private ranges, tailnet ranges, and IP literals, cap redirects at zero, and cap response bytes at `10485760`.
- Manifest webhook-ingest operation declares no connector-owned egress with `host_allow = ["none.invalid"]`, `port_allow = [0]`, `dns_max_ips = 0`, and a `1048576` byte response cap.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120000 ms` wall-clock timeout, no exec, no ptrace, read-only `/usr` and `/lib`, and writable `$CONNECTOR_STATE`.
- The connector does not open inbound sockets.
- Provider 401/403 style failures map through Telegram-specific errors into FCP auth/capability failures.
- Provider 429 honors Telegram `retry_after` from either `Retry-After` or the Bot API `parameters.retry_after` body field when available.
- Server errors and timeout/connect errors are retryable in the generic request helper.

## Capability Families

| Capability | Purpose |
|------------|---------|
| `telegram.send` | Send text/media messages, answer callback queries, broadcast chat actions, and set message reactions. |
| `telegram.read` | Read Telegram file metadata and construct safe download URLs. |
| `telegram.webhook` | Manage Telegram webhook registration and accept host-forwarded Telegram webhook updates into the event stream. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `telegram.send_message` | `POST /sendMessage` | `telegram.send` | `Risky` | `Medium` | `None` | Sends user-visible chat content. |
| `telegram.send_media` | `POST /sendPhoto` etc. | `telegram.send` | `Risky` | `Medium` | `None` | Sends user-visible media content. |
| `telegram.get_file` | `GET /getFile` | `telegram.read` | `Safe` | `Low` | `Strict` | Reads metadata and a temporary file path for an existing Telegram file. |
| `telegram.answer_callback_query` | `POST /answerCallbackQuery` | `telegram.send` | `Safe` | `Low` | `None` | Acknowledges an already-received button press. |
| `telegram.send_chat_action` | `POST /sendChatAction` | `telegram.send` | `Safe` | `Low` | `None` | Broadcasts transient typing/upload state without creating durable chat content. |
| `telegram.set_message_reaction` | `POST /setMessageReaction` | `telegram.send` | `Safe` | `Low` | `BestEffort` | Sets or clears the bot's chosen non-paid reaction on an existing message. |
| `telegram.set_webhook` | `POST /setWebhook` | `telegram.webhook` | `Risky` | `Medium` | `BestEffort` | Changes Telegram's delivery endpoint for this bot. |
| `telegram.delete_webhook` | `POST /deleteWebhook` | `telegram.webhook` | `Risky` | `Medium` | `BestEffort` | Disables Telegram webhook delivery for this bot. |
| `telegram.get_webhook_info` | `GET /getWebhookInfo` | `telegram.webhook` | `Safe` | `Low` | `Strict` | Reads Telegram webhook status and delivery diagnostics. |
| `telegram.ingest_webhook_update` | host-forwarded local ingest | `telegram.webhook` | `Safe` | `Low` | `Strict` | Validates and converts a forwarded Telegram Update to an FCP event. |

## Resource URIs

Runtime capability verification binds these resource URI shapes:

| Operation family | Resource URI shape |
|------------------|--------------------|
| Chat send | `telegram:chat:{chat_id}` |
| Topic send | `telegram:chat:{chat_id}:topic:{message_thread_id}` |
| File lookup | `telegram:file:{file_id}` |
| Callback acknowledgement | `telegram:callback:{callback_query_id}` |
| Message reaction | `telegram:chat:{chat_id}:message:{message_id}` |
| Webhook management and ingest | `telegram:webhook` |

## Explicit Non-Goals

The current implementation does not include:

- MTProto user sessions
- Telegram login widgets
- Bot creation or BotFather automation
- Webhook custom-certificate management
- Payment, invoice, shipping, or checkout operations
- Chat administration, moderation, invite-link, forum-topic, or boost management operations
- Inline query answering
- Message edit/delete/pin operations
- Downloading file bytes
- Uploading local files by multipart form data
- Event replay or explicit event acknowledgement
- Local Bot API server production mode
- Approval-token enforcement for send operations

## Verification

The connector proof lane is tracked at `scripts/e2e/telegram_connector_verification.sh`.
It offloads Cargo work through fail-closed `fwc proof run` / `rch` evidence,
runs format, the no-live-credential loopback JSONL matrix, the connector-local
`local_non_mock` acceptance test, the Telegram conformance contract, optional
live-smoke structured skip handling, clippy, and a diff whitespace check on the
owned Telegram proof files.

```bash
bash scripts/e2e/telegram_connector_verification.sh
```

By default the script writes artifacts under `/tmp/fcp-telegram-e2e/<run-id>/`.
The primary evidence file is `evidence/loopback_matrix.jsonl`; the live lane
emits `evidence/live_optional_skip.jsonl` unless `TELEGRAM_BOT_TOKEN` and
`TELEGRAM_LIVE_WRITE_APPROVAL=yes` are both present. Cargo-backed steps also
write proof-governor artifacts under `${OUT_ROOT}/proof`.

Only `accepted_remote_proof` rows in `*.rch_remote_proof.jsonl` are green
closeout evidence for Cargo-backed steps. `refused_local_fallback`,
`infra_blocked`, `remote_command_failed`, `failed_closed`, `not_proof`, or a
missing proof row keep the verifier non-green. `format_check` is a source-state
check, not accepted remote Cargo proof. Set `PROOF_GOVERNOR=0` only for legacy
diagnostics; the default `PROOF_GOVERNOR=1` is the tracked proof lane.

The loopback evidence records are redaction-safe and include command line, git
revision, fixture ID, operation, update/chat/user hashes, sender-policy
decision, capability decision, retry/backoff outcome, HTTP status, FCP error
mapping, event topic, payload byte counts, artifact paths, cleanup state, and
skip reason.

## Operator Guidance

Rerun commands:

```bash
bash scripts/e2e/telegram_connector_verification.sh
PROOF_GOVERNOR=1 bash scripts/e2e/telegram_connector_verification.sh
FWC_BIN=/path/to/current/target/debug/fwc PROOF_GOVERNOR=1 bash scripts/e2e/telegram_connector_verification.sh
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-telegram-local-non-mock CARGO_INCREMENTAL=0 cargo test -p fcp-telegram --test local_non_mock -- --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-telegram-conformance CARGO_INCREMENTAL=0 cargo test -p fcp-telegram --test conformance_contract -- --nocapture
```

Treat live Telegram checks as opt-in only. Provide `TELEGRAM_BOT_TOKEN` and
`TELEGRAM_LIVE_WRITE_APPROVAL=yes` only in a controlled sandbox; the default
verification lane is the redaction-safe local loopback suite.
