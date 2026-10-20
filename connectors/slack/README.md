# Slack Connector V3 Contract

> **Status**: PROVEN runtime contract documented; capability/approval drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/slack_connector_verification.sh`
> **Slack chat.postMessage**: https://docs.slack.dev/reference/methods/chat.postMessage
> **Slack Socket Mode**: https://docs.slack.dev/apis/events-api/using-socket-mode
> **Slack Events API**: https://docs.slack.dev/apis/events-api/

## Purpose

This document fixes the operator-facing contract for `fcp.slack`. The connector currently exposes a Slack Web API and Socket Mode surface implemented in this crate: channel messages, thread replies, progress drafts, channel history, message search, channel/user lookup, file upload/download metadata, reactions, channel topic updates, and policy-gated Socket Mode events.

The connector is intentionally a bounded Slack collaboration bridge. It is not a complete Slack SDK, admin API client, workflow builder, Enterprise Grid admin tool, SCIM client, OAuth app installer, durable event store, file-content vault, or general Slack API proxy.

## Current Runtime Snapshot

The current crate exposes these invoke operations:

- `slack.post_message`
- `slack.reply_thread`
- `slack.update_progress_draft`
- `slack.get_channel_history`
- `slack.search_messages`
- `slack.list_channels`
- `slack.get_user_info`
- `slack.upload_file`
- `slack.download_file`
- `slack.add_reaction`
- `slack.set_channel_topic`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-slack`.
- Runtime `BaseConnector` ID is `slack`.
- Manifest connector ID is `fcp.slack`.
- Manifest interface hash is `blake3-256:fcp.interface.v2:465bcd3768e237219ee05f9bfeb616589fd0ba695399a70fdb3c27f85de231ff`.
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`, not the manifest interface hash.
- Configuration requires a nonblank `token`.
- Optional `app_token` is used for Socket Mode when present.
- If `app_token` is omitted, Socket Mode uses the bot token as a fallback.
- Optional `base_url` must parse as `https://slack.com...` outside local test/debug builds.
- Local test/debug hosts `localhost`, `127.0.0.1`, and `::1` are allowed by base URL policy.
- Base URL policy rejects userinfo, query strings, fragments, non-HTTPS Slack URLs, and Slack-looking strings hidden in an evil host/path.
- Non-string `base_url` values are ignored and the default `https://slack.com/api` is used.
- Slack HTTP client timeout is 30 seconds.
- Slack HTTP retry config is `max_retries = 3`, initial delay `1000 ms`, max delay `60000 ms`.
- Runtime `invoke` uses `operation`, not `operation_id`.
- Runtime `invoke` requires a serialized `capability_token`.
- Runtime installs a `CapabilityVerifier` during handshake and verifies bound capability tokens for invoke and simulate.
- Runtime does not verify approval tokens for policy-approved manifest operations.
- `handle_configure()` stops any Socket Mode loop, resets subscribed topics, monitor policy, progress drafts, and chat coordination config, then sets configured.
- `handle_configure()` does not clear verifier, session ID, or base handshaken state.
- `handle_handshake()` accepts a valid handshake request and installs the verifier without checking that Slack has been configured.
- `handle_health()` reports `healthy` when a client is configured; it does not require handshake or `auth.test`.
- `handle_doctor()` and `handle_self_check()` call Slack `auth.test` and inspect `x-oauth-scopes`.
- `handle_shutdown()` stops Socket Mode, clears progress drafts, and shuts down the client runtime, but does not clear client, token, verifier, session ID, configured, or handshaken state.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Manifest and introspection describe capability IDs such as `slack.read`, `slack.write`, `slack.files.read`, and `slack.files.write`.
- Runtime bound-token verification instead requires the operation ID itself for most operations:
  - `slack.post_message`
  - `slack.reply_thread`
  - `slack.get_channel_history`
  - `slack.search_messages`
  - `slack.list_channels`
  - `slack.get_user_info`
  - `slack.add_reaction`
  - `slack.set_channel_topic`
- Runtime bound-token verification uses manifest-style capability IDs only for:
  - `slack.update_progress_draft` -> `slack.write`
  - `slack.upload_file` -> `slack.files.write`
  - `slack.download_file` -> `slack.files.read`
- Manifest marks `slack.post_message`, `slack.reply_thread`, `slack.update_progress_draft`, `slack.upload_file`, and `slack.set_channel_topic` as policy-approved operations. Runtime `OperationInfo` sets `requires_approval = None`, and invoke checks no approval token.
- Doctor/self-check required scopes are only `channels:read`, `channels:history`, `chat:write`, and `users:read`; they do not prove file upload/download, reactions, topic updates, search, or Socket Mode app-token readiness.
- Runtime `download_file` returns redacted Slack file metadata and a deterministic content object ID, but it does not download or persist file bytes.
- Runtime `upload_file` sends host-materialized `resolved_content` through legacy `files.upload` JSON handling and redacts returned file URLs.
- Runtime `handle_subscribe()` starts Socket Mode only after client and verifier exist, but subscribe itself does not verify a subscribe capability token.
- Manifest state model is singleton-writer. Runtime keeps token, Socket Mode state, progress drafts, monitor policy, subscriptions, and verifier/session state in process memory.
- Manifest rate-limit pools are documented intent; runtime relies on Slack 429 handling and the client retry loop, not connector-local pool enforcement.
- The dedicated tracked verification script is `scripts/e2e/slack_connector_verification.sh`, which writes loopback and live-smoke JSONL evidence under `/tmp/fcp-slack-e2e/<run-id>/` by default.

A follow-up parity bead should align runtime bound-token capability IDs with manifest capability IDs, add approval-token verification for policy-approved mutations, decide whether shutdown/reconfigure should clear verifier/session state, expand doctor/self-check scope readiness, and document or replace legacy `files.upload`.

## First-Slice Scope

The current Slack README slice documents the existing runtime surface:

- bot-token configuration plus optional app-token Socket Mode auth
- Slack Web API transport, timeout, retry, rate-limit, error, and scope-check behavior
- message, thread, progress draft, read, search, channel/user, file, reaction, and topic operations
- bound capability-token verification and current capability-ID drift
- Socket Mode event streaming with monitor-policy gating
- lifecycle, health, doctor, self-check, simulation, introspection, subscribe, and shutdown behavior
- deterministic connector tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanism: Slack bearer token, with optional app-level token for Socket Mode.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Runtime metadata capability surface:
  - `slack.read`
  - `slack.write`
  - `slack.files.read`
  - `slack.files.write`
- Runtime verification surface currently differs from metadata as described in Drift.
- Invoke rejects missing, malformed, unbound, wrong-operation, wrong-resource, or wrong-capability tokens.
- Invoke does not verify approval tokens.
- The connector does not persist tokens, Slack messages, file contents, file URLs, search results, channel/user data, Socket Mode events, progress drafts, request counters, or provider errors outside process memory.
- Slack content can contain private, work, credential, or regulated data. Treat live output according to the workspace and channel policy.

## Network And Runtime Invariants

- Default endpoint: `https://slack.com/api`.
- Slack API requests send `Authorization: Bearer {token}` and `Accept: application/json`.
- JSON write requests send `Content-Type: application/json`.
- Socket Mode URL acquisition calls `apps.connections.open`.
- Socket Mode events are received over a Slack-provided WebSocket URL and acknowledged by `envelope_id`.
- Socket Mode reconnect delay starts at `1000 ms` and caps at `30000 ms`.
- Socket event buffer capacity is `200`.
- Socket event replay is not supported.
- Default Socket Mode topics:
  - `slack.message.new`
  - `slack.message.edited`
  - `slack.message.deleted`
  - `slack.reaction.added`
  - `slack.reaction.removed`
- Custom subscription topic count is capped at `64`.
- Topic components are sanitized and unknown event types collapse to `unknown` when unsafe.
- Monitor policy defaults to requiring a bot mention for public message payloads.
- Direct messages bypass the mention requirement.
- Monitor policy can configure `require_mention`, `strict_mention`, `bot_user_id`, `allowed_channels`, `allowed_users`, and `free_response_channels`.
- Chat coordination defaults to in-memory coordination and can parse `agent_mail`, `mesh_gossip`, or `in_memory` backend configuration.
- Progress draft IDs are caller-owned and bound to a channel/thread after first use.
- Progress draft updates can be skipped as empty, duplicate, throttled, stopped, or sealed.
- The connector does not open inbound HTTP sockets, run a Slack app installer, or store durable event cursors. Slack Events API requests are verified by the host/fcp-webhook boundary and handed to `slack.handle_events_api` as verified payloads.

## Operation Inventory

| Operation | Runtime Slack method/path | Runtime verification capability | Metadata capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|---------------------------|---------------------------------|---------------------|------------|-----------|-------------|----------------|
| `slack.post_message` | `chat.postMessage` | `slack.post_message` | `slack.write` | `Risky` | `Medium` | `None` | `channel`, `text` |
| `slack.reply_thread` | `chat.postMessage` with `thread_ts` | `slack.reply_thread` | `slack.write` | `Risky` | `Medium` | `None` | `channel`, `text`, `thread_ts` |
| `slack.update_progress_draft` | `chat.postMessage`, `chat.update`, `chat.delete` | `slack.write` | `slack.write` | `Risky` | `Medium` | `BestEffort` | `draft_id`, `channel`; update requires `text` or `progress_lines` |
| `slack.get_channel_history` | `conversations.history` | `slack.get_channel_history` | `slack.read` | `Safe` | `Low` | `Strict` | `channel`; optional `limit` |
| `slack.search_messages` | `search.messages` | `slack.search_messages` | `slack.read` | `Safe` | `Low` | `Strict` | `query` |
| `slack.list_channels` | `conversations.list` | `slack.list_channels` | `slack.read` | `Safe` | `Low` | `Strict` | optional `types` |
| `slack.get_user_info` | `users.info` | `slack.get_user_info` | `slack.read` | `Safe` | `Low` | `Strict` | `user` |
| `slack.handle_events_api` | Host/fcp-webhook verified Events API payload | `slack.read` | `slack.read` | `Safe` | `Medium` | `BestEffort` | `payload`, `signature_result="verified"` |
| `slack.upload_file` | `files.upload` | `slack.files.write` | `slack.files.write` | `Risky` | `Medium` | `None` | `channels`, `content_object_id`, `resolved_content` |
| `slack.download_file` | `files.info` metadata | `slack.files.read` | `slack.files.read` | `Safe` | `Low` | `Strict` | `file_id` |
| `slack.add_reaction` | `reactions.add` | `slack.add_reaction` | `slack.write` | `Safe` | `Low` | `BestEffort` | `channel`, `timestamp`, `name` |
| `slack.set_channel_topic` | `conversations.setTopic` | `slack.set_channel_topic` | `slack.write` | `Risky` | `Medium` | `BestEffort` | `channel`, `topic` |

## Explicit Non-Goals

The current implementation does not include:

- Slack OAuth installation, token refresh, app manifest creation, or workspace provisioning
- Slack admin, audit logs, SCIM, user-group, Enterprise Grid, Workflow Builder, Canvas, Lists, or app-management APIs
- durable event replay, durable subscriptions, message cursors, queueing, dead-letter storage, or exactly-once Socket Mode processing
- connector-owned public HTTP Events API request verification or inbound HTTP request URL handling
- full file byte download, durable file storage, file upload streaming, multipart upload, or external object-store integration
- arbitrary Slack Web API proxying, granular per-channel policy storage, or rate-limit pool enforcement
- approval-token verification for message/file/topic mutations

These are excluded on purpose:

- Slack write operations can notify people, alter collaboration state, and leak private work data.
- Socket Mode event streams can carry sensitive messages and should remain policy-gated.
- A general Slack API proxy would bypass the connector's typed capability model.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, `handle_introspect()`, `handle_subscribe()`, and `handle_shutdown()` are part of the public closeout contract. They surface:

- local configured state, request/error/event metrics, Socket Mode running state, subscribed topics, and redacted monitor policy
- live token and Slack API readiness through `auth.test`
- missing required scope reporting for the limited scope set
- typed introspection with operations, schemas, capability metadata, risk levels, safety tiers, idempotency, default event topics, event caps, and redacted monitor policy
- simulation allow/deny with input validation, resource URI derivation, and bound capability-token verification
- provider/FCP error mapping for Slack API errors, 429 rate limits, retryable transport failures, malformed responses, missing input, and capability denial

The deterministic integration evidence is anchored on connector-local tests covering:

- local non-mock loopback acceptance for production `handle_invoke()` paths across `slack.post_message`, `slack.list_channels`, and `slack.set_channel_topic`
- configuration, base URL policy, handshake, capability verification, simulate, introspection, health, doctor, self-check, shutdown, and counters
- all eleven invoke operations and required-input validation
- operation metadata, safety tier, risk, idempotency, capability metadata, and manifest drift checks
- Socket Mode topic parsing, topic filtering, reconnect/start gating, event topic derivation, monitor-policy gating, and event envelope construction
- progress draft rendering, duplicate/throttle/clear/seal behavior, block limits, and text compaction
- file URL redaction, object ID derivation, provider error classes, scope extraction, and rate-limit handling

## Source Notes

- `connectors/slack/src/connector.rs` defines configuration parsing, lifecycle handlers, operation catalog, capability verification, chat coordination, progress drafts, Socket Mode, monitor policy, simulation, introspection, and invoke dispatch.
- `connectors/slack/src/client.rs` defines Slack Web API transport, auth headers, base URL, retry behavior, rate-limit handling, method paths, scope extraction, and provider error mapping.
- `connectors/slack/src/types.rs` defines Slack API envelopes, messages, channels, users, files, Socket Mode frames, progress lines, and doctor report shapes.
- `connectors/slack/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/slack/manifest.toml` defines the manifest operation catalog, event topics, network constraints, sandbox boundary, zone policy, approval intent, and rate-limit intent.
- `connectors/slack/tests/` contains connector integration coverage in addition to inline tests.

## Verification Bundle

Run these after changing this connector contract:

```bash
scripts/e2e/slack_connector_verification.sh
git diff --check -- connectors/slack/README.md
ubs connectors/slack/README.md
LC_ALL=C rg -n '[^ -~]' connectors/slack/README.md
rg -n '\bmaster\b' connectors/slack/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-slack
rch exec -- cargo test -p fcp-slack --test local_non_mock -- --nocapture
rch exec -- cargo check -p fcp-slack --all-targets
rch exec -- cargo clippy -p fcp-slack --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Use a bot token with only the Slack scopes required by the operations you plan to invoke.
- Use a real app-level `xapp` token for Socket Mode; bot-token fallback is only a runtime fallback, not proof that Socket Mode will work.
- `scripts/e2e/slack_connector_verification.sh` is the redaction-safe replay bundle for no-live-credential loopback evidence. It runs Cargo proof through `rch`, captures `SLACK_LOOPBACK_E2E_JSONL` and `SLACK_LIVE_E2E_JSONL` rows, covers Slack Events API URL verification through a host-verified connector payload, and records structured skip rows only for live Slack credential surfaces.
- Rerun commands: `scripts/e2e/slack_connector_verification.sh`, `rch exec -- cargo test -p fcp-slack --test local_non_mock -- --nocapture`, and `scripts/graduation/run_gauntlet.sh connectors/slack`.
- The optional live-smoke evidence lane for canary reply and mention-gating is intentionally side-effect gated. Without an operator credential lease and explicit write approval, `cargo test -p fcp-slack --test live_verification slack_live_smoke_structured_skip_jsonl -- --nocapture` emits redaction-safe `SLACK_LIVE_E2E_JSONL` skip rows and writes `target/fcp-slack/live-smoke-evidence.jsonl` unless `SLACK_LIVE_E2E_ARTIFACT` is set.
- Treat message, file, and topic operations as high-review until approval verification is implemented.
- Keep `monitor_policy.require_mention` enabled for public channels unless the channel is explicitly allowed for free response.
- Do not rely on shutdown to erase token or verifier state; it only stops active runtime work.
- Do not rely on doctor/self-check as proof for file, reaction, topic, search, or Socket Mode app-token scopes.
