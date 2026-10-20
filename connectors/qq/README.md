# QQ Connector V3 Contract

> **Status**: PROVEN (2026-10-20; 12/12 graduation gauntlet, verifier + unit/integration/local_non_mock suites verified)
> **Bead**: `flywheel_connectors-j05nu.1.14.1`
> **Verification script**: `scripts/e2e/qq_gateway_projection_verification.sh`
> **Unblocks**:
> - `flywheel_connectors-j05nu.1.14.2`
> - `flywheel_connectors-j05nu.1.14.6`
> **Follow-on beads**:
> - `flywheel_connectors-j05nu.1.14.3`
> - `flywheel_connectors-j05nu.1.14.4`
> - `flywheel_connectors-j05nu.1.14.5`
> - `flywheel_connectors-j05nu.1.14.7`
> - `flywheel_connectors-j05nu.1.14.8`
> **Primary upstreams**:
> - https://bot.q.qq.com/wiki/
> - https://bot.q.qq.com/wiki/develop/api-v2/
> - https://bot.q.qq.com/wiki/develop/api-v2/server-inter/message/send-receive/send.html
> - https://bot.q.qq.com/wiki/develop/api-v2/dev-prepare/error-trace/openapi.html

## Purpose

This document fixes the accepted first V3 slice for `fcp.qq` so the follow-on runtime work converges on the connector that actually exists today instead of a much broader idea of "QQ bot integration" that would mix outbound sends, websocket ingress, passive-reply policy, channel private messages, media flows, and platform administration into one undefined surface.

The current connector is a request-response QQ bot surface for plain-text outbound sends to channel, group, and C2C targets, plus gateway discovery, credential health verification, raw event normalization, and stateful gateway event projection for a host-owned WebSocket loop. It is not yet the component that opens and owns the WebSocket connection itself, nor is it a full passive-reply policy engine, channel-DM connector, media uploader, or general Tencent bot SDK.

## Current Runtime Snapshot

The current crate exposes these operations:

- `qq.messages.send_channel`
- `qq.messages.send_group`
- `qq.messages.send_c2c`
- `qq.gateway.get`
- `qq.health`
- `qq.events.normalize`
- `qq.gateway.project_event`
- `qq.gateway.drain_events`

Important implementation truths from `connector.rs`, `main.rs`, and `manifest.toml`:

- Configuration is `base_url`, `token_base_url`, `app_id`, `client_secret`, and bounded `request_timeout_ms`.
- One connector instance is bound to one QQ bot app identity through one `app_id` / `client_secret` pair.
- Access tokens are fetched with `POST /app/getAppAccessToken` against the token host and cached in memory only with a refresh safety margin; an API 401/403 clears the cache and refetches once before the request fails closed.
- Live REST calls use `Authorization: QQBot <token>` against the API host.
- Channel sends call `POST /channels/{channel_id}/messages`.
- Group sends call `POST /v2/groups/{group_openid}/messages`.
- C2C sends call `POST /v2/users/{openid}/messages`.
- Outbound channel, group, and C2C sends claim SDK chat ownership before the QQ HTTP call and append redacted `coordination` audit records on successful dispatch.
- The current send bodies only expose plain `content`; simulate and invoke reject unsupported passive-reply or rich-payload fields instead of silently dropping them, because the connector does not yet surface the broader QQ message-type matrix even though the upstream API supports markdown, ark, embed, keyboard, and media payloads.
- Direct and group sends currently hard-code `msg_type = 0` and `msg_seq = 1`, and only optionally thread through `msg_id`.
- `qq.gateway.get` is a plain `GET /gateway` discovery call. The connector does not actually open the websocket session yet.
- `qq.events.normalize` decodes a raw gateway message dispatch into channel/group/C2C routing, quote context, sender metadata, and attachment presence.
- `qq.gateway.project_event` is the stateful gateway-runtime core: it tracks restored session ID, READY/RESUMED dispatch session persistence, negotiated Hello heartbeat interval, sequence cursor, matched heartbeat acknowledgements, duplicate event IDs, bounded accepted-message reply references, global and per-peer queue bounds, group/C2C access policy, and group mention gating before returning `qq.message.authorized` or `qq.event.dropped` projection records. Each projection includes a lifecycle directive for the host-owned WebSocket worker (`drain_events`, `send_heartbeat`, `identify`, `resume`, `reconnect_identify`, `reconnect_resume`, `stop_reconnect`, or `none`). Accepted records are retained in a bounded in-memory queue until `qq.gateway.drain_events` dequeues them for host fan-out. This lets a host-supervised WebSocket worker keep the socket ownership while reusing connector-side security and redaction decisions.
- `qq.health` verifies both token issuance and gateway discovery; `self_check()` is narrower and only validates token issuance.
- `simulate()` validates configuration, handshake, capability, path, and event payload shape; `subscribe()` / `unsubscribe()` still return `StreamingNotSupported`.
- The current crate has inline unit tests for channel-send payload shape, gateway auth-header behavior, and gateway projection state, plus crate-local connector-suite and gateway-projection e2e tests.

## Accepted First Slice

The accepted first QQ slice is intentionally narrow:

- send one plain-text message to one known channel target
- send one plain-text message to one known group target
- send one plain-text message to one known C2C target
- discover the official QQ gateway websocket URL for a higher-level runtime
- expose a safe credential and reachability probe

This slice is intentionally closer to "outbound bot message dispatch plus connectivity primitives" than to "full QQ bot platform integration."

## Service Inventory

| Surface | Status in first slice | Notes |
|---------|-----------------------|-------|
| Channel, group, and C2C text sends | In scope | Implemented as plain-text request-response sends to known identifiers. |
| Gateway discovery | In scope | Implemented as `GET /gateway` so higher layers can later establish websocket ingress. |
| Credential and reachability probe | In scope | `qq.health` issues a token and checks gateway discovery. |
| Websocket connection ownership | Out of scope | No connect/identify/read loop is spawned by this connector slice yet. |
| Gateway event projection | In scope | `qq.gateway.project_event` tracks sequence, session, matched heartbeat ack, duplicate IDs, bounded global/per-peer queue state, access policy, group mention gating, and lifecycle directives for host-fed gateway frames. |
| Gateway event draining | In scope | `qq.gateway.drain_events` dequeues accepted projection records from the bounded queue so the host can fan out only authorized events and observe remaining backlog. |
| Passive reply policy and event-linked sends | Out of scope | The QQ docs distinguish active vs passive messaging, but the connector does not model `event_id`-driven semantics or policy enforcement. |
| Channel private messages | Out of scope | The upstream `POST /dms/{guild_id}/messages` surface is not implemented. |
| Rich payloads and media | Out of scope | No markdown, ark, embed, keyboard, media upload, voice, or file-send support is exposed in the first slice. |
| Guild, channel, user, or group management | Out of scope | The connector does not list channels, inspect guilds, manage groups, or read user profiles. |

## Auth And Scope Boundary

- One connector instance maps to one QQ bot app identity.
- Authentication is app-level `app_id` + `client_secret`, exchanged for an access token.
- The older QQ bot token model is deprecated in the official docs; the connector uses access-token issuance rather than the deprecated token path.
- Access tokens are cached in memory only, refreshed once after API unauthorized/forbidden responses, and are never persisted to disk by this connector.
- Stable first-slice target identifiers are:
  - `channel_id` for text subchannel sends
  - `group_openid` for group-chat sends
  - `openid` for C2C sends
  - optional `msg_id` values for reply-context linkage when the caller already has one
- The connector does not model user OAuth, delegated user tokens, cross-app brokering, or multi-tenant account switching.
- The connector does not acquire identifiers for the caller; upstream event flows or external provisioning must supply `channel_id`, `group_openid`, or `openid`.
- The connector does not currently encode the platform's active-message, passive-reply, recall, or wake-up policy into capability or input validation. That higher-level policy handling belongs in later beads.

## Gateway Projection Configuration

`gateway` is optional and defaults to disabled for compatibility with the first REST-only slice. When enabled, the connector can project host-fed QQ Bot gateway frames through FCP-owned state and policy:

```json
{
  "gateway": {
    "enabled": true,
    "restore_session_id": "previous-session-id",
    "restore_sequence": 42,
    "heartbeat_interval_ms": 45000,
    "reconnect_backoff_ms": 1000,
    "max_reconnect_backoff_ms": 30000,
    "max_reconnect_attempts": 5,
    "dedupe_window_size": 1024,
    "max_queue_depth": 128,
    "max_peer_queue_depth": 32,
    "policy": {
      "channel_policy": "open",
      "channel_allow_from": [],
      "dm_policy": "open",
      "dm_allow_from": [],
      "group_policy": "allowlist",
      "group_allow_from": ["GROUP_OPENID"],
      "group_require_mention": true,
      "bot_user_id": "BOT_OPENID",
      "max_attachment_bytes": 10485760,
      "allowed_attachment_content_types": ["image/png", "audio/amr"]
    }
  }
}
```

The projection operation does not log `client_secret`, access tokens, or raw transport credentials. It returns the normalized message payload already present in the incoming gateway frame, a policy decision, a runtime snapshot with counters and bounded state sizes, and a lifecycle directive that tells the host-owned socket loop which next action is expected without handing socket ownership to the connector. Accepted events are queued in memory until the host calls `qq.gateway.drain_events`; if the queue is already at `gateway.max_queue_depth`, the next otherwise-authorized dispatch is rejected with `queue_full` and no normalized payload or policy body is returned for fan-out. If the same authorized channel, group, or C2C peer already has `gateway.max_peer_queue_depth` queued records, the next otherwise-authorized dispatch for that peer is rejected with `peer_queue_full` so one target cannot consume the whole queue. Access-policy denials are evaluated before queue backpressure, so a full queue cannot hide sender, channel, group, mention, or attachment-policy failures. The drain response includes `drained_count`, `remaining_count`, queued authorized event records, and a fresh runtime snapshot. The snapshot exposes only aggregate peer-queue counts (`peer_queue_count`, `largest_peer_queue_depth`, and `max_peer_queue_depth`) rather than raw target identifiers, and it also exposes redaction-safe reply-reference counters (`reply_reference_count`, `max_reply_references`, `known_reply_references`, and `unknown_reply_references`) so host fan-out can prove whether accepted reply events targeted messages the gateway had already authorized without surfacing raw QQ message IDs. The optional drain `limit` is bounded to `1..=10000`; omitting it drains the available queue.
Channel gateway events apply `policy.channel_policy` before fan-out. `allowlist` may name a `channel_id`, `guild_id`, or sender id; `disabled` drops channel events with `channel_disabled`.
C2C gateway events apply `policy.dm_policy` before fan-out. `allowlist` names the sender openid and `disabled` drops C2C events with `c2c_disabled`.
When `policy.group_require_mention` is enabled, gateway projection treats `GROUP_AT_MESSAGE_CREATE` as an explicit bot mention and also recognizes the configured `bot_user_id` only as a standalone or `@`-prefixed text token, or as a structured raw mention in arrays such as `mentions`, `message`, `message_segments`, `segments`, and `content_segments`. Near-miss substrings inside another identifier do not satisfy the mention gate.
When `policy.max_attachment_bytes` is set, gateway projection denies message events whose declared attachment byte total exceeds the cap or whose attachment size metadata is missing. Present attachment URLs must be nonblank `http` or `https` URLs with a host and without embedded userinfo or fragments; unsafe or blank URL metadata fails closed before fan-out. When `policy.allowed_attachment_content_types` is non-empty, every attachment must carry a MIME content type whose canonical lower-case `type/subtype` token pair is in the allowlist; allowlist entries with parameters or invalid MIME token syntax are rejected at config load, inbound content-type parameters are ignored for matching, and missing, malformed, or disallowed values fail closed before fan-out.
For voice/media gateway messages whose `content` is blank, normalization uses the first non-empty attachment `asr_refer_text` transcript as the event text while evidence logs still emit only redacted text length/hash fields and attachment metadata summaries.
Gateway normalization also classifies command-like text for supervised routing: slash commands expose `interaction_kind`, a normalized `command_name`, and an `approval_action` for approval verbs such as `/approve`, `/reject`, and `/deny`. Evidence logs hash the command name and keep only the coarse action enum. This is routing metadata, not a moderation or admin-review workflow.
When `gateway.enabled` is false, `qq.gateway.project_event` fails closed with `gateway_disabled` and does not update session, sequence, heartbeat, policy, or queue state.
Gateway projection validates envelope bounds before any runtime state mutation, including control frames and payload-derived fallback event IDs. Oversized event IDs, invalid event-type labels, oversized hello `session_id` values, and malformed normalizable message payloads are rejected as malformed input rather than being stored as resume state, advanced sequence state, or emitted into evidence.
Gateway projection also fails closed before authorization when the normalized event is missing the route binding required for its QQ delivery mode: `channel_id` and sender for channel events, `group_openid` and sender for group events, and sender for C2C events.
Events without a stable QQ message id, or replies whose `message_reference` does not carry a usable target message id, are dropped before authorization so fan-out and reply tracking never rely on unbound message identity.
Gateway reconnect (`op=7`) and invalid-session (`op=9`) frames are projected as dropped control records with bounded reconnect attempt accounting and a lifecycle action of `reconnect_resume`, `reconnect_identify`, or `stop_reconnect`; `reconnect_after_ms` scales by reconnect attempt and is capped by `max_reconnect_backoff_ms`, and once `max_reconnect_attempts` is exceeded the reason becomes `reconnect_attempts_exhausted`. Non-resumable invalid-session frames emit `invalid_session_identify_required` with `reconnect_identify` even when a restore token exists, and the lifecycle directive omits `resume_session_id` so the host loop cannot accidentally resume a session QQ rejected. READY dispatches must carry a nonblank `session_id`; projection stores it as the bounded resume token, resets reconnect-attempt accounting, advances the sequence cursor, and returns a redaction-safe `gateway_ready` control record. RESUMED dispatches return `gateway_resumed`, preserve the current resume token unless QQ sends a replacement `session_id`, reset reconnect attempts, and advance the sequence cursor so replay completion is explicit without fan-out. The runtime snapshot increments `terminal_reconnect_failures` whenever it emits `stop_reconnect`, so host evidence can distinguish a terminal failure from an ordinary retry directive. A subsequent hello frame resets the attempt counter, adopts a positive provider `heartbeat_interval` up to five minutes for host timer scheduling when present, and returns `identify` or `resume` depending on whether a session token is available.
Heartbeat ACK (`op=11`) frames count as liveness evidence only after the runtime has emitted a `send_heartbeat` directive for an outstanding heartbeat. Unsolicited ACK frames fail closed as `heartbeat_ack_unmatched` and leave `heartbeat_ack_count` unchanged, so forged or replayed ACKs cannot inflate host liveness proof.
Connector shutdown drops the in-memory gateway runtime with the HTTP client, including any accepted events that were still queued for host fan-out; direct `QqClient` project/drain calls also fail closed after `QqClient::shutdown()` cancels its SDK runtime, so a host-owned worker cannot keep using a stale client handle for gateway fan-out.

## Chat Coordination Configuration

Outbound sends support the shared FCP chat thread-ownership guard through optional `chat_coordination` configuration:

```json
{
  "chat_coordination": {
    "enabled": true,
    "ttl_seconds": 900,
    "fail_open": true,
    "backend": "in_memory",
    "dm_mode": "treat_as_thread",
    "allowlist_channels": ["channel:CHANNEL_ID", "group:GROUP_OPENID", "c2c:OPENID"]
  }
}
```

The connector coordinates before network dispatch. Claim targets are namespaced as `channel:<channel_id>`, `group:<group_openid>`, and `c2c:<openid>`; optional `msg_id` values become native thread IDs. Successful outputs include only redacted audit hashes and claim outcomes, not QQ target identifiers, content, or raw agent instance IDs. A duplicate active claim is denied before the QQ token or message endpoint is called.

## Network And Runtime Invariants

- Production API host: `api.sgroup.qq.com`
- Production token host: `bots.qq.com`
- Port: `443`
- TLS + SNI required for live traffic
- Send, gateway-discovery, and health operations declare per-operation egress only to `api.sgroup.qq.com` and `bots.qq.com`
- Gateway event normalization and gateway event projection are connector-local and declare a no-egress sentinel
- `localhost` and `127.0.0.1` remain accepted only in connector configuration for deterministic tests or local harnesses, not in production manifest egress constraints
- The runtime remains request-response at the transport boundary
- No inbound listener, webhook server, websocket read loop, or durable connector-local state is part of this slice
- Gateway projection state is in-memory only and intentionally bounded by `gateway.dedupe_window_size`, `gateway.max_queue_depth`, and `gateway.max_peer_queue_depth`; the global queue-depth cap bounds the accepted-message reply-reference window
- The connector exposes gateway discovery without consuming the gateway itself; later websocket work must not be assumed already solved just because `qq.gateway.get` exists
- The official send docs explicitly distinguish active vs passive sends and per-scene frequency limits. The current connector does not yet enforce those provider policy rules locally.
- The official docs also note that channel sends require the bot to remain connected to the websocket gateway. The current connector does not manage that online-state requirement yet, so channel send success may depend on external runtime wiring added later.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `qq.messages.write` | Outbound plain-text channel, group, and C2C sends |
| `qq.gateway.read` | Gateway URL discovery for a higher-level ingress runtime |
| `qq.health.read` | Credential and reachability verification |

## Accepted Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Notes |
|-----------|----------------|------------|------------|-----------|-------------|-------|
| `qq.messages.send_channel` | `POST /channels/{channel_id}/messages` | `qq.messages.write` | `Risky` | `Medium` | `None` | Sends plain-text content to one text subchannel after a chat-coordination claim. The current connector does not expose richer QQ message types. |
| `qq.messages.send_group` | `POST /v2/groups/{group_openid}/messages` | `qq.messages.write` | `Risky` | `Medium` | `None` | Sends plain-text content to one QQ group target after a chat-coordination claim. `msg_id` may be supplied, but full passive-reply semantics are not modeled. |
| `qq.messages.send_c2c` | `POST /v2/users/{openid}/messages` | `qq.messages.write` | `Risky` | `Medium` | `None` | Sends plain-text content to one C2C target after a chat-coordination claim. The first slice does not expose wake-up or richer reply fields. |
| `qq.gateway.get` | `GET /gateway` | `qq.gateway.read` | `Safe` | `Low` | `Strict` | Returns the official gateway URL for later websocket ingestion work. |
| `qq.events.normalize` | local decode | `qq.events.read` | `Safe` | `Low` | `Strict` | Normalizes raw QQ Bot gateway message events without mutating runtime state. |
| `qq.gateway.project_event` | local projection | `qq.events.read` | `Safe` | `Low` | `Strict` | Stateful host-fed gateway projection with sequence/replay/policy decisions, lifecycle directives, and redaction-safe runtime snapshot. |
| `qq.gateway.drain_events` | local dequeue | `qq.events.read` | `Safe` | `Low` | `Strict` | Drains accepted gateway projections from the bounded queue after host-fed projection, preserving runtime backlog visibility. |
| `qq.health` | `POST /app/getAppAccessToken` then `GET /gateway` | `qq.health.read` | `Safe` | `Low` | `Strict` | Safe auth and reachability probe backed by access-token issuance and gateway discovery. |

## Explicit Non-Goals

The accepted first QQ slice does not include:

- websocket connect, identify, read-loop ownership, or automatic reconnect worker spawning
- channel private-message sends via `/dms/{guild_id}/messages`
- passive-reply policy orchestration using `event_id`, custom `msg_seq`, or reply-window enforcement
- markdown, ark, embed, keyboard, media, voice, or file payload support
- media upload and attachment download flows
- channel, guild, group, or user discovery and management APIs
- moderation, permission-application, or admin review workflows
- local enforcement of QQ per-scene send quotas or proactive-message policy
- multi-app brokering, delegated user auth, or cross-tenant routing

These are excluded on purpose:

- The current runtime is a small REST wrapper plus token bootstrap, not a full QQ bot session runtime.
- The official platform semantics for active vs passive messages and channel-online requirements are subtle enough that they should be introduced explicitly in later beads instead of being hidden inside the first contract.
- Gateway discovery is useful on its own, but websocket ingress, event normalization, and message-policy handling deserve their own beads and their own capability boundaries.

## Verification

- Gateway projection evidence: `RUN_ID=qq-gateway-projection-<id> RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=1 bash scripts/e2e/qq_gateway_projection_verification.sh`
- The verifier runs the connector-boundary `qq_gateway_projection_logs_policy_replay_and_shutdown` e2e lane through `rch`, requires an accepted `[RCH] remote` summary before treating Cargo output as proof, extracts `QQ_GATEWAY_PROJECTION_JSONL` records, checks the `log_start` metadata exposes only typed artifact-path and command-line fingerprints, checks disabled-gateway, route-binding, malformed-message no-sequence-mutation recovery, channel/group/C2C policy, policy-before-queue-full backpressure, per-peer queue isolation, reply, redaction-safe attachment filename/URL hashes, media byte/unknown-size/content-type/URL policy including malformed MIME syntax and credential-bearing or blank URL rejection, voice-ASR, slash/approval, duplicate and stale-sequence replay drops, Hello heartbeat interval negotiation, heartbeat, restored session/sequence reconnect resume, READY session persistence, RESUMED replay completion, non-resumable invalid-session reconnect identify, reconnect-backoff capping, reconnect-exhaustion/terminal failure, post-terminal hello reset with a resumed retry, drain, post-shutdown no-runtime/no-fan-out coverage, and pending-queue shutdown drop coverage, rejects raw local/private path and auth markers, and writes a replay bundle under `artifacts/e2e/qq-gateway-projection/<run-id>/`. Run IDs are limited to ASCII letters, digits, `.`, `_`, and `-`; JSON artifacts store path classes, full `sha256:<64 lowercase hex>` path and command-line fingerprints, bundle-relative artifact names, and the `RCH_BIN` basename/hash instead of raw checkout, target, log, artifact-root, or patched-binary paths.
- Token-refresh boundary evidence: `RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p fcp-qq --test local_non_mock local_non_mock_gateway_get_refreshes_expired_access_token_once -- --nocapture`, `RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p fcp-qq --test local_non_mock local_non_mock_health_refreshes_expired_access_token_once -- --nocapture`, `RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p fcp-qq --test local_non_mock local_non_mock_channel_send_refreshes_expired_access_token_once -- --nocapture`, `RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p fcp-qq --test local_non_mock local_non_mock_group_and_c2c_sends_refresh_expired_access_tokens_once -- --nocapture`, and `RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p fcp-qq --test local_non_mock local_non_mock_send_stops_after_one_unauthorized_refresh_retry -- --nocapture`. These loopback lanes drive `qq.gateway.get`, `qq.health`, `qq.messages.send_channel`, `qq.messages.send_group`, and `qq.messages.send_c2c` through the production connector, prove one 401/403-triggered token cache invalidation and refresh before the retried gateway discovery, health probe, or route-specific outbound send, and prove a second unauthorized send after refresh fails closed instead of starting another refresh loop. Final unauthorized errors preserve HTTP status while redacting provider bodies that contain token, secret, authorization, or access-material markers. The printed artifacts emit only structured booleans/counts.
- The summary includes `rch_remote_proof.worker_execution_class`, `rch_remote_proof.fallback_decision`, and `artifacts.rch_proof_json`; `worker_execution_class:"remote"` is the only green Cargo proof class. Local fallback, local fallback refusal, or a missing RCH summary is non-green.
- A structured `rch_remote_prerequisite_unavailable` skip means the remote Cargo proof lane did not run; it is not evidence that the full supervised WebSocket runtime is complete.

## Implementation Notes For `flywheel_connectors-j05nu.1.14.2`

- Preserve the one-app, one-bot boundary. Do not widen the connector into a multi-app router.
- Keep `base_url` and `token_base_url` explicit; token issuance and API dispatch are separate surfaces in the current runtime.
- Keep access-token caching in memory only, and make expiry / refresh behavior explicit in the typed client layer.
- Keep identifier families explicit: `channel_id`, `group_openid`, and `openid` are not interchangeable.
- Do not silently broaden the current send surface into markdown, media, or websocket-driven reply semantics as part of the client refactor.
- If channel sends require an active websocket session for trustworthy operation, surface that clearly in readiness and runtime guidance rather than leaving it as an undocumented upstream gotcha.
- Error mapping should preserve provider HTTP status and QQ business-code detail where available instead of collapsing everything into generic external failures.

## Source Notes

This contract is grounded in the current connector implementation and the official QQ bot documentation:

- `connectors/qq/src/connector.rs` defines the current operation inventory, input schema, access-token flow, and gateway / health behavior.
- `connectors/qq/src/main.rs` confirms the connector is currently a request-response JSON-RPC loop with no streaming implementation.
- `connectors/qq/manifest.toml` defines the current capability families, zone posture, and sandbox profile.
- QQ bot start guide and access-ticket docs describe the AppID / AppSecret model and the deprecation of the older token path.
- QQ's send-message docs define the C2C, group, channel, and channel-DM endpoint families plus the platform's active / passive send rules and rate-limit constraints.
- QQ's OpenAPI error docs describe the layered HTTP + business-code failure model that follow-on error mapping should preserve.

## Operation Inventory

See the operation table above (`qq.messages.send_channel`, `qq.messages.send_group`, `qq.messages.send_c2c`, `qq.gateway.get`, `qq.events.normalize`, `qq.gateway.project_event`, `qq.gateway.drain_events`, `qq.health`).

## Operator Guidance

Prerequisites:
- Use the deterministic loopback harness for local verification; never log raw QQ `app_secret`, access tokens, or unredacted user messages.

Rerun commands:
- `bash scripts/e2e/qq_gateway_projection_verification.sh`
- `rch exec -- cargo test -p fcp-qq --test local_non_mock -- --nocapture`
- `rch exec -- cargo test -p fcp-qq --test gateway_projection_e2e -- --nocapture`
- `rch exec -- cargo clippy -p fcp-qq --all-targets -- -D warnings`
