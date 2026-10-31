# Discord Connector V3 Contract

> **Status**: native acknowledged Gateway delivery with durable consumed checkpoints and aligned REST operation authorities
> **Bead**: `flywheel_connectors-6n7.19`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **REST upstream**: https://discord.com/developers/docs/reference
> **Gateway upstream**: https://discord.com/developers/docs/events/gateway
> **Message upstream**: https://discord.com/developers/docs/resources/message

## Purpose

This document fixes the operator-facing contract for `fcp.discord`. The connector exposes the Discord surface implemented in this crate: bot-token REST operations for messages, channels, guilds, reactions, and threads, plus Gateway-backed inbound event streaming with local resume state and gateway lease fencing.

The connector is intentionally a bounded Discord bot bridge. It is not a full Discord SDK, OAuth user-auth workflow, slash-command management surface, webhook receiver, voice client, moderation/admin tool, attachment upload/download client, guild provisioning tool, or interaction-response framework.

## Current Runtime Snapshot

The current runtime exposes these operations:

- `discord.send_message`
- `discord.edit_message`
- `discord.delete_message`
- `discord.get_channel`
- `discord.get_guild`
- `discord.trigger_typing`
- `discord.add_reaction`
- `discord.list_channels`
- `discord.create_thread`

Important runtime truths the contract preserves:

- Configuration requires `bot_credential`.
- `bot_credential` may be supplied with or without the leading `Bot ` prefix; the client stores the token without that prefix and sends `Authorization: Bot <token>`.
- Optional configuration includes `application_id`, `api_url`, `gateway_url`, `timeout`, `retry`, `intents`, `shard`, `gateway_identify_max_concurrency`, `inbound_policy`, and `chat_coordination`.
- Default REST base URL is `https://discord.com/api/v10`.
- Gateway URL is auto-discovered with `GET /gateway/bot` unless `gateway_url` is supplied.
- Default timeout is `30 seconds`.
- Default retry policy is `max_attempts = 3`, initial delay `500 ms`, maximum delay `30_000 ms`, and jitter `0.1`.
- The connector requires the Gateway intent bits for `GUILDS`, `GUILD_MESSAGES`, `DIRECT_MESSAGES`, and `MESSAGE_CONTENT`.
- Configure validates the REST and Gateway endpoint hosts before request construction.
- Configure makes a live `GET /users/@me` probe and requires the credential to authenticate as a bot user.
- Handshake requires `zone_dir`; the connector stores Gateway resume state in `discord_gateway_state.json` and a singleton-writer lease in `discord_gateway_lease.json`. Handshake establishes authority but does not open the Gateway.
- Gateway lease TTL is `120 seconds`; the connector renews it every `30 seconds`.
- Handshake installs a bound `CapabilityVerifier`.
- `invoke` verifies bound capability tokens against the requested operation and resource URIs such as `discord:channel:<id>` and `discord:guild:<id>`.
- `simulate` is stricter than legacy connectors: it checks readiness, operation support, input validation, and bound capability verification.
- Native `health` reports local readiness, instance/zone identity, and terminal Gateway failures. `doctor`, `self_check`, and the provider health helper probe Discord when configured, so invalid or revoked bot credentials surface through diagnostics.
- `subscribe` starts the Gateway only after validating a signed, instance-bound token for `discord.read`, operation `discord.subscribe`, and resource `discord:events:<topic>`. One exact declared topic is selected per native stream.
- The production JSONL loop writes native events and processes consumer acknowledgements concurrently with RPC responses. A local diagnostic listener cannot advance the Gateway checkpoint.
- Heartbeats report the last received provider sequence. The durable resume checkpoint advances only after ordered consumption, including explicit inbound-policy filtering; receiving or printing an event does not count as consuming it.

## Runtime And Manifest Contract

The manifest and runtime use the same nine fully qualified REST operation IDs. The host can select each operation's network policy, capability, approval mode, and quota using the same ID that the connector accepts. Runtime introspection matches the manifest's capability, risk, safety, idempotency, approval, and per-operation rate-limit metadata.

`discord.send_message`, `discord.edit_message`, and `discord.create_thread` declare policy approval; `discord.delete_message` declares interactive approval. Read, typing, and reaction operations declare no approval requirement. Host policy enforces these declarations before issuing an invocation grant.

Each operation is also mapped to its declared shared rate-limit pool. Channel and guild reads share `discord.read`; message sending and typing share `discord.send`. The manifest supplies both the per-operation ceilings and the shared allowances to host rate-limit policy.

The native event catalog and subscription authorities are declared in the manifest and runtime. Runtime allows loopback endpoints for deterministic tests in debug/test builds, while the manifest network constraints remain production-strict.

## Native Gateway Delivery

The host must attach a native event transport and complete configure and handshake before subscribing. A subscription must carry a valid capability token bound to the connector's actual instance and negotiated zone. Tokens must grant `discord.read`, operation `discord.subscribe`, and the exact event resource, such as `discord:events:discord.events`. Missing tokens, undeclared topics, multi-topic requests, unsupported replay seeks, and unavailable native transports fail closed.

The supported topics are:

| Topic | Payload |
|---|---|
| `discord.events` | Aggregate `{ "source_topic": "discord.message", "event": { ... } }` feed of the declared topics below |
| `discord.message` | Created message, after inbound-policy authorization, with stable `fcp_delivery` correlation |
| `discord.message_update` | Edited message |
| `discord.message_delete` | Deleted message |
| `discord.typing` | Typing notification |
| `discord.guild_create` | Available or newly joined guild |
| `discord.guild_update` | Updated guild |
| `discord.channel_create` | Available or newly created channel |
| `discord.channel_update` | Updated channel |
| `discord.ready` | Initial session readiness, without the provider session ID or resume URL |
| `discord.resumed` | Confirmation of a resumed provider session |
| `discord.interaction_create` | Inbound interaction, without its provider response token |

Every native event requires acknowledgement. Its cursor combines an opaque digest of the provider session ID with the provider sequence, so replay within a resumed session has the same cursor while a new session cannot collide with an old one. Envelopes identify `fcp.discord`, the actual connector instance, and the negotiated zone. Unknown provider dispatch kinds are intentionally filtered instead of creating undeclared topics.

The Gateway reader continues processing heartbeats while downstream consumption is pending. Its dispatch queue is bounded by both event count and bytes; overflow or a disconnected consumer cannot move the durable checkpoint beyond unconsumed work. A checkpoint is written only after the exact native acknowledgement. Deliberately filtered events can advance the checkpoint only in order under the active subscription authority. Authority expiry, stream closure, reconfiguration, failed handshake, and shutdown stop delivery without acknowledging pending events.

`replay = false` means the subscription does not implement arbitrary history seeks. Discord may replay buffered dispatches when the connector resumes the same provider session. That provider buffer is finite; durable local checkpoints do not create an independent archive of Discord events.

## Checkpoint State And Recovery

State schema version 2 binds the consumed checkpoint to its credential/configuration, Gateway intents and shard, inbound policy, subscribed topic, and zone. A stable OS sidecar lock serializes checkpoint writes with lease acquisition, renewal, and release. Each write revalidates the lease holder and fencing generation; stale connections and previous lease holders cannot commit. Writes use private temporary files, file synchronization, atomic replacement, and parent-directory synchronization. Releasing a lease preserves its fencing generation rather than removing the lease history.

The initial READY records a provisional session identity without a consumed sequence. If the connector stops before that first event is acknowledged, restart reports recovery required instead of silently starting a different session. Provider invalidation of an existing resume session also records a recovery marker and stops automatic reconnects.

The earlier checkpoint format recorded receipt rather than consumption. A populated legacy checkpoint is therefore rejected with an explicit migration error; it is never silently upgraded into evidence that its events were consumed. A checkpoint for a different subscription scope is rejected for the same reason.

For migration or a deliberate scope change, stop the old connector, retain its state directory for investigation and any application-level recovery, and use a fresh host-assigned `zone_dir` when intentionally beginning a new Gateway session. Starting a new session does not recover historical events. Reuse a version 2 directory only with the same subscription scope when resuming its consumed checkpoint.

## First-Slice Scope

The current Discord README slice documents the existing runtime surface:

- bot-token configuration and live token probe
- REST API v10 endpoint policy
- Gateway discovery, resume-state persistence, and singleton-writer lease fencing
- required Gateway intents
- inbound policy and outbound chat-coordination controls
- message send/edit/delete
- channel and guild reads
- typing indicators
- reactions
- guild channel listing
- thread creation from an existing message
- lifecycle, doctor, health, self-check, introspection, simulation, subscription, and shutdown surfaces
- deterministic WireMock and loopback Gateway tests

## Auth And Scope Boundary

- Authentication mechanism: Discord bot token from the Discord Developer Portal.
- OAuth authorization-code, user token, refresh token, and application-command installation flows are not implemented.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Capability surface:
  - `discord.send` gates message send and typing indicator operations.
  - `discord.edit` gates message edits.
  - `discord.delete` gates message deletion.
  - `discord.read` gates channel, guild, and guild-channel reads, plus signed native Gateway subscriptions.
  - `discord.react` gates adding reactions.
  - `discord.threads` gates thread creation.
- The connector persists Gateway resume and lease state under the handshake `zone_dir`.
- The connector does not persist Discord message bodies, channel names, guild names, user names, bot credentials, provider payloads, or provider error bodies beyond in-memory request handling and normal host-managed logs.

## Network And Runtime Invariants

- Production REST host: `discord.com`.
- Production REST API prefix: `/api/v10`.
- Production Gateway host: `gateway.discord.gg`, or a Discord-provided resume Gateway URL.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Runtime endpoint validation rejects empty URLs, bad schemes, public `http` or `ws`, userinfo, query strings, and fragments.
- Runtime host policy allows `discord.com`, subdomains of `discord.com`, `discord.gg`, and subdomains of `discord.gg`.
- Runtime loopback overrides are test/debug only.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime request timeout defaults to `30 seconds`.
- Manifest network constraints set `10_000 ms` connect timeout and `30_000 ms` total timeout.
- Manifest REST response limits are `1_048_576` bytes. Gateway frame and queue bounds are enforced by the Gateway reader; the native JSONL transport separately caps each event envelope at `262_144` bytes.
- Gateway endpoints are validated by the connector's WebSocket policy. The manifest uses the supported event authority declarations; it contains no unsupported `provides.streaming` table that would prevent host loading.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open network listeners.

## Inbound Policy

`inbound_policy` is optional. The default policy:

- requires a bot mention for guild messages
- allows DMs
- does not restrict guild IDs, channel IDs, or user IDs

Configurable fields:

- `require_mention_in_guilds`
- `require_mention` as an alias for `require_mention_in_guilds`
- `allow_dms`
- `allowed_guilds`
- `allowed_channels`
- `allowed_users`

The policy parser accepts stable Discord snowflake IDs, selected `discord:*` prefixes, and Discord mention forms for users and channels. It rejects non-stable IDs.

## Outbound Coordination

`chat_coordination` is optional and defaults to the in-memory backend. The parser supports:

- `enabled`
- `ttl_seconds`
- `fail_open`
- `allowlist_channels`
- `backend` values `in_memory`, `agent_mail`, and `mesh_gossip`
- `dm_mode`

`discord.send_message` calls the coordination layer before visible/final sends and includes coordination audit records in the response. Hidden non-final progress/tool delivery can be suppressed before a Discord REST send and returns a delivery receipt instead.

## Inbound Delivery Correlation

`discord.message` events include an `fcp_delivery` object that lets an agent tie an inbound Gateway event to a later outbound reply. The object contains:

- `session_key`: opaque correlation key for `discord.send_message`
- `event_kind`: `room_event` for guild messages or `direct_message` for DMs
- `channel_id`
- `guild_id` when the source event came from a guild
- `message_id`: source Discord message ID
- `retention`: `pending_until_outbound_delivery`

`discord.send_message` accepts `delivery.inbound_event.session_key`. Hidden non-final progress/tool sends with that key are suppressed before REST and return `delivery.inbound_event.status = pending`, so the inbound event remains pending. Visible sends to the wrong channel return `target_mismatch` and retain the pending event. Visible Discord REST failures also retain the pending event. A matching visible REST success returns `marked_delivered`, records the source and delivered Discord message IDs, and clears the pending record; a later send with the same session key returns `not_found`. Each connector instance authenticates one bot user, so the account side of the match is the configured bot account and the explicit retained target is the normalized Discord channel ID inside that instance.

Delivery accounting logs are structured and redaction-safe: they include delivery state, visibility, kind, counts, and Discord message IDs, but not bot tokens or message bodies.

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `discord.send_message` | `POST /channels/{channel_id}/messages` | `discord.send` | `Risky` | `Medium` | `None` | Creates provider-visible message state and may notify users. |
| `discord.edit_message` | `PATCH /channels/{channel_id}/messages/{message_id}` | `discord.edit` | `Risky` | `Medium` | `Strict` | Edits bot-owned provider-visible message state. |
| `discord.delete_message` | `DELETE /channels/{channel_id}/messages/{message_id}` | `discord.delete` | `Dangerous` | `High` | `Strict` | Deletes Discord message state. |
| `discord.get_channel` | `GET /channels/{channel_id}` | `discord.read` | `Safe` | `Low` | `Strict` | Reads metadata for one channel visible to the bot. |
| `discord.get_guild` | `GET /guilds/{guild_id}` | `discord.read` | `Safe` | `Low` | `Strict` | Reads metadata for one guild visible to the bot. |
| `discord.trigger_typing` | `POST /channels/{channel_id}/typing` | `discord.send` | `Safe` | `Low` | `None` | Shows a short-lived typing indicator. |
| `discord.add_reaction` | `PUT /channels/{channel_id}/messages/{message_id}/reactions/{emoji}/@me` | `discord.react` | `Safe` | `Low` | `Strict` | Adds the bot's reaction to an existing message. |
| `discord.list_channels` | `GET /guilds/{guild_id}/channels` | `discord.read` | `Safe` | `Low` | `Strict` | Lists channels in one guild visible to the bot. |
| `discord.create_thread` | `POST /channels/{channel_id}/messages/{message_id}/threads` | `discord.threads` | `Risky` | `Medium` | `None` | Creates provider-visible thread state from an existing message. |

## Explicit Non-Goals

The current implementation does not include:

- OAuth user authorization, token refresh, application install automation, or application-command registration
- slash-command response orchestration beyond inbound Gateway event mapping
- message attachments, file upload, file download, media proxying, or CDN access
- bulk delete, pin/unpin, crosspost, webhooks, polls, scheduled events, invites, roles, members, bans, moderation, or guild administration
- voice, presence management, rich presence, activities, or stage channels
- direct REST APIs for channel creation/update/delete, guild creation/update/delete, or thread listing
- arbitrary historical event seeks or an independent provider-event archive
- provider-local credential vaulting

These are excluded on purpose:

- Runtime invocation is capability-token bound and should expose only narrow bot actions.
- Message deletion and thread creation affect shared chat state and must remain explicit operations.
- Broader Discord coverage needs separate operation contracts, permission modeling, event schemas, and provider fixtures.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, `handle_introspect()`, `handle_subscribe()`, and `handle_shutdown()` are part of the public closeout contract. They surface:

- configuration, handshake, Gateway connection, request, and error state
- token presence and live token validity through `/users/@me`
- bot-account validation
- required Gateway intent validation
- REST and Gateway endpoint readiness
- redacted inbound policy status
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- bound capability-token simulation results
- signed native streaming with consumer acknowledgements and arbitrary replay seeks disabled
- bounded Gateway shutdown that releases the lease while preserving the consumed resume checkpoint

The deterministic integration evidence is anchored on connector-local tests covering:

- configure, handshake, health, doctor, self-check, introspection, simulation, subscribe, and shutdown behavior
- REST auth header propagation and token redaction in logs
- message send/edit/delete, channel reads, guild reads, typing, reactions, guild channel listing, and thread creation
- bound capability-token verification and denial cases
- input validation for snowflake IDs, message length, embed count, embed character totals, delivery controls, and thread-name bounds
- endpoint URL policy rejection for userinfo, query strings, fragments, bad schemes, public plaintext, and non-Discord hosts
- Gateway consumed checkpoints, lease fencing, inbound-policy filtering, native event mapping, heartbeat progress during pending consumption, replay across connector restarts, and inbound delivery retention through hidden progress, target mismatch, visible 5xx, final success, and shutdown

## Source Notes

- `connectors/discord/src/connector.rs` defines configuration lifecycle, inbound policy, outbound coordination, capability-token verification, lifecycle handlers, diagnostics, simulation, introspection metadata, subscription handling, Gateway task management, and invoke dispatch.
- `connectors/discord/src/api.rs` defines Discord REST request construction, auth headers, REST endpoint paths, timeout/retry dispatch, rate-limit parsing, and provider error parsing.
- `connectors/discord/src/gateway.rs` defines Gateway connect/resume behavior, heartbeat handling, Gateway event decoding, and `discord_gateway_state.json`.
- `connectors/discord/src/config.rs` defines bot credential, endpoint, timeout, retry, intent, shard, and identify-concurrency configuration.
- `connectors/discord/src/limits.rs` defines Discord payload limits used before REST dispatch.
- `connectors/discord/src/types.rs` defines REST and Gateway payload models.
- `connectors/discord/manifest.toml` defines the operation catalog, event catalog, network constraints, streaming constraints, sandbox boundary, zone policy, rate limits, and AI hints.
- `connectors/discord/tests/integration.rs` covers deterministic HTTP behavior, capability enforcement, Gateway loopback behavior, and handler lifecycle behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/discord_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation contract tests
- deterministic WireMock coverage for REST operations
- Gateway loopback and inbound-policy tests
- auth, endpoint policy, input validation, provider error, lifecycle, introspection, simulation, subscription, and shutdown tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a dedicated Discord application and bot token for verification.
- Enable the required Gateway intents for the bot before running Gateway tests.
- Install the bot only into disposable test guilds for live verification.
- Prefer WireMock and loopback Gateway fixtures for routine proof.

**Dedicated environment**:

- Keep live message sends confined to disposable channels.
- Never run delete-message checks against production Discord history.
- Use synthetic channel IDs, guild IDs, message IDs, thread names, and message content in logs and transcripts.

**Redaction rules**:

- Redact bot tokens, session IDs, Gateway resume URLs when sensitive, guild IDs, channel IDs, user IDs, message IDs, message bodies, provider payloads, provider error bodies, and local paths.
- Verification output should use operation IDs, endpoint shapes, host classes, status/error classes, retry decisions, and synthetic Discord resource identifiers.

**Common remediation**:

- If configuration fails, provide a non-empty bot token and confirm `/users/@me` succeeds for that bot.
- If configuration reports missing intents, enable `GUILDS`, `GUILD_MESSAGES`, `DIRECT_MESSAGES`, and `MESSAGE_CONTENT` or supply the correct bitmask.
- If endpoint policy fails, use `https://discord.com/api/v10` for REST and let the connector discover the Gateway URL.
- If handshake fails, provide `zone_dir` so Gateway resume state and the singleton lease can be persisted.
- If invocation fails with capability errors, mint a bound token for the exact operation ID and resource URI.
- If guild events do not arrive, check the inbound policy before assuming Gateway delivery failed.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-discord-readme cargo check -p fcp-discord --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-discord-readme cargo test -p fcp-discord --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-discord-readme cargo clippy -p fcp-discord --all-targets --no-deps -- -D warnings`
- `ubs connectors/discord/README.md`
