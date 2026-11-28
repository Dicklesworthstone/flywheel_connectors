# Signal Connector V3 Contract

> **Status**: native acknowledged SSE delivery implemented; simulation and daemon-policy drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **signal-cli REST upstream**: https://github.com/bbernhard/signal-cli-rest-api
> **signal-cli REST API reference**: https://bbernhard.github.io/signal-cli-rest-api/

## Purpose

This document fixes the operator-facing contract for `fcp.signal`. The connector exposes the Signal surface implemented in this crate through a local `signal-cli-rest-api` daemon: sending messages, polling pending messages, inspecting groups and identities, trusting identities, and streaming inbound daemon events through the FCP event interface.

The connector is intentionally a local Signal bridge. It is not a Signal server, phone-number registrar, QR-code linker, daemon supervisor, attachment downloader, contact manager, profile manager, group administration client, generic websocket gateway, or durable message store.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `signal.send_message`
- `signal.receive_messages`
- `signal.list_groups`
- `signal.get_group`
- `signal.get_identity`
- `signal.trust_identity`

The current crate also exposes these event topics:

- `signal.message.received`
- `signal.reaction.received`
- `signal.receipt.read`
- `signal.typing.received`
- `signal.policy.denied`
- `signal.events` (all normalized event types on one native stream)

Important runtime truths the contract preserves:

- Configuration requires a `phone_number` in E.164 format.
- `daemon_url` defaults to `http://localhost:8080`.
- Runtime `daemon_url` validation accepts `http` or `https`, rejects query strings and fragments, and trims trailing slashes.
- Runtime `daemon_url` validation does not enforce loopback-only hosting, even though the manifest network constraints are loopback-only.
- `request_timeout_ms` defaults to `30_000` and must be greater than zero.
- `receive_timeout_ms` defaults to `10_000` and is rounded up to whole seconds for `receive_messages`.
- `poll_interval_ms`, `max_reconnect_delay_ms`, `health_check_interval_ms`, and `max_attachment_bytes` must be greater than zero.
- `send_message` posts to `/v2/send` with `number`, `recipients`, `message`, `base64_attachments`, and optional `quote_timestamp`.
- `send_message` claims chat-thread ownership before any daemon health check or `/v2/send` call, using a hashed Signal conversation key plus `quote_timestamp` thread key when present.
- Successful `send_message` responses include `coordination` audit records (`claim_attempt`, `claim_outcome`, and `send_executed`) that do not contain raw recipients or message bodies.
- `receive_messages` polls `GET /v1/receive/{number}` with a `timeout` query parameter and advances an in-memory receive cursor from observed message timestamps.
- `list_groups` and `get_group` use `GET /v1/groups/{number}`.
- `get_identity` uses `GET /v1/identities/{number}/{target}`.
- `trust_identity` uses `PUT /v1/identities/{number}/trust/{target}` with either `verified_safety_number` or `trust_all_known_keys`.
- Handshake installs a `CapabilityVerifier` and returns a real manifest hash.
- `invoke` verifies a bound capability token for the requested operation before calling the daemon.
- Native `subscribe` requires negotiated read authority and a bound `signal.read` token for the dedicated `signal.subscribe` control operation over `signal:events:<topic>`. That grant does not authorize the separate queue-reading `signal.receive_messages` invocation. Subscription starts a supervised SSE reader for `/api/v1/events?account=...` and emits acknowledged JSONL notifications through the host transport.
- The native executable uses one persistent runtime, a bounded request reader, and a serialized stdout writer. ACK controls can arrive while ordinary RPC handlers are running; shutdown exits without waiting for stdin EOF.
- `self_check` performs a live daemon health probe against `/v1/about`.
- `health` is primarily local state plus bridge diagnostics; configured state can report ready before `self_check` proves daemon reachability.
- `simulate` currently returns allowed for any request and does not validate configuration, input, capability token, daemon reachability, or operation-specific policy.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest network constraints allow only loopback daemon hosts on port `8080`, but runtime configuration accepts any `http` or `https` daemon host.
- Manifest forbids `network.listen`, `system.exec`, and `system.privileged`; the current connector talks to an already-running daemon and does not spawn or supervise it.
- Handshake grants only the connector's declared read, send, and admin capabilities, honors the host-requested instance ID, and requires reconfiguration before replacing an existing session.
- `simulate` is permissive and not policy-aware.
- `health` can report ready based on configuration even when the daemon has not been probed yet.
- `shutdown` fences streaming, closes pending delivery, clears configuration, client, verifier, and lifecycle flags, and resets bridge progress. Reconfiguration also revokes the preceding session.
- `trust_identity` requires interactive approval in the operation metadata, but connector-local invoke only enforces the bound `signal.admin` capability token.
- Runtime URL validation reports whether the daemon host is loopback in doctor output but does not fail non-loopback daemon URLs.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should enforce loopback or explicit host policy at runtime, make simulation capability-aware, and decide whether connector-local approval enforcement belongs in this runtime path.

## First-Slice Scope

The current Signal README slice documents the implemented runtime surface:

- local `signal-cli-rest-api` daemon configuration
- message send, receive polling, group list/detail, identity lookup, and identity trust operations
- bound capability-token verification in invoke and subscribe
- SSE event subscription, topic filtering, acknowledged native transport, in-memory cursors, and no-replay event caps
- inbound direct-message and group authorization policy
- bridge health checks, reconnect backoff, group cache, receive cursor, and attachment-size validation
- provider error mapping for 401, 404, 429, retryable 5xx, daemon unreachability, timeout, JSON, and attachment errors
- deterministic WireMock and local SSE integration evidence

## Auth And Scope Boundary

- Authentication mechanism: local `signal-cli-rest-api` daemon state for the configured Signal account.
- Home zone: `z:private`.
- Allowed source zones: `z:owner` and `z:private`.
- Allowed target zone: `z:private`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability surface:
  - `signal.send` gates `signal.send_message`.
  - `signal.read` gates `signal.receive_messages`, `signal.list_groups`, `signal.get_group`, `signal.get_identity`, and event subscriptions.
  - `signal.admin` gates `signal.trust_identity`.
- Outbound chat coordination defaults to the in-memory thread-ownership checker. Operators may override `chat_coordination.enabled`, `ttl_seconds`, `fail_open`, `allowlist_channels`, `backend`, and `dm_mode`; allowlist entries must use the connector's redaction-safe hashed channel identifiers.
- The connector does not persist Signal messages, group lists, identities, attachments, daemon responses, receive cursors, event resume hints, or daemon error bodies beyond process memory.
- Signal phone numbers, usernames, group IDs, group names, safety numbers, message bodies, quote context, attachments, receipts, typing indicators, and sender display names are private data. Treat all live request and response data as private-zone data.

## Network And Runtime Invariants

- Expected daemon host class in the manifest: loopback only.
- Default daemon URL: `http://localhost:8080`.
- Expected daemon endpoints:
  - `GET /v1/about`
  - `POST /v2/send`
  - `GET /v1/receive/{number}`
  - `GET /v1/groups/{number}`
  - `GET /v1/identities/{number}/{target}`
  - `PUT /v1/identities/{number}/trust/{target}`
  - `GET /api/v1/events?account=...`
- Manifest network constraints allow `localhost`, `127.0.0.1`, and `::1` on port `8080`, deny tailnet ranges, and set `max_redirects = 0`.
- Runtime request timeout: `30_000 ms` by default.
- Runtime receive timeout: `10_000 ms` by default.
- SSE stale timeout: `120_000 ms` by default.
- SSE reconnect delay defaults to `1_000 ms` initial and `60_000 ms` max.
- Manifest event caps advertise streaming, no replay, and `100` minimum buffered events.
- Sandbox profile is `strict`, with `64 MB` memory, `25%` CPU, `30_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets. It only initiates outbound daemon requests and outbound daemon SSE streams.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `signal.send` | Send Signal messages to one or more recipients or groups. |
| `signal.read` | Poll messages, inspect groups and identities, and subscribe to authorized inbound Signal events. |
| `signal.admin` | Trust a Signal identity after independent verification. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `signal.send_message` | `POST /v2/send` | `signal.send` | `Risky` | `Medium` | `None` | Sends user-visible Signal messages and attachments. |
| `signal.receive_messages` | `GET /v1/receive/{number}` | `signal.read` | `Safe` | `Low` | `None` | Consumes pending daemon messages and advances receive state. |
| `signal.list_groups` | `GET /v1/groups/{number}` | `signal.read` | `Safe` | `Low` | `Strict` | Lists groups visible to the configured account. |
| `signal.get_group` | `GET /v1/groups/{number}?id=...` | `signal.read` | `Safe` | `Low` | `Strict` | Reads one group by encoded group ID. |
| `signal.get_identity` | `GET /v1/identities/{number}/{target}` | `signal.read` | `Safe` | `Low` | `Strict` | Reads identity and trust metadata for one contact. |
| `signal.trust_identity` | `PUT /v1/identities/{number}/trust/{target}` | `signal.admin` | `Dangerous` | `High` | `BestEffort` | Changes local identity trust state. |

## Event Inventory

| Topic | Source | Ack | Replay | Rationale |
|-------|--------|-----|--------|-----------|
| `signal.message.received` | SSE accepted message or attachment event | yes | no | Emits authorized direct or group message content. |
| `signal.reaction.received` | SSE accepted reaction-only event | yes | no | Emits authorized reaction payloads. |
| `signal.receipt.read` | SSE receipt event | yes | no | Emits read or delivery receipt payloads when configured. |
| `signal.typing.received` | SSE typing event | yes | no | Emits typing indicators when configured. |
| `signal.policy.denied` | Connector policy decision | yes | no | Emits structured denial metadata without message body content. |
| `signal.events` | All five normalized event types | yes | no | Wraps each event as `{"source_topic": "signal.…", "event": {...}}`. |

## Native Delivery And Receive Progress

The native `subscribe` RPC requires one exact topic, a host-issued `stream_id`, a signed instance-bound capability token, and an optional `window_size` from 1 through 64. Use `signal.events` to consume all event types on the single stream. Replay (`since`), batching, and rate options are rejected. Changing the stream ID or topic requires reconfiguration; a repeated subscription for the same active stream renews its token without replacing the pending event.

Each manifest event declares the read capability, subscription operation, and exact resource URI required by the host. The connector rechecks signature, instance, zone, operation, resource restrictions, and token expiry before connecting or delivering, while waiting for acknowledgement, and before committing progress. Events carry the negotiated zone and require acknowledgement.

The producer uses one event credit and waits up to 30 seconds for the host's exact stream/topic/sequence/cursor ACK. Flushing stdout does not advance receive progress. Wrong acknowledgements, closed streams, token expiry, transport failures, and cancelled generations leave the event's cursor uncommitted. Successful acknowledgements advance the in-memory receive cursor and SSE `Last-Event-ID` hint; unsubscribe/resubscribe retains the hint, while reconfiguration, shutdown, and process restart reset it. Polling receive timestamps are never used as SSE event IDs. Explicitly unselected topics may be skipped, so select the aggregate topic when every event type matters.

The daemon decides whether `Last-Event-ID` is useful; the connector does not promise provider replay or durable cross-process recovery. Host acknowledgement does not make downstream effects exactly once. Event notifications are bounded by the SDK's 256 KiB frame limit. Embedded library callers without an attached native transport retain best-effort broadcast delivery: a successful enqueue advances their in-memory cursor, while a missing receiver fails delivery and preserves progress. The native process rejects that embedded subscription entry point.

Native wire cursors are bounded account-scoped digests, separate from the daemon resume hint. A real SSE ID retains its identity even if the daemon incorrectly changes its content; without an ID, the digest includes the original topic, principal, and normalized payload so distinct events sharing a timestamp do not collide. Identical content without a unique provider ID cannot distinguish a duplicate from another identical event; no durable replay guarantee is claimed. Closing and reopening the same stream immediately fences the old producer, including when it is idle.

## Explicit Non-Goals

The current implementation does not include:

- Signal account registration, SMS verification, QR linking, unlinking, or device management
- starting, stopping, updating, or supervising `signal-cli-rest-api`
- direct Signal service calls without the local REST daemon
- contact search, contact sync, profile update, group creation, group mutation, pinning, reactions send/delete, receipts send, or typing send operations
- attachment download, attachment serving, durable attachment storage, or attachment cleanup
- durable replay buffers, exactly-once delivery, or persistent SSE resume state
- generic Signal bot workflow orchestration or pairing approval workflows

These are excluded on purpose:

- Signal message contents, sender identifiers, safety numbers, group IDs, and attachments are sensitive private data.
- The local daemon owns account registration and Signal protocol state; this connector should not duplicate that responsibility.
- Inbound event policy must remain explicit because group and quote context can leak private conversations.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, `introspect()`, `subscribe()`, `unsubscribe()`, and `invoke()` are part of the public closeout contract. They surface:

- configured state, bridge status, daemon host class, phone-number shape, and streaming subscription count
- live daemon reachability through `/v1/about` in `self_check`
- operation metadata with capability, risk, safety tier, idempotency, schemas, and AI hints
- event metadata with stream topics, no-replay posture, no-ack posture, and schema shape
- bound capability-token verification for invoke and subscribe
- receive cursor and cached group count after polling
- current permissive simulation behavior
- current shutdown state retention behavior

The deterministic integration evidence is anchored on connector-local tests covering:

- loopback send and receive lifecycle through WireMock
- daemon health, doctor, self-check, simulate, and shutdown
- bound capability-token setup for send, read, admin, and subscribe paths
- group list/detail, identity lookup, and identity trust operations
- SSE message, reaction, typing, and policy-denial event paths
- redacted proof logging for private Signal fixture data
- attachment-size rejection
- event caps and manifest/runtime operation parity
- error mapping for unauthorized, rate-limited, timeout, attachment, bridge, and provider failures

## Source Notes

- `connectors/signal/src/connector.rs` defines lifecycle handlers, operation metadata, event metadata, capability-token verification, simulation, subscription, local readiness, and invoke dispatch.
- `connectors/signal/src/client.rs` defines signal-cli REST paths, retry dispatch, timeout, request construction, response decoding, and provider error handling.
- `connectors/signal/src/types.rs` defines configuration, inbound policy, request and response types, event normalization, and validation rules.
- `connectors/signal/src/bridge.rs` defines bridge health, reconnect backoff, receive cursor, group cache, and attachment encoding/decoding helpers.
- `connectors/signal/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/signal/manifest.toml` defines operation and event catalogs, loopback network constraints, sandbox boundary, and zone policy.
- `connectors/signal/tests/integration.rs` and `connectors/signal/tests/conformance_contract.rs` cover loopback runtime behavior and manifest/runtime parity.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/signal_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands after the active connector source edits settle.

The verification surface captures:

- runtime operation and event inventory
- deterministic WireMock coverage for signal-cli REST paths
- deterministic local SSE coverage for event policy
- capability-token enforcement in invoke and subscribe
- chat-thread coordination coverage proving duplicate send claims are denied before provider HTTP
- local readiness, validation, provider error, and retryability behavior
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Run `signal-cli-rest-api` locally and keep its configuration directory outside the connector checkout.
- Register or link the Signal account through the daemon before configuring this connector.
- Prefer a loopback daemon URL unless a separate operator-approved trust boundary protects the daemon.
- Use deterministic WireMock and local SSE fixtures for routine proof.

**Dedicated environment**:

- Use a dedicated test Signal account and test groups for live checks.
- Keep group inbound policy on allowlist unless the group is explicitly approved.
- Keep quote context at `allowed_only` or `none` for group events unless full quote exposure is required.
- Avoid `trust_all_known_keys` outside test environments; use a verified safety number when trusting identities.

**Redaction rules**:

- Redact phone numbers, usernames, group IDs, group names, message bodies, quote text, quote authors, attachment payloads, safety numbers, source UUIDs, daemon URLs when they reveal topology, daemon error bodies, and proof logs containing Signal payloads.
- Verification output should use operation IDs, fixture IDs, hashes, event kind, status/error classes, retry decisions, counts, and payload-shape summaries instead of raw Signal content.

**Common remediation**:

- If `configure` fails, provide a valid E.164 `phone_number`, a valid `http` or `https` `daemon_url`, positive timeout values, and nonblank optional paths.
- If `self_check` fails with bridge not running, start or repair the local daemon outside this connector.
- If `invoke` reports a missing capability, mint a bound token for the required Signal capability and exact operation ID.
- If native `subscribe` is rejected, negotiate `signal.read` during handshake, provide a bound token for `signal.subscribe` and `signal:events:<topic>`, and select one exact topic (use `signal.events` for all types).
- If group events disappear, inspect `inbound_policy.group_policy`, `group_allow_from`, and mention settings.
- If messages are unexpectedly consumed, remember that the daemon receive endpoint drains pending messages.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-signal-readme cargo check -p fcp-signal --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-signal-readme cargo test -p fcp-signal --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-signal-readme cargo clippy -p fcp-signal --all-targets --no-deps -- -D warnings`
- `ubs connectors/signal/README.md`
