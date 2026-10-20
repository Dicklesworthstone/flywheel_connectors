# Synology Chat Connector V3 Contract

> **Status**: PROVEN (2026-10-20; 12/12 graduation gauntlet, verifier + unit/integration/local_non_mock suites verified)
> **Bead**: `flywheel_connectors-j05nu.1.16.1`
> **Verification script**: `scripts/e2e/synology_chat_connector_verification.sh`
> **Unblocks**:
> - `flywheel_connectors-j05nu.1.16.2`
> - `flywheel_connectors-j05nu.1.16.6`
> **Follow-on beads**:
> - `flywheel_connectors-j05nu.1.16.3`
> - `flywheel_connectors-j05nu.1.16.4`
> - `flywheel_connectors-j05nu.1.16.5`
> - `flywheel_connectors-j05nu.1.16.7`
> **Primary upstreams**:
> - https://www.synology.com/en-id/dsm/7.2/software_spec/chat
> - https://www.synology.com

## Verification Handoff

Verification script: `scripts/e2e/synology_chat_connector_verification.sh`

## Purpose

This document fixes the accepted first V3 slice for `fcp.synology-chat` and records the first inbound follow-on that now exists, so later work stays aligned with the connector that actually ships instead of assuming a full bidirectional bot runtime already exists.

The current connector is still centered on outbound incoming-webhook delivery, but it now also supports explicit host-forwarded outgoing-webhook normalization and a typed file URL send path with SSRF-oriented URL policy checks. It can send plain text, send one validated media/file URL, forward a raw webhook payload, normalize one forwarded outgoing-webhook payload into stable channel or thread or sender metadata, and report configuration and health details. It is still not an outgoing-webhook receiver, slash-command handler, bot platform runtime, or background inbound bridge.

## Current Runtime Snapshot

The current crate exposes these operations:

- `synology_chat.send_message`
- `synology_chat.send_file_url`
- `synology_chat.send_payload`
- `synology_chat.ingest_outgoing_webhook`
- `synology_chat.health`

Important implementation truths from `connector.rs`, `client.rs`, `types.rs`, and `manifest.toml`:

- Configuration is `incoming_url`, optional `outgoing_token`, optional `allowed_file_url_hosts`, bounded `request_timeout_ms`, `allow_insecure_ssl`, and forwarded-ingress policy settings for sender allowlists, DM policy, body budget, body timeout, invalid-token rate limit, and per-sender rate limit.
- `incoming_url` must be a valid `http://` or `https://` URL and is normalized by trimming surrounding whitespace.
- One connector instance is bound to one incoming webhook delivery target.
- `send_message` requires `text` and optionally accepts `user_id`, `user_ids`, and `bot_name`.
- `user_id` is normalized into a single-entry `user_ids` array; `user_ids` must be an array of non-empty strings.
- `bot_name` is currently translated to the outbound payload field `username`.
- Outbound `send_message`, `send_file_url`, and `send_payload` run SDK chat coordination before webhook dispatch. Successful responses include redacted `coordination` audit records, and duplicate ownership claims are denied before the provider HTTP call.
- `chat_coordination` config can set `enabled`, `ttl_seconds`, `fail_open`, `allowlist_channels`, `backend`, and `dm_mode`; the connector defaults to the in-memory backend for local webhook delivery and tests.
- `send_file_url` requires an HTTP or HTTPS `file_url`, rejects credentials, fragments, oversized URLs, localhost/private/link-local/internal destinations, unresolved hosts, and DNS pin mismatches, then posts `{ "file_url": ... }` with the same optional `user_id`, `user_ids`, and `bot_name` fields.
- `allowed_file_url_hosts` is an exact-host override for private NAS or lab media hosts; it permits that exact host even when it resolves to private or loopback space.
- `send_payload` requires a JSON object and forwards it directly to the webhook endpoint for advanced card or attachment shapes.
- `send_payload` intentionally remains unchecked raw passthrough for provider-specific payloads; callers that want SSRF-checked media URL dispatch should use `send_file_url`.
- Delivery is an outbound `POST` with JSON to the configured incoming webhook URL.
- `ingest_outgoing_webhook` accepts a parsed outgoing-webhook payload forwarded by the host, enforces forwarded body budget and timeout metadata, resolves the token from payload, query, top-level token, or supported header aliases, verifies it with a constant-time comparison, applies sender/DM/rate policy, and emits stable channel, thread, sender, message, reply, attachment, sanitization, and policy metadata without hosting the listener inside the connector.
- Non-success HTTP status codes are surfaced as API errors with the provider body preserved.
- Successful empty responses are normalized to `{ "status": "ok" }`; successful non-JSON bodies are wrapped as `{ "status": "ok", "body": "<raw>" }`.
- `health` reports configured target details, manifest hash, `allow_insecure_ssl`, whether `outgoing_token` is present, forwarded-ingress policy, and whether the receive path is still disabled or ready for host-forwarded outgoing-webhook ingest, but it does not perform a live delivery probe.
- `self_check()` is also configuration-centric: it reports normalized URL and settings, including whether reply semantics are still outbound-only or upgraded to outgoing-webhook response mode, but it does not call the webhook endpoint.
- A `doctor()` helper exists internally and reports configuration state plus the normalized incoming URL, but it is not yet exposed as an FCP operation.
- The connector stores a `ConnectorRuntime`, but it still does not use it for any streaming or inbound server lifecycle.
- `simulate()` always returns allowed, and `subscribe()` / `unsubscribe()` return `StreamingNotSupported`.

## Accepted First Slice

The accepted first Synology Chat slice is intentionally narrow:

- send one plain-text message through one configured incoming webhook
- send one SSRF-checked file/media URL through the same incoming webhook
- send one raw JSON webhook payload through the same incoming webhook
- expose safe configuration and readiness metadata for operators

This slice is intentionally closer to "outbound incoming-webhook sender" than to "full Synology Chat connector."

## Service Inventory

| Surface | Current status | Notes |
|---------|-----------------------|-------|
| Plain-text outbound delivery | In scope | Implemented as `send_message` against a configured incoming webhook URL. |
| Safe file URL outbound delivery | In scope | Implemented as `send_file_url` with connector-side URL validation and exact-host overrides for private deployments. |
| Raw webhook payload passthrough | In scope | Implemented as `send_payload` for cards or attachment-shaped JSON. |
| Forwarded outgoing-webhook normalization | In scope | Implemented as `ingest_outgoing_webhook` for host-forwarded payloads with token verification and stable channel or thread or attachment metadata. |
| Configuration and health reporting | In scope | Implemented without a live webhook round-trip. |
| Incoming webhook hosting | Out of scope | No HTTP listener or outgoing-webhook receive path exists. |
| Inbound event normalization | Partially in scope | Host-forwarded outgoing-webhook payloads are normalized, but there is still no listener, replay buffer, or background ingress runtime. |
| Slash commands, bots, or interactive replies | Out of scope | No command or callback runtime exists. |
| Dedicated binary file upload flow | Out of scope | `send_file_url` can ask Synology Chat to fetch a validated URL, but the connector still does not upload, host, or lifecycle-manage file bytes. |
| Persistent sync or subscription model | Out of scope | No background runtime or event stream exists. |

## Auth And Scope Boundary

- One connector instance maps to one Synology Chat incoming webhook URL.
- In practice, the incoming webhook URL is the primary credential and capability boundary for outbound delivery.
- `outgoing_token` now gates `synology_chat.ingest_outgoing_webhook`; without it, the receive path remains disabled and the connector stays outbound-only.
- The runtime still does not implement incoming webhook validation, slash-command signing, or multi-webhook routing.
- The connector is scoped to `z:work` and `z:project:*` targets rather than community or public zones.
- Host-level placement is intentionally operator-configured because deployments may be public, private, or tailnet-addressed.

## Network And Runtime Invariants

- Transport is outbound HTTP or HTTPS only.
- The reqwest client uses the configured request timeout and may optionally disable certificate verification with `allow_insecure_ssl`.
- Outbound media URL dispatch uses connector-local SSRF checks before the Synology NAS is asked to fetch the URL. Public DNS names must resolve to public IPs; exact `allowed_file_url_hosts` entries are the deliberate escape hatch for private self-hosted media.
- The connector does not listen on a socket or expose any inbound service surface.
- `health` and `self_check()` do not currently prove remote webhook reachability; they only prove that configuration was parsed and stored.
- There is no replay buffer, retry queue, dedupe key, or persistent local state in the current runtime. The connector does keep bounded in-memory fixed-window counters for forwarded invalid-token and per-sender rate decisions.
- The current implementation is still request-response only: outbound delivery plus explicit host-forwarded ingest, with no connector-hosted listener or event stream.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `synology_chat.write` | Send messages, checked file URLs, or raw webhook payloads through the configured incoming webhook |
| `synology_chat.read` | Inspect configuration and health metadata |
| `synology_chat.webhook` | Validate and normalize a host-forwarded outgoing-webhook payload |

## Accepted Operation Inventory

| Operation | Protocol shape | Capability | SafetyTier | RiskLevel | Idempotency | Notes |
|-----------|----------------|------------|------------|-----------|-------------|-------|
| `synology_chat.send_message` | HTTP `POST` JSON webhook body with `text`, optional `user_ids`, optional `username` | `synology_chat.write` | `Risky` | `Medium` | `None` | Runs chat coordination before webhook dispatch. The connector does not model inbound reply semantics. |
| `synology_chat.send_file_url` | HTTP `POST` JSON webhook body with checked `file_url`, optional `user_ids`, optional `username` | `synology_chat.write` | `Risky` | `Medium` | `None` | Runs chat coordination before provider dispatch; exact-host overrides are explicit runtime configuration for private deployments. |
| `synology_chat.send_payload` | HTTP `POST` arbitrary JSON object | `synology_chat.write` | `Risky` | `Medium` | `None` | Runs chat coordination before raw passthrough and intentionally does not inspect nested `file_url` values. |
| `synology_chat.ingest_outgoing_webhook` | local policy and payload normalization for one host-forwarded outgoing webhook request | `synology_chat.webhook` | `Safe` | `Low` | `Strict` | Verifies the configured `outgoing_token` from supported aliases, applies body/sender/DM/rate policy, normalizes channel/thread/sender/reply metadata, and exposes attachment and policy hints without hosting a listener. |
| `synology_chat.health` | local configuration report | `synology_chat.read` | `Safe` | `Low` | `Strict` | Returns configured URL and settings, but does not perform a live webhook probe. |

## Explicit Non-Goals

The current Synology Chat runtime still does not include:

- hosting an outgoing webhook receiver
- slash commands, bot callbacks, or interactive response flows
- durable retries, dedupe, or delivery receipts
- multi-webhook routing or tenant multiplexing
- explicit file upload, attachment hosting, or media lifecycle management
- background streaming or subscription support

These are excluded on purpose:

- The current runtime is not a full bidirectional Synology Chat integration; it adds explicit forwarded ingest without silently implying a hosted listener.
- `outgoing_token` now powers one normalization path, but `ConnectorRuntime` still does not imply a general inbound server or bot runtime.
- Self-hosted deployment guidance and richer inbound behavior still deserve explicit follow-on design instead of being silently implied by the current contract.

## Implementation Notes For `flywheel_connectors-j05nu.1.16.2`

- Preserve the one-webhook, one-instance boundary. Do not silently widen the client into a multi-target router.
- Keep the distinction between outbound incoming-webhook delivery and any future inbound outgoing-webhook receive path explicit in types and capabilities.
- Keep `allow_insecure_ssl` visible and deliberate because it weakens the transport boundary for self-hosted operators.
- Preserve provider response detail in error mapping; HTTP status plus provider body is important for operator diagnosis.
- Keep `outgoing_token` scoped to the explicit forwarded ingest path; do not silently widen it into a general inbound runtime guarantee.
- Keep `send_message` and `send_payload` distinct: one is a constrained ergonomic helper, the other is a raw provider passthrough.
- If live health probes are added later, make that a deliberate expansion of the contract instead of changing `health` semantics invisibly.

## Verification Bundle

Verification script: `scripts/e2e/synology_chat_connector_verification.sh`

The tracked verifier runs the Synology Chat crate check, formatting check,
deterministic loopback integration suite, full connector test suite, clippy, and
a redaction scan over JSONL/log artifacts. The script requires accepted `rch`
remote worker execution for each Cargo step; local fallback is classified as
`infra_blocked` rather than proof.

Current deterministic local coverage lives in
`connectors/synology-chat/tests/integration.rs`. It exercises loopback incoming
webhook delivery, safe file URL dispatch and SSRF policy decisions, forwarded
outgoing-webhook token/sender/body/rate policy, manifest operation schemas, and
device-lab structured skip evidence without live Synology credentials. Batch 4
graduation still stops at `local_non_mock` until this coverage is promoted into
the dedicated `connectors/synology-chat/tests/local_non_mock.rs` acceptance
surface.

Focused proof for this connector:

```bash
OUT_ROOT=/tmp/fcp-synology-chat-e2e bash scripts/e2e/synology_chat_connector_verification.sh
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-synology-chat-readme cargo test -p fcp-synology-chat --test integration -- --nocapture
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-synology-chat-readme cargo test -p fcp-synology-chat --tests -- --nocapture
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-synology-chat-readme cargo clippy -p fcp-synology-chat --all-targets -- -D warnings
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-synology-chat-readme cargo fmt -p fcp-synology-chat -- --check
```

## Source Notes

This contract is grounded in the current connector implementation and the published Synology Chat product surface:

- `connectors/synology-chat/src/connector.rs` defines the current operation inventory, capability mapping, health behavior, forwarded outgoing-webhook normalization, and doctor/runtime surfaces.
- `connectors/synology-chat/src/client.rs` defines the outbound webhook HTTP behavior and response normalization.
- `connectors/synology-chat/src/types.rs` defines the current config surface and validation rules.
- `connectors/synology-chat/manifest.toml` defines the work-zone posture, capability families, and intentionally operator-configured network placement.
- Synology's published Chat specs confirm that incoming and outgoing webhooks exist at the product level; the current connector implements incoming-webhook outbound delivery plus explicit host-forwarded outgoing-webhook normalization, but still not a hosted listener.

## Operation Inventory

See the operation table above (`send_message`, `send_file_url`, `send_payload`, `ingest_outgoing_webhook`, `webhook_normalize`, `health`).

## Operator Guidance

Prerequisites:
- Use the deterministic loopback harness for local verification; never log raw Synology webhook tokens or unredacted chat payloads.

Rerun commands:
- `bash scripts/e2e/synology_chat_connector_verification.sh`
- `rch exec -- cargo test -p fcp-synology-chat --test local_non_mock -- --nocapture`
- `rch exec -- cargo test -p fcp-synology-chat --test integration -- --nocapture`
- `rch exec -- cargo clippy -p fcp-synology-chat --all-targets -- -D warnings`
