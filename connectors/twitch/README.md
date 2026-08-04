# Twitch Connector V3 Contract

> **Status**: PROVEN
> **Bead**: `flywheel_connectors-j05nu.8.5.1`
> **Unblocks**: `flywheel_connectors-j05nu.8.5.2`
> **Verification script**: `scripts/e2e/twitch_connector_verification.sh`
> **Primary upstream**: https://dev.twitch.tv/docs/api/reference

## Purpose

This document pins down the first V3-acceptable slice for `fcp.twitch` so the follow-on runtime bead can implement a truthful auth boundary instead of inheriting the current prototype’s mixed assumptions.

The connector targets Twitch Helix APIs at `https://api.twitch.tv/helix` plus Twitch OAuth endpoints at `https://id.twitch.tv/oauth2`.

## Current Runtime Snapshot

The current crate already exposes these operations:

- `twitch.streams.list`
- `twitch.streams.get`
- `twitch.users.get`
- `twitch.channels.get`
- `twitch.channels.modify`
- `twitch.clips.list`
- `twitch.clips.create`
- `twitch.chat.send`
- `twitch.games.list`
- `twitch.health`

Current implementation truths from `connector.rs`, `client.rs`, and `manifest.toml`:

- Configuration is `client_id`, `client_secret`, optional `base_url`, optional `token_url`, retry tuning, and request timeout.
- The runtime acquires exactly one OAuth app access token via the client-credentials grant during `configure()`.
- The connector does not support user OAuth, refresh tokens, broadcaster selection through consent, bot identity, or EventSub subscription management.
- `self_check()` only verifies that a token exists and that a lightweight Helix request succeeds.
- The current implementation does not call Twitch’s `/validate` endpoint, even though Twitch requires third-party apps that maintain OAuth sessions to validate tokens at startup and hourly.
- `localhost` and `127.0.0.1` base URLs are still allowed for tests in the current code path.

## Accepted First Slice

The V3-acceptable first slice should be the app-access-token-compatible, read-heavy Helix surface:

- `twitch.streams.list`
- `twitch.streams.get`
- `twitch.users.get`
- `twitch.channels.get`
- `twitch.clips.list`
- `twitch.games.list`
- `twitch.health`

These endpoints are compatible with an app access token according to Twitch’s current reference docs.

## Auth And Scope Boundary

The accepted first slice uses:

- OAuth client-credentials grant
- One app access token per configured Twitch application
- Helix reads that accept either app or user access tokens
- No delegated broadcaster mutation authority
- No bot-user authority

This means the current prototype’s write operations are not yet V3-truthful:

- `twitch.channels.modify`
  Requires a user access token with `channel:manage:broadcast`.
- `twitch.clips.create`
  Requires a user access token with `clips:edit`, and Twitch treats clip creation as asynchronous work.
- `twitch.chat.send`
  Requires `user:write:chat`; if using an app access token, Twitch also requires prior user authorization such as `user:bot` plus `channel:bot` or equivalent moderator authority.

Inference from the official docs: the current client-credentials-only runtime cannot truthfully promise those write surfaces without an auth redesign.

## Network And Runtime Invariants

- Primary Helix host: `api.twitch.tv`
- OAuth token host: `id.twitch.tv`
- OAuth validation endpoint: `https://id.twitch.tv/oauth2/validate`
- TLS and SNI are required for production traffic
- `localhost` and `127.0.0.1` overrides are test-only escape hatches in the current implementation, not production contract
- No inbound webhook or EventSub receiver is part of the accepted first slice

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `twitch.read` | Read-only Helix discovery for streams, users, channels, clips, and games |
| `twitch.write` | Future broadcaster/bot mutations after user-token auth is implemented |

## Operation Inventory

| Operation | Endpoint | Capability | SafetyTier | RiskLevel | Idempotency | Notes |
|-----------|----------|------------|------------|-----------|-------------|-------|
| `twitch.streams.list` | `GET /helix/streams` | `twitch.read` | `Safe` | `Low` | `None` | Live-stream discovery only; offline channels are absent. |
| `twitch.streams.get` | `GET /helix/streams?user_login=...` | `twitch.read` | `Safe` | `Low` | `None` | Point lookup by login with empty result when the user is offline. |
| `twitch.users.get` | `GET /helix/users` | `twitch.read` | `Safe` | `Low` | `None` | Login-based user lookup; the current connector does not expose the user-token-only “self” variant. |
| `twitch.channels.get` | `GET /helix/channels` | `twitch.read` | `Safe` | `Low` | `None` | Channel metadata lookup by broadcaster ID. |
| `twitch.clips.list` | `GET /helix/clips` | `twitch.read` | `Safe` | `Low` | `None` | Read-only clip discovery by broadcaster. |
| `twitch.games.list` | `GET /helix/games` | `twitch.read` | `Safe` | `Low` | `None` | Category/game lookup by name. |
| `twitch.health` | `GET /helix/users` plus token validation expectations | `twitch.read` | `Safe` | `Low` | `Strict` | Readiness probe; the runtime bead should add `/validate` rather than treating a generic Helix read as sufficient. |

## Prototype Surfaces That Are Not Yet Contract-Accepted

These are present in the current code, but they should not be considered part of the accepted V3 surface until auth and semantics are corrected:

| Operation | Why It Is Not Yet Accepted |
|-----------|----------------------------|
| `twitch.channels.modify` | Current runtime uses an app access token, but Twitch requires a user access token with `channel:manage:broadcast`. |
| `twitch.clips.create` | Current runtime uses an app access token, but Twitch requires a user access token with `clips:edit`; clip creation is also asynchronous, so the contract should model a queued/verification flow rather than strict idempotency. |
| `twitch.chat.send` | Current runtime uses an app access token without the documented bot/user authorization model required for chat sending. |

## Explicit Non-Goals

The accepted first slice does not include:

- EventSub subscription creation, webhook delivery, or conduit management
- Moderation APIs
- Channel mutation flows
- Chat send flows
- Clip creation flows
- Stream schedule, raids, polls, predictions, subscriptions, or whisper features
- Broadcaster- or bot-consent orchestration

## Implementation Notes For `flywheel_connectors-j05nu.8.5.2`

- Either narrow the runtime to the accepted read-only slice, or add a user-token auth model before keeping `channels.modify`, `clips.create`, or `chat.send`.
- If write operations remain, split auth modes explicitly: app access token for read-only discovery and user access token for broadcaster/bot mutations.
- Add `/validate` token checks at startup and on a periodic cadence instead of relying solely on downstream 401s.
- Treat `clips.create` as asynchronous provider work. A truthful contract should not mark it `Strict` idempotency under the current API semantics.
- Keep `localhost`/`127.0.0.1` overrides test-only and make the production contract point at Twitch’s real hosts.
- If EventSub is added later, model it as a separate execution shape with webhook secret management and explicit subscription lifecycle operations.

## Verification Bundle

Verification script: `scripts/e2e/twitch_connector_verification.sh`

The verifier runs the local non-mock loopback Twitch OAuth/Helix proof, the
connector test suite, formatting, check, and clippy through `rch`, and records
non-green infrastructure blockers instead of treating local fallback as proof.

## Operator Guidance

Prerequisites:

- Use Twitch app credentials with the client-credentials grant for the accepted read-only Helix slice.
- Keep production API traffic on `https://api.twitch.tv` and OAuth traffic on `https://id.twitch.tv`.
- Do not enable the prototype write surfaces until user-token auth and broadcaster or bot consent are modeled explicitly.

Rerun commands:

- `RUN_ID=<timestamp> OUT_ROOT=.codex-targets/twitch-verification/<timestamp> RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 bash scripts/e2e/twitch_connector_verification.sh`
- `bash scripts/graduation/run_gauntlet.sh --jsonl .codex-targets/twitch-verification/<timestamp>/evidence/twitch_gauntlet_after_promotion.jsonl connectors/twitch`
- `rch exec -- cargo test -p fcp-conformance --test graduation_gauntlet_conformance all_proven_connectors_pass_gauntlet -- --nocapture`

## Source Notes

This contract is grounded in the current connector implementation plus Twitch’s official docs:

- `connectors/twitch/src/connector.rs` defines the current operation inventory, app-token configuration model, health/self-check behavior, and the prototype write surface.
- `connectors/twitch/src/client.rs` shows the concrete Helix endpoints and confirms that the runtime currently uses the client-credentials grant only.
- `connectors/twitch/manifest.toml` captures the current manifest-declared operation surface.
- Twitch authentication overview: https://dev.twitch.tv/docs/authentication
- Getting OAuth tokens: https://dev.twitch.tv/docs/authentication/getting-tokens-oauth
- Token validation: https://dev.twitch.tv/docs/authentication/validate-tokens/
- API reference: https://dev.twitch.tv/docs/api/reference
