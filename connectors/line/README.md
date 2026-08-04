# LINE Connector V3 Contract

> **Status**: PROVEN
> **Bead**: `flywheel_connectors-j05nu.8.6.1`
> **Unblocks**: `flywheel_connectors-j05nu.8.6.2`
> **Verification script**: `scripts/e2e/line_connector_verification.sh`
> **Primary upstreams**:
> - https://developers.line.biz/en/reference/messaging-api/nojs/
> - https://developers.line.biz/en/docs/basics/channel-access-token/
> - https://developers.line.biz/en/docs/messaging-api/receiving-messages/
> - https://developers.line.biz/en/docs/messaging-api/getting-user-ids/
> - https://developers.line.biz/en/docs/messaging-api/using-rich-menus/

## Purpose

This document fixes the accepted first V3 slice for `fcp.line` so the follow-on runtime bead can converge on a stable contract instead of treating "LINE integration" as an open-ended bucket that mixes outbound messaging, webhook reception, audience management, and rich-menu administration.

The connector is a request-response LINE Messaging API surface for outbound replies and pushes, profile and group lookups, basic rich-menu management, and health checking. It is not a webhook receiver, audience-management tool, or generic LINE platform SDK.

## Current Runtime Snapshot

The current crate already exposes these operations:

- `line.messages.push`
- `line.messages.reply`
- `line.messages.multicast`
- `line.profile.get`
- `line.group.profile`
- `line.group.members`
- `line.rich_menu.list`
- `line.rich_menu.create`
- `line.rich_menu.delete`
- `line.health`

Important implementation truths from `connector.rs`, `client.rs`, and `manifest.toml`:

- Configuration is `base_url`, `channel_access_token`, retry policy, and bounded `request_timeout_ms`.
- The connector is bound to one Messaging API channel through one pre-issued channel access token.
- The runtime now requires a non-empty `channel_access_token`; secretless proxy-injected auth is no longer accepted for this connector slice.
- The accepted production API root is `https://api.line.me`, and manifest operation constraints deny localhost, private-range, tailnet-range, and IP-literal targets. Deterministic verifier mock servers are an explicit harness concern, not part of the graduated operation network policy.
- `line.health` and `self_check()` are grounded in `GET /v2/bot/info`, and the readiness surface now emits operator guidance, verification-script references, provisioning details, and structured self-check evidence.
- `line.messages.reply` depends on a reply token supplied from an external webhook flow, but the connector itself doesn't receive webhooks, verify signatures, or persist webhook state.
- `line.messages.multicast` is implemented only for user IDs, not group chats or multi-person chats.
- `line.messages.push`, `line.messages.reply`, and `line.messages.multicast` now run chat thread-ownership coordination before the LINE HTTP request. Duplicate active claims return `FcpError::Unauthorized` code `4090` before provider dispatch, and successful sends include redaction-safe `coordination` audit records.
- `line.group.members` is implemented against the group-member-ID endpoint and therefore inherits the upstream verified-or-premium-account restriction.
- The current rich-menu slice manages only rich-menu metadata objects. It does not upload rich-menu images, assign menus to users, set aliases, or manage default rich menus.
- The runtime doesn't map `InvokeRequest.idempotency_key` to `X-Line-Retry-Key`, so provider-supported retry keys aren't part of the current connector contract.

## First-Slice Scope

The accepted first LINE slice is intentionally narrow:

- Send push messages to one LINE recipient identifier supplied by the caller.
- Send reply messages using reply tokens that came from a webhook event handled elsewhere.
- Send multicast messages to multiple user IDs.
- Read one user profile.
- Read one group summary and enumerate group member IDs.
- List, create, and delete rich-menu metadata objects.
- Expose a safe readiness and health probe backed by bot-info reachability.

This slice is intentionally closer to "outbound bot operations" than to "complete LINE platform coverage."

## Service Inventory

| Surface | Status in first slice | Notes |
|---------|-----------------------|-------|
| Outbound messaging | In scope | Push, reply, and multicast are implemented. |
| One-on-one profile lookup | In scope | User profile lookup is implemented. |
| Group metadata | In scope | Group summary and group member ID enumeration are implemented. |
| Room and multi-person chat metadata | Out of scope | Push and reply can target IDs from webhook events, but the connector doesn't expose room summary or multi-person membership operations. |
| Webhook reception and verification | Out of scope | Reply tokens come from webhook events, but webhook delivery, signature verification, replay handling, and event persistence are not part of this connector. |
| Rich-menu management | Partial | List, create, and delete metadata objects are implemented; image upload, aliasing, default-menu assignment, and per-user linking are not. |
| Message content retrieval | Out of scope | The current connector doesn't call `api-data.line.me` for user-uploaded media or previews. |
| Audience, broadcast, and narrowcast flows | Out of scope | No broadcast, narrowcast, audience, aggregation-unit, or analytics operations exist in the current slice. |

## Auth And Scope Boundary

- One connector instance maps to one Messaging API channel.
- Authentication is bearer-token based using a pre-issued channel access token.
- The connector does not issue, rotate, or revoke channel access tokens.
- The connector doesn't require a channel secret because it doesn't receive or verify webhooks in the current slice.
- User IDs are provider-scoped. LINE documents that the same user ID is shared across channel types under the same provider, but not across different providers.
- The stable primary identifiers in this slice are `userId`, `groupId`, `roomId`, and `richMenuId`. Reply flows also rely on the provider's short-lived `replyToken`.
- Push accepts a single recipient identifier and can target a `userId`, `groupId`, or `roomId` obtained from webhook events.
- Multicast is narrower: it targets user IDs only.
- Group-member enumeration is only available to verified or premium official accounts according to LINE's user-ID documentation.
- Reply tokens are single-use and should be consumed promptly; LINE documents that they are intended to be used within roughly one minute of receiving the webhook and shouldn't be treated as durable credentials.
- Optional `chat_coordination` config supports `enabled`, `ttl_seconds`, `fail_open`, `allowlist_channels`, `backend`, and `dm_mode`. Empty allowlist means all LINE send targets are coordinated; reply-token and multicast coordination use SHA-256 fingerprints rather than plaintext tokens or recipient lists.

## Network And Runtime Invariants

- Production REST host: `api.line.me`
- Port: `443`
- TLS + SNI required
- `deny_localhost = true`
- `deny_private_ranges = true`
- `deny_tailnet_ranges = true`
- `deny_ip_literals = true`
- The current slice doesn't use `api-data.line.me`; content-download APIs remain out of scope.
- LINE documents endpoint-specific rate limits rather than one global quota. Important first-slice ceilings include:
  - reply: `2,000 requests / second`
  - push: `2,000 requests / second`
  - multicast: `200 requests / second`
  - rich-menu list and read operations: `2,000 requests / second`
  - destructive rich-menu administration can be much lower than ordinary reads
- The connector is request-response only. It exposes no streaming, replay, subscription, or inbound listener surface.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `line.messages.write` | Push, reply, and multicast outbound messages |
| `line.profile.read` | User profile lookup, group summary, group-member enumeration, and health |
| `line.menu.read` | Rich-menu listing |
| `line.menu.write` | Rich-menu creation and deletion |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Notes |
|-----------|----------------|------------|------------|-----------|-------------|-------|
| `line.messages.push` | `POST /v2/bot/message/push` | `line.messages.write` | `Risky` | `Medium` | `BestEffort` | Claims ownership for the recipient conversation before dispatch, then sends a real outbound message to one `userId`, `groupId`, or `roomId`. LINE supports retry keys, but the connector doesn't currently wire them. |
| `line.messages.reply` | `POST /v2/bot/message/reply` | `line.messages.write` | `Risky` | `Medium` | `None` | Claims ownership using a reply-token fingerprint before dispatch, then consumes a short-lived, single-use reply token originating from a webhook event handled elsewhere. |
| `line.messages.multicast` | `POST /v2/bot/message/multicast` | `line.messages.write` | `Risky` | `Medium` | `BestEffort` | Claims ownership for a fingerprint of the sorted recipient set before dispatch, then sends the same payload to multiple user IDs only. Group and room targets are out of scope for this operation. |
| `line.profile.get` | `GET /v2/bot/profile/{userId}` | `line.profile.read` | `Safe` | `Low` | `Strict` | Canonical point lookup for user identity and display metadata. |
| `line.group.profile` | `GET /v2/bot/group/{groupId}/summary` | `line.profile.read` | `Safe` | `Low` | `Strict` | Canonical group-summary lookup. |
| `line.group.members` | `GET /v2/bot/group/{groupId}/members/ids` | `line.profile.read` | `Safe` | `Low` | `Strict` | Read-only group member ID enumeration with pagination. Upstream account-tier restrictions apply. |
| `line.rich_menu.list` | `GET /v2/bot/richmenu/list` | `line.menu.read` | `Safe` | `Low` | `Strict` | Lists rich-menu metadata objects created through the Messaging API. |
| `line.rich_menu.create` | `POST /v2/bot/richmenu` | `line.menu.write` | `Risky` | `Medium` | `BestEffort` | Creates rich-menu metadata only. Image upload and user/default assignment are separate concerns and not in scope. |
| `line.rich_menu.delete` | `DELETE /v2/bot/richmenu/{richMenuId}` | `line.menu.write` | `Dangerous` | `High` | `Strict` | Permanently removes a rich-menu metadata object. The current connector requires interactive approval at runtime. |
| `line.health` | `GET /v2/bot/info` | `line.profile.read` | `Safe` | `Low` | `Strict` | Safe bot-info reachability and auth probe used by readiness surfaces. |

## Explicit Non-Goals

The accepted first LINE slice does not include:

- webhook ingestion, signature verification, webhook replay handling, or webhook redelivery control
- broadcast, narrowcast, audience, aggregation-unit, delivery-progress, or messaging analytics surfaces
- room summary or multi-person chat member-list operations
- friend-list enumeration
- message-content download from `api-data.line.me`
- LIFF, beacons, coupons, account linking, membership features, or LINE Login
- rich-menu image upload, alias management, default rich-menu assignment, or user-specific menu linking
- token issuance, rotation, revocation, or channel-secret lifecycle management

These are excluded on purpose:

- They materially widen the trust boundary beyond the current outbound bot surface.
- Several of them rely on webhook delivery or on account-manager workflows that the current connector doesn't model.
- Rich-menu metadata management is useful on its own, but rich-menu image and assignment flows deserve separate operations instead of being hidden behind `create`.

## Implementation Notes For `flywheel_connectors-j05nu.8.6.2`

- Preserve the request-response-only posture. If webhook reception is added later, it should be a distinct surface with explicit signature-verification and replay semantics.
- Keep the auth boundary strict: one Messaging API channel per connector instance and one configured token source.
- Surface the verified-or-premium-account restriction clearly for `line.group.members`; don't let it remain a surprising provider error.
- Keep room and multi-person chat behavior explicit. If those surfaces are added, add dedicated operations rather than silently overloading group operations.
- Reconcile runtime and manifest idempotency metadata with actual provider behavior. In particular, push and multicast shouldn't claim exact-once semantics until retry-key propagation is wired; rich-menu create should stay best-effort for the same reason, while rich-menu delete remains strict because the FCP safety model treats dangerous mutations conservatively.
- If production-host validation is part of the accepted V3 contract, enforce it during configure rather than only reporting it via `doctor()`.
- If rich-menu image upload or user/default linking is needed, add separate operations instead of broadening `line.rich_menu.create`.

## Readiness And Verification

The readiness closeout bead for this connector surface is `flywheel_connectors-j05nu.8.6.3`. Verification artifacts should be reproducible without reopening planning notes.

- Replayable verification bundle: `scripts/e2e/line_connector_verification.sh`
- Artifact root: `artifacts/e2e/line_connector/<timestamp>`
- Manifest verification command: `rch exec -- cargo run -q -p fwc -- manifest fix connectors/line/manifest.toml --check --json`
- Focused cargo checks:
  - `rch exec -- cargo check -p fcp-line --all-targets`
  - `rch exec -- cargo fmt --manifest-path connectors/line/Cargo.toml --check`
  - `rch exec -- cargo test -p fcp-line --test integration -- --nocapture`
  - `rch exec -- cargo test -p fcp-line -- --nocapture`
  - `rch exec -- cargo clippy -p fcp-line --all-targets -- -D warnings`

Operator guidance for verification:

- Prefer a disposable LINE bot channel before exercising push, reply, multicast, or rich-menu mutations. Use localhost mock servers only inside the verifier harness, not as the graduated operation network policy.
- Keep one connector instance bound to one `channel_access_token`, and keep live `base_url` on `https://api.line.me`.
- Redact channel access tokens, Authorization headers, reply tokens, user IDs, group IDs, room IDs, `richMenuId` values, picture URLs, and copied request logs before sharing artifacts.
- Treat `line.messages.reply` as dependent on a fresh webhook-sourced reply token that the connector itself does not mint or persist.
- Common remediation:
  - `not_configured`: configure `channel_access_token`, timeout, retry policy, and a valid `base_url`, then rerun `self_check`.
  - `line_auth_rejected`: replace the token and confirm `GET /v2/bot/info` succeeds.
  - `reply_token_invalid_or_expired`: capture a fresh webhook event and rerun the reply path immediately.
  - `membership_tier_restricted`: verify the official-account tier supports group member enumeration or rerun the pagination coverage through the verifier mock harness.
  - `self_check_retryable`: wait for LINE to recover or increase timeout / retry settings before rerunning the verification bundle.
  - `network_constraints_invalid`: use `https://api.line.me` for live runs; mock-server localhost overrides are verifier-only.

## Verification Bundle

The readiness closeout is anchored on `scripts/e2e/line_connector_verification.sh`.
It writes replayable artifacts under `artifacts/e2e/line_connector/<timestamp>` and captures manifest validation, focused `rch`-offloaded cargo checks, targeted readiness evidence, the full integration suite, the full crate test suite, and `clippy`.

## Operator Guidance

Prerequisites:
- Use a disposable LINE channel for live verification, and avoid shared production channels. Localhost mock servers are reserved for deterministic verifier harness coverage.
- Configure a dedicated channel access token for the target environment and keep the token/channel pairing stable while gathering evidence.
- If you need reply-path evidence, obtain a fresh webhook-sourced `replyToken` from an external receiver because this connector does not ingest webhooks.

Dedicated environment:
- Never point the verification bundle at a channel where unexpected push, multicast, or rich-menu deletion would be operationally harmful.

Redaction rules:
- Redact `channel_access_token`, Authorization headers, reply tokens, recipient identifiers, `richMenuId` values, picture URLs, and copied payloads before exporting artifacts.
- Treat bot display names, group names, message text, and chat-bar text as potentially sensitive operational data.

Common remediation:
- If `configure` rejects `base_url`, use `https://api.line.me` for live runs; deterministic mock-server tests should stay inside the verifier harness.
- If `self_check` reports `line_auth_rejected`, rotate the token and confirm `GET /v2/bot/info` succeeds for the intended channel.
- If `line.group.members` fails in live verification, assume official-account tier restrictions first and fall back to the mock-server pagination test for deterministic coverage.
- If verification hits 429s or transport timeouts, respect the upstream backoff window, lower concurrency, and rerun once the provider bucket recovers.

Rerun commands:
- `scripts/e2e/line_connector_verification.sh`
- `rch exec -- cargo run -q -p fwc -- manifest fix connectors/line/manifest.toml --check --json`
- `rch exec -- cargo check -p fcp-line --all-targets`
- `rch exec -- cargo fmt --manifest-path connectors/line/Cargo.toml --check`
- `rch exec -- cargo test -p fcp-line --test integration -- --nocapture`
- `rch exec -- cargo test -p fcp-line -- --nocapture`
- `rch exec -- cargo clippy -p fcp-line --all-targets -- -D warnings`

## Source Notes

This contract is grounded in current repo code plus current official LINE documentation:

- `connectors/line/src/connector.rs` defines the operation inventory, readiness behavior, and current capability mapping.
- `connectors/line/src/client.rs` defines the concrete Messaging API endpoints, health probe, and the absence of retry-key propagation.
- `connectors/line/manifest.toml` defines the current zone, capability, and production network boundary assumptions for the accepted V3 contract.
- LINE's Messaging API reference documents the current endpoint shapes, reply-token constraints, webhook-sourced recipient IDs, and endpoint-specific rate limits.
- LINE's channel access token docs document the available token types and their validity characteristics.
- LINE's webhook docs document the inbound event model and signature-verification requirement, which this connector intentionally leaves out of the current slice.
- LINE's user-ID docs document provider-scoped user IDs and the verified-or-premium-account restriction for full member enumeration.
