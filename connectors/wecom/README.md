# WeCom Connector V3 Contract

> **Status**: PROVEN (2026-10-20; 12/12 graduation gauntlet, verifier + unit/integration/local_non_mock suites verified)
> **Bead**: `flywheel_connectors-j05nu.1.12.1`
> **Verification script**: `scripts/e2e/wecom_connector_verification.sh`
> **Unblocks**:
> - `flywheel_connectors-j05nu.1.12.2`
> - `flywheel_connectors-j05nu.1.12.6`
> **Follow-on beads**:
> - `flywheel_connectors-j05nu.1.12.3`
> - `flywheel_connectors-j05nu.1.12.4`
> - `flywheel_connectors-j05nu.1.12.5`
> - `flywheel_connectors-j05nu.1.12.7`
> - `flywheel_connectors-j05nu.1.12.8`
> **Primary upstreams**:
> - https://developer.work.weixin.qq.com/

## Purpose

This document fixes the accepted first V3 slice for `fcp.wecom` so the follow-on runtime and capability work converges on the connector that actually exists today instead of a broader idea of "WeCom enterprise collaboration integration" that would mix outbound app sends, media lifecycle, tenant directory reads, inbound callbacks, websocket delivery, admin provisioning, and org sync into one undefined surface.

The accepted first slice below was request-response only. The current runtime still preserves that narrow tenant-app boundary, but it now also supports host-forwarded callback URL verification, callback event decrypt/normalization, and media download for inbound `media_id` references. It is still not a websocket session runtime, connector-owned webhook server, tenant admin SDK, or full WeCom messaging platform abstraction.

## Current Runtime Snapshot

The current crate exposes these operations:

- `wecom.messages.send_text`
- `wecom.messages.send_markdown`
- `wecom.messages.send_image`
- `wecom.messages.send_file`
- `wecom.media.upload`
- `wecom.media.download`
- `wecom.users.get`
- `wecom.departments.list`
- `wecom.callback.verify_url`
- `wecom.callback.ingest_event`
- `wecom.health`

Important implementation truths from `connector.rs`, `main.rs`, and `manifest.toml`:

- Configuration is `base_url`, `corp_id`, `agent_id`, `agent_secret`, bounded `request_timeout_ms`, and optional callback credentials (`callback_token`, `callback_encoding_aes_key`, optional `callback_receive_id`).
- One connector instance is bound to one WeCom tenant application through one `corp_id` / `agent_id` / `agent_secret` tuple.
- Authentication is application-level token bootstrap against `GET /cgi-bin/gettoken`; the access token is cached in memory only with a refresh safety margin.
- Text, markdown, image, and file sends all call `POST /cgi-bin/message/send`.
- Message sends require at least one WeCom targeting field: `touser`, `toparty`, or `totag`.
- Message sends claim the target through SDK chat coordination before provider HTTP, so duplicate active owners fail before token issuance or `POST /cgi-bin/message/send`.
- Successful send responses include a redaction-safe `coordination` audit array with claim and send-executed records; raw WeCom target identifiers are not copied into those records.
- Image and file sends consume a temporary `media_id`, which the caller obtains first from `wecom.media.upload`.
- The current send surface supports optional WeCom duplicate-check hints on outbound sends via `enable_duplicate_check` and `duplicate_check_interval`.
- The current send surface still does not expose WeCom voice, video, news, template-card, task-card, or recall semantics.
- Media upload uses `POST /cgi-bin/media/upload` and returns provider media metadata such as `media_id`.
- Media download uses `GET /cgi-bin/media/get` and returns base64-encoded bytes plus content metadata for a supplied `media_id`.
- `wecom.users.get` calls `GET /cgi-bin/user/get` and requires one `userid`.
- `wecom.departments.list` calls `GET /cgi-bin/department/list` with an optional `id`.
- `wecom.callback.verify_url` verifies the signed WeCom callback URL challenge and returns the decrypted plaintext response the host should echo back.
- `wecom.callback.ingest_event` verifies the signed callback POST, decrypts the `Encrypt` wrapper payload, checks timestamp skew plus nonce/`MsgId` replay state, applies configured sender/room/mention policy, and only then returns a normalized `EventEnvelope` with conversation stream keys and attachment references.
- The inbound model is host-forwarded HTTP callback handling, not a connector-owned socket. This is important because upstream WeCom callback delivery is signed and encrypted HTTP, not websocket-based streaming.
- `wecom.health` and `self_check()` are both grounded in token issuance, not in a separate provider health endpoint.
- `doctor()` is the operator-facing readiness surface. It summarizes configuration, host allowlist compliance, callback crypto readiness, handshake state, and redacted remediation guidance without attempting live provider mutations.
- `self_check()` now returns redacted structured details covering provisioning readiness, operator guidance, contract boundaries, and the last token-issuance probe outcome.
- `main.rs` accepts `subscribe` and `unsubscribe` RPC methods because of the shared connector interface, but the connector advertises `streaming = false` and both methods return `StreamingNotSupported`.
- The current crate has inline unit tests for configuration validation, message-send payload shape, callback crypto/XML handling, callback replay/policy behavior, and media transfer behavior, plus a crate-local host-forwarded callback e2e test.
- Runtime configuration validation currently allows only `qyapi.weixin.qq.com` plus `localhost` / `127.0.0.1` for deterministic tests. This first slice is deliberately narrower than a generic operator-supplied host model.

## Accepted First Slice

The accepted first WeCom slice is intentionally narrow:

- send one text message to WeCom users, parties, or tags
- send one markdown message to WeCom users, parties, or tags
- send one image message to WeCom users, parties, or tags using a previously uploaded `media_id`
- send one file message to WeCom users, parties, or tags using a previously uploaded `media_id`
- upload one temporary media object and return its provider metadata
- fetch one user profile by known `userid`
- list departments, optionally from a supplied department root
- expose a safe credential and reachability probe

This slice is intentionally closer to "tenant-bound enterprise app automation" than to "full WeCom collaboration platform integration."

## Service Inventory

| Surface | Status in first slice | Notes |
|---------|-----------------------|-------|
| Outbound text and markdown sends | In scope | Implemented through the WeCom app send API with explicit target fields and optional duplicate-check hints. |
| Outbound image and file sends | In scope in current runtime | Implemented through the same send API using a caller-supplied temporary `media_id` from `wecom.media.upload`. |
| Temporary media upload | In scope | Implemented so media-aware outbound flows and inbound attachment resolution can reference returned provider metadata. |
| Media download for inbound attachments | In scope in current runtime | Implemented for callback-derived `media_id` fetches; still bounded to explicit operator invocation. |
| User lookup | In scope | Implemented as direct lookup by known `userid`. |
| Department listing | In scope | Implemented as bounded org-structure discovery. |
| Credential and reachability probe | In scope | `wecom.health` and `self_check()` validate token issuance. |
| Host-forwarded inbound callbacks and event normalization | In scope in current runtime | Signature verification, AES decrypt, XML parse, and `EventEnvelope` normalization exist, but the host must own the actual HTTP endpoint. |
| Conversation or message history readback | Out of scope | The connector does not fetch prior messages, receipts, or chat state. |
| Rich message families beyond text, markdown, image, or file | Out of scope | No voice, video, news, template-card, task-card, or recall flows are exposed yet. |
| Tenant admin and provisioning flows | Out of scope | The connector does not create apps, manage secrets, or administer WeCom tenant policy. |
| Broad directory or org sync | Out of scope | The current runtime only exposes one user lookup and one department-list surface. |

## Auth And Scope Boundary

- One connector instance maps to one WeCom tenant application.
- Authentication is application-level `corp_id` + `agent_id` + `agent_secret`, exchanged for an access token.
- The connector caches access tokens in memory only and does not persist token material to disk.
- Optional callback verification is configured separately with `callback_token` plus `callback_encoding_aes_key`; when `callback_receive_id` is omitted it defaults to `corp_id`.
- The runtime acts as the configured enterprise application only. It does not impersonate arbitrary users and does not model delegated user OAuth.
- The operator must provision the WeCom application out of band, keep the app secret available to the connector, and grant the app whatever outbound-send and directory-read privileges are required for the intended tenant workflow.
- Stable first-slice target identifiers are:
  - `touser` for one or more known user IDs
  - `toparty` for one or more known department IDs
  - `totag` for one or more known tag IDs
  - `userid` for direct user-profile lookups
- The current runtime does not discover recipients for the caller. The caller must already know the intended user, department, or tag identifiers.
- The connector does not model cross-tenant brokering, user-granted OAuth, secretless credential injection, callback verification secrets, or message-origin validation in this first slice.

## Network And Runtime Invariants

- Production API host: `qyapi.weixin.qq.com`
- Port: `443`
- TLS + SNI required for live traffic
- Outbound message, media, directory, and health operations declare per-operation egress only to `qyapi.weixin.qq.com`
- Callback URL verification and callback event ingest are connector-local host-forwarded crypto/policy paths and declare a no-egress sentinel
- `localhost` and `127.0.0.1` remain accepted only in connector configuration for deterministic tests, not in production manifest egress constraints
- The runtime is request-response only
- No inbound listener, webhook server, or websocket loop exists inside the connector itself; callback replay state is a bounded connector-local safety cache loaded from the host-provided zone directory when available
- Callback ingress is a host-forwarded HTTP pattern: the host receives the GET or POST, then invokes `wecom.callback.verify_url` or `wecom.callback.ingest_event`
- Health proves credential issuance and basic API reachability, not inbound-event readiness
- Runtime config validation intentionally pins the first slice to the official WeCom API host rather than allowing arbitrary operator-selected endpoints in production
- The host allowlist assumption is part of the security boundary for this first slice: production traffic is constrained to the official WeCom API host, while local harnesses are the only accepted exception

## Readiness And Deployment Guidance

- Prefer `doctor()` as the fast preflight summary. It is purely local and tells the operator whether configuration, client initialization, endpoint policy, callback crypto material, and handshake state line up with the accepted first slice.
- Use `self_check()` when you need a live bounded probe. The connector performs token issuance against `GET /cgi-bin/gettoken` and returns redacted structured details instead of only a pass or fail bit.
- Use `wecom.health` inside capability-gated flows when a caller needs a lightweight runtime snapshot before making a mutation.
- For inbound callback deployments, the public HTTPS endpoint belongs to the host. The host receives the signed GET or POST, then forwards raw query/body material into `wecom.callback.verify_url` or `wecom.callback.ingest_event`; the connector does not expose its own listener.
- Callback readiness requires both `callback_token` and `callback_encoding_aes_key`. If those are omitted, outbound send and directory operations remain usable, but live callback verification and event ingest are not deployment-ready.
- Callback safety policy is configured with `callback_timestamp_skew_secs`, `callback_replay_window_secs`, `callback_replay_cache_entries`, `callback_allowed_user_ids`, `callback_allowed_external_user_ids`, `callback_allowed_room_ids`, `callback_dm_allowed`, `callback_room_allowed`, `callback_require_room_mention`, and `callback_mention_patterns`.
- Outbound send ownership is configured with optional `chat_coordination`: `enabled`, `ttl_seconds`, `fail_open`, `allowlist_channels`, `backend`, and `dm_mode`. This slice defaults to the in-memory backend for deterministic connector-local proof; production operators can select `agent_mail` or `mesh_gossip` through the shared SDK config surface.
- Duplicate callbacks are acknowledged as verified policy drops with `event: null` so hosts can safely return success to WeCom without re-emitting the event.
- Treat `agent_secret`, access tokens, callback secrets, decrypted callback plaintext, and tenant-specific IDs as sensitive. The connector’s readiness surfaces are intentionally redacted and should stay that way in external logs or artifacts.
- Recommended verification bundle:
  - `rch exec -- cargo fmt --manifest-path connectors/wecom/Cargo.toml --check`
  - `rch exec -- cargo check --manifest-path connectors/wecom/Cargo.toml --all-targets`
  - `rch exec -- cargo test --manifest-path connectors/wecom/Cargo.toml --lib`
  - `rch exec -- cargo clippy --manifest-path connectors/wecom/Cargo.toml -p fcp-wecom --all-targets --no-deps -- -D warnings`

## Verification Handoff

Verification script: `scripts/e2e/wecom_connector_verification.sh`

- Deterministic unit coverage now exercises:
  - outbound send payload shaping for text and image messages, including duplicate-check hints
  - outbound send ownership claims, redacted coordination audit records, and duplicate-owner denial before provider HTTP
  - media upload and media download request handling
  - callback URL verification, callback decrypt + XML parse, replay/policy gating, and normalized event routing
  - health and doctor readiness surfaces, including unconfigured and callback-ready states
- The current replayable evidence bundle is:
  - `rch exec -- cargo check --manifest-path connectors/wecom/Cargo.toml --all-targets`
  - `rch exec -- cargo clippy --manifest-path connectors/wecom/Cargo.toml -p fcp-wecom --all-targets --no-deps -- -D warnings`
  - `rch exec -- cargo test --manifest-path connectors/wecom/Cargo.toml --lib`
- The host-forwarded callback e2e harness is `cargo test --manifest-path connectors/wecom/Cargo.toml --test host_forwarded_callback_e2e`; it writes redaction-safe JSONL logs under the OS temp directory as `fcp-wecom-host-forwarded-callback-e2e-*/wecom_callback_e2e.jsonl`.
- Conformance note: the connector still truthfully models a host-forwarded callback transport, not a connector-owned listener or websocket stream. Verification should preserve that boundary rather than introducing fake standalone ingress behavior.
- Known infra noise outside the connector itself: `rch` can finish the remote command successfully and still fail artifact retrieval on the pathological `.beads/recovery_*` tree. Treat the remote cargo exit status as authoritative until that repo-level sync issue is repaired.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `wecom.messages.write` | Outbound text and markdown sends |
| `wecom.media.write` | Temporary media upload |
| `wecom.media.read` | Downloading bytes for a WeCom `media_id` |
| `wecom.users.read` | User profile lookup by known `userid` |
| `wecom.departments.read` | Department listing |
| `wecom.events.read` | Callback verification and inbound event normalization |
| `wecom.health.read` | Credential and reachability verification |

## Accepted Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Notes |
|-----------|----------------|------------|------------|-----------|-------------|-------|
| `wecom.messages.send_text` | `POST /cgi-bin/message/send` | `wecom.messages.write` | `Risky` | `Medium` | `None` | Claims the target through chat coordination before HTTP, then sends one text message to at least one supplied WeCom target family; accepts optional duplicate-check hints. |
| `wecom.messages.send_markdown` | `POST /cgi-bin/message/send` | `wecom.messages.write` | `Risky` | `Medium` | `None` | Claims the target through chat coordination before HTTP, then sends one markdown message to at least one supplied target family; accepts optional duplicate-check hints. |
| `wecom.messages.send_image` | `POST /cgi-bin/message/send` | `wecom.messages.write` | `Risky` | `Medium` | `None` | Claims the target through chat coordination before HTTP, then sends one image message using a previously uploaded temporary `media_id`; accepts optional duplicate-check hints. |
| `wecom.messages.send_file` | `POST /cgi-bin/message/send` | `wecom.messages.write` | `Risky` | `Medium` | `None` | Claims the target through chat coordination before HTTP, then sends one file message using a previously uploaded temporary `media_id`; accepts optional duplicate-check hints. |
| `wecom.media.upload` | `POST /cgi-bin/media/upload` | `wecom.media.write` | `Risky` | `Medium` | `BestEffort` | Uploads one temporary media object and returns provider metadata such as `media_id`. |
| `wecom.media.download` | `GET /cgi-bin/media/get` | `wecom.media.read` | `Safe` | `Low` | `Strict` | Downloads bytes for a known `media_id`, primarily for inbound callback attachments. |
| `wecom.users.get` | `GET /cgi-bin/user/get` | `wecom.users.read` | `Safe` | `Low` | `Strict` | Fetches one user profile for a known `userid`. |
| `wecom.departments.list` | `GET /cgi-bin/department/list` | `wecom.departments.read` | `Safe` | `Low` | `Strict` | Lists departments with an optional starting `id`. |
| `wecom.callback.verify_url` | host-forwarded callback GET | `wecom.events.read` | `Safe` | `Low` | `Strict` | Verifies the signed callback URL challenge and returns the plaintext response body the host should echo. |
| `wecom.callback.ingest_event` | host-forwarded callback POST | `wecom.events.read` | `Safe` | `Low` | `Strict` | Verifies, decrypts, replay-checks, policy-gates, and normalizes one signed callback event into an `EventEnvelope` when accepted. |
| `wecom.health` | `GET /cgi-bin/gettoken` | `wecom.health.read` | `Safe` | `Low` | `Strict` | Safe auth and reachability probe backed by token issuance. |

## Explicit Non-Goals

The accepted first WeCom slice does not include:

- message history readback, thread reconstruction, or receipt tracking
- voice, video, news, template-card, task-card, recall, or other richer message families beyond the current image/file send surface
- app provisioning, secret rotation, tenant admin, or org-policy management
- broad people or directory synchronization beyond direct user lookup and department listing
- user OAuth, delegated-user auth, or multi-tenant brokering
- connector-owned network listeners or websocket session management
- runtime enforcement of enterprise policy beyond capability verification and the documented scope boundary

These are excluded on purpose:

- The current runtime is a small tenant-app wrapper with explicit outbound/admin primitives, not a full collaboration or event-ingestion runtime.
- The parent feature's voice/video and richer-card ambitions belong to later beads and should not be implied by the current operation inventory.
- App-provisioning and callback-management flows are a different trust and risk class from bounded outbound messaging and read-only tenant lookup surfaces.

## Implementation Notes For `flywheel_connectors-j05nu.1.12.2`

- Preserve the one-tenant, one-app boundary. Do not widen the runtime into a multi-tenant broker.
- Keep token cache state in memory only and make refresh behavior explicit; token issuance is the central readiness dependency for this connector.
- Keep the first-slice host boundary explicit around `qyapi.weixin.qq.com` for production and deterministic localhost harnesses for tests.
- Preserve the current target model where at least one of `touser`, `toparty`, or `totag` is required for sends.
- Do not silently expand the current runtime beyond text, markdown, image, and file sends, inbound callbacks, and user-impersonation exclusions as part of the typed-config or client refactor.
- Error mapping should preserve provider error detail such as `errcode` / `errmsg` rather than collapsing failures into opaque internal errors.

## Source Notes

This contract is grounded in the current connector implementation:

- `connectors/wecom/src/connector.rs` defines the operation inventory, token bootstrap, input validation, capability boundary, and current truth about send, upload, and lookup behavior.
- `connectors/wecom/src/main.rs` confirms the connector is currently a request-response JSON-RPC loop with no streaming implementation.
- `connectors/wecom/manifest.toml` defines the current capability families, zone posture, sandbox profile, and production host assumptions.
- The WeCom developer portal documents the broader enterprise messaging platform, including the richer outbound and inbound surfaces that remain explicit non-goals for this first slice.

## Operation Inventory

See the operation table above (`send_text`, `send_markdown`, `send_image`, `send_file`, `upload_media`, `download_media`, `get_user`, `list_departments`, `callback_verify_url`, `callback_ingest_event`, `health`).

## Operator Guidance

Prerequisites:
- Use the deterministic loopback harness for local verification; never log raw `agent_secret`, access tokens, or AES callback keys.

Rerun commands:
- `bash scripts/e2e/wecom_connector_verification.sh`
- `rch exec -- cargo test -p fcp-wecom --test local_non_mock -- --nocapture`
- `rch exec -- cargo test -p fcp-wecom --test host_forwarded_callback_e2e -- --nocapture`
- `rch exec -- cargo clippy -p fcp-wecom --all-targets -- -D warnings`
