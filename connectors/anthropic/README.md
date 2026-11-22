# Anthropic Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://docs.anthropic.com/
> **Claude Code auth docs cited**: https://code.claude.com/docs/en/authentication and https://code.claude.com/docs/en/settings

## Purpose

This document fixes the operator-facing contract for `fcp.anthropic`. The connector exposes Anthropic Claude through the Messages API, a simple single-turn chat wrapper, SSE message streaming, local usage accounting, auth-method introspection, OAuth refresh status reporting, and model normalization.

The connector is built around Claude Messages. It does not expose Anthropic Files, Batches, Admin, or workspace-management APIs.

## Current Runtime Snapshot

The current crate exposes these operations:

- `anthropic.chat`
- `anthropic.message`
- `anthropic.message.stream`
- `anthropic.get_usage`
- `anthropic.auth.list_methods`
- `anthropic.auth.refresh_oauth`
- `anthropic.models.normalize`

Important runtime truths the contract preserves:

- Configuration accepts exactly one auth method: `api_key`, `auth_token`, `bearer_token`, `claude_code_oauth_token`, `oauth_token`, `setup_token`, or `credential_id`.
- This connector intentionally does not implement Claude Code's own credential-precedence chain. Connector configuration is stricter: choose one FCP auth source per configured instance.
- Current Claude Code precedence puts cloud-provider env auth first, then `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_API_KEY`, `apiKeyHelper`, `CLAUDE_CODE_OAUTH_TOKEN`, and finally subscription OAuth from `/login`.
- `claude setup-token` prints a one-year OAuth token for `CLAUDE_CODE_OAUTH_TOKEN`; the connector can reject unsafe direct API use and report its lifetime boundary, but it cannot mint, persist, or refresh that token.
- `credential_id` must parse as a UUID and requires host-side egress credential injection for live traffic.
- API-key mode sends `x-api-key`.
- Bearer-token mode sends `Authorization: Bearer ...` for provider-mediated or gateway deployments.
- Claude Code OAuth and setup-token modes are Claude Code runtime credentials, not direct default Anthropic API credentials; configuration rejects them against `https://api.anthropic.com` and only allows them behind a localhost verification or host-managed provider boundary.
- Claude Code OAuth and setup-token modes automatically add `claude-code-20250219` and `oauth-2025-04-20` beta headers when they are configured behind that boundary.
- Default base URL is `https://api.anthropic.com`.
- Loopback HTTP base URLs are accepted only for deterministic tests.
- Default API version is `2023-06-01`, overridable by config `api_version` or `FCP_ANTHROPIC_API_VERSION`.
- Default model is `claude-sonnet-4-6`.
- Supported models are limited to the crate-local canonical list and aliases normalized by `Model::normalize`.
- Prompt-cache accounting preserves Anthropic's detailed `cache_creation.ephemeral_5m_input_tokens` and `cache_creation.ephemeral_1h_input_tokens` counters; local cost estimates charge 1-hour cache writes at the higher TTL rate.
- Image requests are accepted only as Anthropic image blocks with supported media types (`image/jpeg`, `image/png`, `image/gif`, `image/webp`) or `http`/`https` image URLs, capped at 600 images per request.
- `claude-opus-4-7` accepts adaptive thinking only; the connector rejects manual `thinking: {"type":"enabled"}` for that model before provider I/O.
- Thinking is rejected with non-default temperature and forced tool choice before provider I/O.
- Thinking content is never returned verbatim in `content_blocks`; it is represented as `{"type":"thinking","redacted":true}`.
- `anthropic.message.stream` consumes provider SSE and returns one assembled invocation result with tool-use blocks, usage, and provenance. The native host does not advertise an FCP event stream or subscription support.
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`, the actual instance identifier, and only supported capabilities requested by the host.
- Configuration and handshake attempts revoke previous authority, including rejected attempts. A new handshake rotates the instance; reconfiguration is required before binding the account to a different zone.
- Introspection exposes all seven operations directly from the manifest, including the local auth and model helpers.

## Native Host Contract

The executable uses the shared bounded JSONL transport and protocol `2.0` or `2.0.0` handshake. Invocation parameters are a complete FCP `InvokeRequest`: `type`, a nonempty `id`, `connector_id: "fcp.anthropic"`, `zone_id`, `operation`, object `input`, and `capability_token`. JSON-RPC transport IDs and invocation IDs are independent. Successful invocation results use the complete `InvokeResponse` envelope.

Health follows `HealthSnapshot`. Configuration alone reports degraded readiness until handshake succeeds. Redacted account metadata, actual instance, configured/handshaken state, bound zone, and counters are in `details`. Shutdown terminates the native loop without waiting for stdin to close and prevents buffered requests from running afterward.

Invocation and simulation validate the manifest input schema and local model, thinking, tool, and media rules. Model aliases are normalized before capability resource checks, so a canonical model deny rule also covers its aliases. Authorization checks the requested connector, negotiated zone and capabilities, signed operation scope, and actual instance.

Admitted invocations enforce signed call and byte budgets through the shared session. The byte counter covers the compact complete FCP request and response; it does not meter provider HTTP traffic. Native JSONL requests and released invocation responses have 16 MiB limits. Simulation performs no provider request and consumes no call allowance; a successful preview does not reserve execution capacity. Provider retry and cancellation behavior remains owned by the existing client/runtime path.

## First-Slice Scope

The first Anthropic README slice documents the existing runtime surface:

- single-turn `anthropic.chat` requests
- multi-message `anthropic.message` requests with system content, tools, cache control, service tier, thinking, output config, and per-request beta headers
- SSE `anthropic.message.stream` requests with text, thinking, tool-use, usage, and stop-reason aggregation
- local token and cost counters through `anthropic.get_usage`
- auth method listing and OAuth refreshability reporting
- model alias normalization and 1M-context guardrails
- prompt-cache TTL accounting and 1-hour cache cost handling
- local image/media request validation
- unsupported thinking-mode denial before provider I/O
- bound capability-token verification before dispatch
- redaction-safe diagnostics and live skip/pass test behavior

## Auth And Scope Boundary

- Authentication mechanisms: Anthropic API key, bearer token, Claude Code OAuth token, setup token, or host-injected credential ID.
- Direct Anthropic API calls use `api_key` or `credential_id`; Claude Code OAuth and setup-token credentials must be routed through a host-managed Claude CLI/provider boundary or a localhost verification fixture.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden source zone: `z:public`.
- Capability surface:
  - `anthropic.chat` gates simple chat requests.
  - `anthropic.message` gates structured non-streaming Messages API requests.
  - `anthropic.message.stream` gates streaming Messages API requests.
  - `anthropic.get_usage` gates local usage/cost counters.
  - `anthropic.auth` gates auth method and OAuth refresh status operations.
  - `anthropic.models` gates model normalization.
- The connector does not persist prompts, completions, thinking content, streamed chunks, tool inputs, usage snapshots, provider payloads, or provider responses.
- The connector exposes local usage counters only; remote organization usage snapshots remain host/provider-router scope because they require host-owned OAuth/API account authority outside the direct Messages capability.
- Credential-id mode is a host-egress contract, not direct proof that live Anthropic will accept the request without an injection layer.

## Network And Runtime Invariants

- Production host: `api.anthropic.com`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and unsafe host forms for live operations.
- Base URL overrides must be origins without path, query, or fragment.
- Localhost HTTP overrides are test-only.
- Request connect timeout: `10_000 ms`.
- Total operation timeout: `120_000 ms`.
- Maximum response bytes are `10_485_760`.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120_000 ms` wall-clock timeout, read-only `/usr` and `/lib`, no exec, and no ptrace.
- Handshake event capabilities remain disabled: provider SSE is buffered into the invocation response, and the native transport does not emit incremental FCP events.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `anthropic.chat` | Send a simple one-turn chat request. |
| `anthropic.message` | Send structured multi-message Claude requests with optional tools and advanced options. |
| `anthropic.message.stream` | Stream a structured Claude response through SSE and return an assembled result. |
| `anthropic.get_usage` | Read local request, token, and cost counters. |
| `anthropic.auth` | Inspect configured auth mode and refreshability metadata. |
| `anthropic.models` | Normalize Claude model aliases to canonical API IDs. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `anthropic.chat` | `POST /v1/messages` | `anthropic.chat` | `Safe` | `Medium` | `None` | Model output depends on prompt, model, system content, and advanced generation options. |
| `anthropic.message` | `POST /v1/messages` | `anthropic.message` | `Safe` | `Medium` | `None` | Structured conversation output depends on message history, tools, thinking, cache, and service-tier input. |
| `anthropic.message.stream` | `POST /v1/messages` with SSE | `anthropic.message.stream` | `Safe` | `Medium` | `None` | Stream output depends on event ordering, content-block deltas, and provider stop metadata. |
| `anthropic.get_usage` | Local counters | `anthropic.get_usage` | `Safe` | `Low` | `Strict` | Read-only local accounting for this connector instance. |
| `anthropic.auth.list_methods` | Local metadata | `anthropic.auth` | `Safe` | `Low` | `Strict` | Read-only auth capability discovery. |
| `anthropic.auth.refresh_oauth` | Local metadata | `anthropic.auth` | `Safe` | `Low` | `Strict` | Reports that Claude Code OAuth/setup-token credentials are not connector-refreshable and must be rotated outside the connector. |
| `anthropic.models.normalize` | Local normalization | `anthropic.models` | `Safe` | `Low` | `Strict` | Deterministic alias-to-model mapping. |

## Explicit Non-Goals

The current implementation does not include:

- Anthropic Files, Batches, Admin, workspace, or organization APIs
- persistent conversation storage
- FCP subscription-based streaming
- direct credential vaulting or OAuth refresh
- direct use of Claude Code subscription/setup tokens against `https://api.anthropic.com`
- connector-local minting, storage, or refresh of `claude setup-token` output
- public-zone invocation
- connector-local storage of prompts, thinking traces, streamed deltas, or tool inputs
- automatic 1M-context beta header injection for retired beta paths
- replay or duplicate-request rehydration; direct Messages calls remain non-idempotent and `event_caps.replay=false`
- remote organization/workspace usage snapshots; `anthropic.get_usage` is connector-local accounting

These are excluded on purpose:

- The useful first slice is Claude Messages with clear FCP capability boundaries.
- Host credential flows own OAuth and credential refresh behavior.
- Thinking output can expose sensitive intermediate work, so the connector redacts it from structured content blocks.
- Replay and provider-wide usage snapshots belong in a host/router surface that can own idempotency receipts, account authority, and credential refresh.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, auth mode, base URL, API version, request counters, error counters, and cost totals
- redacted auth labels rather than raw API keys or bearer tokens
- base URL policy for `api.anthropic.com` and loopback-compatible origins
- credential-injection status for secretless mode
- operation schemas, safety, risk, idempotency, and AI hints
- simulation checks for the same input schema, provider semantics, target, zone, negotiated capability, and normalized model resources used by invocation

Deterministic coverage includes the actual shipped executable connected to a loopback HTTP/SSE server, alongside WireMock and connector-local tests covering:

- simple chat and multi-turn message invokes
- system prompts
- SSE chunk parsing, ping keepalives, and mid-stream error events
- tool use and streamed tool-input JSON deltas
- 401, 429, 529, 500, and context-length error mapping
- usage and cost accounting
- default-deny capability-token behavior, signed call/byte limits, and canonical-model alias scopes
- native response and health schemas, bounded JSONL framing, malformed input recovery, and shutdown with buffered input
- lifecycle revocation for successful and failed configure/handshake attempts, zone binding, health, doctor, self-check, introspection, simulate, and shutdown
- live verification skip/pass behavior gated by `ANTHROPIC_API_KEY`

## Source Notes

- `connectors/anthropic/src/client.rs` defines auth headers, API-version resolution, retry behavior, usage counters, health checks, Messages API calls, and SSE parsing.
- `connectors/anthropic/src/connector.rs` defines configuration validation, capability verification, operation dispatch, thinking redaction, introspection, simulation, and lifecycle behavior.
- `connectors/anthropic/src/types.rs` defines Claude model IDs, alias normalization, pricing, 1M-context support, Messages request/response types, content blocks, tools, cache control, service tier, thinking, and stream events.
- `connectors/anthropic/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, event capability metadata, and no-listener/no-storage/no-exec posture.
- `connectors/anthropic/tests/conformance_contract.rs` checks contract-level operation metadata.
- `connectors/anthropic/tests/provider_contract.rs` checks provider/auth behavior.
- `connectors/anthropic/tests/v3_lifecycle.rs` checks lifecycle expectations.
- `connectors/anthropic/tests/integration.rs` covers deterministic loopback, authority transitions, local admission, and error behavior.
- `connectors/anthropic/tests/native_host.rs` drives the shipped executable through real pipes and loopback HTTP/SSE with signed budgeted tokens.
- `connectors/anthropic/tests/live_verification.rs` emits live skip/pass results when `ANTHROPIC_API_KEY` is absent or present.
- Claude Code authentication docs define the current CLI auth precedence and setup-token semantics; this connector keeps those credentials out of direct `api.anthropic.com` calls unless a host-managed or loopback boundary is explicitly configured.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/anthropic_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock integration coverage
- live provider smoke tests gated by `ANTHROPIC_API_KEY`
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use `ANTHROPIC_API_KEY` only for live provider verification.
- Use WireMock loopback fixtures for deterministic proof.
- Use `FCP_ANTHROPIC_API_VERSION` only when the operator intentionally needs a non-default version header.

**Dedicated environment**:

- Prefer deterministic loopback evidence for routine verification.
- Use a test Anthropic account for live runs and keep live prompts intentionally small.
- Treat Claude Code OAuth and setup-token auth as host-mediated credentials.

**Redaction rules**:

- Redact API keys, bearer tokens, setup tokens, credential IDs where needed, prompts, completions, thinking blocks, streamed text chunks, tool inputs, provider payloads, and provider error bodies.
- Verification output should use counts, byte lengths, operation IDs, status values, error classes, model IDs when non-sensitive, and cleanup state.

**Common remediation**:

- If health details report `configured=false`, configure with exactly one auth method and then run handshake. If `configured=true` and `handshaken=false`, negotiate a new session and sign tokens for its returned `instance_id`.
- If `self_check` reports `credential_injection_required`, run behind the host egress injection layer or switch to a direct live-test key.
- If `claude_code_oauth_token`, `oauth_token`, or `setup_token` is rejected against the default API origin, use `api_key` or `credential_id` for direct Anthropic API calls, or route the Claude Code credential through a host-managed Claude CLI/provider boundary.
- If `anthropic.auth.refresh_oauth` reports `refreshable=false`, rerun `claude setup-token` or rotate the host-managed credential outside the connector, then reconfigure with the new token.
- If base URL validation fails, use `https://api.anthropic.com` or a localhost origin for tests.
- If a model is rejected, run `anthropic.models.normalize` or choose one of the supported canonical IDs.
- If `enable_1m_context` fails, switch to `claude-opus-4-7`, `claude-opus-4-6`, or `claude-sonnet-4-6`.
- If `claude-opus-4-7` rejects manual thinking, use `thinking: {"type":"adaptive"}` with `output_config.effort`.
- If thinking conflicts with `temperature` or forced tool choice, remove those controls or disable thinking for that request.
- If an image request is rejected, use one of the supported image media types, an `http`/`https` image URL, and no more than 600 images.
- If a streamed response looks incomplete, inspect SSE event ordering and `stop_reason` before changing aggregation logic.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-anthropic-e2e cargo check -p fcp-anthropic --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-anthropic-e2e cargo test -p fcp-anthropic --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-anthropic-e2e cargo test -p fcp-anthropic --test live_verification -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-anthropic-e2e cargo clippy -p fcp-anthropic --all-targets --no-deps -- -D warnings`
