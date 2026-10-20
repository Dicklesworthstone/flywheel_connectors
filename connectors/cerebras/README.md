# Cerebras Connector V3 Contract

> **Status**: PROVEN (2026-10-20; 12/12 graduation gauntlet, verifier + unit/integration/local_non_mock suites verified)
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/cerebras_connector_verification.sh`
> **Primary upstream**: https://inference-docs.cerebras.ai/

## Purpose

This document fixes the operator-facing contract for `fcp.cerebras`. The connector exposes Cerebras Inference through the OpenAI-compatible chat-completions surface, SSE chat-completion streaming, model listing, and a bounded health probe.

The connector is intentionally narrow. It does not expose Cerebras embeddings as an invokable provider call; `cerebras.embeddings.create` is declared only so introspection can honestly report that embeddings are not supported by this first-party Cerebras slice.

## Current Runtime Snapshot

The current crate exposes these operations:

- `cerebras.chat.completions`
- `cerebras.chat.completions_stream`
- `cerebras.models.list`
- `cerebras.health`
- `cerebras.embeddings.create`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of `api_key` or `credential_id`.
- API-key mode sends `Authorization: Bearer ...`.
- Credential-id mode sends `x-fcp-credential-id` and requires host-side egress credential injection for live traffic.
- Default base URL is `https://api.cerebras.ai/v1`.
- Base URL overrides must use path `/v1`, must not include query or fragment components, and may only target `api.cerebras.ai` or loopback test hosts.
- Loopback HTTP/HTTPS base URLs are accepted only for deterministic tests.
- Default model is `llama3.1-8b`.
- Default `request_timeout_ms` is `180_000`.
- Default `model_cache_ttl_seconds` is `3600`.
- `wait_on_rate_limit_ms` switches rate-limit behavior from fail-fast to bounded wait/retry.
- The client parses Cerebras request and token rate-limit headers and honors `retry-after` when the configured wait policy permits it.
- `cerebras.models.list` uses a shared in-memory model cache and supports `{"refresh": true}` to invalidate it.
- FCP subscribe is not implemented; streaming is exposed as the bounded invoke operation `cerebras.chat.completions_stream`.
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.

## First-Slice Scope

The first Cerebras README slice documents the existing runtime surface:

- non-streaming chat completions through `POST /v1/chat/completions`
- SSE chat completions through the same endpoint with `stream: true`
- model discovery through `GET /v1/models`
- a health operation backed by a short model-list probe
- local validation for empty messages, duplicate token-budget fields, invalid auth material, and invalid base URLs
- rate-limit retry behavior for configured bounded waits
- redaction-safe doctor and error output
- bound capability-token verification before dispatch
- an explicit not-supported embeddings operation for introspection honesty

## Auth And Scope Boundary

- Authentication mechanisms: Cerebras API key or host-injected credential ID.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, `z:work`, and `z:project:*`.
- Allowed target zone: `z:work`.
- Forbidden source zone: `z:public`.
- Capability surface:
  - `cerebras.chat` gates chat and streaming chat completions.
  - `cerebras.models.read` gates model listing.
  - `cerebras.health.read` gates the health probe.
  - `cerebras.embeddings` is associated only with the not-supported embeddings declaration.
- The connector does not persist prompts, completions, streamed chunks, tool-call arguments, model catalogs, provider payloads, or provider responses.
- Credential-id mode is a host-egress contract, not proof that live Cerebras will accept a request without an injection layer.

## Network And Runtime Invariants

- Production host: `api.cerebras.ai`.
- Production path root: `/v1`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and unsafe host forms for live operations.
- Localhost HTTP/HTTPS overrides are test-only.
- Runtime default `request_timeout_ms`: `180_000`.
- Manifest chat and streaming network constraints set connect timeout `10_000 ms` and total timeout `180_000 ms`.
- Manifest model-list network constraints set total timeout `30_000 ms`.
- Manifest health network constraints set total timeout `5_000 ms`.
- Maximum response bytes are `10_485_760`.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `180_000 ms` wall-clock timeout, no exec, and no ptrace.
- Event capability metadata declares streaming support, no replay, no acknowledgement requirement, and a minimum buffer of 0 events.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `cerebras.chat` | Send non-streaming and streaming chat-completion requests. |
| `cerebras.models.read` | List available Cerebras model IDs with cache reuse. |
| `cerebras.health.read` | Probe provider reachability through a bounded model-list request. |
| `cerebras.embeddings` | Report the intentionally unavailable embeddings surface. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `cerebras.chat.completions` | `POST /v1/chat/completions` | `cerebras.chat` | `Safe` | `Medium` | `None` | Model output depends on prompt, tools, sampling options, and model ID. |
| `cerebras.chat.completions_stream` | `POST /v1/chat/completions` with SSE | `cerebras.chat` | `Safe` | `Medium` | `None` | Stream output depends on event ordering, content deltas, tool-call deltas, and finish metadata. |
| `cerebras.models.list` | `GET /v1/models` | `cerebras.models.read` | `Safe` | `Low` | `Strict` | Read-only model catalog discovery with in-memory caching. |
| `cerebras.health` | `GET /v1/models` bounded probe | `cerebras.health.read` | `Safe` | `Low` | `Strict` | Read-only readiness probe for credentials and network path. |
| `cerebras.embeddings.create` | Local not-supported response | `cerebras.embeddings` | `Safe` | `Low` | `None` | Declared for honest introspection; invocation fails before provider dispatch. |

## Explicit Non-Goals

The current implementation does not include:

- invokable Cerebras embeddings
- image, audio, video, file, batch, fine-tuning, admin, or deployment-management APIs
- FCP subscription-based streaming
- connector-local credential vaulting
- public-zone invocation
- durable storage of prompts, completions, model catalogs, streamed deltas, or provider errors
- proxying unsupported embeddings through a different provider

These are excluded on purpose:

- The useful first slice is a direct first-party Cerebras chat and model-discovery connector.
- Unsupported embeddings are represented explicitly so operators do not infer a hidden fallback.
- Provider credentials and host egress injection stay outside the connector-local storage boundary.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, auth mode, base URL, default model, request counters, and error counters
- redacted auth labels rather than raw API keys
- base URL policy for `api.cerebras.ai/v1` and loopback-compatible test origins
- credential-injection status for secretless mode
- operation schemas, safety, risk, idempotency, and AI hints
- simulate-time operation support, including the embeddings not-supported explanation
- capability-token checks against bound resources before dispatch

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- API-key and credential-id auth header behavior
- base URL normalization and rejection
- Cerebras and Cloudflare-style rate-limit header parsing
- non-streaming chat completion dispatch and redacted doctor output
- SSE chunk assembly without prompt echoing
- model-list caching and health reuse of the shared client
- bounded rate-limit retry behavior
- long completion handling without prompt leakage
- provider error mapping with sensitive body redaction
- embeddings failing locally before network dispatch
- duplicate token budget rejection before network dispatch
- FCP trait invoke, capability-token validation, and shutdown behavior

## Source Notes

- `connectors/cerebras/src/client.rs` defines auth headers, base URL normalization, user agent, Cerebras rate-limit header mapping, OpenAI-compatible request dispatch, model listing, and model-cache invalidation.
- `connectors/cerebras/src/connector.rs` defines configuration validation, lifecycle handlers, operation dispatch, capability verification, introspection, simulation, health, doctor, self-check, and shutdown behavior.
- `connectors/cerebras/src/types.rs` defines chat input parsing and local validation for messages, token-budget fields, and provider extensions.
- `connectors/cerebras/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and not-supported embeddings declaration.
- `connectors/cerebras/tests/conformance.rs` checks manifest operation coverage, network policy, sandbox timeout, and runtime introspection parity.
- `connectors/cerebras/tests/integration.rs` covers deterministic loopback behavior, error mapping, rate-limit retry, redaction, unsupported embeddings, and FCP trait behavior.

## Verification Bundle

The dedicated `scripts/e2e/cerebras_connector_verification.sh` bundle records the closeout surface for this connector.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock integration coverage
- base URL, auth, rate-limit, and redaction tests
- formatting, check, and clippy proof through `rch`
- extracted local non-mock JSONL evidence with prompt, response, API key, and loopback endpoint redaction checks
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a Cerebras API key only for live provider verification.
- Use `credential_id` only behind a host egress injection layer.
- Use WireMock loopback fixtures for deterministic proof.

**Dedicated environment**:

- Prefer deterministic loopback evidence for routine verification.
- Use a test Cerebras account for live runs and keep live prompts intentionally small.
- Do not treat the not-supported embeddings operation as a fallback or provider bridge.

**Redaction rules**:

- Redact API keys, credential IDs where needed, prompts, completions, reasoning text, streamed chunks, tool-call arguments, model-list response bodies, provider payloads, and provider error bodies.
- Verification output should use counts, byte lengths, operation IDs, model IDs when non-sensitive, status values, error classes, and cleanup state.

**Common remediation**:

- If `health` reports `unconfigured`, configure with exactly one of `api_key` or `credential_id`.
- If `health` reports `degraded`, complete handshake before invoking operations that require bound capability tokens.
- If `self_check` reports `credential_injection_required`, run behind the host egress injection layer or switch to direct API-key mode for live probes.
- If base URL validation fails, use `https://api.cerebras.ai/v1` or a loopback `/v1` origin for tests.
- If both `max_tokens` and `max_completion_tokens` are set, keep only one token-budget field.
- If `cerebras.embeddings.create` is requested, route the request to a connector that actually supports embeddings.

**Rerun commands**:

- `RUN_ID=manual-cerebras OUT_ROOT=/Volumes/trj-data/fcp-artifacts/cerebras/manual-cerebras CARGO_TARGET_PREFIX=/Volumes/trj-data/tmp/fcp-cerebras-manual scripts/e2e/cerebras_connector_verification.sh`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-cerebras-e2e cargo check -p fcp-cerebras --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-cerebras-e2e cargo test -p fcp-cerebras --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-cerebras-e2e cargo clippy -p fcp-cerebras --all-targets --no-deps -- -D warnings`
