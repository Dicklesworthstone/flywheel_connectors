# DeepSeek Connector V3 Contract

> **Status**: PROVEN manifest-derived runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Interface hash**: `blake3-256:fcp.interface.v2:a2d5c2ff83484ed0e81fce9363edaafe7b2e0ff22bca65ec3e35b3e4538b588f`
> **Verification script**: `scripts/e2e/deepseek_connector_verification.sh`
> **Primary upstream**: https://api-docs.deepseek.com/

## Purpose

This document fixes the operator-facing contract for `fcp.deepseek`. The connector exposes DeepSeek through OpenAI-compatible chat, SSE chat streaming, model listing, and a bounded health probe while preserving DeepSeek reasoning output separately from final answer content.

The connector also declares an embeddings operation for introspection honesty. DeepSeek's first-party API does not currently expose embeddings through this connector, so `deepseek.embeddings.create` deterministically returns not supported before network dispatch.

## Current Runtime Snapshot

The current crate exposes these operations:

- `deepseek.chat.completions`
- `deepseek.chat.completions_stream`
- `deepseek.embeddings.create`
- `deepseek.models.list`
- `deepseek.health`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of `api_key` or `credential_id`, plus optional `base_url`, default model, request timeout, model-cache TTL, and rate-limit wait policy.
- API-key mode sends a bearer token to DeepSeek.
- Credential-id configuration is recognized, but this connector does not yet implement host-mediated credential injection. Readiness is degraded and invoke/simulate refuse provider work in this mode.
- Default base URL is `https://api.deepseek.com`.
- `https://api.deepseek.com/v1` is also accepted.
- Loopback HTTP base URLs are accepted for deterministic tests.
- Default model is `deepseek-v4-pro`.
- `thinking.type` accepts `enabled` or `disabled`.
- `reasoning_effort` accepts `high`, `max`, `low`, `medium`, or `xhigh`.
- Non-streaming chat returns `reasoning_content` separately from `content` when the provider includes it.
- SSE chat streaming assembles `reasoning_content` and final `content` separately and records only delta byte counts in chunk metadata.
- FCP subscribe is not implemented; streaming is a bounded invoke operation.
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.
- Handshake accepts only the manifest's `z:work` target zone, negotiates declared capabilities, and reports the actual rotated instance ID. Configure, rehandshake, and shutdown invalidate the preceding authority, including failed replacement attempts.
- Native and typed invokes use the complete FCP request envelope. Connector, zone, operation, instance, model resources, and signed key scopes are checked before provider traffic.
- Signed call and message-byte limits use the shared SDK's atomic session accounting. Request bytes and response reservations are charged before dispatch; failures, cancellation, and oversized responses retain the charge. This is FCP-message accounting, not provider billing or mesh-global quota.
- Simulate performs the same input and authority checks without provider I/O or consuming the call allowance. Strict model-list and health invokes require a non-empty `idempotency_key`; this requirement does not add result deduplication.
- Runtime introspection derives operation descriptions, schemas, capabilities, safety, risk, idempotency, approval mode, rate-limit metadata, and AI hints from the embedded manifest while preserving the five-operation order below.

## First-Slice Scope

The first DeepSeek slice is intentionally narrow:

- create non-streaming DeepSeek chat completions from caller-supplied message arrays
- create SSE chat completions and return assembled content, assembled reasoning content, chunk counts, and redaction-safe chunk metadata
- forward typed DeepSeek extensions such as `thinking`, `reasoning_effort`, and `user_id`
- list and cache DeepSeek model IDs
- run a bounded health probe using model listing
- declare embeddings as unavailable without dispatching provider traffic
- enforce capability-token checks for invoke paths
- emit redaction-safe loopback and optional live JSONL evidence

## Auth And Scope Boundary

- Authentication mechanism: DeepSeek API key. Credential-id mode remains unavailable for live invocation until host-mediated transport is implemented.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden source zone: `z:public`.
- Capability surface:
  - `deepseek.chat` gates chat and SSE chat operations.
  - `deepseek.models.read` gates model discovery.
  - `deepseek.health.read` gates the health probe.
  - `deepseek.embeddings` gates the introspection-only embeddings placeholder.
- The connector does not persist prompts, completions, reasoning content, streamed chunks, model catalogs, provider payloads, or provider responses.
- Model resource checks bind the exact typed model sent to the provider, including a configured default. Accepted remote image URLs also require `deepseek:image_url:<canonical-url>` resource authority; inline data remains part of the metered request. Provider extensions cannot override standard request fields or bypass typed DeepSeek controls.

## Network And Runtime Invariants

- Production host: `api.deepseek.com`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and unsafe host forms for live operations.
- Localhost HTTP overrides are test-only.
- Default request timeout: `240_000 ms`.
- Model-list timeout: `30_000 ms`.
- Health probe timeout: `5_000 ms`.
- SSE chat streaming declares a `300_000 ms` network ceiling, but the configured timeout and `240_000 ms` sandbox ceiling further constrain each invocation. Configuration cannot extend that sandbox limit.
- One shared request budget covers input validation, cache access, provider retries, streaming setup, and the complete SSE body. The caller's deadline, configured timeout, native execution deadline, and operation ceiling can only shorten it. Expired or cancelled work is not automatically retried.
- Maximum response bytes are `10_485_760`.
- The complete returned FCP envelope is also capped at `10_485_760` bytes, or the signed grant's remaining byte allowance if smaller. Responses exceeding that allowance are withheld.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `240_000 ms` wall-clock timeout, no exec, and no ptrace.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `deepseek.chat` | Create DeepSeek chat and SSE chat completions. |
| `deepseek.models.read` | List DeepSeek model identifiers. |
| `deepseek.health.read` | Run a bounded model-list readiness probe. |
| `deepseek.embeddings` | Represent the intentionally unavailable embeddings operation in introspection. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `deepseek.chat.completions` | `POST /chat/completions` | `deepseek.chat` | `Safe` | `Medium` | `None` | Model output depends on prompt, tools, sampling input, thinking mode, and reasoning effort. |
| `deepseek.chat.completions_stream` | `POST /chat/completions` with SSE | `deepseek.chat` | `Safe` | `Medium` | `None` | Streaming output depends on event ordering and provider deltas. |
| `deepseek.embeddings.create` | Not dispatched | `deepseek.embeddings` | `Safe` | `Low` | `None` | Declared for introspection honesty; first-party DeepSeek embeddings are not supported here. |
| `deepseek.models.list` | `GET /models` | `deepseek.models.read` | `Safe` | `Low` | `Strict` | Read-only model catalog discovery with in-memory cache support. |
| `deepseek.health` | `GET /models` bounded probe | `deepseek.health.read` | `Safe` | `Low` | `Strict` | Health probe confirms DeepSeek reachability and model-list path. |

## Explicit Non-Goals

The first implementation slice does not include:

- embeddings dispatch to DeepSeek or to a third-party provider
- image generation, video generation, speech APIs, file upload APIs, fine-tuning, batch jobs, or dataset APIs
- FCP subscription-based streaming
- persistent prompt, completion, reasoning, stream, or model-cache storage
- direct credential vaulting
- public-zone invocation
- translating deprecated model aliases into current v4 model IDs

These are excluded on purpose:

- The useful first slice is first-party DeepSeek chat with explicit separation between reasoning output and final answer output.
- Embeddings would be misleading if proxied through another provider or silently simulated.
- Reasoning content can expose sensitive intermediate work, so verification records only byte lengths and status metadata.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake, auth mode, base URL, default model, request counters, and error counters
- redacted auth labels rather than bearer tokens
- base URL policy for `api.deepseek.com`, optional `/v1`, and loopback-compatible paths
- explicit reasoning redaction policy
- model-list probe health metadata
- operation schemas, safety, risk, idempotency, and AI hints
- manifest-derived runtime operation metadata parity
- deterministic denial for unsupported embeddings

The deterministic integration evidence is anchored on WireMock loopback runs covering:

- non-reasoning chat with `thinking.type = disabled`
- reasoning chat with `thinking.type = enabled`
- SSE streaming that assembles reasoning and final content separately
- model listing and cache use
- health probe
- rate-limit retry policy
- provider error redaction, including reasoning-content redaction
- request timeout mapping
- embeddings denial before network dispatch
- FCP trait invoke capability-token validation
- shutdown cleanup
- redaction-safe JSONL evidence

## Source Notes

- `connectors/deepseek/src/client.rs` defines DeepSeek base URL policy, auth headers, model cache behavior, and provider identity.
- `connectors/deepseek/src/connector.rs` defines lifecycle, capability verification, operation dispatch, reasoning/content output shaping, introspection, and health/doctor behavior.
- `connectors/deepseek/src/types.rs` defines chat request validation and the typed extension mapping for `thinking`, `reasoning_effort`, and `user_id`.
- `connectors/deepseek/manifest.toml` defines the five-operation catalog, network constraints, sandbox boundary, and no-listener/no-exec posture.
- `connectors/deepseek/tests/integration.rs` covers loopback chat, streaming, models, health, redaction, rate limits, timeout, embeddings denial, trait invoke, and JSONL evidence.
- `connectors/deepseek/tests/live_verification.rs` emits structured skip records unless `DEEPSEEK_API_KEY` is present.

## Verification Bundle

The closeout bundle is anchored on `scripts/e2e/deepseek_connector_verification.sh`. It writes artifacts under `artifacts/e2e/deepseek/<run_id>` by default and offloads Cargo work through `rch`.

The bundle captures:

- manifest check through `fwc` or `rch exec -- cargo run -p fwc`
- `rch exec -- cargo check -p fcp-deepseek --all-targets`
- `rch exec -- cargo fmt -p fcp-deepseek -- --check`
- WireMock JSONL loopback coverage
- optional live smoke coverage gated by `DEEPSEEK_E2E=1`
- live provider tests gated by `DEEPSEEK_API_KEY`
- JSONL extraction for fixture and live records
- `rch exec -- cargo clippy -p fcp-deepseek --all-targets -- -D warnings`
- replay script and environment metadata

## Operator Guidance

**Prerequisites**:

- Use a DeepSeek API key in `DEEPSEEK_API_KEY` for live provider verification.
- Set `DEEPSEEK_E2E=1` when the verification bundle should run live smoke tests.
- Use WireMock loopback fixtures for deterministic proof.

**Dedicated environment**:

- Prefer deterministic loopback evidence for routine verification.
- Use a test DeepSeek account for live runs and keep live prompts intentionally small.
- Keep reasoning-enabled prompts minimal; evidence should contain byte lengths rather than returned reasoning text.

**Redaction rules**:

- Redact API keys, bearer headers, credential IDs, prompts, completions, reasoning content, streamed text chunks, tool-call arguments, model catalogs when sensitive, provider payloads, and provider error bodies.
- The verification JSONL records use counts, byte lengths, status values, cleanup state, retry decisions, error mappings, and model IDs.

**Common remediation**:

- If `health` reports `unconfigured`, configure with exactly one of `api_key` or `credential_id`, then run handshake.
- If `self_check` reports `credential_injection_required`, run behind the host egress injection layer or switch to API-key mode for direct live probes.
- If base URL validation fails, use `https://api.deepseek.com`, `https://api.deepseek.com/v1`, or a localhost loopback URL for tests.
- If `thinking` is rejected, use `{"type":"enabled"}` or `{"type":"disabled"}`.
- If `reasoning_effort` is rejected, use `low`, `medium`, `high`, `xhigh`, or `max`.
- If reasoning output appears in final content, inspect caller handling before changing the connector; the runtime intentionally returns `content` and `reasoning_content` separately.
- If embeddings fail, this is expected. Use model listing to explain availability and route embeddings to a connector that actually owns that provider API.

**Rerun commands**:

- `scripts/e2e/deepseek_connector_verification.sh`
- `DEEPSEEK_E2E=1 scripts/e2e/deepseek_connector_verification.sh`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-deepseek-e2e cargo check -p fcp-deepseek --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-deepseek-e2e cargo test -p fcp-deepseek --test integration -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-deepseek-e2e cargo test -p fcp-deepseek --test live_verification -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-deepseek-e2e cargo clippy -p fcp-deepseek --all-targets -- -D warnings`
