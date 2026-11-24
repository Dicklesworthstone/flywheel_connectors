# Groq Connector V3 Contract

> **Status**: PROVEN (2026-10-20; 12/12 graduation gauntlet, verifier + unit/integration/local_non_mock suites verified)
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/groq_connector_verification.sh`
> **Primary upstream**: https://console.groq.com/docs/api-reference

## Purpose

This document fixes the operator-facing contract for `fcp.groq`. The connector exposes Groq's OpenAI-compatible text inference surface: chat completions, SSE chat streaming, model listing, a bounded health probe, and a deprecated legacy completions operation for older OpenAI-compatible callers.

The connector is intentionally text-inference focused. Groq embeddings and audio endpoints are not exposed by this runtime; `groq.embeddings.create` is declared only so introspection can honestly report that embeddings are not supported by this first-party Groq slice.

## Current Runtime Snapshot

The current crate exposes these operations:

- `groq.chat.completions`
- `groq.chat.completions_stream`
- `groq.models.list`
- `groq.health`
- `groq.embeddings.create`
- `groq.completions.legacy`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of `api_key` or `credential_id`.
- API-key mode sends `Authorization: Bearer ...`.
- Credential-id configuration is retained for diagnostics, but invocation fails before network I/O: this connector's native transport does not yet implement host-mediated credential injection. Use API-key mode for live traffic.
- Default base URL is `https://api.groq.com/openai/v1`.
- Base URL overrides must use `/openai/v1` or `/v1`, must not include query or fragment components, and may only target `api.groq.com` or loopback test hosts.
- Loopback HTTP/HTTPS base URLs are accepted only for deterministic tests.
- Default model is `llama-3.1-8b-instant`.
- Default `request_timeout_ms` is `60_000`, with a maximum of `120_000`. Each invocation uses the smallest configured, manifest-operation, caller and native-context deadline.
- Default `model_cache_ttl_seconds` is `3600`.
- `wait_on_rate_limit_ms` switches rate-limit behavior from fail-fast to bounded wait/retry.
- Chat input rejects unsupported OpenAI fields before network dispatch: `logprobs`, `logit_bias`, `top_logprobs`, `messages[].name`, and `n` values other than 1.
- `groq.models.list` uses the shared OpenAI-compatible model cache and supports `{"refresh": true}` to invalidate it.
- `groq.completions.legacy` is available only for old prompt-completion callers; new work should use chat completions.
- FCP subscribe is not implemented; streaming is exposed as the bounded invoke operation `groq.chat.completions_stream`.
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.

### Invocation authority and execution limits

Both the JSONL process boundary and the Rust `FcpConnector` interface require
the complete canonical `InvokeRequest`: `type`, `id`, `connector_id`, `zone_id`,
`operation`, `input` and a signed capability. Ad hoc operation/input/token objects
do not acquire an implicit connector or zone. Handshakes accept protocol `2.0`
or `2.0.0`, bind to `z:work`, and negotiate only declared capabilities. Every
handshake rotates the actual instance ID; obtain it from handshake or health
before signing invocation tokens. Failed handshakes and configuration changes
invalidate the prior authority, and failed reconfiguration clears old credentials.

The shared SDK atomically charges signed `max_calls` and `max_bytes` allowances,
checks the signed idempotency-key scope, and rejects reused token IDs with
different claims. Model-list and health requests require a non-empty
`idempotency_key`. Byte accounting measures the complete compact JSON request
and response envelopes, with a 16 MiB response ceiling; it does not replace host
accounting for provider traffic. Failed, cancelled and unknown outcomes retain
their reservations. Simulation validates the same input, resource and session
authority without spending a call or causing provider I/O. This admission ledger
does not deduplicate provider calls or cache results for an idempotency key.

Resource checks use the model actually selected by the request or configured
default. Remote image inputs also require `groq:image_url:<canonical-url>`
resource authority, and dispatch sends that same canonical URL. Inline data is
covered by request-byte accounting. Provider extensions cannot override typed fields such as `model`,
`messages`, `stream` or generation limits. A single narrowing execution budget
covers cache access, provider attempts, retry waits, stream collection and result
validation. Cancellation and deadline exhaustion return terminal errors because
the provider outcome may be unknown.

### Streaming response

`groq.chat.completions_stream` returns a bounded materialized response containing
the complete assistant choices, assembled tool-call IDs, names and arguments,
and provider usage when supplied. Top-level content, reasoning, finish reason,
and tool calls describe choice zero; `chunks` remains payload-free metadata.
The collector rejects incomplete transport termination and malformed or oversized
streams without publishing partial success. See the
[shared streaming response contract](../../crates/fcp-openai-compat/README.md#streaming-completion-results)
for field meanings, termination requirements, and resource limits.

## First-Slice Scope

The first Groq README slice documents the existing runtime surface:

- non-streaming chat completions through `POST /openai/v1/chat/completions`
- SSE chat completions through the same endpoint with `stream: true`
- model discovery through `GET /openai/v1/models`
- a health operation backed by a short model-list probe
- deprecated legacy prompt completions through the OpenAI-compatible completions surface
- local validation for unsupported Groq/OpenAI fields
- local validation for invalid auth material and invalid base URLs
- rate-limit retry behavior for configured bounded waits
- redaction-safe doctor and provider error output
- bound capability-token verification before dispatch
- an explicit not-supported embeddings operation for introspection honesty

## Auth And Scope Boundary

- Live authentication mechanism: Groq API key. Credential references are accepted for configuration diagnostics and denied at invocation until host egress is wired into this transport.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, `z:work`, and `z:project:*`.
- Allowed target zone: `z:work`.
- Forbidden source zone: `z:public`.
- Capability surface:
  - `groq.chat` gates chat, streaming chat, and legacy completions.
  - `groq.models.read` gates model listing.
  - `groq.health.read` gates the health probe.
  - `groq.embeddings` is associated only with the not-supported embeddings declaration.
- The connector does not persist prompts, completions, streamed chunks, tool-call arguments, model catalogs, provider payloads, or provider responses.
- Credential-id mode never sends a credential reference directly to Groq as an authentication substitute.

## Network And Runtime Invariants

- Production host: `api.groq.com`.
- Production path root: `/openai/v1`.
- Compatibility path accepted by runtime: `/v1`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and unsafe host forms for live operations.
- Localhost HTTP/HTTPS overrides are test-only.
- Runtime default `request_timeout_ms`: `60_000`.
- Manifest chat and legacy-completions network constraints set total timeout `60_000 ms`.
- Manifest streaming network constraints set total timeout `300_000 ms`.
- Manifest model-list network constraints set total timeout `30_000 ms`.
- Manifest health network constraints set total timeout `5_000 ms`.
- Manifest provider response limit is `10_485_760` bytes. The standalone FCP response ceiling is 16 MiB and may be narrowed by the signed grant's remaining byte allowance.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `120_000 ms` wall-clock timeout, no exec, and no ptrace.
- Event capability metadata declares streaming support, no replay, no acknowledgement requirement, and a minimum buffer of 0 events.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `groq.chat` | Send chat, streaming chat, and legacy prompt-completion requests. |
| `groq.models.read` | List available Groq model IDs with cache reuse. |
| `groq.health.read` | Probe provider reachability through a bounded model-list request. |
| `groq.embeddings` | Report the intentionally unavailable embeddings surface. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `groq.chat.completions` | `POST /openai/v1/chat/completions` | `groq.chat` | `Safe` | `Medium` | `None` | Model output depends on prompt, tools, sampling options, and model ID. |
| `groq.chat.completions_stream` | `POST /openai/v1/chat/completions` with SSE | `groq.chat` | `Safe` | `Medium` | `None` | Stream output depends on event ordering, content deltas, tool-call deltas, and finish metadata. |
| `groq.models.list` | `GET /openai/v1/models` | `groq.models.read` | `Safe` | `Low` | `Strict` | Read-only model catalog discovery with in-memory caching. |
| `groq.health` | `GET /openai/v1/models` bounded probe | `groq.health.read` | `Safe` | `Low` | `Strict` | Read-only readiness probe for credentials and network path. |
| `groq.embeddings.create` | Local not-supported response | `groq.embeddings` | `Safe` | `Low` | `None` | Declared for honest introspection; invocation fails before provider dispatch. |
| `groq.completions.legacy` | `POST /openai/v1/completions` | `groq.chat` | `Safe` | `Medium` | `None` | Deprecated prompt-completion compatibility for older callers. |

## Explicit Non-Goals

The current implementation does not include:

- invokable Groq embeddings
- Groq audio transcription, audio translation, or text-to-speech APIs
- image, video, file, batch, fine-tuning, admin, or deployment-management APIs
- FCP subscription-based streaming
- connector-local credential vaulting
- public-zone invocation
- durable storage of prompts, completions, model catalogs, streamed deltas, or provider errors
- proxying unsupported embeddings through a different provider

These are excluded on purpose:

- The useful first slice is a direct first-party Groq text inference connector.
- Unsupported embeddings are represented explicitly so operators do not infer a hidden fallback.
- Provider credentials and host egress injection stay outside the connector-local storage boundary.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, auth mode, base URL, default model, request counters, and error counters
- redacted auth labels rather than raw API keys
- base URL policy for `api.groq.com/openai/v1` and loopback-compatible test origins
- credential-injection status for secretless mode
- operation schemas, safety, risk, idempotency, and AI hints
- simulate-time input, resource and negotiated-authority checks without provider execution
- capability-token checks against bound resources before dispatch

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- API-key auth header behavior
- chat completion dispatch and redacted doctor output
- SSE chunk assembly without prompt echoing
- model-list caching and health reuse of the shared client
- bounded rate-limit retry behavior
- provider error mapping with sensitive body redaction
- embeddings failing locally before network dispatch
- unsupported OpenAI fields failing locally before network dispatch
- FCP trait invoke, capability-token validation, and shutdown behavior
- manifest operation coverage and runtime introspection parity
- canonical request routing, negotiated capabilities, stale-instance denial, failed reconfiguration, cumulative call/byte ceilings, configured default model binding and reserved provider-extension denial

## Source Notes

- `connectors/groq/src/client.rs` defines auth headers, base URL normalization, user agent, OpenAI-compatible request dispatch, model listing, and model-cache invalidation.
- `connectors/groq/src/connector.rs` defines configuration validation, lifecycle handlers, operation dispatch, capability verification, introspection, simulation, health, doctor, self-check, and shutdown behavior.
- `connectors/groq/src/types.rs` defines chat and legacy-completions input parsing plus local rejection of unsupported Groq fields.
- `connectors/groq/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, not-supported embeddings declaration, and deprecated legacy completions declaration.
- `connectors/groq/tests/conformance.rs` checks manifest operation coverage, network policy, not-supported embeddings, and runtime introspection parity.
- `connectors/groq/tests/integration.rs` covers deterministic loopback behavior, error mapping, rate-limit retry, redaction, unsupported embeddings, unsupported fields, and FCP trait behavior.

## Verification Bundle

The closeout bundle is anchored on `scripts/e2e/groq_connector_verification.sh`. It writes artifacts under `artifacts/e2e/groq/<run_id>` by default and offloads Cargo work through `rch`.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock integration coverage
- local non-mock loopback HTTP acceptance coverage with extracted redaction-safe JSONL
- base URL, auth, unsupported-field, rate-limit, and redaction tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a Groq API key only for live provider verification.
- Use API-key mode for this transport; `credential_id` invocation is explicitly unavailable until a host-mediated adapter is implemented.
- Use WireMock loopback fixtures for deterministic proof.

**Dedicated environment**:

- Prefer deterministic loopback evidence for routine verification.
- Use a test Groq account for live runs and keep live prompts intentionally small.
- Keep audio, embeddings, and deployment-management expectations out of this connector.

**Redaction rules**:

- Redact API keys, credential IDs where needed, prompts, completions, streamed chunks, tool-call arguments, model-list response bodies, provider payloads, and provider error bodies.
- Verification output should use counts, byte lengths, operation IDs, model IDs when non-sensitive, status values, error classes, and cleanup state.

**Common remediation**:

- If `health` reports `unconfigured`, configure with exactly one of `api_key` or `credential_id`.
- If `health` reports `degraded`, complete handshake and check `auth_ready`; credential-ID configurations require a transport with host-mediated credential injection.
- If `self_check` reports `credential_injection_required`, use API-key mode for live probes; configuring a host proxy alone does not wire this connector's native client into it.
- If base URL validation fails, use `https://api.groq.com/openai/v1`, `https://api.groq.com/v1`, or a loopback `/openai/v1` or `/v1` origin for tests.
- If chat input is rejected for unsupported fields, remove `logprobs`, `logit_bias`, `top_logprobs`, `messages[].name`, or set `n` to 1.
- If `groq.embeddings.create` is requested, route the request to a connector that actually supports embeddings.
- If a legacy prompt-completion path is requested for new work, use `groq.chat.completions` instead.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-groq-e2e cargo check -p fcp-groq --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-groq-e2e cargo test -p fcp-groq --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-groq-e2e cargo test -p fcp-groq --test local_non_mock -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-groq-e2e cargo clippy -p fcp-groq --all-targets --no-deps -- -D warnings`
