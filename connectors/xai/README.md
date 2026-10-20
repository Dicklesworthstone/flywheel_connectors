# xAI Connector V3 Contract

> **Status**: PROVEN (2026-10-20; 12/12 graduation gauntlet, verifier + unit/integration/local_non_mock suites verified)
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/xai_connector_verification.sh`
> **Primary upstream**: https://docs.x.ai/

## Purpose

This document fixes the operator-facing contract for `fcp.xai`. The connector exposes xAI Grok through OpenAI-compatible chat, SSE chat streaming, model listing, a bounded health probe, and the xAI Responses API web-search path with structured citation extraction.

The connector keeps ordinary chat and server-side web search distinct. Chat completions do not enable live search by default; current web-search behavior belongs to `xai.responses.create`.

## Current Runtime Snapshot

The current crate exposes these operations:

- `xai.chat.completions`
- `xai.chat.completions_stream`
- `xai.responses.create`
- `xai.models.list`
- `xai.health`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of `api_key` or `credential_id`, plus optional `base_url`, default model, request timeout, model-cache TTL, and rate-limit wait policy.
- API-key mode sends a bearer token to xAI.
- Credential-id mode emits an `x-fcp-credential-id` header and requires host-side egress credential injection for live traffic.
- Default base URL is `https://api.x.ai/v1`.
- Loopback HTTP base URLs ending in `/v1` are accepted for deterministic tests.
- Default model is `grok-4.3`.
- Chat completions can forward explicit legacy `search_parameters`, but this connector does not add them automatically.
- Responses API web search requires either `web_search` shorthand or a raw `type = "web_search"` tool.
- Responses output includes `output_text`, byte counts, structured citations, citation hosts, usage, server-side tool usage, and the raw provider response for authorized invoke callers.
- SSE chat streaming returns redaction-safe chunk metadata and assembled text from a bounded invoke call; FCP subscribe is not implemented.
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.

## First-Slice Scope

The first xAI slice is intentionally narrow:

- create non-streaming Grok chat completions from caller-supplied message arrays
- create SSE chat completions and return assembled content plus chunk metadata
- list and cache xAI model IDs
- run a bounded health probe using model listing
- create Responses API web-search calls with domain filters and optional image understanding
- extract citation annotations and legacy citation URLs into a structured summary
- enforce capability-token checks for invoke paths
- emit redaction-safe loopback and optional live JSONL evidence

## Auth And Scope Boundary

- Authentication mechanism: xAI API key, with host-injected credential-id mode.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, `z:work`, and `z:project:*`.
- Allowed target zone: `z:work`.
- Forbidden source zone: `z:public`.
- Capability surface:
  - `xai.chat` gates chat and SSE chat operations.
  - `xai.responses.web_search` gates Responses API web-search calls.
  - `xai.models.read` gates model discovery.
  - `xai.health.read` gates the health probe.
- The connector does not persist prompts, completions, streamed chunks, Responses input, citation URL paths, model catalogs, provider payloads, or provider responses.
- Credential-id mode is a host-egress contract, not direct proof that live xAI will accept the request without an injection layer.

## Network And Runtime Invariants

- Production host: `api.x.ai`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and unsafe host forms for live operations.
- Localhost HTTP overrides are test-only and must include the `/v1` path.
- Default request timeout: `180_000 ms`.
- Model-list timeout: `30_000 ms`.
- Health probe timeout: `5_000 ms`.
- SSE chat streaming and Responses web search may run up to `300_000 ms`.
- Maximum response bytes are `10_485_760`.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `xai.chat` | Create Grok chat and SSE chat completions. |
| `xai.responses.web_search` | Create Responses API web-search calls and extract citation summaries. |
| `xai.models.read` | List xAI model identifiers. |
| `xai.health.read` | Run a bounded model-list readiness probe. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `xai.chat.completions` | `POST /v1/chat/completions` | `xai.chat` | `Safe` | `Medium` | `None` | Model output depends on prompt, tools, sampling input, and optional provider extensions. |
| `xai.chat.completions_stream` | `POST /v1/chat/completions` with SSE | `xai.chat` | `Safe` | `Medium` | `None` | Streaming output depends on event ordering and provider deltas. |
| `xai.responses.create` | `POST /v1/responses` with `web_search` tool | `xai.responses.web_search` | `Safe` | `Medium` | `None` | Server-side search and model output depend on query input, filters, tools, and provider state. |
| `xai.models.list` | `GET /v1/models` | `xai.models.read` | `Safe` | `Low` | `Strict` | Read-only model catalog discovery with in-memory cache support. |
| `xai.health` | `GET /v1/models` bounded probe | `xai.health.read` | `Safe` | `Low` | `Strict` | Health probe confirms xAI reachability and model-list path. |

## Explicit Non-Goals

The first implementation slice does not include:

- image generation, video generation, speech APIs, file upload APIs, fine-tuning, batch jobs, or dataset APIs
- FCP subscription-based streaming
- persistent prompt, completion, stream, citation, response, or model-cache storage
- direct credential vaulting
- public-zone invocation
- automatic enabling of chat-completions web search
- using another provider as a web-search fallback

These are excluded on purpose:

- The useful first slice is Grok chat plus current xAI Responses API web search with clear citation and redaction boundaries.
- Legacy chat `search_parameters` remain pass-through only for explicit callers; new work should use `xai.responses.create`.
- Full citation URL paths can reveal user intent and browsing context, so operator evidence records use citation hostnames rather than raw URLs.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake, auth mode, base URL, default model, request counters, and error counters
- redacted auth labels rather than bearer tokens
- base URL policy for `api.x.ai/v1` and loopback-compatible paths
- explicit routing of web search through `/v1/responses` with `tools = [web_search]`
- model-list probe health metadata
- operation schemas, safety, risk, idempotency, and AI hints

The deterministic integration evidence is anchored on WireMock loopback runs covering:

- chat completion without implicit web search
- SSE chat streaming
- model listing and health cache use
- Responses API web search with `allowed_domains`
- structured citation host extraction
- zero-citation response summaries
- provider error redaction
- rate-limit retry policy for the Responses path
- timeout and cancellation handling
- FCP trait invoke capability-token validation
- shutdown cleanup
- redaction-safe JSONL evidence

## Source Notes

- `connectors/xai/src/client.rs` defines xAI base URL policy, auth headers, rate-limit headers, direct Responses API routing, model cache behavior, and provider identity.
- `connectors/xai/src/connector.rs` defines lifecycle, capability verification, operation dispatch, Responses summarization, introspection, and health/doctor behavior.
- `connectors/xai/src/types.rs` defines chat request validation, Responses web-search request validation, domain-filter rules, and citation extraction.
- `connectors/xai/manifest.toml` defines the five-operation catalog, network constraints, sandbox boundary, and no-listener/no-exec posture.
- `connectors/xai/tests/integration.rs` covers loopback chat, streaming, models, health, Responses web search, redaction, rate limits, cancellation, live skip/pass evidence, and JSONL validation hooks.

## Verification Bundle

The closeout bundle is anchored on `scripts/e2e/xai_connector_verification.sh`. It writes artifacts under `artifacts/e2e/xai/<run_id>` by default and extracts `XAI_CONNECTOR_E2E_JSONL` records.

Important shared-session note: the script runs Cargo proof through `rch exec` and writes a summary plus redaction-checked JSONL artifacts. Set `CARGO_TARGET_PREFIX` to place target directories on a spacious volume when the local checkout is disk constrained.

The bundle captures:

- WireMock JSONL loopback coverage
- optional live smoke coverage gated by `XAI_API_KEY`
- required operation records for chat, stream, model list, and Responses web search
- manifest schema/hash validation, formatting, check, conformance, local non-mock, and clippy proof
- citation-host validation for Responses web search
- leakage checks for test token, prompt text, and citation URL paths
- command line and git revision metadata

## Operator Guidance

**Prerequisites**:

- Use an xAI API key in `XAI_API_KEY` for live provider verification.
- Use WireMock loopback fixtures for deterministic proof.
- Install `jq` before running `scripts/e2e/xai_connector_verification.sh`.

**Dedicated environment**:

- Prefer deterministic loopback evidence for routine verification.
- Use a test xAI account for live runs and keep live prompts intentionally small.
- Keep the local script out of shared proof loops unless the operator has intentionally selected local Cargo execution.

**Redaction rules**:

- Redact API keys, bearer headers, credential IDs, prompts, completions, streamed text chunks, tool-call arguments, Responses input, raw citation URL paths, provider payloads, and provider error bodies.
- The verification JSONL records use counts, byte lengths, status values, cleanup state, retry decisions, and citation hostnames.

**Common remediation**:

- If `health` reports `unconfigured`, configure with exactly one of `api_key` or `credential_id`, then run handshake.
- If `self_check` reports `credential_injection_required`, run behind the host egress injection layer or switch to API-key mode for direct live probes.
- If base URL validation fails, use `https://api.x.ai/v1` or a localhost loopback URL ending in `/v1`.
- If chat search behavior is missing, switch to `xai.responses.create`; chat completions do not enable web search automatically.
- If Responses input is rejected, supply non-null `input` and either `web_search` shorthand or a raw `{"type":"web_search"}` tool.
- If domain filters are rejected, use one to five domain names, not URLs, and do not combine `allowed_domains` with `excluded_domains`.
- If citation evidence looks too detailed, reduce it to citation hostnames and byte counts before writing logs.

**Rerun commands**:

- `RUN_ID=manual-xai OUT_ROOT=/Volumes/trj-data/fcp-artifacts/xai/manual-xai CARGO_TARGET_PREFIX=/Volumes/trj-data/tmp/fcp-xai-manual scripts/e2e/xai_connector_verification.sh`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-xai-e2e cargo check -p fcp-xai --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-xai-e2e cargo test -p fcp-xai --test integration xai_connector_wiremock_e2e -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-xai-e2e cargo test -p fcp-xai --test integration xai_connector_live_smoke_e2e -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-xai-e2e cargo clippy -p fcp-xai --all-targets --no-deps -- -D warnings`
