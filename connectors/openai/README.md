# OpenAI Connector V3 Contract

> **Status**: manifest/runtime contract documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://platform.openai.com/docs

## Purpose

This document fixes the operator-facing contract for `fcp.openai`. The connector exposes OpenAI Responses, chat, embeddings, image generation, video generation, audio transcription, realtime transcription, realtime voice, browser realtime client-secret minting, text-to-speech, fine-tuning jobs, Assistants, Threads, messages, and runs.

The connector is broad, but it is not a credential store. OpenAI Codex OAuth/device-code transport is explicitly host-mediated and rejected inside connector-local configuration.

## Current Runtime Snapshot

The current runtime invoke IDs are:

- `openai.chat`
- `openai.responses.create`
- `openai.responses.get`
- `openai.responses.cancel`
- `openai.responses.delete`
- `openai.simple_chat`
- `openai.get_usage`
- `openai.embeddings`
- `openai.images.generate`
- `openai.videos.generate`
- `openai.audio.transcribe`
- `openai.realtime.transcribe`
- `openai.realtime.voice`
- `openai.realtime.browser_session`
- `openai.audio.tts`
- `openai.finetune.create`
- `openai.finetune.list`
- `openai.finetune.get`
- `openai.finetune.cancel`
- `openai.finetune.events`
- `openai.assistants.create`
- `openai.assistants.list`
- `openai.assistants.get`
- `openai.assistants.delete`
- `openai.threads.create`
- `openai.threads.get`
- `openai.threads.messages.create`
- `openai.threads.messages.list`
- `openai.threads.runs.create`
- `openai.threads.runs.get`
- `openai.threads.runs.cancel`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of `api_key` or `credential_id`.
- Credential IDs must parse as UUIDs and require host-side egress credential injection for live traffic.
- API-key mode sends `Authorization: Bearer ...`.
- Credential-id mode sends `X-FCP-Credential-ID`.
- Optional `organization` adds `OpenAI-Organization`.
- Optional `deployment_profile` can provide profile name, base URL, organization, and default model.
- Default base URL is `https://api.openai.com`.
- `https://api.openai.com`, `https://api.openai.com/v1`, `https://api.deepseek.com`, and `https://api.deepseek.com/v1` are allowed API origins, plus loopback HTTP/HTTPS for tests.
- Connector-local Codex OAuth/device-code fields are rejected, including access tokens, refresh tokens, device codes, authorization codes, and verifier material.
- Codex base URLs are canonicalized only to explain that connector-local Codex transport is deferred to host credential flows.
- Default chat model is `gpt-4o`.
- FCP subscribe is not implemented; streaming and realtime operations are bounded invoke paths.
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.

## Native Host Session

The executable uses bounded JSONL RPC frames and a single async runtime. Configure the account, negotiate protocol `2.0` or `2.0.0`, and mint capability tokens against the returned `instance_id`. Reconfiguration and every new handshake revoke the previous authority; changing the account's zone requires reconfiguration.

Invoke parameters are complete FCP requests: `type: "invoke"`, a non-empty `id`, `connector_id: "fcp.openai"`, `zone_id`, `operation`, object `input`, and a host-signed `capability_token`. Native replies contain a typed `InvokeResponse` with the invocation ID inside the JSON-RPC response. Health is a `HealthSnapshot`; configuration, instance identity and redacted diagnostics are under `details`.

All operation metadata and input/output validation come from the bundled manifest. Admission enforces negotiated capabilities, bound model/resource scopes, signed call and byte budgets, and idempotency constraints. Simulation validates the same input contracts and authorization without calling the provider or consuming the invocation budget. A nonzero `deadline_ms` bounds provider execution.

Native input is limited to 64 MiB so the existing audio-upload limit remains usable after base64 encoding. Output limits follow each operation's manifest allowance, including binary media expansion. Shutdown cancels the client runtime, revokes account authority, and terminates before processing another buffered request.

Authority and budget counters are process-local. The trusted host remains responsible for egress policy, credential injection and any durable or cross-process accounting. These boundaries are also reported in `health.details.runtime_boundary`.

## First-Slice Scope

The first OpenAI README slice documents the existing runtime surface:

- structured Responses generation, function calls and retained-context continuation
- chat and simple chat through Chat Completions
- SSE chat streaming at the client layer
- embeddings with `text-embedding-3-small`, `text-embedding-3-large`, and `text-embedding-ada-002`
- image generation with DALL-E models
- video generation through asynchronous submit, polling, and video-byte download
- audio transcription through Whisper-compatible upload
- realtime transcription and realtime voice WebSocket sessions
- browser realtime client-secret creation for WebRTC SDP offer flows
- TTS audio generation
- fine-tune create/list/get/cancel/events operations
- Assistants create/list/get/delete operations
- Threads create/get, message create/list, and run create/get/cancel operations
- local token and cost accounting
- bound capability-token verification before dispatch

## Responses API And Function Continuation

Use `openai.responses.create` for the current OpenAI Responses API. It accepts a model ID from the configured account without the legacy Chat Completions enum, text or ordered input items, reasoning configuration, structured text output, and flat function definitions. The operation requires the OpenAI API origin; loopback endpoints remain available for deterministic tests.

The `input` portion of a typed FCP invocation can be:

```json
{
  "model": "gpt-6.2-astra",
  "input": "What is the weather in Paris?",
  "tools": [{
    "type": "function",
    "name": "weather",
    "parameters": {
      "type": "object",
      "properties": {"city": {"type": "string"}},
      "required": ["city"],
      "additionalProperties": false
    },
    "strict": true
  }],
  "tool_choice": "auto",
  "max_output_tokens": 1024
}
```

The operation result is `{ response, output_text, cost_usd }`. The complete provider object is retained under `response`, including ordered output items, function call IDs and raw argument strings, reasoning continuity, annotations, provider status/error details, and future fields. `output_text` is a convenience projection. Always inspect `response.status`; a provider result marked failed or incomplete retains its diagnostic fields.

Execute requested functions in the caller, then continue with the returned response ID and the matching function `call_id`:

```json
{
  "model": "gpt-6.2-astra",
  "previous_response_id": "resp_previous",
  "input": [{
    "type": "function_call_output",
    "call_id": "call_weather",
    "output": "18 C, sunny"
  }]
}
```

Explicit history may also contain messages, function calls, function outputs, reasoning items and item references. The connector preserves supplied data and never executes function arguments. The provider controls model availability and storage; the optional `store` field is forwarded, and retained-context continuation depends on provider retention. Instructions are sent per request.

Signed resource grants cover the model and every referenced provider object or external content URL:

| Request field | Resource scope |
|---|---|
| `model` | `openai:model:<model>` |
| `previous_response_id` | `openai:response:<id>` |
| Any top-level input item's `id` | `openai:response_item:<id>` |
| Content-part `file_id` | `openai:file:<id>` |
| HTTP(S) `file_url` or `image_url` | `openai:input_url:<canonical-url>` |

Content-part references are checked in both message content and function outputs. Inline `data:image` content is caller-supplied data. URL scopes use `url::Url` canonicalization. All scope suffixes then escape `%`, `?` and `*`, in that order, as `%25`, `%3F` and `%2A`. This keeps literal URL characters from becoming capability-policy glob operators. For example, `https://example.com/a?b=1` requires `openai:input_url:https://example.com/a%3Fb=1`.

This operation supports client-executed function tools and optional background execution. Hosted/MCP tools, active hosted-tool continuation items and streaming are rejected during local validation. Simulation applies the same request and reference checks without provider traffic or budget debit.

Actual input/output token counts supplied in a creation response are retained in `response.usage` and added to the connector's session counters. `cost_usd` is explicitly null because the legacy chat price table cannot price arbitrary Responses models or provider services. `openai.get_usage.unpriced_response_requests` counts accepted creation responses; its `total_cost_usd` excludes them. Response budgeting includes the additional `output_text` projection.

### Background jobs and retained response lifecycle

Pass `"background": true` to `openai.responses.create` and retain the returned `response.id`. Creation may return `queued` or `in_progress` with no usage yet. Use `openai.responses.get` with `{"response_id":"resp_job"}` to poll that exact job. Retrieval also accepts an `include` array, for example `{"response_id":"resp_job","include":["reasoning.encrypted_content"]}`. Stop polling at a terminal status and inspect the complete provider object, including failure or incomplete details. Polling never repeats the creation request.

Use `openai.responses.cancel` with the same response ID to cancel a background job. The provider may return an already completed result; a successful call does not necessarily mean the final status is `cancelled`. Use `openai.responses.delete` to remove a retained response. Cancellation and deletion have separate capabilities and require interactive host approval. Deletion is not a substitute for cancelling running work. A lost or timed-out reply leaves the outcome uncertain.

Every lifecycle operation requires its own capability and the exact `openai:response:<response_id>` resource. Model-generation authority alone does not grant access to an existing response. IDs must contain 1–512 ASCII letters, digits, underscores or hyphens; URL delimiters and whitespace aliases are rejected before admission. Provider replies must identify the requested response before they are released. Deletion accepts a matching affirmative JSON acknowledgement or HTTP 204 with an empty body.

Retrieval and cancellation preserve `response.usage` but do not increment generation counters. This prevents repeated polls from counting the same generation repeatedly. Consequently, session token totals exclude background usage that was unavailable in the creation reply; the terminal response's usage is the authoritative per-job record. As with synchronous Responses, no dollar price is inferred. The connector does not run an autonomous polling worker, and stopping the connector does not cancel accepted provider jobs.

Provider references: [background mode](https://developers.openai.com/api/docs/guides/background), [retrieve](https://developers.openai.com/api/reference/resources/responses/methods/retrieve), [cancel](https://developers.openai.com/api/reference/resources/responses/methods/cancel), and [delete](https://developers.openai.com/api/reference/resources/responses/methods/delete).

OpenAI [retired the Assistants API on August 26, 2026](https://developers.openai.com/api/docs/assistants/migration). Existing Assistants/Threads bindings remain in the catalog, and the Responses operation provides the current generation and function-continuation path. API details: [create response](https://developers.openai.com/api/reference/resources/responses/methods/create) and [function calling](https://developers.openai.com/api/docs/guides/function-calling).

## Auth And Scope Boundary

- Authentication mechanisms: OpenAI API key or host-injected credential ID.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden source zone: `z:public`.
- Capability surface:
  - `openai.chat` gates chat, simple chat, and local usage accounting.
  - `openai.responses.create` gates synchronous or background generation and its separately scoped context references.
  - `openai.responses.get`, `openai.responses.cancel`, and `openai.responses.delete` independently gate access to a named response; cancellation and deletion require host approval.
  - `openai.embeddings` gates embedding creation.
  - `openai.images` gates image generation.
  - `openai.videos` gates video generation.
  - `openai.audio.transcribe` gates file transcription.
  - `openai.realtime.transcribe` gates realtime transcription WebSocket sessions.
  - `openai.realtime.voice` gates realtime voice WebSocket sessions.
  - `openai.realtime.browser_session` gates browser client-secret minting.
  - `openai.audio.tts` gates text-to-speech.
  - Fine-tune, Assistants, Threads, messages, and runs each have operation-specific capabilities.
- The connector does not persist prompts, completions, streamed deltas, generated media, audio input, transcripts, realtime client secrets, fine-tune payloads, assistant instructions, thread messages, provider payloads, or provider responses.
- Credential-id mode is a host-egress contract, not direct proof that live OpenAI will accept the request without an injection layer.

## Network And Runtime Invariants

- Production hosts for most REST operations: `api.openai.com`, with `api.deepseek.com` also allowed by this connector's OpenAI-compatible base URL policy.
- Production host for OpenAI video, realtime, and browser client-secret flows: `api.openai.com`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, IP literals, and unsafe host forms for live operations.
- Localhost HTTP overrides are test-only.
- Standard REST connect timeout: `10_000 ms`.
- Standard REST total timeout: `120_000 ms`.
- Realtime total timeout defaults to `30_000 ms` and is bounded to `300_000 ms`.
- Realtime transcription processes at most `1024` server events; realtime voice processes at most `2048` events.
- Realtime audio chunks must be non-empty base64 and each decoded chunk must be at most `15 MiB`.
- Browser realtime client secrets default to `60 s` TTL and are capped at `600 s`.
- Maximum response bytes are `10_485_760` for standard responses, `52_428_800` for image/TTS audio, and `104_857_600` for downloaded video bytes.
- These limits are enforced while receiving provider bodies, including chunked replies; error bodies have a separate 64 KiB ceiling. HTTP redirects and automatic transport retries are disabled. A response timeout or interrupted body is terminal because the provider may already have accepted generation or a mutation.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120_000 ms` wall-clock timeout, read-only `/usr` and `/lib`, no exec, and no ptrace.
- Event capability metadata declares streaming support, no replay, and a minimum buffer of 10 events.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `openai.chat` | Chat completions, simple chat, and local usage counters. |
| `openai.embeddings` | Text embedding generation. |
| `openai.images` | Image generation. |
| `openai.videos` | Video job submission, polling, and download. |
| `openai.audio.transcribe` | File-based audio transcription. |
| `openai.realtime.transcribe` | Realtime transcription WebSocket sessions. |
| `openai.realtime.voice` | Realtime voice WebSocket sessions. |
| `openai.realtime.browser_session` | Ephemeral browser client-secret minting. |
| `openai.audio.tts` | Text-to-speech audio generation. |
| `openai.finetune.*` | Fine-tune job create, read, cancel, and event access. |
| `openai.assistants.*` | Assistant create, list, get, and delete access. |
| `openai.threads.*` | Thread, message, and run access. |

## Operation Inventory

| Operation family | Invoke IDs | Safety and risk | Notes |
|------------------|------------|-----------------|-------|
| Chat | `openai.chat`, `openai.simple_chat`, `openai.get_usage` | Chat is `Safe`/`Medium`; usage is `Safe`/`Low` and `Strict` | Chat output is model-dependent. Usage reads local counters. |
| Embeddings | `openai.embeddings` | `Safe`/`Low` | Embedding generation is read-like but still provider-dispatched and input-sensitive. |
| Images and video | `openai.images.generate`, `openai.videos.generate` | `Safe`/`Medium` | Media generation returns base64 artifacts; video generation polls an async job and downloads final bytes. |
| Audio | `openai.audio.transcribe`, `openai.audio.tts` | `Safe`/`Medium` | Audio input/output is sensitive and must not be persisted by verification. |
| Realtime | `openai.realtime.transcribe`, `openai.realtime.voice`, `openai.realtime.browser_session` | `Safe`/`Medium` | WebSocket/WebRTC-oriented paths are bounded by event, timeout, audio-size, and TTL limits. |
| Fine-tuning | `openai.finetune.create`, `openai.finetune.cancel` | `Risky`/`High`, interactive approval | Create and cancel are mutating, cost-bearing operations. |
| Fine-tune reads | `openai.finetune.list`, `openai.finetune.get`, `openai.finetune.events` | `Safe`/`Low`, `Strict` | Read-only job status and event discovery. |
| Assistants | `openai.assistants.create`, `openai.assistants.delete` | Create is `Safe`/`Medium`; delete is mutating | Assistant writes require careful audit context. |
| Assistant reads | `openai.assistants.list`, `openai.assistants.get` | `Safe`/`Low`, `Strict` | Read-only assistant discovery. |
| Threads and runs | `openai.threads.create`, `openai.threads.messages.create`, `openai.threads.runs.create`, `openai.threads.runs.cancel` | Mixed medium risk, mutating where create/cancel | Thread and run operations affect provider-side state. |
| Thread reads | `openai.threads.get`, `openai.threads.messages.list`, `openai.threads.runs.get` | `Safe`/`Low`, `Strict` | Read-only state inspection. |

## Explicit Non-Goals

The current implementation does not include:

- connector-local Codex OAuth/device-code transport
- connector-local storage of OpenAI secrets
- Files API upload/download as a standalone operation surface
- persistent conversation, assistant, thread, run, media, or realtime state storage
- FCP subscription-based streaming
- public-zone invocation
- automatic use of unapproved public or private-network base URLs

These are excluded on purpose:

- Host credential flows own Codex OAuth/device-code credentials.
- Provider-side state creation and cancellation must remain capability-gated and auditable.
- Realtime client secrets and generated media are sensitive artifacts and should be returned only to authorized invoke callers.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, auth mode, base URL, organization, deployment profile, default model, request counters, error counters, token counters, and cost totals
- redacted auth labels rather than raw API keys or credential values
- base URL host policy, Codex transport rejection, and loopback test handling
- operation schemas, safety, risk, idempotency, and AI hints
- simulate-time capability-token checks against bound resources

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- simple chat and multi-turn chat invokes
- system prompts
- SSE chunk parsing, tool-call deltas, and `[DONE]` termination
- tool/function-calling shapes
- 401, 429, 503, context-length, and content-filter error mapping
- usage and cost accounting
- default-deny capability-token behavior
- lifecycle behavior for configure, handshake, health, doctor, self-check, introspection, simulate, and shutdown
- base URL rejection for untrusted hosts
- realtime transcription and realtime voice WebSocket fixtures
- live verification skip/pass behavior gated by `OPENAI_API_KEY`

## Source Notes

- `connectors/openai/src/client.rs` defines auth headers, organization headers, retry behavior, usage counters, health checks, REST calls, SSE parsing, embeddings, media, fine-tune, Assistants, Threads, and video polling behavior.
- `connectors/openai/src/connector.rs` defines configuration validation, Codex transport rejection, base URL normalization, deployment profile parsing, capability verification, operation dispatch, realtime WebSocket/WebRTC orchestration, introspection, simulation, and lifecycle behavior.
- `connectors/openai/src/types.rs` defines model IDs, pricing, message and tool shapes, embeddings, images, video, audio, TTS, fine-tune, Assistants, Threads, runs, and response types.
- `connectors/openai/manifest.toml` defines the broad operation catalog, network constraints, sandbox boundary, event capability metadata, and no-listener/no-storage/no-exec posture.
- `connectors/openai/tests/integration.rs` covers deterministic loopback, error behavior, capability boundaries, lifecycle, realtime WebSocket fixtures, and validation.
- `connectors/openai/tests/native_host.rs` exercises the shipped executable with real loopback HTTP, chat and Responses tool-call conversations, signed resource/budget constraints, malformed frames and terminal shutdown.
- `connectors/openai/tests/responses.rs` covers provider request shapes, retained/stateless continuation, reference validation, retries, actual usage accounting and lossless failed/incomplete outputs.
- `connectors/openai/tests/live_verification.rs` emits live skip/pass results when `OPENAI_API_KEY` is absent or present.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/openai_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- deterministic WireMock integration coverage
- live provider smoke tests gated by `OPENAI_API_KEY`
- realtime WebSocket fixture coverage
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use `OPENAI_API_KEY` only for live provider verification.
- Use WireMock and local WebSocket fixtures for deterministic proof.
- Use `credential_id` for host-injected secretless deployments.

**Dedicated environment**:

- Prefer deterministic loopback evidence for routine verification.
- Use a test OpenAI account for live runs and keep live prompts intentionally small.
- Keep media, realtime, fine-tune, Assistants, Threads, and run operations out of live smoke unless the operator explicitly scopes and budgets them.

**Redaction rules**:

- Redact API keys, credential IDs where needed, prompts, completions, streamed deltas, tool-call arguments, embedding input and vectors, generated media bytes, audio input, transcripts, realtime client secrets, assistant instructions, thread messages, provider payloads, and provider error bodies.
- Verification output should use counts, byte lengths, operation IDs, status values, error classes, model IDs when non-sensitive, and cleanup state.

**Common remediation**:

- If `health.details.configured` is false, configure with exactly one of `api_key` or `credential_id`, then negotiate an FCP 2.0 handshake.
- If `self_check` reports credential injection is required, run behind the host egress injection layer or switch to direct API-key mode for live probes.
- If base URL validation fails, use an allowed OpenAI-compatible origin or localhost for tests.
- If a Codex OAuth/device-code field is rejected, move that credential into host credential flows and reference it by `credential_id`.
- If realtime transcription fails before completion, check audio format, decoded chunk size, event cap, and timeout bounds.
- If browser realtime session creation fails, confirm the base URL is `api.openai.com` or a localhost test origin.
- If video generation times out, increase polling only within the documented bounds and check provider job status separately.
- If fine-tune create or cancel is requested, require explicit operator intent and record the provider job ID.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-openai-e2e cargo check -p fcp-openai --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-openai-e2e cargo test -p fcp-openai --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-openai-e2e cargo test -p fcp-openai --test live_verification -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-openai-e2e cargo clippy -p fcp-openai --all-targets --no-deps -- -D warnings`
