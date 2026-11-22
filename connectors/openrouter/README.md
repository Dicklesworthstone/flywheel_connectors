# OpenRouter Connector Runtime Contract

> **Status**: canonical FCP 2 native protocol, signed session admission, bounded provider operations
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/openrouter_connector_verification.sh`
> **OpenRouter API overview upstream**: https://openrouter.ai/docs/api-reference/overview
> **OpenRouter chat completions upstream**: https://openrouter.ai/docs/api-reference/chat-completion
> **OpenRouter models upstream**: https://openrouter.ai/docs/api/api-reference/models/get-models
> **OpenRouter video generation upstream**: https://openrouter.ai/docs/guides/overview/multimodal/video-generation
> **OpenRouter video submit upstream**: https://openrouter.ai/docs/api/api-reference/video-generation/create-videos
> **OpenRouter video polling upstream**: https://openrouter.ai/docs/api/api-reference/video-generation/get-videos

## Purpose

This document fixes the operator-facing contract for `fcp.openrouter`. The connector exposes the OpenRouter API surface currently implemented in this crate: non-streaming chat completions, model catalog reads, and bounded video generation with job polling and generated-asset download.

The connector is intentionally a bounded OpenRouter request-response bridge. It is not a full OpenAI-compatible SDK, streaming relay, Responses API adapter, embeddings client, image-generation wrapper, provider-key manager, model-router policy engine, video-to-video tool, persistent generation tracker, usage analytics collector, or durable media store.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `openrouter.chat.completions`
- `openrouter.models.list`
- `openrouter.videos.generate`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-openrouter`.
- Manifest ID is `fcp.openrouter`.
- `BaseConnector` runtime ID is `fcp.openrouter`.
- Runtime connector version is `0.1.0`.
- Manifest format is `native`.
- Manifest schema version is `2.1`.
- Configuration requires exactly one auth source:
  - `api_key`
  - `credential_id`
- Direct API-key mode sends `Authorization: Bearer <api_key>`.
- `credential_id` mode is accepted at configure time but no host credential-injection path is implemented in this slice.
- Runtime `invoke()` rejects all supported operations in `credential_id` mode.
- Runtime `simulate()` returns blocked for supported operations in `credential_id` mode.
- Default base URL is `https://openrouter.ai/api/v1`.
- Custom `base_url` must use HTTPS and host `openrouter.ai`, except HTTP loopback is accepted for tests.
- Custom `base_url` must not include userinfo, query string, or fragment.
- Optional `app_name` becomes the `X-Title` provider header.
- Optional `app_url` becomes the `HTTP-Referer` provider header.
- Default request timeout is 60000 ms.
- Every configure attempt revokes previous authority and clears the old account, including attempts that fail validation. A successful configuration creates the HTTP client and compiles the embedded manifest contracts.
- `handle_handshake()` parses a full FCP `HandshakeRequest`, accepts protocol `2.0` or `2.0.0`, and uses the shared SDK `StandaloneSession`. It returns a canonical `HandshakeResponse`, manifest hash, and the actual fresh `instance_id` to which the host must bind tokens.
- Only requested capabilities declared by the manifest are granted. An empty request grants nothing. `z:public` is forbidden, and rebinding an account to a different zone requires reconfiguration.
- Every handshake attempt invalidates previous authority, including malformed and rejected handshakes. A repeated host-preferred instance ID cannot preserve old tokens.
- `handle_health()` returns a canonical `HealthSnapshot`; configured/handshaken state, actual instance, zone/session, live-request readiness, counters, and base URL are in `details`. It does not call OpenRouter.
- Runtime `handle_doctor()` checks local configuration, client initialization, credential-injection readiness, handshake state, and documented surface boundary. It does not call OpenRouter.
- Runtime `handle_self_check()` calls `GET /models` in direct API-key mode.
- Runtime `handle_self_check()` reports degraded in `credential_id` mode because host credential injection is not implemented.
- `handle_invoke()` requires a complete typed `InvokeRequest`, including `type`, nonempty request ID, `connector_id`, `zone_id`, operation, object input, and signed capability token. It checks manifest input schemas and local provider semantics before admission.
- Shared admission verifies negotiated capability, signature, expiry, operation, actual instance, zone, resources, signed call/byte ceilings, and any signed idempotency-key scope. This does not replace host holder-proof, revocation, approval, lease, or mesh-wide enforcement.
- `handle_simulate()` requires a typed `SimulateRequest` and checks the same schemas, provider semantics, resource scopes, and session authority. It performs no provider I/O and does not reserve or debit usage; an allowed preview cannot guarantee later admission.
- `handle_shutdown()` revokes authority, cancels the client execution context, and clears configuration. The native process flushes its shutdown response and exits without waiting for stdin to close.
- The executable uses bounded shared SDK JSONL framing (16 MiB per request) and wraps operation outputs in canonical, correlated `InvokeResponse` messages. Malformed envelopes recover with a parse error; an oversized frame terminates the transport.
- Runtime events and resource types are empty.
- Streaming is not supported.

## Runtime API Adapter

The runtime uses these request shapes under `{base_url}`:

| Operation | Capability | Required input | Runtime behavior |
|-----------|------------|----------------|------------------|
| `openrouter.chat.completions` | `openrouter.chat` | `messages` | `POST /chat/completions`; returns normalized first-choice content plus raw provider payload. |
| `openrouter.models.list` | `openrouter.models` | none | `GET /models`; returns provider model catalog JSON. |
| `openrouter.videos.generate` | `openrouter.video` | `prompt` | `POST /videos`; polls returned job URL until terminal completion, then downloads the generated video and returns base64. |

Chat behavior:

- `messages` must be a non-empty array.
- `model` defaults to `openai/gpt-4.1-mini`.
- `stream=true` is rejected.
- Runtime forwards only this subset of optional chat fields: `max_tokens`, `temperature`, `top_p`, `response_format`, `tools`, and `tool_choice`.
- Runtime does not forward provider-routing fields, transforms, web-search plugins, reasoning parameters, `models`, `modalities`, `metadata`, or streaming-only debug options.
- Runtime output is a normalized object with `id`, `model`, `content`, `finish_reason`, `usage`, and `raw`.
- Null assistant content requires nonempty tool calls; tool messages require a nonempty, unpadded `tool_call_id`. Tool definitions are limited to named function tools.

Video behavior:

- `model` defaults to `google/veo-3.1-fast`.
- `prompt` must be a non-empty string.
- `duration_seconds` is normalized to one of 4, 6, or 8 seconds.
- Optional `resolution`, `aspect_ratio`, `size`, `audio`, `callback_url`, and `seed` are forwarded to OpenRouter using the current runtime mapping.
- `provider_options.callback_url` and `provider_options.seed` override the top-level callback URL and seed when present.
- `input_images` accepts up to four objects using `url`, `data_url`, or `base64`.
- Image roles are mapped into `frame_images` for first/last frames and `input_references` for reference images or extras.
- Non-empty `input_videos` is rejected.
- `poll_interval_ms` defaults to 5000, is capped at 60000, and may be 0.
- `max_poll_attempts` defaults to 120 and is clamped to 1 through 120.
- `max_download_bytes` defaults to 128 MiB and can only narrow that hard ceiling. It is enforced while receiving the asset, including chunked responses without a `Content-Length`.
- If OpenRouter returns `unsigned_urls`, the runtime downloads the first non-empty URL.
- If no unsigned URL is present, runtime falls back to `videos/{job_id}/content?index=0`.
- Provider auth headers are included only for same-origin polling or download URLs.
- Cross-origin polling or unsigned download URLs are fetched without provider auth headers.
- HTTP redirects are disabled so that a checked URL and credential decision cannot be replaced by an implicit redirect.
- Download URLs must use HTTPS, except localhost URLs are allowed only when the configured base URL is also localhost.
- Output embeds the downloaded video as base64 with MIME type, byte length, and a stable file name.
- One invocation deadline covers submission, polling, polling sleeps, and download: at most 600 seconds for video and 60 seconds for chat/catalog, narrowed by `deadline_ms` when supplied. `request_timeout_ms` still bounds each HTTP exchange.
- After successful submission, polling/download failures are nonretryable at the whole-operation boundary and identify the submitted job. Retrying the whole operation could create a second paid job. Ambiguous submission timeouts and server failures also remain nonretryable.

## Resource And Usage Admission

Signed resource constraints bind the values actually forwarded to the provider. Chat and video use `openrouter:model:<model>`; caller-supplied media URLs use `openrouter:input_url:<canonical-url>`; chat file IDs use `openrouter:file:<id>`; video callbacks use `openrouter:callback_url:<canonical-url>`. URLs are canonicalized with `url::Url` and require HTTP(S), a host, and no credentials or fragment. Inline data URLs contain caller-supplied bytes and do not represent an external resource lookup.

Literal `%`, `?`, and `*` in resource suffixes are encoded as `%25`, `%3F`, and `%2A` respectively. This keeps URL queries and literal wildcard characters from becoming capability glob syntax. For example, `HTTPS://EXAMPLE.COM/a?b=1` is scoped as `openrouter:input_url:https://example.com/a%3Fb=1`, distinct from `/axb=1`.

The SDK atomically reserves a signed call and compact serialized request/response bytes before provider dispatch. Responses are checked against the manifest and the exact reservation before release. Chat/catalog have a bounded JSON response allowance; video also reserves headroom for base64 expansion. Failed or interrupted calls retain their reservation. These process-local counters reset only with rotated instance authority; they are not a durable billing ledger or business-level result deduplication.

Provider JSON bodies are capped at 10 MiB, error bodies at 64 KiB, and video bodies at the selected bounded download size. These limits apply during receipt. The final FCP envelope has an independent byte limit, so a response that cannot fit its signed allowance is withheld with an uncertain-outcome error.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- OpenRouter documents that chat completions support both streaming and non-streaming modes. Runtime intentionally rejects `stream=true`.
- OpenRouter documents a broad OpenAI-compatible request schema. Runtime forwards only a narrow chat subset.
- OpenRouter documents models, generation metadata, image/audio/video inputs, and many routing features. Runtime exposes only `/models`, `/chat/completions`, and `/videos`.
- The manifest declares no durable state and no event surface. Runtime matches that.
- The manifest declares network constraints for `openrouter.ai`, but runtime also permits localhost base URLs for tests.
- Runtime accepts `credential_id`, but all live operations are blocked in that mode because host-side credential injection is not implemented in this connector slice.
- Simulation proves local schema and session admission, not provider quota, model availability, billing status, moderation policy, or the future size of generated assets.
- Runtime request/error counters increment only through `handle_invoke()`.
- Video generation still returns a bounded in-memory base64 asset. Host blob storage and durable generation tracking remain future work.
- A dedicated tracked verification shell script exists at `scripts/e2e/openrouter_connector_verification.sh`; it records manifest, build, test, local evidence, redaction, and clippy artifacts under `artifacts/e2e/openrouter/<run-id>/`.

A follow-up parity bead can implement host credential injection, decide whether streaming chat should use an event surface, widen chat parameter forwarding where safe, add provider-scope/billing/model availability diagnostics, expose generation metadata reads, and integrate host blob storage for generated assets.

## First-Slice Scope

The current OpenRouter README slice documents the existing runtime surface:

- API-key and current credential-ID configuration
- Non-streaming chat completions, model listing, and bounded video generation operations
- Local health, doctor, live self-check, introspection, simulate, invoke, and shutdown behavior
- Header handling for `Authorization`, `X-Title`, and `HTTP-Referer`
- Video polling, cross-origin credential stripping, generated-asset size caps, and base64 return behavior
- Runtime/manifest/provider-doc boundaries around streaming, broad request schemas, credential injection, and inline media handling
- Existing integration-test orientation through provider contracts, connector suite tests, manifest schema checks, and WireMock-backed OpenRouter flows

## Auth And Zone Boundary

- Authentication mechanisms: direct OpenRouter API key or currently-blocked host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability families:
  - `openrouter.chat`
  - `openrouter.models`
  - `openrouter.video`
- Manifest required capabilities are `network.dns`, `network.egress`, and `network.tls.sni`.
- Manifest forbids `system.exec` and `network.listen`.
- The connector does not intentionally persist API keys, credential IDs beyond configuration metadata, prompts, completions, model catalogs, video jobs, generated videos, request counters, or error counters outside process memory.
- OpenRouter payloads can contain prompts, messages, tool schemas, model outputs, usage data, provider metadata, image references, callback URLs, seeds, and generated videos. Treat live input and output as private or work-zone sensitive unless the host supplies a stricter zone policy.

## Explicit Non-Goals

- No streaming chat delivery.
- No Responses API surface.
- No embeddings endpoint.
- No provider-key management.
- No automatic model routing policy.
- No OpenRouter generation metadata operation.
- No video-to-video generation.
- No durable video storage.
- No external blob upload for generated videos.
- No downstream data-use enforcement.
- No cross-zone model invocation.

## Verification

Run the tracked verifier from the repository root:

```bash
RUN_ID=openrouter-local-$(date -u +%Y%m%dT%H%M%SZ) scripts/e2e/openrouter_connector_verification.sh
```

The verifier writes a replay bundle and summary:

```bash
OPENROUTER_E2E_JSONL=artifacts/e2e/openrouter/<run-id>/evidence/local_non_mock.jsonl
OPENROUTER_E2E_SUMMARY=artifacts/e2e/openrouter/<run-id>/summary.json
```

The required local evidence contract is two redaction-safe `local_non_mock` JSONL records covering `models_list` and `chat_completions` through a loopback HTTP boundary. The extracted evidence must not contain the local API key, loopback socket, prompt text, or completion text.

For README-only changes, also run `git diff --check -- connectors/openrouter/README.md scripts/e2e/openrouter_connector_verification.sh` and `ubs --files connectors/openrouter/README.md,scripts/e2e/openrouter_connector_verification.sh --format=json --ci`.
