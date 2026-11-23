# Hugging Face Connector V3 Contract

> **Status**: INCUBATING — native invocation and provider transports are implemented; credential-backed production evidence remains outstanding.
> **Connector**: `fcp.huggingface` (`fcp-huggingface` package and binary)
> **Original contract bead**: `flywheel_connectors-4kw5f.2.4.4`

## Supported operations

The connector exposes Hugging Face's first-party `hf-inference` task API and the Hub model catalog. Every operation requires a configured, negotiated FCP session and a signed capability token, including anonymous public-model reads.

| Operation | Provider route | Capability | Safety / risk | Idempotency |
|-----------|----------------|------------|---------------|-------------|
| `huggingface.inference.text_generation` | `POST https://router.huggingface.co/hf-inference/models/{model_id}` | `huggingface.inference` | Risky / medium | None |
| `huggingface.inference.summarization` | `POST https://router.huggingface.co/hf-inference/models/{model_id}` | `huggingface.inference` | Risky / medium | None |
| `huggingface.models.list` | `GET https://huggingface.co/api/models` | `huggingface.models` | Safe / low | Strict |
| `huggingface.models.info` | `GET https://huggingface.co/api/models/{model_id}` | `huggingface.models` | Safe / low | Strict |

The embedded manifest is the source of operation schemas, capabilities, approval requirements, safety metadata, idempotency, and AI hints. Runtime introspection reads that same manifest. Inputs are validated before provider I/O; successful outputs are validated before delivery.

This connector does not implement streaming, chat completions, third-party provider selection, dedicated Inference Endpoints, model uploads, datasets, Spaces, fine-tuning, billing, or account administration. Model availability still depends on the provider, account permissions, and current hosted inventory.

The upstream text-generation task page currently reports no provider support for that task. Its retained operation and default model are not a claim of live availability; production callers must verify a serving model. Summarization and catalog fixtures likewise do not replace credential-backed provider checks.

## Configuration and credentials

Configuration accepts:

| Field | Default / behavior |
|-------|--------------------|
| `api_token` | Optional direct Hugging Face bearer token. |
| `credential_id` | Optional UUID referencing a host-managed credential. Mutually exclusive with `api_token`. |
| `inference_url` | `https://router.huggingface.co/hf-inference` |
| `hub_url` | `https://huggingface.co/api` |
| `request_timeout_ms` | `30000`; accepted range `1..=60000`. |
| `retry` | Shared SDK retry configuration, subject to the operation's replay rules and total invocation deadline. |

With neither credential field, the connector can attempt public model-catalog access. Anonymous mode does not remove FCP authorization requirements, and provider authentication may still be required for inference or gated resources.

Production endpoint overrides must retain the supported HTTPS host and path above, with port 443. Query strings, fragments, embedded credentials, arbitrary remote hosts, and obsolete inference endpoints are rejected. Explicit `localhost` or literal loopback URLs are accepted for deterministic fixtures; the production manifest continues to deny loopback and private-network egress.

### Host-managed credentials

`credential_id` now uses the SDK's real host egress proxy. Set `FCP_HOST_EGRESS_PROXY_URL` in the connector's launch environment and provision a matching credential in the host. Configuration fails if the proxy is missing or invalid.

For each admitted invocation, the connector forwards the original signed COSE capability, connector ID, operation, zone, request ID, correlation ID, requested URL, and credential reference to the host. The host validates authority and injects the provider secret. The connector never substitutes a credential-reference header for authentication and never falls back to direct HTTP if the proxy rejects or fails. It verifies host response attribution and requires confirmation that credentials were injected.

The signed capability must authorize both the connector's logical resource (below) and the actual HTTP URL checked by host egress. The host's credential allow-list must also permit the supplied credential reference. Each invocation gets a private client clone, so concurrent requests cannot share or overwrite authority context.

## Native process contract

The binary uses the shared SDK JSONL control channel with a **1 MiB input-frame limit** and one process-wide async runtime. A successful shutdown writes its acknowledgement and exits even if stdin remains open. EOF, oversized frames, and channel failures clear configuration and revoke the active session.

Each outer frame is an SDK request with `id`, `method`, and `params`. Methods are `configure`, `handshake`, `health`, `doctor`, `self_check`, `introspect`, `invoke`, `simulate`, and `shutdown`. The outer frame ID correlates the control reply; the canonical invoke ID inside `params` identifies the invocation. They need not be equal.

A host must perform these steps:

1. Configure provider credentials and endpoint policy.
2. Send a canonical `HandshakeRequest` with the supported protocol version, target zone, nonce, requested capabilities, and Ed25519 host verification key. The only accepted target zone is `z:work`, matching the manifest.
3. Read the newly generated `instance_id` from the handshake response.
4. Issue signed capabilities bound to that instance, connector, zone, operation, capability family, validity interval, and permitted resources.
5. Send a complete canonical `InvokeRequest`, including its signed token and a nonempty `idempotency_key`. All four operations require a key because inference is risky and catalog reads have strict idempotency. Successful replies contain a canonical `InvokeResponse` with `result` and `resource_uris`; errors use the SDK error envelope.

Malformed or failed replacement configuration, failed handshake, re-handshake, and shutdown revoke previous authority. Tokens for an old instance cannot be reused after these transitions. Negotiation cannot grant capabilities absent from the manifest or requested handshake.

### Resource and usage boundaries

| Operation target | Logical resource URI |
|------------------|----------------------|
| Text generation, summarization, or model metadata | `huggingface:model:{model_id}` |
| Model catalog listing | `huggingface:models` |

Resource authorization uses the actual selected model, including a default model when omitted. Model identifiers must be a single model name or `organization/model`, with no empty segments, traversal, encoded separators, query/fragment syntax, controls, or whitespace.

Admission checks signature, issuer key, connector, actual instance, target zone, negotiated capability, operation, resource restrictions, expiration, and cumulative call/byte constraints through `StandaloneSession`. Usage is reserved before execution and is not refunded when effects may have occurred. Accounting is scoped to the current connector session; host admission remains responsible for its durable and cross-process policy.

`simulate` accepts a canonical `SimulateRequest` and checks the same input schema and authority without provider I/O or consuming the token's call budget. It reports `would_succeed` and missing capabilities. Simulation does not promise that a model is available or that a later provider request will succeed.

## Inputs and results

Text generation defaults to `gpt2`. It accepts `prompt`, optional `model_id`, and optional `max_new_tokens`, `temperature`, `top_p`, `top_k`, `repetition_penalty`, `do_sample`, and `return_full_text`. Results are arrays of objects containing `generated_text`.

Summarization defaults to `facebook/bart-large-cnn`. It accepts `text`, optional `model_id`, and optional `max_length`, `min_length`, and `do_sample`. All advertised parameters are forwarded. When both lengths are supplied, `min_length` must not exceed `max_length`. Results are arrays of objects containing `summary_text`.

Prompts and source text must be nonempty and at most 262144 characters, subject to the smaller JSONL frame budget after encoding. Model IDs are at most 256 characters. Integer options must fit their declared positive or nonnegative 32-bit range. Unknown input properties and wrong parameter types are rejected rather than silently ignored.

Model listing accepts optional `search` (up to 512 characters), `pipeline_tag` (up to 128), and `limit` (`1..=100`, default `25`). Its result contains `models`, `catalog`, and `limit`; it is not a raw Hub array. Model metadata requires `model_id` and returns the typed metadata object. See `manifest.toml` for the exact schemas.

## Bounded requests and replay behavior

The invocation deadline covers all provider attempts, retry delays, and body reads. Its budget is the minimum of the caller's relative `deadline_ms`, configured timeout, and 60 seconds. A zero deadline is rejected. Once execution may have occurred, cancellation or deadline exhaustion reports a nonretryable error with an unknown provider outcome and retains the admission charge.

Provider response bodies are limited to **1 MiB**, including chunked bodies and error responses. Host proxy envelopes have a separate **2 MiB** cap to accommodate base64 encoding and attribution. HTTP redirects, implicit transport retries, and ambient HTTP proxies are disabled on the direct provider client.

Read-only Hub requests can use bounded retries for transient provider errors. Inference POSTs use stricter rules:

- Connection failures proven to precede dispatch can be retried.
- Explicit rate limits and recognized model-loading responses can be retried within policy and the total deadline.
- Model-loading delays preserve the provider's fractional estimate, with at least a one-second delay.
- Other provider failures after dispatch, truncated or malformed successful responses, and ambiguous host-proxy failures are terminal. They do not trigger a second billable inference attempt.
- Redirects are rejected without forwarding tokens or prompt bodies.

Provider body text and request URLs are not copied into external error messages. Authentication, not-found, rate-limit, oversized-response, malformed-response, and uncertain-outcome errors retain useful classifications without echoing tokens, prompts, or provider payloads.

## Health and lifecycle

`health` uses the canonical SDK `HealthSnapshot` on the wire. Local readiness requires configuration and successful handshake; authenticated or host-injected sessions can be locally ready. This is not evidence of provider availability or account access. Anonymous configurations remain degraded.

`doctor` reports local configuration, handshake, client, runtime, and auth mode. `self_check` returns a canonical `SelfCheckReport`:

- Direct-token mode, after handshake, checks `https://huggingface.co/api/whoami-v2`.
- Anonymous mode reports that there is no token to validate and does not probe the provider.
- Host-injected mode reports `credential_injection_requires_invoke`. A health check cannot manufacture signed invocation authority; use an authorized provider invocation to validate that path.

The connector does not persist provider prompts, generated text, summaries, tokens, responses, or model catalogs. Shutdown clears the active runtime, client, credentials, configuration, and negotiated session.

## Verification

The crate contains three complementary integration surfaces:

- `tests/provider_contract.rs`: deterministic provider behavior, signed authority rejection, selected/default resource scope, cumulative call constraints, non-consuming simulation, session invalidation, schema validation, retries, privacy, and lifecycle.
- `tests/local_non_mock.rs`: real loopback HTTP sockets for invocation, parameter forwarding, and failure behavior.
- `tests/native_stdio.rs`: the actual compiled binary, canonical configure/handshake/health/invoke dialogue, distinct control and invocation IDs, unauthorized no-egress checks, real HTTP dispatch, and process termination while stdin remains open.

Client unit tests additionally exercise real host proxy envelopes, original capability preservation, credential injection and attribution checks, operation isolation, refusal without direct fallback, response bounds, and inference replay rules. These are local deterministic tests; their presence alone does not establish a live provider or production-readiness claim.

Run the focused suite using the repository's pinned toolchain and shared remote compiler where available:

```bash
rch exec -- cargo check -p fcp-huggingface --all-targets --locked
cargo fmt --package fcp-huggingface --check
rch exec -- cargo test -p fcp-huggingface --locked
rch exec -- cargo clippy -p fcp-huggingface --all-targets --no-deps --locked -- -D warnings
```

The existing `scripts/e2e/huggingface_connector_verification.sh` also emits redaction-safe provider-fixture JSONL and replay metadata. Set `REPO_TOOLCHAIN` to the toolchain in `rust-toolchain.toml` when using that older wrapper. Production graduation still needs credential-backed evidence for model availability and real host egress policy.

## Upstream references

- [Hugging Face Inference Providers](https://huggingface.co/docs/inference-providers/index)
- [HF Inference provider](https://huggingface.co/docs/inference-providers/providers/hf-inference)
- [Text generation](https://huggingface.co/docs/inference-providers/tasks/text-generation)
- [Summarization](https://huggingface.co/docs/inference-providers/tasks/summarization)
- [Hub API](https://huggingface.co/docs/hub/api)
