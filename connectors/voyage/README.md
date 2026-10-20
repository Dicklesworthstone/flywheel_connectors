# Voyage Connector V3 Contract

> **Status**: PROVEN (2026-10-20; 12/12 graduation gauntlet, verifier + unit/integration/local_non_mock suites verified)
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/voyage_connector_verification.sh`
> **Primary upstream**: https://docs.voyageai.com/

## Purpose

This document fixes the operator-facing contract for `fcp.voyage`. The connector exposes Voyage AI's retrieval primitives: text embeddings, multimodal embeddings, reranking, a conservative documented model catalog, and local readiness metadata.

The connector is intentionally a retrieval API bridge, not a vector store or content cache. It forwards validated requests to Voyage, returns provider JSON, and keeps prompts, documents, images, vectors, API keys, and credential references out of durable connector state.

## Current Runtime Snapshot

The current crate exposes these operations:

- `voyage.embeddings.create`
- `voyage.embeddings.create_multimodal`
- `voyage.rerank`
- `voyage.models.list`
- `voyage.health`

Important runtime truths the contract preserves:

- Configuration requires exactly one of `api_key` or `credential_id`.
- API-key mode sends `Authorization: Bearer ...`.
- Credential-id mode sends `x-fcp-credential-id` and requires host-side egress credential injection for live traffic.
- Default base URL is `https://api.voyageai.com/v1`.
- Non-loopback base URLs must be exactly `https://api.voyageai.com/v1`.
- Loopback HTTP/HTTPS base URLs are accepted only for deterministic tests.
- Default text embedding model is `voyage-3.5`.
- Default multimodal embedding model is `voyage-multimodal-3.5`.
- Default rerank model is `rerank-2.5`.
- Default `request_timeout_ms` is `60_000`.
- Default `model_cache_ttl_seconds` is `3_600`.
- Rate-limit handling is fail-fast unless `wait_on_rate_limit_ms` is configured.
- `voyage.embeddings.create` accepts a string or string batch as `input`, optional `input_type`, `truncation`, `output_dimension`, `output_dtype`, and `provider_extensions`.
- Text embedding input batches must contain 1 to 1,000 non-empty strings.
- `voyage.embeddings.create_multimodal` accepts `inputs` with 1 to 1,000 entries, optional `input_type`, `truncation`, `output_encoding`, `output_dimension`, and `provider_extensions`.
- `voyage.rerank` requires a non-empty `query` and 1 to 1,000 non-empty `documents`.
- `top_k`, when present, must be at least 1 and no greater than the number of documents.
- `voyage.models.list` returns a static documented catalog and does not call a provider model-list endpoint.
- `voyage.health` returns local readiness metadata and documented model count.
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.

## First-Slice Scope

The first Voyage README slice documents the existing runtime surface:

- text embeddings through `POST /v1/embeddings`
- multimodal embeddings through `POST /v1/multimodalembeddings`
- reranking through `POST /v1/rerank`
- static documented model catalog reporting
- local readiness without a paid provider probe
- direct bearer auth and host credential reference auth
- base URL, auth material, model, batch, dimension, dtype, input type, and `top_k` validation
- provider response/error mapping through the shared OpenAI-compatible transport layer
- optional bounded retry on `Retry-After` rate-limit responses
- lifecycle, introspection, simulation, doctor, and self-check surfaces

## Auth And Scope Boundary

- Authentication mechanisms: Voyage API key / `VOYAGE_API_KEY` equivalent, or host-injected credential ID.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, `z:work`, and `z:project:*`.
- Allowed target zone: `z:work`.
- Forbidden source zone: `z:public`.
- Capability surface:
  - `voyage.embeddings` gates text and multimodal embedding operations.
  - `voyage.rerank` gates reranking.
  - `voyage.models.read` gates the documented model catalog.
  - `voyage.health.read` gates readiness metadata.
- The connector does not persist input text, image references, document bodies, embedding vectors, rerank scores, provider payloads, API keys, or credential IDs.
- Credential-id mode is a host-egress contract, not proof that live Voyage will accept a request without an injection layer.

## Network And Runtime Invariants

- Production host: `api.voyageai.com`.
- Production path root: `/v1`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback overrides are test-only.
- Runtime default `request_timeout_ms`: `60_000`.
- Manifest text embedding, multimodal embedding, and rerank network constraints set total timeout `60_000 ms`.
- Manifest model catalog constraints set total timeout `30_000 ms`.
- Manifest health constraints set total timeout `5_000 ms`.
- Maximum response bytes are `10_485_760`.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `60_000 ms` wall-clock timeout, no exec, and no ptrace.
- Handshake declares no FCP streaming support.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `voyage.embeddings` | Create Voyage text and multimodal retrieval vectors. |
| `voyage.rerank` | Rerank candidate documents against a query. |
| `voyage.models.read` | Return the connector's documented Voyage model catalog. |
| `voyage.health.read` | Return connector readiness metadata without provider work. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `voyage.embeddings.create` | `POST /v1/embeddings` | `voyage.embeddings` | `Safe` | `Low` | `Strict` | Deterministic provider inference for supplied text inputs; sensitive text and vector contents must stay out of logs. |
| `voyage.embeddings.create_multimodal` | `POST /v1/multimodalembeddings` | `voyage.embeddings` | `Safe` | `Low` | `Strict` | Deterministic provider inference over text/image multimodal inputs; image references and vectors are sensitive. |
| `voyage.rerank` | `POST /v1/rerank` | `voyage.rerank` | `Safe` | `Low` | `Strict` | Read-only relevance scoring over caller-supplied query/document candidates. |
| `voyage.models.list` | Static catalog | `voyage.models.read` | `Safe` | `Low` | `Strict` | Lists documented model IDs without provider traffic. |
| `voyage.health` | Local readiness metadata | `voyage.health.read` | `Safe` | `Low` | `Strict` | Confirms connector configuration and catalog count without sending retrieval data. |

## Explicit Non-Goals

The current implementation does not include:

- contextualized chunk embeddings
- batch inference job submission
- provider-side file upload or URL fetching controls beyond pass-through request validation
- vector database storage, indexing, nearest-neighbor search, or cache management
- automatic model discovery from a live provider endpoint
- token counting or local model-specific token-budget enforcement
- public-zone invocation
- FCP subscription-based streaming
- durable storage of prompts, documents, images, vectors, rerank scores, provider payloads, or provider errors
- connector-local credential vaulting

These are excluded on purpose:

- The useful first slice is a narrow retrieval API connector that preserves FCP security boundaries around sensitive corpus material.
- Voyage owns exact model token limits and provider-side schema evolution; this connector validates stable FCP-facing shapes and safety boundaries.
- Static model catalog output avoids a live discovery dependency and keeps readiness checks low-cost.
- Embedding vectors and rerank results can leak corpus semantics, so verification should prefer shape and count assertions over raw value logging.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, auth mode, base URL, request counters, error counters, default models, and model cache TTL
- redacted API-key labels rather than raw API keys
- host credential reference status
- supported operations, capability IDs, risk, safety, idempotency, resource URIs, and AI hints
- local readiness and documented model catalog count without a live provider request
- credential-injection warnings for `credential_id` mode

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- bearer auth and `x-fcp-credential-id` header behavior
- base URL normalization and loopback test overrides
- text embedding request validation and provider response decoding
- direct `/v1/rerank` and `/v1/multimodalembeddings` endpoint usage
- rerank `top_k` bounds, document count bounds, and empty input rejection
- multimodal input count and shape validation
- rate-limit mapping with optional bounded wait policy
- static catalog contents including text, multimodal, and rerank models
- lifecycle, introspection, simulation, self-check, doctor, and shutdown behavior
- manifest operation coverage and strict sandbox/network policy checks

## Source Notes

- `connectors/voyage/src/connector.rs` defines configuration parsing, auth mode selection, operation dispatch, capability resources, lifecycle handlers, diagnostics, and operation metadata.
- `connectors/voyage/src/client.rs` defines provider headers, default models, base URL normalization, request execution, provider error mapping, rate-limit retry behavior, and static model listing.
- `connectors/voyage/src/types.rs` defines FCP-facing text embedding, multimodal embedding, and rerank request validation.
- `connectors/voyage/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and operation AI hints.
- `connectors/voyage/tests/integration.rs` covers deterministic provider behavior, validation, rate-limit mapping, lifecycle, catalog, and readiness behavior.
- `connectors/voyage/tests/conformance.rs` covers manifest operation and sandbox/network conformance.

## Verification Bundle

`scripts/e2e/voyage_connector_verification.sh` is the dedicated closeout bundle for this connector. It writes a summary, environment metadata, raw logs, integration JSONL, and redaction-safe local non-mock evidence under its artifact root.

The verification surface captures:

- manifest/runtime contract tests
- deterministic WireMock retrieval coverage
- auth, base URL, model, batch, input type, dimension, dtype, rerank, catalog, health, rate-limit, and redaction-sensitive lifecycle tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a Voyage API key only for live provider verification.
- Use `credential_id` only behind a host egress injection layer.
- Prefer explicit `input_type = "query"` for search queries and `input_type = "document"` for indexed documents.
- Use WireMock loopback fixtures for deterministic proof.
- Use live calls only when the operator intentionally accepts provider cost and retrieval-data handling.

**Dedicated environment**:

- Prefer deterministic loopback evidence for routine verification.
- Use a test Voyage account for live runs and keep text/document/image fixtures synthetic and small.
- Keep vector storage, search, batch jobs, and contextualized chunk embeddings out of this connector until they have separate beads and capability contracts.

**Redaction rules**:

- Redact API keys, credential IDs where needed, input text, query text, candidate documents, image URLs, base64 image content, embedding vectors, rerank scores when tied to sensitive documents, provider payloads, and provider error bodies.
- Verification output should use model IDs when non-sensitive, operation names, input counts, output counts, dimensions, dtype, status/error classes, retry decisions, and catalog counts.

**Common remediation**:

- If `health` reports `unconfigured`, configure with exactly one of `api_key` or `credential_id`.
- If `health` reports `degraded`, complete handshake before invoking operations.
- If base URL validation fails, use `https://api.voyageai.com/v1` or a loopback test origin.
- If embedding validation fails, check for empty input strings, empty batches, batch size above 1,000, invalid `input_type`, invalid `output_dimension`, or invalid `output_dtype`.
- If rerank validation fails, check for an empty query, empty documents, more than 1,000 documents, empty document strings, or `top_k` greater than the document count.
- If rate limits occur, either let the caller own retry scheduling or configure `wait_on_rate_limit_ms` for a bounded connector-side retry.

**Rerun commands**:

- `RUN_ID=voyage-local OUT_ROOT=/tmp/fcp-voyage-e2e scripts/e2e/voyage_connector_verification.sh`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-voyage-e2e cargo check -p fcp-voyage --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-voyage-e2e cargo test -p fcp-voyage --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-voyage-e2e cargo clippy -p fcp-voyage --all-targets --no-deps -- -D warnings`
