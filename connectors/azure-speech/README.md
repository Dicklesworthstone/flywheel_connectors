# Azure Speech Connector

> **Status**: PROVEN
> **Verification script**: `scripts/e2e/azure_speech_connector_verification.sh`

This connector implements the core Azure Speech REST surface for FCP:

- regional token exchange through `issueToken`
- Microsoft Entra access-token handoff for documented keyless REST paths
- `voices/list` discovery
- REST text-to-speech synthesis through `/cognitiveservices/v1`
- Speech-to-text fast and batch transcription through `2025-10-15`
- Speech-to-text custom speech project, dataset, model, and endpoint lifecycle through `2025-10-15`

Realtime WebSocket sessions remain an intentionally separate follow-up surface: `flywheel_connectors-4kw5f.2.9.6.1.2`. Custom speech lifecycle is implemented under `flywheel_connectors-4kw5f.2.9.6.2` for the current `2025-10-15` REST operation families. Connector-local IMDS/MSAL token acquisition was reviewed under `flywheel_connectors-4kw5f.2.9.6.3` and is retained as a host-token-broker-only boundary.

## Enterprise Auth Status

`flywheel_connectors-4kw5f.2.9.6.1.4` supports three auth modes without writing secrets to disk:

- `subscription_key` / `api_key`: the connector preserves the existing key path. TTS and voices exchange the key for an issued Speech bearer token; 2025-10-15 STT operations send `Ocp-Apim-Subscription-Key` because the REST reference declares that security scheme.
- `entra_access_token`: the host supplies a current Microsoft Entra access token. When `entra_resource_id` is present, the connector constructs the documented `aad#<resource-id>#<token>` bearer payload and returns only the resource-id hash. When `entra_token_format = "bearer_token"`, the connector sends the raw bearer token for current keyless speech endpoints that document standard Entra bearer auth. `entra_token_source = "managed_identity"` means the host token broker obtained the token from managed identity; the connector does not contact IMDS itself.
- `credential_id`: the connector emits `X-FCP-Credential-ID` for host/egress credential injection. Direct live self-check remains degraded because Microsoft endpoints require the host to materialize a concrete bearer token before egress.

The connector validates Azure Cognitive Services resource IDs, tracks optional `entra_token_expires_in_seconds`, refuses expired Entra tokens with refresh guidance, and redacts access tokens, subscription keys, tenant/resource identifiers, and provider SAS URLs from connector outputs.

Connector-local managed identity acquisition is intentionally rejected with structured guidance. Current Microsoft IMDS docs require a local HTTP request to `169.254.169.254/metadata/identity/oauth2/token` with `Metadata: true`, `api-version=2018-02-01`, a target resource such as `https://cognitiveservices.azure.com/`, and optional identity selectors. FCP runtime network policy treats local/LAN exceptions as all-local operation policies, while Azure Speech operations also need external Microsoft Speech hosts. Mixing both in every provider operation would broaden the runtime network claim, so the supported production shape is host-token-broker acquisition plus `entra_access_token` or `credential_id` handoff.

All invoke paths require a bound FCP capability token after handshake. The connector verifies the token zone, target instance, operation, capability, and resource constraints before any provider request is built, so a wrong-zone or wrong-instance grant is denied without contacting Azure.

Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.

## Speech-to-text REST Status

`flywheel_connectors-4kw5f.2.9.6.1.3` covers the current `2025-10-15` REST paths that are explicit in Microsoft Learn: fast transcription via `/speechtotext/transcriptions:transcribe` and batch transcription submit/status/files via `/speechtotext/transcriptions:submit` plus the transcription resource and files links returned by that API. Batch input accepts storage URLs or a Blob container URL; runtime output redacts provider URLs and SAS-bearing file links into hashes/descriptors. Batch submit also accepts validated custom `project`, `dataset`, and `model` references, including ergonomic `*_id` and `*_url` inputs. These references are pinned to the configured Speech-to-text host and `api-version=2025-10-15`; retired v3.x URLs and cross-region hosts are rejected before provider egress.

## Custom Speech Lifecycle

`flywheel_connectors-4kw5f.2.9.6.2` implements the stable Custom Speech operation families documented by Microsoft for Speech-to-text REST API `2025-10-15`:

- projects: `azure.speech.stt.custom.projects.create/list/get/delete`
- datasets: `azure.speech.stt.custom.datasets.create/list/get/delete`
- models: `azure.speech.stt.custom.models.create/list/get/delete`
- endpoints: `azure.speech.stt.custom.endpoints.create/list/get/delete`

All custom speech operations use the `azure.speech.stt` capability and the same bound-token zone/instance checks as fast and batch transcription. Create requests validate required schema fields, locale, custom property bounds, dataset kind, external `content_url`, and project/model/dataset reference objects. Get/delete requests accept either an ID or provider URL, normalize the URL to the configured STT host, pin `api-version=2025-10-15`, and reject retired v3.x paths. Provider `self`, `location`, `contentUrl`, and related links are returned as redacted host/path/query/hash descriptors; project/model/resource identifiers are exposed only as SHA-256 hashes in connector outputs and e2e logs.

The intentionally excluded subsurfaces are dataset upload blocks and file downloads, custom speech evaluations, web hooks, endpoint logs, and model copy authorization/cross-subscription copy. Those are separate operation families with different data-retention and cleanup semantics, not missing pieces of the create/list/get/delete lifecycle implemented here.

Current docs rechecked for this slice:

- <https://learn.microsoft.com/en-us/azure/ai-services/speech-service/rest-speech-to-text>
- <https://learn.microsoft.com/en-us/azure/ai-services/speech-service/migrate-2025-10-15>
- <https://learn.microsoft.com/en-us/rest/api/speechtotext/projects?view=rest-speechtotext-2025-10-15>
- <https://learn.microsoft.com/en-us/rest/api/speechtotext/datasets?view=rest-speechtotext-2025-10-15>
- <https://learn.microsoft.com/en-us/rest/api/speechtotext/models?view=rest-speechtotext-2025-10-15>
- <https://learn.microsoft.com/en-us/rest/api/speechtotext/endpoints?view=rest-speechtotext-2025-10-15>

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Notes |
|-----------|----------------|------------|------------|-----------|-------------|-------|
| `azure.speech.voices.list` | `GET /cognitiveservices/voices/list` | `azure.speech.voices` | `safe` | `low` | `strict` | Discover configured-region voices before synthesis. |
| `azure.speech.tts.synthesize` | `POST /cognitiveservices/v1` | `azure.speech.tts` | `safe` | `medium` | `none` | Synthesize one SSML/text payload to provider audio output. |
| `azure.speech.stt.transcribe_fast` | `POST /speechtotext/transcriptions:transcribe?api-version=2025-10-15` | `azure.speech.stt` | `safe` | `medium` | `strict` | Fast transcription for bounded audio input. |
| `azure.speech.stt.batch.submit` | `POST /speechtotext/transcriptions:submit?api-version=2025-10-15` | `azure.speech.stt` | `safe` | `medium` | `none` | Submit a batch transcription using storage or custom-speech references. |
| `azure.speech.stt.batch.get` | `GET /speechtotext/transcriptions/{id}?api-version=2025-10-15` | `azure.speech.stt` | `safe` | `low` | `strict` | Read batch transcription status and redacted provider links. |
| `azure.speech.stt.batch.files` | `GET /speechtotext/transcriptions/{id}/files?api-version=2025-10-15` | `azure.speech.stt` | `safe` | `low` | `strict` | List batch output files with SAS/provider URLs redacted. |
| `azure.speech.stt.custom.projects.create` | `POST /speechtotext/custom/projects?api-version=2025-10-15` | `azure.speech.stt` | `safe` | `medium` | `none` | Create a Custom Speech project container. |
| `azure.speech.stt.custom.projects.list` | `GET /speechtotext/custom/projects?api-version=2025-10-15` | `azure.speech.stt` | `safe` | `low` | `strict` | List Custom Speech projects with bounded pagination. |
| `azure.speech.stt.custom.projects.get` | `GET /speechtotext/custom/projects/{id}?api-version=2025-10-15` | `azure.speech.stt` | `safe` | `low` | `strict` | Inspect one Custom Speech project by ID or normalized provider URL. |
| `azure.speech.stt.custom.projects.delete` | `DELETE /speechtotext/custom/projects/{id}?api-version=2025-10-15` | `azure.speech.stt` | `dangerous` | `high` | `none` | Delete a project only after interactive approval. |
| `azure.speech.stt.custom.datasets.create` | `POST /speechtotext/custom/datasets?api-version=2025-10-15` | `azure.speech.stt` | `safe` | `medium` | `none` | Register a Custom Speech dataset from provider-accessible storage. |
| `azure.speech.stt.custom.datasets.list` | `GET /speechtotext/custom/datasets?api-version=2025-10-15` | `azure.speech.stt` | `safe` | `low` | `strict` | List Custom Speech datasets. |
| `azure.speech.stt.custom.datasets.get` | `GET /speechtotext/custom/datasets/{id}?api-version=2025-10-15` | `azure.speech.stt` | `safe` | `low` | `strict` | Inspect one dataset by ID or normalized provider URL. |
| `azure.speech.stt.custom.datasets.delete` | `DELETE /speechtotext/custom/datasets/{id}?api-version=2025-10-15` | `azure.speech.stt` | `dangerous` | `high` | `none` | Delete a dataset only after interactive approval. |
| `azure.speech.stt.custom.models.create` | `POST /speechtotext/custom/models?api-version=2025-10-15` | `azure.speech.stt` | `safe` | `medium` | `none` | Train or register a Custom Speech model from project/dataset references. |
| `azure.speech.stt.custom.models.list` | `GET /speechtotext/custom/models?api-version=2025-10-15` | `azure.speech.stt` | `safe` | `low` | `strict` | List Custom Speech models. |
| `azure.speech.stt.custom.models.get` | `GET /speechtotext/custom/models/{id}?api-version=2025-10-15` | `azure.speech.stt` | `safe` | `low` | `strict` | Inspect one model by ID or normalized provider URL. |
| `azure.speech.stt.custom.models.delete` | `DELETE /speechtotext/custom/models/{id}?api-version=2025-10-15` | `azure.speech.stt` | `dangerous` | `high` | `none` | Delete a model only after interactive approval. |
| `azure.speech.stt.custom.endpoints.create` | `POST /speechtotext/custom/endpoints?api-version=2025-10-15` | `azure.speech.stt` | `safe` | `medium` | `none` | Deploy a Custom Speech endpoint for a model reference. |
| `azure.speech.stt.custom.endpoints.list` | `GET /speechtotext/custom/endpoints?api-version=2025-10-15` | `azure.speech.stt` | `safe` | `low` | `strict` | List Custom Speech endpoints. |
| `azure.speech.stt.custom.endpoints.get` | `GET /speechtotext/custom/endpoints/{id}?api-version=2025-10-15` | `azure.speech.stt` | `safe` | `low` | `strict` | Inspect one endpoint by ID or normalized provider URL. |
| `azure.speech.stt.custom.endpoints.delete` | `DELETE /speechtotext/custom/endpoints/{id}?api-version=2025-10-15` | `azure.speech.stt` | `dangerous` | `high` | `none` | Delete an endpoint only after interactive approval. |

## Realtime WebSocket Status

`flywheel_connectors-4kw5f.2.9.6.1.2` rechecked current Microsoft Learn docs on 2026-05-08. Azure Speech TTS text streaming is documented through Speech SDK `TextStream` on the WebSocket v2 endpoint, and realtime STT is documented through Speech SDK `SpeechRecognizer`/`AudioConfig` stream APIs. Microsoft does not publish the direct WebSocket frame protocol needed for a standalone Rust connector.

This connector therefore keeps realtime STT/TTS WebSocket operations blocked instead of guessing the live wire format. The implementation gate is explicit in runtime introspection under `streaming_blocker` and `deferred_operations`.

Current docs:

- <https://learn.microsoft.com/en-us/azure/ai-services/speech-service/how-to-lower-speech-synthesis-latency#how-to-use-text-streaming>
- <https://learn.microsoft.com/en-us/azure/ai-services/speech-service/how-to-recognize-speech>
- <https://learn.microsoft.com/en-us/azure/ai-services/speech-service/how-to-control-connections>
- <https://learn.microsoft.com/en-us/azure/ai-services/speech-service/rest-text-to-speech#authentication>
- <https://learn.microsoft.com/en-us/azure/ai-services/speech-service/how-to-configure-azure-ad-auth>
- <https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token>
- <https://learn.microsoft.com/en-us/azure/ai-services/speech-service/llm-speech>

## Verification

The closeout proof lane is `scripts/e2e/azure_speech_connector_verification.sh`. It runs the no-live-credential loopback matrix through the production connector boundary and emits redacted JSONL records for token issue, voices.list, TTS synth, STT fast transcription, batch submit/get/files, custom project create/list/get/delete, custom dataset/model/endpoint create/get/delete, host-brokered managed-identity token handoff, connector-local IMDS policy skips, provider error redaction, rate-limit retry, timeout, malformed input, unsupported format, oversized audio, capability-token zone and instance denial, harness cancellation, streaming blocker disposition, shutdown cleanup, and optional live-smoke skip/pass state.

The JSONL contract records command line, git revision, connector id, operation id, capability, zone, instance id, fixture/live mode, region and endpoint class, auth mode, token source class, API version, resource/model/project id hashes, voice/language/model labels, content type, audio byte counts, transcript length only, stream chunk count, HTTP status, retry/backoff decision, FCP error mapping, latency, result, audit receipt id, cleanup result, and skip reason. It deliberately rejects keys, bearer tokens, raw tenant/resource IDs, raw custom speech resource IDs, SAS URLs, SSML/text content, transcripts, raw audio bytes, provider bodies, local absolute paths, and PII.

## Operator Guidance

Prerequisites:

- For the default verifier path, no Azure credentials are required; it uses loopback fixtures and proves the connector boundary without live egress.
- Optional live smoke requires `AZURE_SPEECH_LIVE=1`, `AZURE_SPEECH_KEY`, and `AZURE_SPEECH_REGION`; run that only against a disposable Azure Speech resource.
- Production keyless use requires the host to broker Microsoft Entra or managed-identity tokens and pass `entra_access_token` or `credential_id`; the connector does not contact IMDS directly.

Common remediation:

- `host_token_broker_required` means connector-local IMDS/MSAL acquisition was correctly refused; configure the host token broker instead of broadening connector network policy.
- `InvalidRequest` on audio or SSML inputs should be debugged from shape fields only; do not paste raw transcripts, SSML, audio bytes, SAS URLs, subscription keys, or bearer tokens into shared logs.
- `UpstreamTimeout` and `429_retry_after_ms_then_success` are covered by the verifier; retry with the same redaction rules before treating the provider as unavailable.
- `blocked_official_sdk_only_protocol` on realtime streaming is expected until Microsoft publishes a standalone wire protocol or the project accepts an SDK-backed design.

Rerun commands:

- `RUN_ID=$(date -u +%Y%m%dT%H%M%SZ) OUT_ROOT=.codex-targets/azure-speech-verification/$RUN_ID RCH_QUEUE_WHEN_BUSY=1 bash scripts/e2e/azure_speech_connector_verification.sh`
- `RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 rch exec -- env CARGO_TARGET_DIR=/Volumes/USB_NVME/cargo-target CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 cargo run -q -p fwc -- manifest fix connectors/azure-speech/manifest.toml --check --json`
- `scripts/graduation/run_gauntlet.sh --jsonl .codex-targets/azure-speech-verification/$RUN_ID/evidence/azure_speech_gauntlet_after_operator_guidance.jsonl connectors/azure-speech`
- `RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 rch exec -- env CARGO_TARGET_DIR=/Volumes/USB_NVME/cargo-target CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 cargo test -p fcp-conformance --test graduation_gauntlet_conformance all_proven_connectors_pass_gauntlet -- --nocapture`
