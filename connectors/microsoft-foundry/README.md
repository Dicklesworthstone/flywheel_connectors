# Microsoft Foundry Connector

> **Status**: PROVEN (2026-10-20; 12/12 graduation gauntlet, verifier + unit/integration/local_non_mock suites verified)
> **Bead**: `flywheel_connectors-angoc.16.5`
> **Verification script**: `scripts/e2e/microsoft_foundry_connector_verification.sh`

`fcp.microsoft-foundry` is the direct Microsoft Foundry / Azure OpenAI v1 provider connector. It is separate from `microsoft365` Graph, generic `azure`, and `azure-speech`.

## Operations

- `microsoft_foundry.responses.create`
- `microsoft_foundry.responses.cancel`
- `microsoft_foundry.responses.input_items.list`
- `microsoft_foundry.chat.completions`
- `microsoft_foundry.chat.completions_stream`
- `microsoft_foundry.embeddings.create`
- `microsoft_foundry.deployments.list`
- `microsoft_foundry.health`

## Configuration

Required:

- `base_url`: `https://<resource>.openai.azure.com/openai/v1` or `https://<resource>.services.ai.azure.com/openai/v1`
- exactly one of `api_key`, `entra_access_token`, or `credential_id`

Optional:

- `credential_auth_policy`: `entra_bearer` or `api_key`; defaults to `entra_bearer`
- `default_model`: the deployment name to use when an operation omits `model`
- `request_timeout_ms`
- `model_cache_ttl_seconds`
- `wait_on_rate_limit_ms`

`credential_id` mode is the production path for host-owned credential injection. Entra credential references request the `https://ai.azure.com/.default` token scope from the host credential broker. The connector never shells out to Azure CLI on production invocation paths.

## Runtime Contract

- Manifest interface hash is `blake3-256:fcp.interface.v2:dd5f28d4d0643e6695f6e38d8b835a760350b4d64dcd07ea1cb65ddba2182193`.
- Runtime operation introspection derives operation descriptions, schemas, capabilities, safety, risk, idempotency, approval mode, and AI hints from the embedded strict manifest.
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.
- Invoke capability verification still uses a connector-local operation-to-capability mapping before checking the host-issued capability token.

## Security Boundaries

- The `model` field is a Foundry deployment name, not an Azure resource path.
- Logs and e2e artifacts must not contain prompts, completions, embedding vectors, API keys, bearer tokens, tenant IDs, raw resource IDs, or full resource hostnames.
- The connector allows loopback HTTP only for deterministic fixture tests. Production endpoints require HTTPS, SNI, and Microsoft Foundry/Azure OpenAI hosts.
- Microsoft Graph, Azure resource management, and Azure Speech stay in their own connectors.

## Proof Lane

Focused implementation proof is anchored on `scripts/e2e/microsoft_foundry_connector_verification.sh`. It runs Cargo proof through `rch exec`, writes a summary plus redaction-checked JSONL artifacts, and should use `CARGO_TARGET_PREFIX` on a spacious volume when the local checkout is disk constrained.

```bash
RUN_ID=manual-microsoft-foundry OUT_ROOT=/Volumes/trj-data/fcp-artifacts/microsoft-foundry/manual-microsoft-foundry CARGO_TARGET_PREFIX=/Volumes/trj-data/tmp/fcp-microsoft-foundry-manual scripts/e2e/microsoft_foundry_connector_verification.sh
ubs connectors/microsoft-foundry scripts/e2e/microsoft_foundry_connector_verification.sh Cargo.toml
```

The bundle captures manifest schema/hash validation, formatting, check, conformance, WireMock integration, optional live smoke, local non-mock loopback acceptance, clippy, and redaction checks for secrets, prompts, completions, raw hostnames, and loopback endpoints.

## Operator Guidance

Prerequisites:
- Use the deterministic loopback harness or `WireMock` fixture for local verification; never log raw API keys, Entra tokens, prompts, or completions.

Rerun commands:
- `scripts/e2e/microsoft_foundry_connector_verification.sh`
- `rch exec -- cargo test -p fcp-microsoft-foundry --test local_non_mock -- --nocapture`
- `rch exec -- cargo test -p fcp-microsoft-foundry --test integration -- --nocapture`
- `rch exec -- cargo clippy -p fcp-microsoft-foundry --all-targets -- -D warnings`
