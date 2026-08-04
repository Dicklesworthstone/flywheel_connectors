# Inworld Connector

Native FCP connector for the current Inworld character and voice-agent APIs.
> **Status**: PROVEN runtime contract documented with remote Inworld verifier proof

Interface hash: `blake3-256:fcp.interface.v2:4d069076fab4ef08a8245bac1815899c5718fbc2906ab34e859a61e31f407bd2`.

The initial implementation focuses on the operational surfaces that Inworld
currently documents for new integrations:

- Realtime WebSocket sessions at `/api/v1/realtime/session`
- TTS bidirectional WebSocket contexts at `/tts/v1/voice:streamBidirectional`
- Router chat completions at `/v1/chat/completions`

Older REST-style `openSession`, `sendText`, `characters.list`, and
`scenes.list` operation names are intentionally absent from the connector
catalog and tests.

Runtime introspection derives operation descriptions, schemas, capabilities,
safety, risk, idempotency, approval, rate-limit, and AI-hint metadata from the
embedded `manifest.toml` while preserving the five-operation order listed
below.

## Operations

| Operation | Capability | Provider surface |
| --- | --- | --- |
| `inworld.realtime.text_turn` | `inworld.realtime.invoke` | Realtime WebSocket `session.update`, `conversation.item.create`, `response.create` |
| `inworld.realtime.audio_turn` | `inworld.realtime.invoke` | Realtime WebSocket `input_audio_buffer.*`, `response.create` |
| `inworld.tts.context_roundtrip` | `inworld.tts` | TTS WebSocket `create`, `send_text`, `close_context` |
| `inworld.router.chat_completion` | `inworld.router.chat` | Router REST `POST /v1/chat/completions` |
| `inworld.health` | `inworld.health.read` | Local health/configuration report (no provider egress) |

## Configuration

Exactly one credential mode must be supplied:

- `api_key`: sent as an `Authorization: Basic ...` header
- `bearer_token`: sent as an `Authorization: Bearer ...` header
- `credential_id`: accepted for host-side credential injection, but direct
  connector egress reports that injection is required

Optional URL overrides are accepted for deterministic loopback tests:

- `realtime_ws_url`
- `tts_ws_url`
- `router_base_url`
- `request_timeout_ms`

Production URLs are restricted to `api.inworld.ai` and loopback plaintext
`ws://` / `http://` URLs are only allowed for local fixtures.
Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.

## Redaction Contract

Operation outputs are metadata-first. They include hashes, byte counts, event
types, and usage objects where useful, but do not preserve raw prompts, user
text, generated transcripts, synthesized audio, API keys, JWTs, or provider
response bodies. Tests assert this contract for Realtime, Router, and emitted
fixture JSONL.

## Verification

Verification script: `scripts/e2e/inworld_connector_verification.sh`.

Targeted proof for this connector should run through `rch` once the workspace
manifest includes `connectors/inworld`:

```bash
rch exec -- cargo test -p fcp-inworld -- --nocapture
rch exec -- cargo clippy -p fcp-inworld --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

The integration suite starts real loopback WebSocket servers for Realtime and
TTS, plus a `wiremock` Router endpoint. Manifest-derived runtime metadata tests
guard the operation catalog against drift. Live provider verification is skipped
unless the required Inworld credential environment variables are present.

## Operator Guidance

Rerun commands for promotion or incident verification:

```bash
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)" OUT_ROOT=".codex-targets/inworld-verification/${RUN_ID}" scripts/e2e/inworld_connector_verification.sh
RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 rch exec -- env CARGO_TARGET_DIR=/Volumes/USB_NVME/cargo-target CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 cargo test -j 2 -p fcp-inworld --locked --tests -- --nocapture
RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 rch exec -- env CARGO_TARGET_DIR=/Volumes/USB_NVME/cargo-target CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 cargo clippy -j 2 -p fcp-inworld --locked --all-targets -- -D warnings
```

Use loopback fixtures for routine proof. Live provider smoke remains opt-in and
must provide the documented Inworld credential environment variables; fixture
and retry evidence should stay redaction-safe and avoid raw prompts, audio,
provider bodies, API keys, JWTs, and provider identifiers.
