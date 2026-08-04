# Tlon Connector V3 Contract

> **Status**: PROVEN runtime contract documented with remote Tlon verifier proof
> **Bead**: `flywheel_connectors-6n7.18`
> **Parent**: `flywheel_connectors-6n7`
> **Verification script**: `scripts/e2e/tlon_connector_verification.sh`
> **Tlon developer upstream**: https://dev.tlon.io/
> **Urbit upstream**: https://urbit.org/

## Purpose

`fcp.tlon` exposes a credentialed Urbit Eyre channel runtime for Tlon and Urbit messaging. It supports direct-message send, channel send, and local target normalization through the FCP connector lifecycle and line-delimited JSON-RPC process loop.

The runtime contract is proven with remote verifier evidence, including loopback no-mock HTTP coverage against an Eyre-shaped server. It does not claim production evidence against a real Tlon or Urbit ship.

## Runtime Snapshot

The current crate exposes these implemented operation IDs:

- `tlon.dm.send`
- `tlon.channel.send`
- `tlon.target.resolve`

Important runtime truths:

- Runtime connector ID is `fcp.tlon`.
- Runtime connector version is `0.1.0`.
- The binary reads newline-delimited JSON-RPC from stdin and writes newline-delimited JSON responses to stdout.
- Supported JSON-RPC methods are `configure`, `handshake`, `health`, `doctor`, `self_check`, `introspect`, `invoke`, `simulate`, and `shutdown`.
- `configure` requires `base_url` and exactly one of `session_cookie`/`cookie` or `credential_id`/`auth_ref`.
- `configure` rejects userinfo, query strings, fragments, unsupported schemes, public `http`, and private or loopback targets unless `allow_private_network = true`.
- `handshake` requires prior configuration and returns `surface_status = "implemented"`.
- `handshake` advertises active `tlon.dm` and `tlon.channel` capabilities.
- Bound runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.
- `health` reports `healthy` after successful configure and handshake.
- `self_check` reports `ok` for session-cookie auth and `degraded` with `credential_injection_required` for credential-id mode.
- `introspect` advertises all three operations with `implemented = true`.
- `simulate` returns `allowed = true` for known operations once configured and handshaken.
- Outbound DM and channel sends claim SDK chat ownership before the Eyre HTTP call and append redacted `coordination` audit records on successful dispatch.
- `shutdown` clears configured and handshaken state.

## Auth And Scope Boundary

- Auth modes:
  - `session_cookie`/`cookie`: sends the value as the Eyre `Cookie` header.
  - `credential_id`/`auth_ref`: sends the host credential reference as `X-FCP-Credential-Id` and reports that host credential injection is required.
- Home zone: `z:community`.
- Allowed source zones: `z:owner`, `z:work`, and `z:community`.
- Allowed target zone: `z:community`.
- Runtime capability surface:
  - `tlon.dm` for `tlon.dm.send`.
  - `tlon.channel` for `tlon.channel.send` and `tlon.target.resolve`.
- The connector does not persist ship URLs, cookies, credential IDs, target ships, channel identifiers, message bodies, provider payloads, or provider errors.
- Tlon ship names, channel paths, group/channel membership, login codes, and message bodies can reveal private community context. Treat live request and response data as community-zone or work-zone data according to the configured target.

## Network And Runtime Invariants

- Provider calls are outbound HTTP(S) `PUT` requests to `BASE_URL/~/channel/<channel_id>`.
- The default Eyre channel ID is `fcp-tlon`.
- The request body is a single-element JSON action array shaped like an Urbit poke:
  - `tlon.dm.send` uses mark `tlon-dm-action`.
  - `tlon.channel.send` uses mark `tlon-channel-action`.
- `tlon.target.resolve` is local validation only and opens no provider socket.
- Chat coordination claim targets are namespaced as `dm:<ship>` for direct messages and `channel:<channel_path>` for channel sends. The current Tlon surface has no native thread identifier, so the default `dm_mode = "treat_as_thread"` treats each conversation/channel target as its own thread.
- Manifest sandbox profile is `strict`, with `96 MB` memory, `25%` CPU, `60_000 ms` wall-clock timeout, no exec, and no ptrace.
- Invalid JSON produces a JSON-RPC error with code `FCP-1001`.
- Unknown JSON-RPC methods produce an invalid-request response.

## Chat Coordination Configuration

Outbound sends support the shared FCP chat thread-ownership guard through optional `chat_coordination` configuration:

```json
{
  "chat_coordination": {
    "enabled": true,
    "ttl_seconds": 900,
    "fail_open": true,
    "backend": "in_memory",
    "dm_mode": "treat_as_thread",
    "allowlist_channels": ["dm:~zod", "channel:/ship/~zod/general"]
  }
}
```

The connector coordinates before Eyre dispatch. Successful outputs include only redacted audit hashes and claim outcomes, not raw ship names, channel paths, message bodies, cookies, credential IDs, endpoint URLs, or raw agent instance IDs. A duplicate active claim is denied before the provider socket is opened.

## Operation Inventory

| Operation | Runtime status | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `tlon.dm.send` | implemented | `tlon.dm` | `Safe` | `Medium` | `BestEffort` | Sends a direct message payload to a target ship through Eyre after a chat-coordination claim. |
| `tlon.channel.send` | implemented | `tlon.channel` | `Safe` | `Medium` | `BestEffort` | Sends a message payload into a Tlon or Urbit channel path after a chat-coordination claim. |
| `tlon.target.resolve` | implemented | `tlon.channel` | `Safe` | `Low` | `Strict` | Normalizes and validates a DM ship or channel target before sending. |

## Explicit Non-Goals

The current implementation does not include:

- Tlon account login, Urbit ship login, login-code refresh, cookie refresh, or credential vaulting.
- Message reads, channel history, channel discovery, invite acceptance, app install, desk management, or `%landscape` automation.
- Webhook, websocket, SSE, polling, replay, or durable event delivery.
- Attachment upload, rich-text conversion, thread reply handling, allowlist management, or approval flows.
- Production no-mock evidence against a real Tlon or Urbit ship.

## Verification Surface

`handle_configure()`, `handle_handshake()`, `handle_health()`, `handle_doctor()`, `handle_self_check()`, `handle_introspect()`, `handle_invoke()`, `handle_simulate()`, and `handle_shutdown()` are part of the public closeout contract. They surface:

- configured and handshaken state
- implemented operation metadata
- strict manifest/runtime schema parity
- loopback Eyre channel request construction
- credential-id and session-cookie auth modes
- local target validation and invalid-input denial
- provider 401 and 429 error mapping with redacted provider bodies
- redacted JSONL evidence records
- JSON-RPC handling for invalid JSON, lifecycle requests, and shutdown

The deterministic integration evidence is anchored on connector-local tests covering:

- unconfigured, configured, handshaken, and shutdown lifecycle states
- real loopback HTTP provider requests for DM and channel send
- local target resolution without provider traffic
- malformed, missing-operation, unknown-operation, pre-configure, and pre-handshake denials
- credential-id self-check behavior and credential header forwarding
- redacted JSONL evidence that hashes ship and channel fixtures instead of leaking raw values
- JSON-RPC process behavior for invalid JSON, configure, handshake, and shutdown

## Source Notes

- `connectors/tlon/src/connector.rs` defines configuration validation, Eyre request construction, lifecycle handlers, readiness, invoke, simulation, and shutdown.
- `connectors/tlon/src/main.rs` defines the line-delimited JSON-RPC process loop.
- `connectors/tlon/src/error.rs` defines provider error classes and FCP error conversion.
- `connectors/tlon/manifest.toml` defines the operation catalog, strict schemas, capability declarations, sandbox boundary, and zone policy.
- `connectors/tlon/tests/local_non_mock.rs` covers the raw loopback Eyre channel boundary without `wiremock`.
- `connectors/tlon/tests/integration.rs` covers loopback provider behavior, denial paths, evidence redaction, and JSON-RPC process behavior.
- `connectors/tlon/tests/conformance_contract.rs` covers manifest/runtime operation parity and schema strictness.

## Operator Guidance

**Prerequisites**:

- Configure a dedicated test ship or approved endpoint before live traffic.
- Use `allow_private_network = true` only for a dedicated local test ship or approved LAN endpoint.
- Prefer `session_cookie` for direct test loops and `credential_id`/`auth_ref` when the host owns credential injection.

**Redaction rules**:

- Redact ship names when tenant-revealing, channel paths, login codes, auth references, cookies, message bodies, endpoint URLs, provider error bodies, and filesystem paths from live evidence.
- Verification output should use operation IDs, fixture IDs, hashes, lifecycle phase, status/error classes, and cleanup result instead of raw Tlon or Urbit content.

**Common remediation**:

- If `health` reports `unconfigured`, call `configure` first.
- If `self_check` reports `not_handshaken`, call `handshake` after `configure`.
- If `self_check` reports `credential_injection_required`, verify that the host credential injection layer is configured for the supplied credential reference.
- If `configure` rejects a loopback or LAN endpoint, add `allow_private_network = true` only for an approved test endpoint.
- If provider responses return 401 or 403, refresh the Eyre session cookie or credential reference; the connector redacts provider error bodies.

**Rerun commands**:

- `bash scripts/e2e/tlon_connector_verification.sh`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-tlon-readme cargo check -p fcp-tlon --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-tlon-readme cargo test -p fcp-tlon --test local_non_mock -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-tlon-readme cargo test -p fcp-tlon --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-tlon-readme cargo clippy -p fcp-tlon --all-targets --no-deps -- -D warnings`
- `ubs connectors/tlon/src/connector.rs connectors/tlon/tests/local_non_mock.rs connectors/tlon/tests/integration.rs connectors/tlon/tests/conformance_contract.rs connectors/tlon/README.md scripts/e2e/tlon_connector_verification.sh`
