# Box Connector V3 Contract

> **Status**: PROVEN runtime contract documented; runtime operation metadata derives from manifest
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://developer.box.com/reference/

## Purpose

This document fixes the operator-facing contract for `fcp.box`. The connector exposes a focused Box file, folder, upload, delete, and collaboration-listing surface.

The connector is intentionally a Box content-management bridge. It does not implement full Box administration, search, retention, sign, tasks, comments, groups, metadata templates, events, or webhook ingestion.

## Current Runtime Snapshot

The current crate exposes these operations:

- `box.files.get`
- `box.files.upload`
- `box.files.delete`
- `box.folders.list`
- `box.sharing.list`

Important runtime truths the contract preserves:

- Configuration accepts exactly one of `access_token` or `credential_id`.
- `credential_id` must be a valid UUID and is treated as secretless egress-proxy metadata.
- Default API base URL is `https://api.box.com/2.0`.
- Default upload base URL is `https://upload.box.com/api/2.0`.
- Bearer-token mode restricts `base_url` and `upload_url` to HTTPS `api.box.com`, HTTPS `upload.box.com`, or loopback test hosts.
- Credential-id mode allows custom HTTPS endpoints or loopback test hosts so host-side egress injection can own provider routing.
- Runtime endpoint validation rejects unparseable URLs, missing hosts, non-HTTPS non-loopback endpoints, and non-Box bearer-token endpoints.
- Bearer-token mode sends `Authorization: Bearer ...`.
- Credential-id mode sends `X-FCP-Credential-Id: ...` and self-check reports `credential_injection_required`.
- HTTP client timeout is `30 seconds`.
- The connector retries through the shared connector runtime with a maximum of two retries.
- File and folder identifiers reject empty values, path traversal, slash, backslash, `..`, `%2f`, and `%5c`.
- Upload is a simplified multipart request that sends JSON attributes plus text content from the optional `content` field.
- Upstream 401, 403, 404, 409, 429, and other provider failures are mapped into FCP auth, permission, not-found, conflict, rate-limit, or external errors.
- Runtime introspection derives operation descriptions, schemas, capability, risk, safety, idempotency, approval mode, and AI hints from `manifest.toml`.
- Runtime introspection exposes manifest approval intent for `box.files.upload` and `box.files.delete`, but `invoke` and `simulate` do not verify approval tokens.

## First-Slice Scope

The current Box README slice documents the existing runtime surface:

- bearer token and credential-id configuration
- API and upload endpoint policy
- file metadata lookup
- simplified file upload
- file deletion
- folder item listing
- file collaboration listing
- provider error mapping, retry behavior, and redaction posture
- lifecycle, introspection, simulation, doctor, self-check, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanisms: OAuth2 bearer token or host credential reference.
- Provisioning recipe: OAuth2 authorization code with PKCE against Box authorization and token endpoints.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Capability surface:
  - `box.files.read` gates file metadata lookup.
  - `box.files.write` gates upload and delete.
  - `box.folders.read` gates folder item listing.
  - `box.sharing.read` gates collaboration listing.
- The manifest allows `media.download`, but the current runtime does not expose a file download operation.
- The connector does not persist file contents, folder listings, collaboration payloads, bearer tokens, credential IDs beyond configuration metadata, provider payloads, or provider error bodies.

## Network And Runtime Invariants

- Production API host: `api.box.com`.
- Production API prefix: `/2.0`.
- Production upload host: `upload.box.com`.
- Production upload prefix: `/api/2.0`.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback overrides are test-only.
- Runtime request timeout: `30 seconds`.
- Manifest network constraints set total timeout `30_000 ms`.
- Maximum response bytes are `10_485_760` for read/list operations and `1_048_576` for upload/delete.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300_000 ms` wall-clock timeout, no exec, and no ptrace.
- Handshake declares no FCP streaming support.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `box.files.read` | Read Box file metadata. |
| `box.files.write` | Upload or delete Box files. |
| `box.folders.read` | List Box folder contents. |
| `box.sharing.read` | List file collaborations. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `box.files.get` | `GET /files/{file_id}` | `box.files.read` | `Safe` | `Low` | `Strict` | Read-only file metadata lookup. |
| `box.files.upload` | `POST upload:/files/content` | `box.files.write` | `Risky` | `Medium` | `None` | Creates provider-visible file content in a folder. |
| `box.files.delete` | `DELETE /files/{file_id}` | `box.files.write` | `Dangerous` | `High` | `None` | Destructive file deletion; manifest marks it for interactive approval. |
| `box.folders.list` | `GET /folders/{folder_id}/items` | `box.folders.read` | `Safe` | `Low` | `Strict` | Read-only folder item inventory. |
| `box.sharing.list` | `GET /files/{file_id}/collaborations` | `box.sharing.read` | `Safe` | `Low` | `Strict` | Read-only collaboration listing for a file. |

## Explicit Non-Goals

The current implementation does not include:

- file download despite the manifest-level `media.download` allowance
- chunked upload, resumable upload, file versioning, copy, move, lock, restore, or trash listing
- folder creation, deletion, copy, move, metadata templates, comments, tasks, events, webhooks, or Box Sign
- shared-link creation, update, or removal
- enterprise, user, group, retention, legal hold, governance, or admin APIs
- connector-local OAuth refresh/token lifecycle beyond the provisioning recipe
- FCP subscription-based streaming
- connector-local credential vaulting

These are excluded on purpose:

- Upload and delete are explicit write/destructive operations with separate risk posture.
- The runtime currently sends simplified text content for upload; host-managed binary artifact transfer needs a separate contract before broad file-upload claims.
- Download behavior would need explicit media and redaction boundaries before exposure.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration and handshake state
- auth mode, base URL, upload URL, credential-injection state, request counters, and error counters
- self-check degradation for unconfigured and credential-id configurations
- simulation denial for unsupported operation IDs
- five operation descriptors with manifest-derived capability, risk, safety tier, idempotency, approval mode, schemas, and AI hints

The deterministic integration evidence is anchored on connector-local tests covering:

- access-token and credential-id configuration
- API and upload base URL acceptance and rejection
- auth header propagation
- file get, upload, delete, folder listing, and collaboration listing loopback requests
- path traversal rejection for file and folder identifiers
- provider 401, 403, 404, 409, 429, malformed JSON, and retryability behavior
- manifest operation inventory, rate-limit pools, and network constraints
- lifecycle, health, doctor, self-check, simulation, and shutdown behavior

## Source Notes

- `connectors/box/src/connector.rs` defines configuration parsing, endpoint validation, lifecycle handlers, diagnostics, introspection, simulation, and invoke dispatch.
- `connectors/box/src/client.rs` defines Box API and upload request paths, auth headers, timeout, retry config, path-segment guards, multipart upload shape, and provider error mapping.
- `connectors/box/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/box/manifest.toml` defines operation schemas, network constraints, sandbox boundary, zone policy, rate limits, and AI hints.
- `connectors/box/tests/integration.rs` covers deterministic HTTP behavior and manifest/runtime contract checks.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/box_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- manifest-derived runtime operation metadata with explicit approval-mode parity
- deterministic WireMock coverage for all five operations
- auth, URL policy, input validation, provider error, lifecycle, and introspection tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a test Box application and bearer token for live provider verification.
- Use a disposable folder and disposable files for upload/delete testing.
- Use WireMock loopback fixtures for routine proof.

**Dedicated environment**:

- Keep live uploaded content synthetic and non-sensitive.
- Confirm folder ID `0` means the Box root before using it in live tests.
- Do not expect binary artifact download or resumable upload behavior from this connector slice.

**Redaction rules**:

- Redact bearer tokens, credential IDs where needed, file IDs when sensitive, folder IDs when sensitive, file names, file contents, collaboration users, provider payloads, provider error bodies, and local paths.
- Verification output should use operation IDs, endpoint shapes, host classes, status/error classes, retry decisions, synthetic file names, and payload-shape summaries.

**Common remediation**:

- If configuration fails, provide exactly one of `access_token` or `credential_id`.
- If bearer-token URL validation fails, use `https://api.box.com/2.0`, `https://upload.box.com/api/2.0`, or a loopback test origin.
- If credential-id mode self-check reports `credential_injection_required`, use a bearer token or wire the egress proxy injection path.
- If file or folder validation fails, pass numeric/string Box IDs rather than paths, names, URLs, or traversal-like values.
- If upload places files in the wrong location, verify `folder_id`; `0` means the root folder.
- If delete is denied by policy, verify the operation has explicit approval and a token for `box.files.write`.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-box-readme cargo check -p fcp-box --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-box-readme cargo test -p fcp-box --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-box-readme cargo clippy -p fcp-box --all-targets --no-deps -- -D warnings`
