# Google Meet Connector V3 Contract

> **Status**: PROVEN runtime contract documented; live-session boundary documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/google_meet_connector_verification.sh`
> **Meet API upstream**: https://developers.google.com/workspace/meet/api/reference/rest/v2
> **Meet spaces upstream**: https://developers.google.com/workspace/meet/api/reference/rest/v2/spaces
> **Meet conference records upstream**: https://developers.google.com/workspace/meet/api/reference/rest/v2/conferenceRecords
> **Meet transcripts upstream**: https://developers.google.com/workspace/meet/api/reference/rest/v2/conferenceRecords.transcripts
> **Meet transcript entries upstream**: https://developers.google.com/workspace/meet/api/reference/rest/v2/conferenceRecords.transcripts.entries

## Purpose

This document fixes the operator-facing contract for `fcp.google-meet`. The connector exposes the Google Meet API surface implemented in this crate: meeting-space normalization and lookup, space creation and ending, conference-record reads, participants, participant sessions, attendance synthesis, recordings, transcripts, smart notes, Drive-backed artifact text export, and delegated live-session handoff state.

The connector is intentionally a bounded Meet bridge. It is not a Calendar event client, full browser controller, media recorder, realtime caption engine, Workspace admin tool, push-notification receiver, or durable meeting warehouse.

## Current Runtime Snapshot

The current crate exposes these operations:

- `gmeet.normalize_space_name`
- `gmeet.space.get`
- `gmeet.space.create`
- `gmeet.space.end_active_conference`
- `gmeet.conference_record.get`
- `gmeet.conference_records.list`
- `gmeet.conference_record.latest`
- `gmeet.participants.list`
- `gmeet.participant_sessions.list`
- `gmeet.attendance.list`
- `gmeet.recordings.list`
- `gmeet.transcripts.list`
- `gmeet.transcript_entries.list`
- `gmeet.smart_notes.list`
- `gmeet.transcripts.with_text.list`
- `gmeet.smart_notes.with_text.list`
- `gmeet.drive_document_text.export`
- `gmeet.live.join`
- `gmeet.live.status`
- `gmeet.live.transcript`
- `gmeet.live.bridge_event`
- `gmeet.live.say`
- `gmeet.live.leave`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-google-meet`.
- Runtime `BaseConnector` ID is `google-meet`.
- Configuration requires a `service_selector` that resolves to `meet:v2`; the default selector is `meet`.
- Configuration requires exactly one Google auth source accepted by `GoogleAuthSelection`.
- Required scopes can be supplied explicitly through `required_scopes`, or selected through `scope_triggers`, but not both.
- Direct bearer-token mode sends the Google Authorization header through `reqwest`.
- `credential_id` mode is secretless and requires host egress credential injection.
- Default Meet base URL is `https://meet.googleapis.com/v2`.
- Default Drive export base URL is `https://www.googleapis.com/drive/v3`.
- Public Meet base URLs must use HTTPS, must target exact host `meet.googleapis.com`, and must not contain userinfo, query strings, or fragments.
- Public Drive export base URLs must use HTTPS, must target exact host `www.googleapis.com`, and must not contain userinfo, query strings, or fragments.
- `localhost`, `127.0.0.1`, and `::1` are accepted with HTTP or HTTPS for deterministic loopback tests.
- Runtime HTTP timeout is 30 seconds.
- Runtime `invoke` requires `capability_token` and verifies a bound token before dispatch.
- Runtime `simulate` validates operation inventory, configured state, handshaken state, and bound capability token before returning an allowed result.
- Meet API read operations are scope-gated before provider execution.
- Drive-backed text operations require `https://www.googleapis.com/auth/drive.meet.readonly`.
- Live-session operations are local handoff/state operations. The connector returns a browser handoff contract and records bridge events; it does not embed a browser runtime or directly join a call.
- `gmeet.live.say` requires an active realtime session and `meeting.live_speak`; speech text is not logged in the queue record.
- `handle_shutdown` stops any active live session and reports `no_orphan_supervised_tasks = true`.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest connector ID is `fcp.google-meet`, while runtime `BaseConnector` ID is `google-meet`.
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.
- Runtime capability-token verification currently uses an empty resource URI list for Meet operations. Capabilities are operation-bound but not resource-bound to a normalized space, conference record, participant, transcript, or Drive document.
- Runtime `health()` and `doctor()` are local/config/scope diagnostics. `self_check()` deliberately returns `api_probe_deferred` for direct-token configurations instead of probing Meet.
- `GoogleMeetClient::shutdown()` is a placeholder. Connector shutdown clears active live-session state, but it does not clear config, client, verifier, session, configured flags, or handshaken flags.
- Manifest network host allow-lists include `www.googleapis.com` broadly for Meet API operations because Drive-backed artifact export shares this connector; runtime Drive egress is limited to explicit text-export paths.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should add resource URI binding, decide whether provider-backed self-check belongs here, narrow manifest host policy if operation-level separation is desired, and reset lifecycle state consistently on shutdown.

## First-Slice Scope

The current Google Meet README slice documents the existing runtime surface:

- Google bearer-token, credential-reference, and OAuth refresh auth selection through the shared Google layer
- Meet service selection, required-scope selection, and scope-trigger handling
- Meet and Drive export base URL policy and loopback test allowance
- space, conference-record, participant, attendance, recording, transcript, smart-note, Drive text export, and live-session operations
- bound capability-token verification during both `invoke` and `simulate`
- provider error mapping, response-size limits, async checkpoint behavior, redaction posture, and health behavior
- lifecycle, doctor, health, self-check, introspection, simulation, invoke, and shutdown surfaces
- deterministic WireMock tests, conformance-contract tests, and live-session loopback harness coverage

## Auth And Scope Boundary

- Authentication mechanisms: Google bearer token, host credential reference, or OAuth refresh material through the shared Google auth layer.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability surface:
  - `meet.space.read` gates space normalization and lookup.
  - `meet.space.create` gates space creation.
  - `meet.space.end` gates ending an active conference.
  - `meet.conference.read` gates conference records, participants, participant sessions, and attendance synthesis.
  - `meet.artifact.read` gates recording, transcript, transcript-entry, and smart-note metadata.
  - `meet.drive_artifact.read` gates Drive-backed transcript/smart-note text export and direct Drive document text export.
  - `meeting.live_join` gates live join handoff and bridge events.
  - `meeting.live_read` gates live status and transcript reads.
  - `meeting.live_leave` gates live leave.
  - `meeting.live_speak` gates queued speech for realtime sessions.
- Manifest capability surface uses the same capability names.
- The connector does not persist meeting records, transcript text, smart-note text, participant identities, access tokens, credential IDs, provider payloads, or provider error bodies beyond process memory.
- Meet data can contain private attendee, transcript, recording, chat, and Drive artifact metadata. Treat all live reads and live-session state as work-zone data.

## Network And Runtime Invariants

- Production Meet host: `meet.googleapis.com`.
- Production Meet API prefix: `/v2`.
- Production Drive export host: `www.googleapis.com`.
- Production Drive export prefix: `/drive/v3`.
- Live meeting URL host accepted by live handoff: `meet.google.com`.
- Production port: `443`.
- TLS and SNI are required by the manifest for live traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback base URLs are test-only.
- Runtime HTTP timeout: `30 seconds`.
- Manifest network constraints use `10_000 ms` connect timeout.
- Manifest total timeout is generally `30_000 ms`; live handoff has `120_000 ms` wall-clock sandbox budget.
- Manifest maximum response bytes are operation-specific, usually `1_048_576`.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `120_000 ms` wall-clock timeout, no exec, and no ptrace.
- Manifest forbids `browser.control`; live operations return a delegated browser handoff contract rather than performing browser automation in this connector.
- The connector does not open inbound sockets.
- Runtime handshake event caps report no streaming and no replay.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `meet.space.read` | Normalize and read Google Meet spaces. |
| `meet.space.create` | Create Google Meet spaces. |
| `meet.space.end` | End active conferences for spaces created by the calling app. |
| `meet.conference.read` | Read completed or ongoing conference records, participants, sessions, and derived attendance. |
| `meet.artifact.read` | Read recording, transcript, transcript-entry, and smart-note metadata. |
| `meet.drive_artifact.read` | Export text from Drive-backed Meet artifact documents. |
| `meeting.live_join` | Create or update a delegated live-session handoff and record bridge events. |
| `meeting.live_read` | Read local live-session status and transcript buffer. |
| `meeting.live_leave` | Stop the local live-session handoff. |
| `meeting.live_speak` | Queue policy-gated speech for an active realtime session. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `gmeet.normalize_space_name` | local normalization | `meet.space.read` | `Safe` | `Low` | `Strict` | Normalizes Meet URL, meeting code, or `spaces/*` name without provider egress. |
| `gmeet.space.get` | `GET /v2/{name=spaces/*}` | `meet.space.read` | `Safe` | `Low` | `Strict` | Reads one Meet space. |
| `gmeet.space.create` | `POST /v2/spaces` | `meet.space.create` | `Risky` | `High` | `BestEffort` | Creates a Meet space and returns its meeting URI. |
| `gmeet.space.end_active_conference` | `POST /v2/{name=spaces/*}:endActiveConference` | `meet.space.end` | `Risky` | `High` | `BestEffort` | Ends the active conference for an app-created space. |
| `gmeet.conference_record.get` | `GET /v2/{name=conferenceRecords/*}` | `meet.conference.read` | `Safe` | `Low` | `Strict` | Reads one conference record. |
| `gmeet.conference_records.list` | `GET /v2/conferenceRecords` | `meet.conference.read` | `Safe` | `Low` | `Strict` | Lists conference records, optionally filtered by Meet space. |
| `gmeet.conference_record.latest` | composite list filtered by space | `meet.conference.read` | `Safe` | `Low` | `Strict` | Selects the latest conference record for a meeting space. |
| `gmeet.participants.list` | `GET /v2/{parent=conferenceRecords/*}/participants` | `meet.conference.read` | `Safe` | `Low` | `Strict` | Lists participants in a conference record. |
| `gmeet.participant_sessions.list` | `GET /v2/{parent=conferenceRecords/*/participants/*}/participantSessions` | `meet.conference.read` | `Safe` | `Low` | `Strict` | Lists join/leave sessions for one participant. |
| `gmeet.attendance.list` | composite conference, participant, and session reads | `meet.conference.read` | `Safe` | `Low` | `Strict` | Builds attendance rows with participant evidence. |
| `gmeet.recordings.list` | `GET /v2/{parent=conferenceRecords/*}/recordings` | `meet.artifact.read` | `Safe` | `Low` | `Strict` | Lists recording artifacts for a conference record. |
| `gmeet.transcripts.list` | `GET /v2/{parent=conferenceRecords/*}/transcripts` | `meet.artifact.read` | `Safe` | `Low` | `Strict` | Lists transcript artifacts for a conference record. |
| `gmeet.transcript_entries.list` | `GET /v2/{parent=conferenceRecords/*/transcripts/*}/entries` | `meet.artifact.read` | `Safe` | `Low` | `Strict` | Lists transcript entry text exposed by the Meet API. |
| `gmeet.smart_notes.list` | `GET /v2/{parent=conferenceRecords/*}/smartNotes` | `meet.artifact.read` | `Safe` | `Low` | `Strict` | Lists smart-note artifacts for a conference record. |
| `gmeet.transcripts.with_text.list` | transcript list plus Drive text export | `meet.drive_artifact.read` | `Safe` | `Low` | `Strict` | Lists transcripts and exports docsDestination text with partial-error evidence. |
| `gmeet.smart_notes.with_text.list` | smart-note list plus Drive text export | `meet.drive_artifact.read` | `Safe` | `Low` | `Strict` | Lists smart notes and exports docsDestination text with partial-error evidence. |
| `gmeet.drive_document_text.export` | `GET /drive/v3/files/{document_id}/export?mimeType=text/plain` | `meet.drive_artifact.read` | `Safe` | `Low` | `Strict` | Exports bounded text from a strict Drive document ID. |
| `gmeet.live.join` | local browser handoff contract | `meeting.live_join` | `Dangerous` | `High` | `BestEffort` | Creates or replaces a delegated live-session handoff after consent. |
| `gmeet.live.status` | local state read | `meeting.live_read` | `Risky` | `Medium` | `Strict` | Reads active or last-stopped live-session state. |
| `gmeet.live.transcript` | local transcript buffer read | `meeting.live_read` | `Risky` | `Medium` | `Strict` | Reads transcript entries recorded through bridge events. |
| `gmeet.live.bridge_event` | local bridge event record | `meeting.live_join` | `Risky` | `Medium` | `BestEffort` | Records status, transcript, or cancellation checkpoint events from a delegated worker. |
| `gmeet.live.say` | local speech queue record | `meeting.live_speak` | `Dangerous` | `High` | `BestEffort` | Queues speech metadata for an active realtime session without logging speech text. |
| `gmeet.live.leave` | local handoff stop | `meeting.live_leave` | `Risky` | `Medium` | `BestEffort` | Stops the active local live-session handoff. |

## Live-Session Boundary

Live-session operations are intentionally not browser automation:

- `gmeet.live.join` validates a canonical `https://meet.google.com/<code>` URL and returns a `browser_handoff` contract.
- `gmeet.live.bridge_event` records delegated worker events such as transcript, status, and cancellation checkpoints.
- `gmeet.live.transcript` returns only transcript entries already recorded into local state.
- `gmeet.live.say` queues speech metadata only for `mode = realtime`; speech text is represented by byte count and redaction markers.
- `gmeet.live.leave` clears active local state and stores the stopped-session summary.

This contract keeps browser execution, audio capture, and voice bridge work outside this connector boundary.

## Explicit Non-Goals

The current implementation does not include:

- Calendar event create/update, Calendar conference-data provisioning, or Calendar attendee management
- embedded browser automation, direct media capture, direct microphone/speaker control, realtime caption provider execution, or voice bridge execution
- webhook receiving, push notifications, durable event queues, or streaming replay
- recording media download, Drive file permission management, Drive folder placement, or arbitrary Drive export
- participant identity reconciliation beyond the current attendance-row synthesis
- durable transcript stores, long-running conference warehouses, or connector-local credential vaulting

These are excluded on purpose:

- Meet artifacts and live transcripts contain high-sensitivity human communication.
- Live meeting control needs explicit consent, delegation, and audit contracts separate from read-only artifact APIs.
- Drive-backed artifact text export needs bounded byte caps and partial-error evidence.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, auth mode, Meet base URL, Drive export base URL, service identity, required scopes, and request counters
- operation metadata with capability, risk, safety tier, idempotency, schemas, and AI hints
- bound capability-token verification during `invoke`
- simulation denial for unknown operation, unconfigured connector, missing handshake, and bound capability-token mismatch
- secretless credential-injection requirements
- scope diagnostics for Meet reads and Drive-backed artifact export
- live-session boundary diagnostics
- local-only health and deferred provider probe behavior
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- space lookup, space create, active conference end, conference records, participants, sessions, attendance, recordings, transcripts, transcript entries, smart notes, and Drive text export
- live join/status/transcript/bridge/say/leave behavior and JSONL loopback evidence
- base URL validation, Drive document ID extraction, path encoding, response-size caps, and async checkpoints
- provider 401, 403, 404, 429, malformed JSON, response-too-large, and FCP error mapping
- manifest/interface hash checks, manifest capability declarations, forbidden `browser.control`, operation catalog parity, and network constraints

## Source Notes

- `connectors/google-meet/src/connector.rs` defines configuration parsing, base URL policy, required-scope selection, lifecycle handlers, introspection, simulation, capability-token verification, invoke dispatch, attendance synthesis, Drive text attachment, and live-session state.
- `connectors/google-meet/src/client.rs` defines Meet paths, Drive export paths, Google auth header application, resource-name normalization, URL building, response decoding, response-size limits, and provider error mapping.
- `connectors/google-meet/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/google-meet/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, event caps, and rate-limit pools.
- `connectors/google-meet/tests/integration.rs` covers deterministic HTTP behavior, redaction, and runtime invoke coverage.
- `connectors/google-meet/tests/conformance_contract.rs` covers manifest/runtime contract checks.

## Verification Bundle

The tracked verification bundle is `scripts/e2e/google_meet_connector_verification.sh`. It runs the graduation gauntlet, manifest check, crate-local compilation, formatting, integration/conformance suites, `local_non_mock` loopback acceptance suite, JSONL redaction/evidence checks, and clippy through `rch`.

The verification surface captures:

- runtime operation inventory and policy metadata
- deterministic WireMock coverage for Meet API and Drive export paths
- live-session handoff loopback coverage
- auth, endpoint policy, provider error, lifecycle, simulation, and introspection tests
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a Google Workspace test tenant with Meet API access enabled for live verification.
- Prefer credential-reference mode when host policy should own Google secret material.
- Use loopback WireMock fixtures for routine proof.
- Enable Drive Meet readonly scope before using text export from Meet artifacts.

**Dedicated environment**:

- Keep test meetings separate from personal and production calls.
- Use completed conferences for artifact and attendance proof.
- Use explicit meeting URLs or `spaces/*` names in shared environments.
- Treat live-session handoff operations as consented interactive operations.

**Redaction rules**:

- Redact access tokens, credential IDs where needed, meeting URLs, meeting codes, space names, conference record IDs, participant IDs, participant display names, transcript text, smart-note text, Drive document IDs, provider payloads, provider error bodies, and endpoint URLs when they reveal tenant topology.
- Verification output should use operation IDs, endpoint shapes, auth mode, host class, result counts, status/error classes, retry decisions, payload-shape summaries, and redacted live-session queue metadata.

**Common remediation**:

- If configuration fails, provide exactly one Google auth source and a service selector that resolves to `meet:v2`.
- If scope resolution fails, provide either `required_scopes` or `scope_triggers`, not both.
- If Drive-backed export fails, confirm `drive.meet.readonly` was requested and the document ID came from a Meet docsDestination.
- If `gmeet.space.end_active_conference` fails, verify the space was created by the calling app and that the current conference is active.
- If live speech fails, confirm the active session uses `mode = realtime` and the capability token grants `meeting.live_speak`.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-meet-readme cargo check -p fcp-google-meet --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-meet-readme cargo test -p fcp-google-meet --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-google-meet-readme cargo clippy -p fcp-google-meet --all-targets --no-deps -- -D warnings`
- `ubs connectors/google-meet/README.md`
