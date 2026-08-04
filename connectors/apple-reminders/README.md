# Apple Reminders Connector V3 Contract

> **Status**: runtime contract documented; manifest-derived operation metadata; platform drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Apple scripting upstream**: https://developer.apple.com/documentation/foundation/scripting-support
> **Apple scripting terminology upstream**: https://developer.apple.com/library/archive/documentation/LanguagesUtilities/Conceptual/MacAutomationScriptingGuide/AboutScriptingTerminology.html
> **Apple Reminders upstream**: https://support.apple.com/guide/reminders/welcome/mac

## Purpose

This document fixes the operator-facing contract for `fcp.apple-reminders`. The connector exposes the Apple Reminders surface currently implemented in this crate: local connector health, reminder-list inventory, reminder inventory, reminder creation, and reminder completion through a bounded `/usr/bin/osascript` bridge to the macOS Reminders app.

The connector is intentionally a bounded macOS-local bridge. It is not a Reminders sync engine, iCloud API client, EventKit service, Reminders database reader, reminder editor, reminder deleter, list manager, Smart List client, tag/priority/location/due-date manager, shared-list assignment manager, streaming event source, or cross-device task replication layer.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `apple_reminders.health`
- `apple_reminders.list_lists`
- `apple_reminders.list_reminders`
- `apple_reminders.create_reminder`
- `apple_reminders.complete_reminder`

Runtime introspection derives operation descriptions, schemas, risk, safety,
idempotency, approval mode, and AI hints from the checked-in manifest operation
sections. Manifest `requires_approval = "none"` serializes as omitted
`requires_approval` in `OperationInfo`; policy approval remains explicit.

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-apple-reminders`.
- Manifest ID is `fcp.apple-reminders`.
- `BaseConnector` runtime ID is `fcp.apple-reminders`.
- Manifest version is `0.1.0`.
- Manifest format is `native`.
- Manifest schema version is `2.1`.
- Configuration accepts:
  - `default_list`
  - `osascript_path`
  - `subprocess_timeout_secs`
- `osascript_path` defaults to `/usr/bin/osascript`.
- Configuration rejects empty, whitespace-bearing, relative, command-carrier, or non-canonical `osascript_path` values. Production clients only run `/usr/bin/osascript`.
- `subprocess_timeout_secs` defaults to 30 and must be greater than zero.
- `default_list` is optional and applies when list/create inputs omit `list_name`.
- There is no provider token, OAuth flow, credential ID, or network auth material.
- Runtime access to Reminders data is mediated by macOS, the Reminders app scripting dictionary, and the user's local Automation permission grant.
- `configure()` validates config, builds the process client, sets configured, clears handshaken state, and clears the verifier.
- `handshake()` parses a full `HandshakeRequest`, honors `requested_instance_id`, installs a `CapabilityVerifier`, hashes the checked-in manifest, and reports non-streaming event caps.
- `handshake()` grants only requested capabilities matching `apple_reminders.read` or `apple_reminders.write`.
- `health()` reports local configured state, platform, manifest hash, and uptime. It does not touch Reminders.app.
- `doctor()` reports platform support and configured state. It does not touch Reminders.app.
- `self_check()` reports degraded when not configured, failed on non-macOS platforms, and otherwise returns ok with an Automation permission hint. It does not touch Reminders.app.
- Runtime `invoke()` uses the FCP `InvokeRequest` shape: `operation`, `input`, and `capability_token`.
- Runtime `invoke()` requires configured and handshaken base state and verifies a bound capability token for the operation capability.
- Runtime capability verification currently passes an empty resource URI list for all Apple Reminders operations.
- Runtime `simulate()` validates known operation, configured state, handshake state, and bound capability token. It does not validate full input schema, macOS platform availability, Reminders.app availability, or Automation permission.
- Runtime `shutdown()` clears config, client, verifier, configured state, and handshaken state.
- Runtime `subscribe()` and `unsubscribe()` are unsupported.

## Runtime API Adapter

The runtime uses these local AppleScript request shapes:

| Operation | Capability | Required input | Runtime behavior |
|-----------|------------|----------------|------------------|
| `apple_reminders.health` | `apple_reminders.read` | none | Return local status, platform, and manifest hash without launching Reminders.app. |
| `apple_reminders.list_lists` | `apple_reminders.read` | none | Run a static script that lists Reminders lists and returns id/name pairs. |
| `apple_reminders.list_reminders` | `apple_reminders.read` | none | Run a static script that lists reminders across lists or within optional `list_name`. |
| `apple_reminders.create_reminder` | `apple_reminders.write` | `title` | Run a static script that creates a reminder in requested `list_name`, configured default list, or first list. |
| `apple_reminders.complete_reminder` | `apple_reminders.write` | `reminder_id` | Run a static script that finds a reminder by stable identifier and sets `completed` to true. |

Process and parsing behavior:

- The connector launches `/usr/bin/osascript` directly, never through a shell wrapper.
- User-controlled values are passed as argv, not interpolated into the AppleScript source.
- Child stdin is closed.
- Child stdout and stderr are drained concurrently with a 1 MiB cap per stream.
- The child is polled every 50 ms until it exits or `subprocess_timeout_secs` expires.
- On timeout, the child is killed and the connector returns an internal FCP error.
- Non-zero `osascript` exit status becomes an internal FCP error carrying bounded stderr text.
- `create_reminder` rejects an empty or whitespace-only `title` before subprocess launch.
- `complete_reminder` rejects an empty or whitespace-only `reminder_id` before subprocess launch.
- `list_reminders` does not filter completed reminders locally; callers must inspect the returned `completed` field.
- Reminder list output is parsed from tab-separated lines into `{ "lists": [...] }`.
- Reminder output is parsed from tab-separated lines into `{ "reminders": [...] }` with `id`, `title`, `list`, `completed`, and `due`.
- Reminder completion output is parsed into `id`, `title`, and `completed`.
- The connector does not escape tabs in reminder IDs, titles, or list names.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- The manifest forbids `system.exec`, but the sandbox uses `deny_exec = false` because this connector has a narrow `/usr/bin/osascript` subprocess carveout.
- The connector is a native Rust binary, but the provider interaction is implemented through static AppleScript executed by `osascript`.
- Runtime has no network capability and intentionally does not call iCloud or any Apple web service.
- Runtime `health()` can report ready on non-macOS after configuration because platform failure is checked by `doctor()`, `self_check()`, and actual client operations.
- `self_check()` does not verify that Reminders.app can be automated; it only returns the Automation permission hint on macOS.
- `simulate()` does not validate required input fields, blank string constraints, platform support, app availability, or Automation permission.
- Runtime capability verification does not bind reminder list IDs, list names, reminder IDs, or reminder titles as resource URIs.
- The manifest and introspection expose reminder creation and completion writes. There is no edit, delete, reopen, move, due date, priority, notes, tag, subtask, location, assignment, section, or list-management operation.
- List selection is by display list name only. Duplicate list names are not disambiguated.
- The connector lists all reminders returned by the Reminders scripting dictionary, including completed reminders.
- `create_reminder` sets only the reminder name. It does not set due date, notes, URL, priority, tags, subtasks, or flagged state.
- `complete_reminder` is best-effort idempotent and returns the completed flag; callers needing certainty must inspect the response.
- `InvokeRequest.deadline_ms` is not used to shorten the `osascript` timeout.
- No dedicated tracked verification shell script exists for this connector.

A follow-up parity bead should decide whether to expose richer reminder fields, add resource URI binding for lists and reminders, make simulation validate input and platform state, surface Automation permission failure more explicitly, consider a safe reminder-update path if needed, add stable list disambiguation, and reconcile the manifest's `system.exec` prohibition with the intentional bounded `osascript` carveout in a machine-checkable way.

## First-Slice Scope

The current Apple Reminders README slice documents the existing runtime surface:

- macOS-local `osascript` configuration and canonical binary enforcement
- List inventory, reminder inventory, reminder creation, and reminder completion operations
- Local health, doctor, self-check, introspection, simulate, invoke, subscribe, unsubscribe, and shutdown behavior
- Capability-token verification and current empty resource-URI binding
- Static-script and argv behavior for user values
- Bounded subprocess timeout, kill, stdout/stderr cap, and process-error behavior
- Runtime/manifest/platform drift around the subprocess carveout, Automation permission, list ambiguity, limited reminder fields, simulation, deadlines, and unsupported Reminders features
- Existing test orientation through manifest/introspection contract checks, capability denial tests, streaming-denial tests, bounded subprocess tests, argv-shape tests, non-macOS skip behavior, and explicit operator-gated live fixture skips

## Auth And Zone Boundary

- Authentication mechanism: macOS user session and local Reminders.app Automation permission.
- Home zone: `z:owner`.
- Allowed source zones: `z:owner` and `z:private`.
- Allowed target zones: `z:owner` and `z:private`.
- Forbidden zones: `z:public`, `z:community`, and `z:work`.
- Runtime capability families:
  - `apple_reminders.read`
  - `apple_reminders.write`
- Manifest required capabilities are `apple_reminders.read` and `apple_reminders.write`.
- Manifest forbids `network.listen`, `network.outbound`, `system.exec`, and `system.privileged`, with the current bounded `osascript` carveout represented by `deny_exec = false`.
- The connector does not intentionally persist Reminders contents, reminder IDs, list names, due dates, subprocess output, request counters, or error counters outside process memory.
- Apple Reminders payloads can contain private tasks, schedule metadata, list names, completed task history, and iCloud-synced content visible in the local Reminders app. Treat live input and output as owner/private-zone sensitive unless the host supplies a stricter zone policy.

## Explicit Non-Goals

- No iCloud API client.
- No EventKit service.
- No direct Reminders database access.
- No reminder edit, delete, reopen, move, due date, priority, note, URL, tag, subtask, section, or location operation.
- No reminder-list creation, rename, delete, template, sharing, or assignment operation.
- No account-scoped list selection.
- No Smart List management.
- No streaming reminder-change events.
- No durable local reminder cache.
- No cross-zone task publication.

## Verification

README-only changes do not require Cargo or `rch` verification. Before committing this file, run:

```bash
git diff --check -- connectors/apple-reminders/README.md
LC_ALL=C rg -n '[^ -~]' connectors/apple-reminders/README.md
rg -n '\bmaster\b' connectors/apple-reminders/README.md
ubs connectors/apple-reminders/README.md
```

For code changes in this connector, use the workspace-required proof lane from the root `AGENTS.md`:

```bash
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
rch exec -- cargo fmt --check
```
