# Generic Email Connector V1 Contract

> **Status**: IMAP/SMTP runtime contract with supervised inbound polling and acknowledged native JSONL delivery
> **Bead**: `flywheel_connectors-4kw5f.4.2`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/email_generic_connector_verification.sh`
> **IMAP upstream**: https://datatracker.ietf.org/doc/html/rfc3501
> **SMTP upstream**: https://datatracker.ietf.org/doc/html/rfc5321
> **SMTP STARTTLS upstream**: https://datatracker.ietf.org/doc/html/rfc3207

## Purpose

This document fixes the operator-facing contract for `fcp.email-generic`. The connector exposes the generic email surface currently implemented in this crate: local connector health metadata, IMAP mailbox listing, IMAP UID search, bounded IMAP RFC822 poll-once invocation for inbound previews, supervised IMAP RFC822 polling for inbound preview events, SMTP message sending, and redacted inbound-monitor policy configuration for one configured IMAP account and one configured SMTP identity.

The connector is intentionally a minimal IMAP/SMTP adapter. It is not a Gmail or Microsoft Graph client, OAuth client, mailbox synchronization engine, general-purpose MIME rendering engine, arbitrary attachment fetcher, delivery-status tracker, replay-buffered event system, spam classifier, rules engine, address book client, calendar client, or generic mail-admin tool.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `email_generic.health`
- `email_generic.list_mailboxes`
- `email_generic.search_messages`
- `email_generic.poll_inbound_once`
- `email_generic.send_message`

Subscribing to `email.inbound.preview` starts a supervised poller over the configured `monitor_policy.mailbox` on the IMAP account. The native executable delivers accepted messages through the shared JSONL event transport and waits for an exact host acknowledgement before advancing past each accepted UID. Sender allowlist, automated-message suppression, account and mailbox epoch checks, body bounding, attachment classification, and thread metadata shaping apply before delivery. Embedded callers without a native transport can use the existing bounded broadcast channel.

The inbound poll-once surface is a read-only FCP invoke operation over the same bounded RFC822 parsing and monitor-policy preparation path. It returns a caller-owned `cursor` for account- and UIDVALIDITY-bound progress; pass that complete cursor into later polls. It does not own durable UID state. The legacy `seen_uids` input remains available as a bounded compatibility mode.

Important runtime truths the contract preserves:

- Package and binary name are `fcp-email-generic`.
- Runtime and manifest connector ID are `fcp.email-generic`.
- Configuration requires `imap.host`, `imap.username`, `imap.password`, `smtp.host`, `smtp.username`, `smtp.password`, and `smtp.from_address`.
- `imap.port` defaults to `993`.
- `imap.tls` defaults to `true`.
- `smtp.port` defaults to `587`.
- `smtp.starttls` defaults to `true`.
- `smtp.from_name` is optional.
- `request_timeout_ms` defaults to `15000` and must be greater than zero.
- Debug output redacts IMAP and SMTP passwords.
- The IMAP client uses a direct TCP stream, optional TLS, explicit read/write timeouts, `LOGIN`, `LIST`, `EXAMINE`, `UID SEARCH TEXT`, `UID SEARCH UNSEEN` with a cursor range when resuming, bounded `UID FETCH <uid> (UID BODY.PEEK[])`, and `LOGOUT`.
- `email_generic.poll_inbound_once` applies the configured monitor policy and returns bounded message previews, sender-policy decisions, attachment metadata only, thread reply metadata, an epoch cursor, and compatibility `seen_uids` state.
- Inbound RFC822 parsing uses `mailparse`, prefers `text/plain`, falls back to stripped `text/html`, records thread headers, and extracts attachment metadata without exposing attachment bytes.
- The SMTP client uses `lettre`, configured credentials, optional STARTTLS relay mode, and plain message bodies.
- `health()` is local readiness state and does not prove IMAP reachability.
- The `email_generic.health` invoke operation returns local metadata, redacted monitor policy, and supervised inbound monitor state.
- `self_check()` calls the client health path, which logs in to IMAP and lists mailboxes.
- Runtime computes `manifest_hash` from `manifest.toml`.
- Runtime `invoke` verifies a bound capability token before provider dispatch.
- Runtime `simulate` uses the same capability verifier and reports missing capabilities when appropriate.
- Native `subscribe` requires a host-issued stream ID and an instance-bound `email_generic.read` token authorizing `email_generic.subscribe` over `email_generic:events:email.inbound.preview`. `unsubscribe`, reconfiguration, rehandshake, shutdown, and transport retirement stop or fence pending delivery.
- The native executable uses one persistent runtime and a bounded JSONL reader. ACK controls remain readable while ordinary RPC handlers run; responses and events share a serialized stdout writer. Successful shutdown exits without waiting for stdin EOF.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- The manifest operation keys are unprefixed suffixes such as `health`; runtime operation IDs are fully qualified IDs such as `email_generic.health`.
- Runtime `health()` and `email_generic.health` report local state; `self_check()` is the IMAP reachability probe.
- The manifest defers exact host constraints to runtime configuration because IMAP and SMTP hosts may be public, private, or tailnet infrastructure.
- The manifest requires `network.outbound`, while many newer connector contracts use `network.egress`; this README documents the current manifest as-is.
- The supervised inbound monitor uses in-memory UID state today; durable UID ownership and replay buffers remain out of scope.
- There is connector-local IMAP/SMTP loopback fixture coverage plus a tracked acceptance shell script for this connector.
- IMAP parsing is intentionally narrow and does not implement full RFC 3501 mailbox, BODYSTRUCTURE, multipart rendering, flag mutation, or durable mailbox synchronization.

Durable UID-state ownership and cross-process recovery remain separate from the native transport's explicit acknowledgement boundary.

## First-Slice Scope

The current Generic Email README slice documents the existing runtime surface:

- IMAP and SMTP credential configuration
- local health metadata and IMAP-backed self-check behavior
- mailbox listing, message UID search, bounded inbound RFC822 poll-once invocation, and SMTP send operations
- redacted inbound monitor policy helpers, tested poll-once parsing, and supervised `email.inbound.preview` event stream
- bound capability-token enforcement for read and write operations
- doctor, health, self-check, introspect, simulate, subscribe, unsubscribe, and shutdown
- drift around host constraints, durable UID state, replay/ack semantics, and provider-specific auth

## Auth And Scope Boundary

- Authentication mechanism: IMAP username/password plus SMTP username/password.
- Runtime does not implement OAuth, XOAUTH2, SASL mechanism selection, client certificates, password vault lookup, shared credential references, secret rotation, or connector-local credential persistence.
- Home zone: `z:private`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zones: `z:private` and `z:work`.
- Tailscale tag hint: `tag:fcp-private`.
- Capability families:
  - `email_generic.read` gates health metadata, mailbox listing, message search, one-shot inbound polling, and the native subscription control operation.
  - `email_generic.write` gates SMTP sends.
- Required capabilities: `network.dns` and `network.outbound`.
- Forbidden capabilities: `system.exec`, `system.privileged`, and `network.listen`.
- Email addresses, mailbox names, UID search queries, message subjects, message bodies, headers, message IDs, thread references, SMTP recipients, provider error strings, IMAP/SMTP hosts, and credentials are sensitive private or work data. Redact them before sharing evidence.

## Network And Runtime Invariants

- IMAP endpoint is the configured `imap.host:imap.port`.
- SMTP endpoint is the configured `smtp.host:smtp.port`.
- IMAP TLS is enabled by default and uses `native_tls`.
- SMTP STARTTLS relay mode is enabled by default through `lettre::SmtpTransport::relay`.
- SMTP plaintext builder mode is used only when `smtp.starttls=false`.
- IMAP values are quoted and backslash/quote escaped before command construction.
- `list_mailboxes` sends `LIST "" "*"`.
- `search_messages` sends `EXAMINE "<mailbox>"` followed by `UID SEARCH TEXT "<query>"`.
- `search_messages` rejects blank mailbox or query before sending IMAP commands.
- Inbound polling opens the mailbox with `EXAMINE`, then sends `UID SEARCH UNSEEN` and per-UID `UID FETCH <uid> (UID BODY.PEEK[])`. These reads preserve the provider's `\Seen` flags. The monitor uses the explicit `monitor_policy.mailbox`; `poll_inbound_once` uses its requested mailbox and cursor, or legacy UID list when explicitly selected.
- A complete FETCH response must identify the requested UID, close its attribute list, and finish with the exact successful tagged status. Failed fetches, malformed MIME, truncated responses, and oversized literals abort the connection and leave all candidates from that poll unacknowledged for a fresh-session retry.
- Retrieval never advances a cursor. One-shot results return a checkpoint with the completed response. The native monitor advances an accepted UID only after the host acknowledges its exact stream, topic, sequence, and cursor; explicit policy rejections also advance progress. Failed delivery retains the completed prefix and leaves the failed UID and tail retryable, without consuming an event sequence. The separate embedded broadcast mode commits on successful enqueue and remains best-effort delivery.
- Modern polls require exactly one valid nonzero `UIDVALIDITY` from `EXAMINE`. A changed epoch restarts at UID zero; within the same epoch, both the server query and an independent client-side filter select UIDs above the committed high-water. This filter also handles IMAP's reversed `n:*` range behavior. An exhausted `u32::MAX` UID still checks the epoch and performs no overflowing range query.
- RFC822 literals and response metadata are each capped at `1048576` bytes. A poll returns at most 128 messages and stops after reaching 8 MiB of raw message data (with at most one additional 1 MiB message); remaining UIDs can be fetched on the next poll.
- `send_message` requires at least one `to` recipient.
- `send_message` parses `smtp.from_address`, `to`, and `cc` through `lettre` address parsing before dispatch.
- `send_message` sends plain body text and does not include attachments.
- IO errors map to retryable external FCP errors; IMAP and SMTP protocol errors map to non-retryable external FCP errors.
- TLS errors currently map to internal FCP errors.
- Sandbox profile is `strict`, with `96 MB` memory, `25%` CPU, `30000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets.

## Resuming Inbound Polls

Start a modern one-shot scan with `{"mailbox":"INBOX","cursor":null}`, or omit both `cursor` and `seen_uids`. Each successful response includes a structured cursor containing `version`, a non-secret `account_fingerprint`, `mailbox`, `uid_validity`, and `last_uid`. Send that complete value as `cursor` in the next request. The fingerprint binds the IMAP endpoint, port, TLS mode, username, mailbox, and cursor version; passwords and token bytes are never included. Cursor objects reject unknown fields, unsupported versions, invalid identifiers, and oversized mailbox names.

Explicit `cursor:null` starts a fresh scan even when `seen_uids` is also supplied. A non-null cursor takes precedence over legacy UID lists. Modern retrieval ignores those unscoped lists and returns compatibility `seen_uids` for the current batch only. A request that supplies `seen_uids` without a `cursor` retains the old bounded-cache behavior and returns `cursor:null`; no high-water is inferred from those entries. That legacy mode can repeat old unread messages and can stall newer messages once its cache window is exceeded, so use the cursor mode for ongoing polling.

The cursor tracks new message UIDs, not flag changes. Marking an older message unread again does not replay it below the committed high-water. A mailbox rebuild that changes `UIDVALIDITY` does restart the scan, including reused lower UIDs. Event cursors include the account fingerprint and epoch, and event payloads include `uid_validity`, so a reused UID in a new epoch has a distinct identity.

The supervised monitor retains its in-memory cursor across unsubscribe/resubscribe. Reconfiguration, shutdown, and process restart clear that monitor-owned progress; caller-persisted one-shot cursors remain subject to account/mailbox/epoch validation when reused. Poll generations fence cancelled workers and old sessions before enqueue, including when an epoch changes while a previous poll is still finishing. Progress follows only the successfully published or deliberately rejected prefix of an ordered batch.

Native acknowledgements protect the current process's progress; they do not persist the connector's mailbox cursor or add exactly-once delivery. A restart can replay unread messages. The host's retained event journal and consumers must use the account- and epoch-qualified event cursor to handle duplicates. Embedded broadcast subscribers continue to use enqueue as their commit boundary.

## Native Event Subscription

The host-pinned event declaration names capability `email_generic.read`, subscription operation `email_generic.subscribe`, and resource `email_generic:events:email.inbound.preview`. The native `subscribe` RPC accepts one exact topic, a host-issued `stream_id`, an instance-bound capability token, and an optional `window_size` from 1 through 64. The producer conservatively uses one event credit. Replay (`since`), rate, and batching options are rejected because this implementation does not provide those semantics.

The connector honors `requested_instance_id` during handshake before constructing its verifier. It checks the subscription token's signature, instance, zone, operation, resource restriction, and expiry before polling and delivery, while waiting for ACK, and again before committing an acknowledged event. Repeating the same active stream subscription refreshes its valid token without replacing its pending event. A replacement stream waits for the preceding monitor to stop before starting another generation.

Events use the SDK's `event` notification shape. The host sends an ID-less `ack` control with matching `stream_id` and an `ack` object containing `type:"ack"`, the exact topic, one sequence in `seqs`, and the matching cursor in `cursors`. Reading or flushing stdout alone never advances the mailbox cursor. A missing ACK times out after 30 seconds; wrong ACK identities are rejected. Stream closure, lost input, token expiry, shutdown, and failed writes leave the unacknowledged UID retryable. Event notifications are capped by the shared 256 KiB transport limit; reduce `max_body_chars` if a configured preview cannot fit.

The in-process `subscribe_events()` broadcast API remains available for embedded usage. A connector with a native transport attached rejects the plain typed `subscribe()` entry point, so it cannot bypass native subscription admission.

## Inbound Monitor Policy Helpers

The supervised inbound monitor uses these poll-once and policy helpers before event emission:

- `mailbox` defaults to `INBOX`, rejects blanks, and is quoted through the same IMAP escaping path as message search.
- `allowed_senders` accepts an array or comma-separated string and is normalized before use.
- `require_allowed_sender` defaults to `true`.
- `drop_automated` defaults to `true`.
- `allow_attachments` defaults to `false`.
- `poll_interval_secs` defaults to `15` and must be between `1` and `3600`.
- `max_body_chars` defaults to `50000` and must be between `1` and `1000000`.
- `seen_uid_cap` defaults to `2000` and must be between `1` and `100000`. It bounds the legacy cache and compatibility output; supervised progress uses an epoch cursor and continues past that cache size.
- `allowed_senders` is capped at `512` entries and rejects duplicates after normalization.
- Automated sender detection checks sender patterns and common automated-message headers.
- Prepared inbound previews are marked `tainted`, bound body length, classify attachments, and carry thread reply metadata only when policy accepts the message.
- Poll-once fetches are read-only and return the cursor that callers should retain for the next call. Fetch or projection failure changes no caller-owned checkpoint.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `email_generic.read` | Read local health metadata, list IMAP mailboxes, search messages by UID, run one-shot inbound polls, and authorize native inbound subscriptions. |
| `email_generic.write` | Send email through the configured SMTP identity. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|----------------|------------|------------|-----------|-------------|----------------|
| `email_generic.health` | local readiness plus monitor policy metadata | `email_generic.read` | `Safe` | `Low` | `Strict` | None. |
| `email_generic.list_mailboxes` | IMAP `LIST "" "*"` | `email_generic.read` | `Safe` | `Low` | `Strict` | None. |
| `email_generic.search_messages` | IMAP `EXAMINE` plus `UID SEARCH TEXT` | `email_generic.read` | `Safe` | `Low` | `Strict` | `mailbox`, `query`. |
| `email_generic.poll_inbound_once` | IMAP `EXAMINE`, epoch-bound `UID SEARCH UNSEEN`, bounded PEEK fetch, monitor-policy preview | `email_generic.read` | `Safe` | `Low` | `Strict` | `mailbox`; optional `cursor`, or legacy `seen_uids`. |
| `email_generic.send_message` | SMTP message submission | `email_generic.write` | `Risky` | `Medium` | `None` | `to`, `subject`, `body`; optional `cc`. |

## Explicit Non-Goals

The current implementation does not include:

- Gmail API, Microsoft Graph, Exchange Web Services, JMAP, POP3, NNTP, CalDAV, CardDAV, or provider-specific APIs
- OAuth, XOAUTH2, SASL mechanism negotiation, app-password provisioning, password vault integration, or secret rotation
- full MIME rendering, arbitrary attachment fetch, attachment send, inline image handling, DKIM signing, S/MIME, PGP, or spam/phishing analysis
- public message fetch by UID, full mailbox synchronization, flag mutation, folder creation, folder deletion, move/copy/delete, draft handling, or delivery status tracking
- webhook delivery, connector-owned replay buffers, durable UID state, or cross-process monitor recovery
- address book lookup, contact dedupe, calendar invite parsing, unsubscribe handling, or auto-reply generation

These are excluded on purpose:

- Generic email accounts can expose private and work-sensitive content with minimal provider-side boundaries.
- Sending email has external side effects and poor idempotency semantics.
- Provider-specific auth and setup flows belong in dedicated provider connectors or setup surfaces.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configured state, IMAP host, SMTP host, manifest hash, uptime, monitor policy redacted state, redacted mailbox-binding presence, supervised monitor status, event topic, buffer size, poll counters, emitted/dropped event counters, blocking-boundary cancellation counter, and last error
- operation catalog, schemas, capabilities, risk levels, safety tiers, idempotency classes, examples, and AI hints
- IMAP mailbox-list reachability through `self_check()`
- bound capability-token acceptance and denial in both `invoke` and `simulate`
- specific degraded state when the connector is not configured
- streaming event capabilities for `email.inbound.preview` and clean subscribe/unsubscribe behavior

The deterministic evidence currently covers:

- configuration validation and default values
- password debug redaction
- IMAP quoted-string escaping, mailbox parsing, and UID parsing
- monitor policy normalization, duplicate rejection, sender evaluation, automated sender dropping, body bounding, attachment classification, and seen-UID cache bounds
- RFC822 parsing for text/plain, text/html fallback, message/thread headers, attachment metadata, and IMAP literal length bounds
- IMAP/SMTP loopback tests for mailbox listing, UID search, FCP-invoked inbound RFC822 poll-once previews, UID-cache duplicate suppression, supervised inbound event fan-out, sender-policy drops before emission, SMTP success/failure, STARTTLS downgrade denial, capability enforcement, shutdown cleanup, and redacted JSONL evidence
- operation inventory, manifest/introspection shape, capability assignment, handshake grants, doctor/health/self-check/shutdown behavior, and invoke health behavior
- error mapping for configuration, IMAP, SMTP, IO, TLS, and address errors

The remaining design gap is durable UID/replay ownership. Regression coverage includes real SDK ACK waits, wrong ACK rejection, closed-tail replay, stale-generation rejection, token expiration during delivery, and a native subprocess communicating over stdin/stdout with a real loopback IMAP fixture. These tests are separate from any live provider qualification.

## Source Notes

- `connectors/email-generic/src/types.rs` defines configuration, monitor policy, inbound preview policy, redacted state, attachment classification, and seen-UID cache behavior.
- `connectors/email-generic/src/client.rs` defines IMAP command construction, bounded RFC822 fetch/parsing, SMTP message submission, TLS/STARTTLS behavior, and address parsing.
- `connectors/email-generic/src/connector.rs` defines lifecycle handlers, capability-token enforcement, operation metadata, diagnostics, simulate behavior, supervised inbound monitor task ownership, event fan-out, and shutdown cleanup.
- `connectors/email-generic/src/error.rs` defines provider/FCP error mapping and retry classification.
- `connectors/email-generic/manifest.toml` defines the operation catalog, event catalog, capability families, zone policy, sandbox boundary, and runtime host constraints.
- Inline `#[cfg(test)]` coverage in the source files is the current local proof surface.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/email-generic/README.md
ubs connectors/email-generic/README.md
LC_ALL=C rg -n '[^ -~]' connectors/email-generic/README.md
rg -n '\bmaster\b' connectors/email-generic/README.md
```

For source or behavior changes, use an `rch`-offloaded connector proof lane:

```bash
fwc manifest fix connectors/email-generic/manifest.toml --check --json
rch exec -- cargo fmt --manifest-path connectors/email-generic/Cargo.toml --check
rch exec -- cargo check -p fcp-email-generic --all-targets
EMAIL_GENERIC_FIXTURE_JSONL=1 rch exec -- cargo test -p fcp-email-generic --test integration -- --nocapture
rch exec -- cargo test -p fcp-email-generic -- --nocapture
rch exec -- cargo clippy -p fcp-email-generic --all-targets -- -D warnings
```

For the checked-in loopback verification bundle, run:

```bash
bash scripts/e2e/email_generic_connector_verification.sh
```

## Operator Guidance

Prerequisites:

- Provide an IMAP host, IMAP username, IMAP password, SMTP host, SMTP username, SMTP password, and SMTP from address.
- Prefer TLS for IMAP and STARTTLS for SMTP.
- Use a disposable test mailbox for proof.

Dedicated environment:

- Prefer a local deterministic IMAP/SMTP fixture before testing against a live mailbox.
- Use an isolated sending account and non-production recipients for SMTP proof.
- Keep search queries synthetic in archived evidence.

Redaction rules:

- Redact IMAP and SMTP passwords, usernames, hostnames when sensitive, mailbox names, search queries, message UIDs, subjects, bodies, recipients, sender addresses, message IDs, thread references, provider error strings, and raw protocol logs.

Common remediation:

- If `configure` fails, verify nonblank hosts, credentials, `smtp.from_address`, and positive `request_timeout_ms`.
- If `self_check` fails, verify IMAP host/port reachability, TLS mode, username/password, and mailbox permissions.
- If `list_mailboxes` fails after login, inspect IMAP server capabilities and mailbox namespace behavior.
- If `search_messages` rejects input, provide nonblank `mailbox` and `query`.
- If `send_message` rejects recipients, validate `to`, `cc`, and `smtp.from_address` syntax through the target SMTP provider.
- If `simulate` reports missing capabilities, mint a bound token for `email_generic.read` or `email_generic.write` according to the operation.

Rerun commands:

- `git diff --check -- connectors/email-generic/README.md`
- `ubs connectors/email-generic/README.md`
- `rch exec -- cargo test -p fcp-email-generic -- --nocapture`
