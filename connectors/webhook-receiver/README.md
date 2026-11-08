# Webhook Receiver Connector V3 Contract

> **Status**: authenticated host-forwarded intake with encrypted local persistence, signed endpoint approvals, and an opt-in host HTTP adapter
> **Bead**: `flywheel_connectors-yin4m`
> **Host HTTP adapter bead**: `flywheel_connectors-whing1`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **GitHub webhook signature guide**: https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
> **Stripe webhook signature guide**: https://docs.stripe.com/webhooks/signature
> **Slack request verification guide**: https://docs.slack.dev/authentication/verifying-requests-from-slack/
> **Slack URL verification**: https://docs.slack.dev/reference/events/url_verification/
> **Twilio webhook security guide**: https://www.twilio.com/docs/usage/webhooks/webhooks-security

## Purpose

This document fixes the operator-facing contract for `fcp.webhook-receiver`. The connector currently exposes a host-forwarded webhook ingestion surface implemented in this crate: endpoint create/list/delete/rotate, verified event ingestion, cursor-based replay with retention-loss detection, recent event inspection, health reporting, and provider-specific signature checks for generic, GitHub, Stripe, Slack, and Twilio-style deliveries.

The connector provides a bounded webhook intake buffer backed by an explicitly configured encrypted local journal. It commits endpoint changes, verified events, and replay state before returning success. Canonical mesh replication and state handoff remain separate work; it is not a queue service, retry worker, webhook delivery sender, subscription manager, provider API client, or secret vault.

`fcp-host` provides an opt-in HTTP adapter at `POST /webhooks/{*path}`. It forwards the original provider body through the normal host invocation path to `webhook.events.ingest`, using an explicitly configured receiver, zone, public URL, and capability. Authenticated Slack URL-verification requests receive HTTP `200` containing only their challenge. See [Generic webhook HTTP ingress](../../docs/configuration/webhook_receiver_ingress.md) for configuration, proxy requirements, resource limits, and provider response limitations.

## Current Runtime Snapshot

The current crate exposes these operations:

- `webhook.endpoints.create`
- `webhook.endpoints.list`
- `webhook.endpoints.delete`
- `webhook.endpoints.rotate_secret`
- `webhook.events.ingest`
- `webhook.events.recent`
- `webhook.events.poll`
- `webhook.health`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-webhook-receiver`.
- Runtime `BaseConnector` ID is `webhook-receiver`.
- Manifest and reported connector ID are `fcp.webhook-receiver`.
- The embedded manifest interface hash is validated before session negotiation.
- Default `public_base_url` is `http://localhost:8080`.
- Ordinary event delivery requires configured durable `storage`. The explicit `allow_ephemeral_ingest: true` override is for development and tests; its default is `false`.
- Blank or missing `public_base_url` falls back to the default.
- `public_base_url` policy requires `http` or `https`, a host, and no query or fragment.
- Non-local hosts must use `https`.
- `localhost`, `127.0.0.1`, and `::1` are treated as local and may use `http`.
- Local hosts are valid for tests but reported as not publicly routable.
- For the host HTTP adapter, both the connector and host must use the same explicit `public_base_url`, such as `https://hooks.example.test/webhooks`. An endpoint registered as `/github` receives deliveries at `/webhooks/github`.
- `max_body_bytes` defaults to `1048576` and is capped at `16777216`.
- `body_timeout_ms` defaults to `15000` and is capped at `120000`.
- `rate_limit_window_ms` defaults to `60000` and has a minimum of `1`.
- `rate_limit_max` defaults to `120` and is capped at `10000`.
- `in_flight_max` defaults to `8` and is capped at `1024`.
- `signature_tolerance_seconds` defaults to `300` and is capped at `86400`.
- Runtime `invoke` uses the canonical `InvokeRequest` with `type`, `id`, `connector_id`, `operation`, `zone_id`, `input`, and `capability_token`. An `operation_id`-only request is rejected.
- Every invoke verifies the signed capability against negotiated capabilities, zone, operation, and the actual instance returned by handshake. Signed call and byte ceilings are charged before dispatch through the SDK's bounded admission path.
- Endpoint creation, deletion, and secret rotation additionally require a signed execution approval in `approval_tokens`, verified against the separately configured `approval_public_key`.
- `simulate` consumes a canonical signed `SimulateRequest` and checks authority without charging an invocation. Endpoint mutations report a missing approval because that request type carries no approval evidence.
- Every configure attempt invalidates prior authority and detaches live state before opening the selected store. Durable recovery must complete before configuration succeeds; an invalid path, key, zone, namespace, or journal leaves the connector unauthorized. Committed files are preserved.
- Handshake requires a canonical `HandshakeRequest`, accepts protocol `2.0` or `2.0.0`, negotiates only manifest-declared capabilities, rejects forbidden zones, echoes the nonce, and returns a fresh actual `instance_id`. Empty requested capabilities grant no access. Failed handshakes revoke the previous session.
- Rehandshake within the same zone rotates instance authority while preserving receiver state. A durable store is bound to its configured zone and public namespace; reconfiguration cannot rebind those retained secrets and payloads to a different scope.
- `health()` returns a canonical `HealthSnapshot` with `details.configured`, `details.handshaken`, and `details.instance_id`, enabling the host to prepare an instance-bound session. Ready means local authenticated intake is available. Public ingress remains separately reported as unbound because the connector cannot attest the host route, proxy, DNS, or TLS mapping.
- The JSON-RPC transport returns a canonical `InvokeResponse` with the invocation ID inside the outer JSON-RPC response, including typed operation errors.
- `doctor()` is degraded in the current no-native-listener build because native ingress listener and gateway binding checks fail non-critically.
- `self_check()` is degraded for local/non-public base URLs and for the current unbound gateway-ingress mode.
- `handle_shutdown()` revokes authority, clears live memory, and releases the writer lock without deleting or resetting committed storage. Request/error counters remain in memory.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- The connector has no native HTTP listener. The optional host HTTP adapter forwards deliveries through `webhook.events.ingest`; endpoint creation alone does not activate that route.
- Manifest optional capabilities include `network.dns`, `network.egress`, and `tls.sni`, but runtime opens no outbound sockets and no inbound listener.
- Manifest and introspection both mark endpoint creation and rotation as policy-approved and deletion as interactive approval. All three require valid signed execution evidence at dispatch.
- Manifest singleton-writer admission remains host-owned. The receiver's encrypted local journal preserves endpoint metadata, secrets, retained events, replay identities, and cursor state across reopening, but does not publish a canonical mesh checkpoint.
- `doctor()` currently cannot reach `ok` in the no-native-listener build because it reports no connector-owned listener or verified gateway binding.
- `self_check()` currently cannot reach `ok` without evidence of gateway binding. Enabling the host adapter does not change this connector-local claim automatically.
- Endpoint creation and rotation return signing secrets in the response; endpoint listing only returns `signing_secret_configured`.
- The connector hashes source IPs in recent-event and polling output. Durable mode encrypts retained verified event data, including its source address; the existing body-retention limits still apply.
- There is no dedicated tracked verification shell script for this connector.

Remaining work includes canonical mesh persistence and state transfer, verified external ingress-binding evidence, alignment of manifest network capabilities with the no-native-listener runtime, and a live provider verification bundle.

## First-Slice Scope

The current Webhook Receiver README slice documents the existing runtime surface:

- endpoint lifecycle management
- in-process endpoint secret generation and rotation
- host-forwarded event ingestion through `webhook.events.ingest`
- bounded cursor-based replay through `webhook.events.poll`, including explicit unread-history gap detection
- encrypted local recovery of endpoint secrets, retained events, replay protection, and polling cursors
- optional bounded HTTP delivery through the host's `/webhooks/{*path}` adapter
- provider-specific signature verification for generic HMAC, GitHub, Stripe, Slack, and Twilio styles
- content-type policy, body-size policy, rate limiting, in-flight limiting, deduplication, and redaction behavior
- lifecycle, health, doctor, self-check, simulation, introspection, and shutdown behavior
- instance-bound capability verification, signed endpoint approvals, and session invalidation
- explicit limits around native listeners and canonical mesh state handoff
- deterministic connector tests and direct proof commands

## Auth And Scope Boundary

- Provider authentication mechanism: endpoint signing secret.
- Connector management authentication: SDK `StandaloneSession` on the private host control channel, with signed instance-bound capability verification before every operation. Configure and handshake are trusted host control messages, not a public network authentication API.
- Runtime capability metadata:
  - `webhook.endpoints.read`
  - `webhook.endpoints.write`
  - `webhook.events.read`
  - `webhook.events.write`
- Endpoint create, delete, and rotate-secret operations require execution approvals signed by the independent configured approval key. The capability signer is never implicitly an approver.
- Set `approval_public_key` in connector configuration to the 32 unsigned bytes of the trusted Ed25519 approval public key. Use the public half of the key trusted by the host's `FCP_HOST_APPROVAL_PUBLIC_KEY[_FILE]` setting. This is a public key, not a signing secret. The host does not populate this connector setting automatically.
- Omitting `approval_public_key` permits authenticated read/ingest operations but denies endpoint mutations. Malformed keys reject configuration and leave prior authority revoked.
- Approval signatures use the same encoding as the host: Ed25519 over `fcp_cbor::to_canonical_cbor` of the complete approval token with `signature = None`. Approval validity, zone, connector, method pattern, request-object binding, canonical input hash, and JSON Pointer constraints are checked before mutation.
- Host policy, revocation, holder-proof, lease fencing, and FCP invocation idempotency remain host responsibilities. The receiver persists its own authenticated-delivery replay protection; that does not provide a canonical mesh receipt or exactly-once downstream processing.
- Resource allow/deny constraints bind to the configured endpoint URLs, derived from the requested path or the stored endpoint ID. Collection reads check every endpoint they could disclose; an excluded endpoint denies the whole collection read. Health and empty collections use the configured public base URL as the namespace resource. Caller-supplied alternative resource identifiers never override these targets.
- Durable mode encrypts endpoint secrets, endpoint records, verified events, source IPs, replay digests, redacted headers, payload bodies, and cursor authentication material. Its encryption key is supplied separately through a protected file. Rate windows, request counters, and error counters remain process-local.
- Webhook payloads can contain public, private, work, credential, or regulated data. Treat live event output according to the provider and endpoint zone.

## Durable Storage Configuration

Configure storage before registering production endpoints. The storage directory and encryption key file are explicit native filesystem paths; the host-provided handshake directory is a cache and is not used as durable authority.

```json
{
  "public_base_url": "https://hooks.example.test/webhooks",
  "storage": {
    "directory": "/var/lib/fcp/webhook-receiver-work",
    "key_file": "/run/secrets/fcp-webhook-state.key",
    "zone": "z:work",
    "initialize": false
  }
}
```

The example shows ordinary recovery. Provision a separate random 32-byte encryption key, stored as exactly 32 raw bytes or 64 hexadecimal characters in a private key file. Keep the directory private to the receiver's operating-system account and keep the key separate from stored ciphertext. Endpoint administration still needs the independent `approval_public_key` described above.

Set `initialize: true` only for the first creation of a new empty store, then change it to `false` for later starts. Initialization is create-only and refuses an existing store. Ordinary recovery never initializes missing state and never substitutes an empty receiver for corrupt, truncated, or unauthenticated data. There is no automatic journal-tail repair. Preserve the original files for operator recovery if opening fails.

The journal authenticates the exact configured zone and public base URL. Reopening under another zone, another public namespace, or a different key fails. A successful handshake must also select the stored zone. Namespace changes need a deliberate migration into a separate store; they cannot silently rebase retained endpoint URLs and Twilio signature destinations.

One process holds the store's exclusive writer lock for its entire writable lifetime. Endpoint creation, secret rotation, deletion, and event acceptance synchronize an encrypted record before publishing the corresponding in-memory change or successful response. A failed or uncertain write fences further data access and ingestion until the configured store is reopened and validated. Health, doctor, and self-check expose the fenced state without returning key material or event payloads.

Restart and same-store reconfiguration preserve endpoint IDs, signing secrets, both replay indexes, arrival sequences, eviction history, and polling-cursor authentication. A fresh session still requires fresh instance-bound capabilities; persisted receiver state does not preserve old process authority. Graceful shutdown releases the lock and live state while retaining committed files.

This persistence protects local restart and recovery. It does not replicate data to another host, establish a canonical writer lease, or detect replacement of the entire directory by an older otherwise-valid copy. Existing host singleton ownership, lease fencing, and stateful replacement restrictions continue to apply.

Without `storage`, endpoint setup and read operations remain available, but ordinary event ingest is refused. Authenticated Slack URL verification can still return its challenge because it creates no event. Development fixtures can explicitly set `allow_ephemeral_ingest: true`; health reports the ephemeral mode, and restart or reconfiguration discards its accepted events, replay protection, and cursors.

## Runtime And Ingress Invariants

- No native listener is started by this connector.
- Host-forwarded ingress operation: `webhook.events.ingest`.
- The host HTTP adapter is absent unless `FCP_HOST_WEBHOOK_INGRESS_CONFIG_FILE` selects a valid explicit binding. Its body, timeout, and concurrency limits are separate from the connector's own limits; both apply.
- Intake remains `Risky` and requires fresh [signed deployment evidence](../../docs/configuration/deployment_evidence.md) for its zone to pass the host's deployment gate. The manifest's singleton-writer ownership and lease fences remain separate requirements; the [ingress guide](../../docs/configuration/webhook_receiver_ingress.md#deployment-admission-and-singleton-ownership) describes their configuration.
- The host binding names an absolute `capability_token_file`. The host reloads its bounded base64 content for each admitted delivery, allowing authority for the actual prepared receiver instance to be renewed without restarting the host. Unavailable or invalid authority fails closed with `503`; there is no stale-token fallback.
- The adapter preserves raw body bytes and path/query spelling, constructs signature URLs from the configured public base, and takes the source IP only from the TCP connection. `Forwarded` and `X-Forwarded-*` never establish client identity or FCP authority. Behind a reverse proxy, source allowlists and rate keys see the proxy's address.
- The invocation is the operator's fixed intake command in the configured zone. Its provenance retains the public-input taint and a public-origin payload receipt in the chain; the adapter neither elevates provider data nor creates approval evidence. Normal host policy remains in force.
- Each HTTP attempt receives fresh host-generated invocation and delivery identities. Provider metadata cannot choose a host idempotency key; the receiver's authenticated-content replay check rejects ordinary event retries with `409`. Authenticated Slack URL-verification retries return the challenge again without creating events or reserving event replay identities.
- Ordinary provider-facing HTTP responses contain only `accepted`, `status_code`, and `reason_code`. Successful Slack URL verification returns only the authenticated `challenge`. Endpoint IDs, other payload fields, signature diagnostics, capability material, and source hashes remain outside these public responses.
- Durable event acceptance commits before the host receives a successful invoke result and returns HTTP `202`. A storage failure cannot produce a successful provider acknowledgment.
- Endpoint limit: `100`.
- Event retention limit: `1000` events per endpoint.
- Retained event data is also capped at `16 MiB` per endpoint and `64 MiB` across the connector, measured as serialized complete events. These are data budgets; allocator and parsed-JSON overhead are additional. The oldest arrivals are evicted when either budget is reached.
- Event-body eviction never removes replay protection. Public delivery IDs are limited to `1024` UTF-8 bytes. Each accepted delivery retains at most two `32`-byte BLAKE3 digests: its public ID and its authenticated replay identity. The limit is `100000` accepted deliveries per endpoint and across the connector, for at most `6.4 MB` of digest data plus hash-table overhead. New deliveries at capacity return a nonretryable `507`; previously accepted public IDs or authenticated identities still return duplicate `409`.
- Health, doctor, and self-check expose replay exhaustion. Durable reopening preserves that exhaustion and every accepted replay identity; do not replace the store to recover capacity without an explicit operator continuity plan.
- Recent-event queries select and limit borrowed records before copying payloads. A query no longer copies the entire store to return a small result.
- Shared byte eviction may remove every retained body for an endpoint, so `min_buffer_events` is `0`; the `1000` count is a ceiling, not a minimum guarantee.
- Recent-events limit defaults to `50` and is capped at `100`.
- Endpoint paths must start with `/`.
- Endpoint paths must be unique among active endpoints.
- Source allowlists accept exact IPv4/IPv6 addresses and CIDR ranges. Every entry is validated before endpoint creation; malformed addresses and prefixes outside `0..=32` (IPv4) or `0..=128` (IPv6) are rejected. Mixed-family lists are a union: a range for another address family is a non-match, so list ordering does not block permitted deliveries. IPv4-mapped IPv6 addresses remain IPv6 and require a matching IPv6 entry.
- Endpoint provider values are `generic`, `github`, `stripe`, `slack`, and `twilio`.
- Generated secrets use URL-safe random bytes with provider prefixes:
  - generic: `whsec_`
  - GitHub: `ghsec_`
  - Stripe: `whsec_`
  - Slack: `slksec_`
  - Twilio: `twsec_`
- List endpoints does not expose signing secrets.
- Rotate secret returns the new signing secret in the operation response.
- Delete endpoint durably removes the endpoint, its retained events, and its replay identities when storage is configured.
- Ingest accepts only `POST`.
- Ingest requires a configured endpoint, content type, body or payload, and a valid provider signature.
- JSON content types are accepted when they are `application/json` or end in `+json`.
- Twilio also accepts `application/x-www-form-urlencoded`.
- Allowed source filters support exact IP and CIDR matches.
- Source IP is read from `source_ip`, `remote_addr`, or `client_ip`.
- Client rate keys combine endpoint path and `client_id`, source IP, or `unknown-client`.
- Client identities are capped at `1024` bytes, and each authentication stage retains at most `4096` fixed-size client-key digests. Live rate windows are never evicted to admit a new client; expired windows are reclaimed using monotonic time.
- Headers are capped at `100` entries and `32 KiB` of names and values, with at most `256` bytes per name. Invalid HTTP header names, control characters in values other than tabs, and case-insensitive duplicate names are rejected before signature verification or replay admission.
- Rate limiting is applied before and after signature verification.
- Body timeout/cancellation inputs reject the ingest as timed out.
- Duplicate events are rejected per endpoint when either the public event ID or authenticated replay identity has already been accepted.
- Stored headers redact the endpoint signature header plus authorization, cookie, signature, secret, token, `api-key`, and `api_key`-style headers before retaining events or exposing them to polling consumers.
- Recent-event and polling output hash source IPs before returning them.

## Cursor-Based Event Consumption

Use `webhook.events.poll` to consume one endpoint's retained deliveries in arrival order. The existing `webhook.events.recent` operation remains a timestamp-based inspection query. Polling requires the signed `webhook.events.read` capability for the requested operation and the actual endpoint URL; possession of a cursor grants no authority. Every page passes normal zone, instance, resource, and signed usage checks.

An initial invocation can read from the earliest retained event:

```json
{
  "endpoint_id": "ep_abc123",
  "start": "earliest",
  "limit": 50,
  "max_bytes": 1048576
}
```

`start` defaults to `earliest`. Use `start: "latest"` to obtain an empty page and a cursor at the current arrival frontier, then poll for subsequent deliveries. To continue either mode, send the exact same `endpoint_id` and returned `next_cursor`, omitting `start`:

```json
{
  "endpoint_id": "ep_abc123",
  "cursor": "<next_cursor from the previous successful page>",
  "limit": 50,
  "max_bytes": 1048576
}
```

Each response contains `endpoint_id`, `events`, `start_cursor`, `next_cursor`, `has_more`, `serialized_event_bytes`, and `retention`. Events add a monotonic `sequence` to the existing redacted event shape. Sequence ordering follows acceptance, so equal or out-of-order provider timestamps cannot reorder or skip deliveries. Sequence values are global to the receiver and can have gaps for a particular endpoint. Stored sensitive headers remain suppressed, and output includes only `source_ip_hash` for the source address.

The retention object reports `oldest_available_sequence` (or `null` when empty), the global `next_sequence` frontier, and `history_truncated`. The last flag records whether this endpoint has ever lost retained event bodies to count or byte eviction. Starting from `earliest` deliberately reads what remains; it does not establish that earlier history was delivered.

Persist `start_cursor` before executing consumer effects on the first page. It captures the exact earliest/latest position used by that request, so an interrupted consumer can retry with normal gap detection instead of issuing another initial request that could silently start after newly evicted events. Process the page successfully before advancing saved progress to `next_cursor`. Polling never acknowledges, deletes, or reserves events and never clears delivery replay protection. Reusing a cursor returns the same retained prefix while it remains available, subject to the requested page limits. An empty page still returns a cursor for the current frontier. `has_more` indicates retained work at the time of the call; consumers should poll again after reaching it rather than treating it as a closed stream.

| Condition | Result and recovery |
| --- | --- |
| Normal page | Up to `limit` events; persist `next_cursor` after processing. |
| Unread events were evicted | Nonretryable `410` with `webhook_replay_gap`; reconcile missing deliveries, then deliberately select a new starting position. |
| Receiver state identity changed | Nonretryable `410` with `webhook_cursor_expired`; restore application progress from an external source or deliberately restart consumption. Reopening the same durable store preserves this identity. |
| Malformed, modified, wrong-endpoint, or future cursor | `400`, except a different encoded lifetime is reported as expired. No events are returned. |
| First unread event exceeds `max_bytes` | `413`; increase the byte budget before retrying the same cursor. |

`limit` defaults to `50` and must be `1..=100`. `max_bytes` defaults to `1 MiB` and must be `1..=16 MiB`. It bounds the sum of complete stored-event JSON sizes; the response envelope, sequence fields, redaction representation, and transport framing are additional. A later event that would exceed the byte budget ends the page with `has_more: true`. The connector clones only the selected page. Cursor inputs are bounded to `128` encoded bytes and authenticated with a per-store secret.

Retention is bounded to `1000` event bodies per endpoint, `16 MiB` per endpoint, and `64 MiB` shared across the receiver. Durable recovery preserves those retained bodies, both replay indexes, and eviction history used for gap detection. Configure, shutdown, and process restart preserve cursors when reopening the same durable store; ephemeral resets and replacement stores invalidate them. A same-zone rehandshake preserves state while rotating invocation authority. Consumers still own their progress checkpoints and downstream effect idempotency.

## Signature And Event ID Behavior

| Provider | Default header | Algorithm | Signature notes |
|----------|----------------|-----------|-----------------|
| generic | `X-Signature` | `hmac-sha256` | Hex HMAC over raw body, optional `sha256=` prefix accepted |
| github | `X-Hub-Signature-256` | `hmac-sha256` | Hex HMAC over raw body, optional `sha256=` prefix accepted |
| stripe | `Stripe-Signature` | `stripe-signature-v1` | Uses `t=` and `v1=` fields, signs `{timestamp}.{raw_body}`, enforces tolerance |
| slack | `X-Slack-Signature` | `slack-signature-v0` | Requires `X-Slack-Request-Timestamp`, signs `v0:{timestamp}:{raw_body}`, enforces tolerance |
| twilio | `X-Twilio-Signature` | `twilio-hmac-sha1` | Form: Base64 HMAC-SHA1 over the exact URL plus sorted field names and values. JSON: HMAC-SHA1 over the exact URL, with its `bodySHA256` binding the raw body. |

Twilio adapters should pass the original body and externally visible URL. The URL's scheme, host, effective port, and path must match the configured endpoint; query parameters remain part of the exact signed URL. Configure `public_base_url` to the provider-visible base, including `/webhooks` when using the host HTTP adapter.

Native form bodies decode percent escapes and `+` spaces with strict UTF-8 validation. Repeated values are sorted and deduplicated to match Twilio's signing rules; stored fields are strings or arrays of distinct strings. An optional `params` object must describe that same authenticated field set and cannot replace a different body or payload. Form intake accepts at most `1024` fields and bounds the expanded canonical signing data to `16 MiB` before copying repeated names and values; the configured body-size limit still applies.

Twilio JSON intake requires `body` with the exact original bytes and exactly one valid `bodySHA256` query parameter. Reserializing the same JSON value changes its hash. Nonempty form `params` are rejected for JSON, and a form request containing `bodySHA256` is rejected so changing Content-Type cannot bypass body authentication.

Public event ID precedence:

- input fields: `delivery_id`, `event_id`, `request_id`
- headers: `X-GitHub-Delivery`, `X-Request-ID`, `Stripe-Request-Id`, `X-Slack-Request-Id`
- payload fields: `id`, `event_id`, `eventId`, `delivery_id`; `MessageSid`, `SmsSid`, and `CallSid` are also considered for non-Twilio providers
- fallback: `evt_` plus a redacted hash of endpoint ID and raw body; Twilio forms use the normalized authenticated payload so equivalent field ordering and percent escapes deduplicate

The host HTTP adapter supplies its own fresh `delivery_id`, so HTTP deliveries use that first branch. Provider IDs remain untrusted metadata in stored, redacted headers or payloads; authenticated-content digests provide replay denial across HTTP attempts.

Twilio resource SIDs identify a message or call, not an individual delivery. Without an explicit delivery ID, successive status callbacks for one SID receive distinct IDs when their payload changes, while equivalent retries remain duplicates.

Replay checks also use a separate identity derived after successful signature verification. Input delivery/request IDs and the listed transport headers remain public metadata; changing or removing them cannot make previously accepted authenticated content new. Reusing a public ID still returns `409`, even when authenticated content differs.

For ordinary events from generic, GitHub, Stripe, and Slack endpoints, the authenticated identity hashes the exact raw body. Stripe and Slack timestamps are excluded, so a retry re-signed at another valid timestamp remains a duplicate. Identical authenticated content is conservatively treated as the same delivery within an endpoint, even if a sender assigns a fresh public ID.

For Twilio, the identity hashes the exact verified signing string: signed URL/query plus canonical form fields, or the signed JSON URL carrying its validated body hash. Equivalent form encodings and ambiguous name/value boundaries that produce the same signed bytes are duplicates. A different signed URL/query may distinguish callbacks, but public-ID checks still apply; the fallback public ID does not include that URL/query.

## Operation Inventory

| Operation | Runtime behavior | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|------------------|------------|------------|-----------|-------------|----------------|
| `webhook.endpoints.create` | Create endpoint and signing secret | `webhook.endpoints.write` | `Risky` | `Medium` | `None` | `path`; optional provider/signature policy |
| `webhook.endpoints.list` | List endpoint summaries without secrets | `webhook.endpoints.read` | `Safe` | `Low` | `Strict` | none |
| `webhook.endpoints.delete` | Delete endpoint, events, and dedup IDs | `webhook.endpoints.write` | `Dangerous` | `High` | `Strict` | `endpoint_id` |
| `webhook.endpoints.rotate_secret` | Replace endpoint signing secret | `webhook.endpoints.write` | `Risky` | `High` | `None` | `endpoint_id`; optional `signing_secret` |
| `webhook.events.ingest` | Verify and record one host-forwarded delivery, or answer a signed Slack URL-verification challenge | `webhook.events.write` | `Risky` | `High` | `Strict` | `path`, headers, body or payload |
| `webhook.events.recent` | Return recent verified events | `webhook.events.read` | `Safe` | `Low` | `Strict` | optional `endpoint_id`, `limit`, `since_ts` |
| `webhook.health` | Return config, endpoint, event, and ingress state | `webhook.endpoints.read` | `Safe` | `Low` | `Strict` | none |

## Explicit Non-Goals

The current implementation does not include:

- connector-owned HTTP listener startup, TLS termination, DNS management, public tunnel provisioning, automatic gateway registration, or direct provider subscription setup
- canonical mesh state replication, cross-host state handoff, dead-letter queues, retry workers, or exactly-once downstream effect delivery
- outbound provider API calls, provider webhook registration, provider secret rotation through remote APIs, or provider-specific subscription discovery
- arbitrary content-type support, multipart handling, file upload persistence, or large body storage; the host adapter collects accepted UTF-8 bodies with bounded streaming reads
- arbitrary response customization for providers, Twilio TwiML responses, webhook delivery sending, retry callback endpoints, or bidirectional webhook workflows
- per-endpoint zone routing, per-endpoint data retention policy, or secret vault integration
- long-term audit storage, PII classification, or payload redaction beyond selected headers

These are excluded on purpose:

- Public ingress, invocation authority, and canonical mesh state ownership remain host responsibilities.
- Webhook payloads frequently contain sensitive account, message, billing, or credential-adjacent data.
- Endpoint secret creation and rotation require signed approvals independently of the local storage encryption key.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configured/unconfigured state, session ID, endpoint counts, event counts, ingress state, request counters, and error counters
- serialized retained bytes, replay-identity usage, remaining replay capacity, exhausted endpoints, and bounded rate-client counts
- local/public base URL policy and clearing of prior state on reconfiguration
- degraded readiness for local URLs, no native listener, and unbound gateway ingress
- typed introspection with operations, schemas, capability IDs, risk levels, safety tiers, idempotency, event caps, and ingress metadata
- authenticated simulation with explicit missing-approval outcomes for endpoint mutations
- typed provider/FCP error mapping for bad configuration, missing endpoints, duplicate endpoints/events, invalid signatures, stale timestamps, rate limits, in-flight limits, unsupported methods, content-type rejection, body limits, and timeout inputs

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, health, doctor, self-check, introspection, simulation, shutdown, and counters
- endpoint create/list/delete/rotate behavior and secret exposure rules
- GitHub, Stripe, Slack, Twilio, and generic signature verification
- invalid signatures, stale timestamps, missing headers, duplicate events, source allowlists, rate limits, in-flight limits, and body limits
- recent-event filtering, retention, redacted headers, hashed source IPs, and event ID extraction
- local/public URL policy and endpoint URL rebasing
- canonical host handshake, health, introspection, and JSON-RPC invoke envelopes
- missing/forged tokens, wrong zone/operation/connector/instance, unnegotiated capabilities, signed call exhaustion, and collection resource denials
- independent signed approvals with expiry, request/input binding, signature, and scope denial checks
- failed handshake/configuration invalidation and cross-zone state isolation

The host adapter adds request-translation unit tests, bounded runtime tests, and `crates/fcp-host/tests/webhook_receiver_ingress.rs`. The latter uses the real receiver, canonical handshakes, signed capabilities and independent endpoint approvals, and a real loopback HTTP connection. It covers exact GitHub/Stripe/Slack/Twilio payload authentication, replay denial, FCP scope rejection, source allowlists, and redacted public replies. Added test coverage is not a claim that those commands or live-provider callbacks have passed; record actual results when running the verification bundle.

## Source Notes

- `connectors/webhook-receiver/src/connector.rs` defines configuration parsing, lifecycle handlers, endpoint operations, ingest dispatch, introspection, simulation, health, doctor, and self-check.
- `connectors/webhook-receiver/src/client.rs` defines bounded endpoint/event storage, replay-identity retention, and validated recovery from the encrypted local journal in `persistence.rs`. Signature verification, body parsing, rate limiting, source filtering, event ID extraction, and redaction live in `connector.rs`.
- `connectors/webhook-receiver/src/types.rs` defines endpoint, event, provider, signature, config, and introspection shapes.
- `connectors/webhook-receiver/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/webhook-receiver/manifest.toml` defines the manifest operation catalog, ingress/network intent, sandbox boundary, zone policy, approval intent, and state intent.
- `connectors/webhook-receiver/tests/integration.rs` contains the runtime contract proof surface.
- `crates/fcp-host/src/webhook_ingress.rs` defines HTTP request translation, explicit binding validation, and public response mapping.
- `crates/fcp-host/src/bin/fcp-host/webhook_ingress.rs` owns startup configuration, bounded body collection, deadlines, concurrent admission, and dispatch through normal host authority.
- `crates/fcp-host/tests/webhook_receiver_ingress.rs` exercises the shared host translation against the real receiver and signed provider fixtures.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/webhook-receiver/README.md
ubs connectors/webhook-receiver/README.md
LC_ALL=C rg -n '[^ -~]' connectors/webhook-receiver/README.md
rg -n '\bmaster\b' connectors/webhook-receiver/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-webhook-receiver
rch exec -- cargo check -p fcp-webhook-receiver --all-targets
rch exec -- cargo clippy -p fcp-webhook-receiver --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

For the host HTTP adapter, run its focused checks as well:

```bash
rch exec -- cargo test -p fcp-host --lib webhook_ingress::
rch exec -- cargo test -p fcp-host --bin fcp-host webhook_runtime_
rch exec -- cargo test -p fcp-host --bin fcp-host webhook_ingress_admission_
rch exec -- cargo test -p fcp-host --test webhook_receiver_ingress
```

These are verification commands, not stored passing results or live-provider evidence.

## Operator Guidance

- Configure the optional host HTTP adapter using the [ingress guide](../../docs/configuration/webhook_receiver_ingress.md), and configure the receiver's encrypted local store before accepting production deliveries. The connector itself remains host-forwarded and does not bind an HTTP socket.
- Use production `https` public base URLs for non-local endpoints.
- Keep endpoint secrets in a credential manager; endpoint create and rotate responses expose the active secret once.
- Configure an independent approval public key and provide a signed execution approval for endpoint creation, deletion, and secret rotation.
- Do not rely on `doctor()` or `self_check()` reaching `ok` in the current no-native-listener build.
- Plan around the bounded retention and replay-identity budgets. A configured durable store preserves those limits and identities across restart; it does not reset exhausted capacity or replace a downstream work queue.
- Expose only the configured `/webhooks/` route through a TLS-terminating reverse proxy, preserving the raw path, query, and body. Do not expose host administration or unrelated RPC routes as part of that mapping.
- Slack Events API URL verification is supported for endpoints configured with provider `slack` and `slack-signature-v0`. The receiver verifies the fresh signature over the exact raw body and applies normal FCP, resource, source, body, and rate admission before returning the challenge. The deprecated payload token grants no authority. Challenges must be nonempty strings of at most `4096` UTF-8 bytes with no control characters; their exact content is preserved. Fresh signed verification retries succeed without creating events or consuming event replay identities.
- Confirm that ordinary callbacks accept the adapter's minimal HTTP acknowledgment. Twilio flows requiring TwiML and arbitrary provider response formats still need additional response handling.
