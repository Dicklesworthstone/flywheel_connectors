# Webhook Receiver Connector V3 Contract

> **Status**: authenticated host-forwarded intake with signed endpoint approvals
> **Bead**: `flywheel_connectors-yin4m`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **GitHub webhook signature guide**: https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
> **Stripe webhook signature guide**: https://docs.stripe.com/webhooks/signature
> **Slack request verification guide**: https://docs.slack.dev/authentication/verifying-requests-from-slack/
> **Twilio webhook security guide**: https://www.twilio.com/docs/usage/webhooks/webhooks-security

## Purpose

This document fixes the operator-facing contract for `fcp.webhook-receiver`. The connector currently exposes a host-forwarded webhook ingestion surface implemented in this crate: endpoint create/list/delete/rotate, verified event ingestion, recent event replay, health reporting, and provider-specific signature checks for generic, GitHub, Stripe, Slack, and Twilio-style deliveries.

The connector is intentionally a bounded in-process webhook intake buffer. It is not a public HTTP server, durable event bus, queue service, retry worker, webhook delivery sender, subscription manager, provider API client, secret vault, or general ingress gateway.

## Current Runtime Snapshot

The current crate exposes these operations:

- `webhook.endpoints.create`
- `webhook.endpoints.list`
- `webhook.endpoints.delete`
- `webhook.endpoints.rotate_secret`
- `webhook.events.ingest`
- `webhook.events.recent`
- `webhook.health`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-webhook-receiver`.
- Runtime `BaseConnector` ID is `webhook-receiver`.
- Manifest and reported connector ID are `fcp.webhook-receiver`.
- The embedded manifest interface hash is validated before session negotiation.
- Default `public_base_url` is `http://localhost:8080`.
- Blank or missing `public_base_url` falls back to the default.
- `public_base_url` policy requires `http` or `https`, a host, and no query or fragment.
- Non-local hosts must use `https`.
- `localhost`, `127.0.0.1`, and `::1` are treated as local and may use `http`.
- Local hosts are valid for tests but reported as not publicly routable.
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
- Every configure attempt invalidates prior authority and clears endpoints, signing secrets, events, dedup IDs, and ingress state. Configuration replaces the previous intake namespace; preserve required endpoint configuration outside this process before reconfiguring.
- Handshake requires a canonical `HandshakeRequest`, accepts protocol `2.0` or `2.0.0`, negotiates only manifest-declared capabilities, rejects forbidden zones, echoes the nonce, and returns a fresh actual `instance_id`. Empty requested capabilities grant no access. Failed handshakes revoke the previous session.
- Rehandshake within the same zone rotates instance authority. Switching zones requires reconfiguration so prior-zone secrets and payloads cannot cross the boundary.
- `health()` returns a canonical `HealthSnapshot` with `details.configured`, `details.handshaken`, and `details.instance_id`, enabling the host to prepare an instance-bound session. Ready means local authenticated intake is available; public ingress remains separately reported as unbound.
- The JSON-RPC transport returns a canonical `InvokeResponse` with the invocation ID inside the outer JSON-RPC response, including typed operation errors.
- `doctor()` is degraded in the current no-native-listener build because native ingress listener and gateway binding checks fail non-critically.
- `self_check()` is degraded for local/non-public base URLs and for the current unbound gateway-ingress mode.
- `handle_shutdown()` clears endpoints, events, dedup IDs, ingress state, config, session, and base lifecycle flags, but request/error counters remain in memory.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Runtime has no native HTTP listener. Host-forwarded ingress through `webhook.events.ingest` is the only available delivery path.
- Manifest optional capabilities include `network.dns`, `network.egress`, and `tls.sni`, but runtime opens no outbound sockets and no inbound listener.
- Manifest and introspection both mark endpoint creation and rotation as policy-approved and deletion as interactive approval. All three require valid signed execution evidence at dispatch.
- Manifest says endpoint metadata, signing secrets, and deduplication state are stored under singleton-writer state. Runtime stores them in process memory only.
- `doctor()` currently cannot reach `ok` in the no-native-listener build because ingress listener and gateway binding remain deferred.
- `self_check()` currently cannot reach `ok` unless future gateway binding/native-listener support is added.
- Endpoint creation and rotation return signing secrets in the response; endpoint listing only returns `signing_secret_configured`.
- The connector hashes source IPs in recent-event output but stores verified event data in memory until retention eviction or shutdown.
- There is no dedicated tracked verification shell script for this connector.

Remaining work includes durable endpoint/secrets/event state, a host HTTP ingress adapter, alignment of manifest network capabilities with the no-native-listener runtime, and a live provider verification bundle.

## First-Slice Scope

The current Webhook Receiver README slice documents the existing runtime surface:

- endpoint lifecycle management
- in-process endpoint secret generation and rotation
- host-forwarded event ingestion through `webhook.events.ingest`
- provider-specific signature verification for generic HMAC, GitHub, Stripe, Slack, and Twilio styles
- content-type policy, body-size policy, rate limiting, in-flight limiting, deduplication, and redaction behavior
- lifecycle, health, doctor, self-check, simulation, introspection, and shutdown behavior
- instance-bound capability verification, signed endpoint approvals, and session invalidation
- runtime/manifest drift around native listener and persistence
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
- Host policy, revocation, holder-proof, lease fencing, and durable idempotency remain host responsibilities. Local admission does not claim a durable receipt or deduplication guarantee.
- Resource allow/deny constraints bind to the configured endpoint URLs, derived from the requested path or the stored endpoint ID. Collection reads check every endpoint they could disclose; an excluded endpoint denies the whole collection read. Health and empty collections use the configured public base URL as the namespace resource. Caller-supplied alternative resource identifiers never override these targets.
- The connector does not persist signing secrets, endpoint records, verified events, source IPs, deduplication IDs, headers, payload bodies, request counters, or error counters outside process memory.
- Webhook payloads can contain public, private, work, credential, or regulated data. Treat live event output according to the provider and endpoint zone.

## Runtime And Ingress Invariants

- No native listener is started by this connector.
- Host-forwarded ingress operation: `webhook.events.ingest`.
- Endpoint limit: `100`.
- Event retention limit: `1000` events per endpoint.
- Recent-events limit defaults to `50` and is capped at `100`.
- Endpoint paths must start with `/`.
- Endpoint paths must be unique among active endpoints.
- Endpoint provider values are `generic`, `github`, `stripe`, `slack`, and `twilio`.
- Generated secrets use URL-safe random bytes with provider prefixes:
  - generic: `whsec_`
  - GitHub: `ghsec_`
  - Stripe: `whsec_`
  - Slack: `slksec_`
  - Twilio: `twsec_`
- List endpoints does not expose signing secrets.
- Rotate secret returns the new signing secret in the operation response.
- Delete endpoint removes the endpoint and its in-memory events and dedup IDs.
- Ingest accepts only `POST`.
- Ingest requires a configured endpoint, content type, body or payload, and a valid provider signature.
- JSON content types are accepted when they are `application/json` or end in `+json`.
- Twilio also accepts `application/x-www-form-urlencoded`.
- Allowed source filters support exact IP and CIDR matches.
- Source IP is read from `source_ip`, `remote_addr`, or `client_ip`.
- Client rate keys combine endpoint path and `client_id`, source IP, or `unknown-client`.
- Rate limiting is applied before and after signature verification.
- Body timeout/cancellation inputs reject the ingest as timed out.
- Duplicate events are rejected per endpoint/event ID with a conflict response.
- Stored headers redact the endpoint signature header plus authorization, cookie, signature, secret, and token-style headers.
- Recent-event output hashes source IPs before returning them.

## Signature And Event ID Behavior

| Provider | Default header | Algorithm | Signature notes |
|----------|----------------|-----------|-----------------|
| generic | `X-Signature` | `hmac-sha256` | Hex HMAC over raw body, optional `sha256=` prefix accepted |
| github | `X-Hub-Signature-256` | `hmac-sha256` | Hex HMAC over raw body, optional `sha256=` prefix accepted |
| stripe | `Stripe-Signature` | `stripe-signature-v1` | Uses `t=` and `v1=` fields, signs `{timestamp}.{raw_body}`, enforces tolerance |
| slack | `X-Slack-Signature` | `slack-signature-v0` | Requires `X-Slack-Request-Timestamp`, signs `v0:{timestamp}:{raw_body}`, enforces tolerance |
| twilio | `X-Twilio-Signature` | `twilio-hmac-sha1` | Base64 HMAC-SHA1 over URL plus sorted form parameters |

Event ID precedence:

- input fields: `delivery_id`, `event_id`, `request_id`
- headers: `X-GitHub-Delivery`, `X-Request-ID`, `Stripe-Request-Id`, `X-Slack-Request-Id`
- payload fields: `id`, `event_id`, `eventId`, `delivery_id`, `MessageSid`, `SmsSid`, `CallSid`
- fallback: `evt_` plus a redacted hash of endpoint ID and raw body

## Operation Inventory

| Operation | Runtime behavior | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|------------------|------------|------------|-----------|-------------|----------------|
| `webhook.endpoints.create` | Create endpoint and signing secret | `webhook.endpoints.write` | `Risky` | `Medium` | `None` | `path`; optional provider/signature policy |
| `webhook.endpoints.list` | List endpoint summaries without secrets | `webhook.endpoints.read` | `Safe` | `Low` | `Strict` | none |
| `webhook.endpoints.delete` | Delete endpoint, events, and dedup IDs | `webhook.endpoints.write` | `Dangerous` | `High` | `Strict` | `endpoint_id` |
| `webhook.endpoints.rotate_secret` | Replace endpoint signing secret | `webhook.endpoints.write` | `Risky` | `High` | `None` | `endpoint_id`; optional `signing_secret` |
| `webhook.events.ingest` | Verify and record one host-forwarded delivery | `webhook.events.write` | `Risky` | `Medium` | `BestEffort` | `path`, headers, body or payload |
| `webhook.events.recent` | Return recent verified events | `webhook.events.read` | `Safe` | `Low` | `Strict` | optional `endpoint_id`, `limit`, `since_ts` |
| `webhook.health` | Return config, endpoint, event, and ingress state | `webhook.endpoints.read` | `Safe` | `Low` | `Strict` | none |

## Explicit Non-Goals

The current implementation does not include:

- native HTTP listener startup, TLS termination, DNS management, public tunnel provisioning, gateway binding, or direct provider subscription setup
- durable event queueing, durable replay, dead-letter queues, retry workers, cursor persistence, or cross-process deduplication
- outbound provider API calls, provider webhook registration, provider secret rotation through remote APIs, or provider-specific subscription discovery
- arbitrary content-type support, streaming body reads, multipart handling, file upload persistence, or large body storage
- response customization for providers, webhook delivery sending, retry callback endpoints, or bidirectional webhook workflows
- per-endpoint zone routing, per-endpoint data retention policy, or secret vault integration
- long-term audit storage, PII classification, payload redaction beyond selected headers, or encrypted local persistence

These are excluded on purpose:

- Public ingress and durable event retention are security-sensitive host responsibilities.
- Webhook payloads frequently contain sensitive account, message, billing, or credential-adjacent data.
- Endpoint secret creation and rotation need explicit policy before this connector can safely become a durable ingress manager.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configured/unconfigured state, session ID, endpoint counts, event counts, ingress state, request counters, and error counters
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

## Source Notes

- `connectors/webhook-receiver/src/connector.rs` defines configuration parsing, lifecycle handlers, endpoint operations, ingest dispatch, introspection, simulation, health, doctor, and self-check.
- `connectors/webhook-receiver/src/client.rs` defines in-memory endpoint/event storage, signature verification, body parsing, rate limiting, in-flight accounting, source filtering, event ID extraction, and redaction behavior.
- `connectors/webhook-receiver/src/types.rs` defines endpoint, event, provider, signature, config, and introspection shapes.
- `connectors/webhook-receiver/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/webhook-receiver/manifest.toml` defines the manifest operation catalog, ingress/network intent, sandbox boundary, zone policy, approval intent, and state intent.
- `connectors/webhook-receiver/tests/integration.rs` contains the runtime contract proof surface.

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

## Operator Guidance

- Treat this connector as a host-forwarded in-memory webhook receiver, not as a public listener.
- Use production `https` public base URLs for non-local endpoints.
- Keep endpoint secrets in a credential manager; endpoint create and rotate responses expose the active secret once.
- Configure an independent approval public key and provide a signed execution approval for endpoint creation, deletion, and secret rotation.
- Do not rely on `doctor()` or `self_check()` reaching `ok` in the current no-native-listener build.
- Keep event retention expectations low; events and deduplication IDs are process-memory state.
