# Stripe Connector V3 Contract

> **Status**: PROVEN runtime contract documented; operation metadata is manifest-derived
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/stripe_connector_verification.sh`
> **Stripe API upstream**: https://docs.stripe.com/api
> **Stripe auth upstream**: https://docs.stripe.com/api/authentication
> **Stripe idempotency upstream**: https://docs.stripe.com/api/idempotent_requests
> **Stripe PaymentIntents upstream**: https://docs.stripe.com/api/payment_intents
> **Stripe webhook signatures upstream**: https://docs.stripe.com/webhooks/signature

## Purpose

This document fixes the operator-facing contract for `fcp.stripe`. The connector exposes the Stripe REST API surface implemented in this crate: customers, payment intents, refunds, subscriptions, invoices, balance, and host-forwarded webhook event ingestion.

The connector is intentionally a bounded payments bridge. It is not a Checkout Session client, Connect platform manager, product/price catalog manager, dispute workflow, payout manager, tax engine, billing portal, event destination manager, live webhook HTTP listener, or connector-local credential vault.

## Current Runtime Snapshot

The current crate exposes these operations:

- `stripe.create_customer`
- `stripe.get_customer`
- `stripe.list_customers`
- `stripe.update_customer`
- `stripe.delete_customer`
- `stripe.create_payment_intent`
- `stripe.get_payment_intent`
- `stripe.confirm_payment_intent`
- `stripe.capture_payment_intent`
- `stripe.cancel_payment_intent`
- `stripe.create_refund`
- `stripe.create_subscription`
- `stripe.get_subscription`
- `stripe.list_subscriptions`
- `stripe.cancel_subscription`
- `stripe.list_invoices`
- `stripe.get_invoice`
- `stripe.get_balance`
- `stripe.ingest_webhook_event`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-stripe`.
- Runtime `BaseConnector` ID is `stripe`.
- Manifest connector ID is `fcp.stripe`.
- Configuration requires exactly one auth source:
  - `secret_key`
  - `credential_id`
- `credential_id` must be a valid UUID.
- Default API URL is `https://api.stripe.com/v1`.
- Direct-secret mode sends `Authorization: Bearer <secret_key>`.
- `credential_id` mode sends no Stripe auth header; it expects the host egress proxy to inject credentials.
- Direct-secret mode pins live requests to `https://api.stripe.com/v1`; loopback is accepted only in test/debug builds.
- Credential-reference mode accepts HTTPS custom URLs for egress-proxy routing, plus loopback for deterministic tests.
- All configured API URLs reject userinfo, query strings, and fragments.
- Runtime reqwest timeout is `30 seconds`.
- Runtime request context timeout is `30 seconds`.
- Runtime retry policy uses `max_retries = 2`.
- Runtime `invoke` uses `operation`, not `operation_id`.
- Runtime verifies a bound capability token before provider dispatch.
- Runtime resource bindings use `stripe:account:self` or object-shaped URIs such as `stripe:customer:{id}`, `stripe:payment_intent:{id}`, `stripe:subscription:{id}`, and `stripe:invoice:{id}`.
- Side-effect operations include an `audit` object with `operation`, `side_effect`, `idempotency_key`, and `resource_id`.
- Side-effect operations accept explicit `idempotency_key`, or derive one from top-level `operation_id` or `request_id`.
- `stripe.ingest_webhook_event` requires the original raw payload string, `stripe_signature`, configured `webhook_signing_secret`, and optional `received_at`/`delivery_id`.
- Webhook replay protection is process-local and keyed by Stripe `event.id`, not the optional host `delivery_id`.
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.
- `health()` is local state and metrics only.
- `self_check()` calls `GET /balance` only in direct-secret mode and degrades in `credential_id` mode.
- `handle_shutdown()` shuts down the client runtime but does not clear connector configuration.

## Remaining Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Runtime handshake advertises streaming/replay event caps, while introspection exposes no events and no event caps.
- Manifest marks mutating payment/customer operations as `policy` or `interactive`, and runtime introspection now reports those manifest approval modes. The invoke path still checks no approval token.
- Official Stripe examples use form-style request parameters for API calls; this runtime currently sends JSON bodies for create/update/confirm/capture/cancel/refund/subscription operations.
- Official Stripe idempotency guidance says all `POST` requests accept idempotency keys and `GET`/`DELETE` idempotency keys have no effect. Runtime derives or forwards idempotency keys for some delete operations as well.
- `stripe.ingest_webhook_event` validates Stripe signatures inside the connector, but the connector does not open an HTTP listener, register Stripe webhook endpoints, or persist delivery state.
- Webhook replay protection stores only in-memory event IDs and evicts by tolerance window and cache size.
- List operations expose only narrow filters and `limit`; they do not expose full Stripe pagination cursors, search endpoints, expand parameters, or API version selection.
- Manifest says connector format is `wasi`; the current Rust crate is a normal package/bin using reqwest and the FCP runtime helpers.
- `connectors/stripe/tests/local_non_mock.rs` exercises the production connector invoke path against a deterministic loopback Stripe fixture for read, write, and payment/refund operations.

A follow-up enforcement bead should add approval-token checks, decide whether JSON request bodies are an intentional Stripe facade or live API drift, reconcile idempotency behavior for DELETE paths, add pagination/search/expand support if needed, and decide whether the loopback acceptance fixture should grow into Stripe CLI replay.

## First-Slice Scope

The current Stripe README slice documents the existing runtime surface:

- direct secret-key and host credential-reference configuration
- API URL policy, auth mode, timeout, retry, provider error, and idempotency behavior
- customer, payment intent, refund, subscription, invoice, balance, and webhook-ingest operations
- bound capability-token verification and resource URI binding during both `invoke` and `simulate`
- doctor, health, self-check, simulate, introspect, shutdown, redaction posture, and deterministic tests
- runtime/manifest drift around approvals, event caps, form encoding, idempotency, and webhook persistence

## Auth And Zone Boundary

- Authentication mechanisms: Stripe secret key or host credential reference.
- Runtime does not implement Stripe OAuth, Connect account selection, restricted-key provisioning, API-key rotation, account-link creation, client-side publishable-key flows, or connector-local credential vaulting.
- Home zone: `z:private`.
- Allowed source zones: `z:owner` and `z:private`.
- Allowed target zone: `z:private`.
- Forbidden zones: `z:public` and `z:work`.
- Capability families:
  - `stripe.read`
  - `stripe.write`
  - `stripe.payment`
  - `stripe.webhook`
- Stripe payloads can include card-adjacent payment metadata, customer emails, invoice details, subscription state, billing addresses, business revenue, provider error messages, and live payment state. Do not log secret keys, webhook secrets, full customer objects, full invoice bodies, raw webhook payloads, signature headers, or provider error bodies in shared artifacts.

## Network And Runtime Invariants

- Default runtime API URL: `https://api.stripe.com/v1`.
- Live production host: `api.stripe.com`.
- Live port: `443`.
- Runtime HTTP endpoints:
  - `POST /customers`
  - `GET /customers/{id}`
  - `GET /customers?limit=...&email=...`
  - `POST /customers/{id}`
  - `DELETE /customers/{id}`
  - `POST /payment_intents`
  - `GET /payment_intents/{id}`
  - `POST /payment_intents/{id}/confirm`
  - `POST /payment_intents/{id}/capture`
  - `POST /payment_intents/{id}/cancel`
  - `POST /refunds`
  - `POST /subscriptions`
  - `GET /subscriptions/{id}`
  - `GET /subscriptions?customer=...&status=...&limit=...`
  - `DELETE /subscriptions/{id}`
  - `GET /invoices/{id}`
  - `GET /invoices?customer=...&limit=...`
  - `GET /balance`
- Runtime sends direct secret auth as bearer auth.
- Runtime path segments are percent-encoded.
- Runtime maps 401/403 to unauthorized, 404 to not found, 429 to retryable rate-limit using `Retry-After` with a 60 second default, server failures to retryable API errors, and other non-success responses to provider API errors.
- Runtime parses successful JSON responses and treats empty non-error bodies as JSON parse failures except where provider fixtures return JSON.
- Manifest live-operation policy requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, and allows `api.stripe.com` on port 443.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `stripe.read` | Read customers, payment intents, subscriptions, invoices, and balance. |
| `stripe.write` | Create/update/delete customer records. |
| `stripe.payment` | Create, confirm, capture, cancel, refund, create subscription, and cancel subscription. |
| `stripe.webhook` | Verify and ingest host-forwarded Stripe webhook payloads. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|----------------|------------|------------|-----------|-------------|----------------|
| `stripe.create_customer` | `POST /customers` | `stripe.write` | `Risky` | `Medium` | `Strict` | `email`; optional `name`, `idempotency_key`. |
| `stripe.get_customer` | `GET /customers/{id}` | `stripe.read` | `Safe` | `Low` | `Strict` | `customer_id`. |
| `stripe.list_customers` | `GET /customers` | `stripe.read` | `Safe` | `Low` | `Strict` | Optional `limit`, `email`. |
| `stripe.update_customer` | `POST /customers/{id}` | `stripe.write` | `Risky` | `Medium` | `Strict` | `customer_id`; at least one of `email` or `name`. |
| `stripe.delete_customer` | `DELETE /customers/{id}` | `stripe.write` | `Dangerous` | `High` | `Strict` | `customer_id`; optional `idempotency_key`. |
| `stripe.create_payment_intent` | `POST /payment_intents` | `stripe.payment` | `Dangerous` | `High` | `Strict` | `amount`, `currency`; optional `customer`. |
| `stripe.get_payment_intent` | `GET /payment_intents/{id}` | `stripe.read` | `Safe` | `Low` | `Strict` | `payment_intent_id`. |
| `stripe.confirm_payment_intent` | `POST /payment_intents/{id}/confirm` | `stripe.payment` | `Dangerous` | `High` | `Strict` | `payment_intent_id`; optional `payment_method`. |
| `stripe.capture_payment_intent` | `POST /payment_intents/{id}/capture` | `stripe.payment` | `Dangerous` | `High` | `Strict` | `payment_intent_id`; optional `amount_to_capture`. |
| `stripe.cancel_payment_intent` | `POST /payment_intents/{id}/cancel` | `stripe.payment` | `Dangerous` | `High` | `Strict` | `payment_intent_id`; optional `cancellation_reason`. |
| `stripe.create_refund` | `POST /refunds` | `stripe.payment` | `Dangerous` | `High` | `Strict` | `payment_intent`; optional `amount`. |
| `stripe.create_subscription` | `POST /subscriptions` | `stripe.payment` | `Dangerous` | `High` | `Strict` | `customer`, `price`; optional `idempotency_key`. |
| `stripe.get_subscription` | `GET /subscriptions/{id}` | `stripe.read` | `Safe` | `Low` | `Strict` | `subscription_id`. |
| `stripe.list_subscriptions` | `GET /subscriptions` | `stripe.read` | `Safe` | `Low` | `Strict` | Optional `customer`, `status`, `limit`. |
| `stripe.cancel_subscription` | `DELETE /subscriptions/{id}` | `stripe.payment` | `Dangerous` | `High` | `Strict` | `subscription_id`; optional `idempotency_key`. |
| `stripe.list_invoices` | `GET /invoices` | `stripe.read` | `Safe` | `Low` | `Strict` | Optional `customer`, `limit`. |
| `stripe.get_invoice` | `GET /invoices/{id}` | `stripe.read` | `Safe` | `Low` | `Strict` | `invoice_id`. |
| `stripe.get_balance` | `GET /balance` | `stripe.read` | `Safe` | `Low` | `Strict` | None. |
| `stripe.ingest_webhook_event` | local signature verification, no provider egress | `stripe.webhook` | `Risky` | `Medium` | `Strict` | `payload`, `stripe_signature`; optional `received_at`, `delivery_id`. |

## Resource URIs

Runtime capability-token verification binds operations to these resource URI shapes:

| Operation family | Resource URI shape |
|------------------|--------------------|
| Account-level reads/lists | `stripe:account:self` |
| Customer operations | `stripe:customer:{customer_id}` |
| Payment intent operations | `stripe:payment_intent:{payment_intent_id}` |
| Refund creation | `stripe:payment_intent:{payment_intent}` |
| Subscription operations | `stripe:subscription:{subscription_id}` or `stripe:customer:{customer}` |
| Invoice operations | `stripe:invoice:{invoice_id}` or `stripe:customer:{customer}` |
| Webhook ingest | signed object URI when known, such as `stripe:invoice:{id}`, otherwise `stripe:event:{event_id}` |

## Explicit Non-Goals

The current implementation does not include:

- Checkout Sessions, Prices, Products, Coupons, Promotion Codes, Tax, Billing Portal, Quotes, Payouts, Disputes, Mandates, SetupIntents, PaymentMethods, Transfers, Connect accounts, Terminal, Treasury, or Radar operations
- payment method collection, 3DS/browser confirmation flows, customer portal sessions, hosted invoices, or client-side publishable-key flows
- Stripe API version configuration, response expansion, search endpoints, full pagination cursors, connected-account headers, restricted-key provisioning, or API-key rotation
- webhook endpoint registration, inbound HTTP serving, durable webhook replay, persistent event cursoring, event fanout, or event destination management
- connector-local storage of secrets, customers, invoices, payment objects, subscriptions, webhook payloads, replay state, counters, or provider responses beyond process memory

These are excluded on purpose:

- Payment and refund operations can move money or alter customer billing state.
- Customer, invoice, and subscription payloads are private-zone data.
- Webhook replay and event fanout need durable host-level storage before production claims are safe.
- Live Stripe parity for form encoding and DELETE idempotency needs explicit confirmation before broadening the runtime surface.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration, client, auth mode, endpoint policy, credential-injection, and handshake state
- in-memory request/error counters
- direct-secret self-check through `GET /balance`
- degraded credential-reference self-check until the egress proxy injects credentials
- operation metadata, schemas, capabilities, risk levels, safety tiers, idempotency classes, and agent hints
- bound capability-token verification during `invoke` and `simulate`
- provider/FCP error mapping and secret redaction

The deterministic integration evidence is anchored on connector-local tests covering:

- configuration validation, auth-mode redaction, API URL policy, loopback allowance, doctor, health, self-check, handshake, introspection, simulation, and shutdown behavior
- customer, payment intent, refund, subscription, invoice, balance, and webhook-ingest paths through deterministic fixtures
- bound capability-token success and rejection, missing fields, unknown operations, resource URI binding, and idempotency-key derivation
- webhook signature parsing, tolerance checks, replay rejection, delivery-ID substitution rejection, payload size limits, and redacted signature failures
- provider 401, 403, 404, 429, 500, transport, JSON, and API error classes

## Source Notes

- `connectors/stripe/src/connector.rs` defines configuration parsing, endpoint policy, lifecycle handlers, diagnostics, introspection, simulation, bound capability verification, resource URI binding, idempotency derivation, webhook signature verification, replay cache, and invoke dispatch.
- `connectors/stripe/src/client.rs` defines Stripe REST request construction, auth behavior, retry dispatch, timeout configuration, path/query encoding, JSON request bodies, and provider error mapping.
- `connectors/stripe/src/types.rs` defines Stripe customer, payment intent, refund, subscription, invoice, balance, deleted-object, list, and webhook event shapes.
- `connectors/stripe/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/stripe/src/limits.rs` defines webhook payload and replay-cache bounds.
- `connectors/stripe/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, event caps, and rate-limit pools.
- `connectors/stripe/tests/integration.rs`, `connectors/stripe/tests/conformance_contract.rs`, `connectors/stripe/tests/local_non_mock.rs`, and `connectors/stripe/tests/live_verification.rs` cover deterministic HTTP behavior, contract assertions, local loopback acceptance, and opt-in live proof.

## Verification Bundle

The closeout surface is the verifier, crate-local test suite, and fail-closed
`fwc proof run` evidence for Cargo-backed `rch` proof commands. The verifier
writes proof-governor artifacts under `${OUT_ROOT}/proof`. Only
`accepted_remote_proof` rows in `*.rch_remote_proof.jsonl` are green closeout
evidence for Cargo-backed steps. `refused_local_fallback`, `infra_blocked`,
`remote_command_failed`, `failed_closed`, `not_proof`, or a missing proof row
keep the batch bead open. `format_check` is a source-state check, not accepted
remote Cargo proof.

Run these after changing this connector contract:

```bash
scripts/e2e/stripe_connector_verification.sh
PROOF_GOVERNOR=1 scripts/e2e/stripe_connector_verification.sh
FWC_BIN=/path/to/current/target/debug/fwc PROOF_GOVERNOR=1 scripts/e2e/stripe_connector_verification.sh
git diff --check -- connectors/stripe/README.md
ubs connectors/stripe/README.md
LC_ALL=C rg -n '[^ -~]' connectors/stripe/README.md
rg -n '\bmaster\b' connectors/stripe/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-stripe
rch exec -- cargo check -p fcp-stripe --all-targets
rch exec -- cargo clippy -p fcp-stripe --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

For opt-in live verification, inspect `connectors/stripe/tests/live_verification.rs` and run only against a dedicated Stripe test-mode account.

The tracked verifier skips live Stripe tests by default. To include that lane, set `STRIPE_RUN_LIVE_TESTS=1` and provision `STRIPE_SECRET_KEY` in the worker environment; the script passes only `FCP_LIVE_SANDBOX=1` on the command line so secret keys do not appear in proof argv.

## Operator Guidance

Rerun commands:

```bash
scripts/e2e/stripe_connector_verification.sh
scripts/graduation/run_gauntlet.sh connectors/stripe
```

- Use a Stripe test-mode account for mutation proof.
- Prefer `credential_id` mode when host policy should own the secret key.
- Treat all `stripe.payment` operations as approval-gated until runtime approval enforcement is aligned with the manifest.
- Use explicit idempotency keys for money-moving POST operations and avoid sensitive material in idempotency keys.
- Pass the exact raw webhook payload string and Stripe signature header for webhook ingest; parsed/reformatted JSON invalidates signature verification.
- Keep webhook signing secrets and secret keys out of logs. The connector redacts its own auth debug output, but provider fixtures and operator transcripts still need manual care.
