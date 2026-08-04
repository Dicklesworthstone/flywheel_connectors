# Square Connector V3 Guide

> **Status**: implementation-reviewed and verification-oriented
> **Beads**: `flywheel_connectors-j05nu.6.3.1`, `flywheel_connectors-j05nu.6.3.2`, `flywheel_connectors-j05nu.6.3.3`
> **Verification script**: `scripts/e2e/square_connector_verification.sh`
> **Primary upstream**: https://developer.squareup.com/reference/square

## Purpose

This guide fixes the accepted first V3 slice for `fcp.square` and records the verification bundle that proves the runtime, manifest, doctor output, and operator guidance stay truthful.

The connector is a merchant-scoped request-response Square REST connector for payments, refunds, orders, catalog reads, customer reads, location discovery, and connectivity verification.

## Current Runtime Snapshot

The current crate already exposes these operations:

- `square.payments.list`
- `square.payments.get`
- `square.payments.create`
- `square.payments.refund`
- `square.orders.list`
- `square.orders.get`
- `square.orders.create`
- `square.catalog.list`
- `square.customers.list`
- `square.customers.get`
- `square.locations.list`
- `square.health`

Important truths from `connector.rs`, `client.rs`, and `manifest.toml`:

- Configuration is `base_url`, `access_token`, retry policy, and bounded `request_timeout_ms`.
- One connector instance is bound to one injected Square bearer token.
- The token can be a personal access token or a seller OAuth token that was provisioned out of band.
- Runtime introspection derives operation descriptions, schemas, capabilities, risk levels, safety tiers, idempotency classes, approval modes, and AI hints from the strict `manifest.toml`.
- The live runtime is request-response only. It does not expose webhook ingest, event streaming, or long-lived subscriptions.
- The connector is merchant-scoped, but location-sensitive workflows still matter. `square.orders.list` requires explicit `location_ids`, `square.orders.create` requires one `location_id`, and `square.payments.create` can optionally rely on Square's main-location default if `location_id` is omitted.
- `square.health` and `self_check()` are tied to the Locations API, which makes location visibility part of the readiness boundary.
- The current implementation already excludes invoice operations, inventory adjustments, catalog mutation, customer mutation, and OAuth installation flows.
- `health`, `doctor`, and `self_check` now surface verification script paths, artifact-root hints, provisioning state, operator guidance, manifest hashes, and live probe evidence.

## Accepted First Slice

The accepted first slice is the currently implemented merchant-scoped REST surface:

- payments: list, get, create, refund
- orders: list, get, create
- catalog: list
- customers: list, get
- locations: list
- health and self-check

This is intentionally narrower than "all of Square commerce". The point of the first slice is to expose one truthful seller-token boundary with clear risk semantics, not to model every Square product family.

## Auth And Scope Boundary

- One connector instance maps to one Square seller boundary.
- Accepted credentials are:
  - a production or sandbox personal access token
  - a production or sandbox seller OAuth access token obtained outside the connector
- The connector does not run OAuth install, code exchange, refresh, revocation, or merchant discovery workflows.
- Token environment and API base URL must match:
  - production token -> `https://connect.squareup.com/v2`
  - sandbox token -> `https://connect.squareupsandbox.com/v2`
- Merchant scope and location scope are related but not identical:
  - the token identifies the seller boundary
  - many operations still require explicit `location_id` or `location_ids`
  - Square's Locations docs note that some APIs such as `CreatePayment` use the seller's main location if a location is omitted

## Network And Runtime Invariants

- Production REST base URL: `https://connect.squareup.com/v2`
- Sandbox REST base URL: `https://connect.squareupsandbox.com/v2`
- Deterministic verification may use a localhost `/v2` override, but live operator guidance and doctor remediation still treat the two canonical Square hosts as the accepted production and sandbox targets
- TLS and SNI are required for live traffic
- Runtime is stateless aside from in-memory configuration and HTTP client state
- No inbound listeners, browser steps, or webhook receivers are part of this slice

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `square.locations.read` | Read the visible seller locations and run readiness probes |
| `square.payments.read` | List and inspect payments |
| `square.payments.write` | Create payments and refunds |
| `square.orders.read` | Search and inspect orders |
| `square.orders.write` | Create orders |
| `square.catalog.read` | List catalog objects |
| `square.customers.read` | List and inspect customer records |

## Accepted Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Notes |
|-----------|----------------|------------|------------|-----------|-------------|-------|
| `square.health` | `GET /locations` | `square.locations.read` | `Safe` | `Low` | `Strict` | Auth and reachability probe tied to seller-visible locations. |
| `square.locations.list` | `GET /locations` | `square.locations.read` | `Safe` | `Low` | `Strict` | Enumerates visible business locations for downstream workflows. |
| `square.payments.list` | `GET /payments` | `square.payments.read` | `Safe` | `Low` | `Strict` | Optional cursor and location filter. |
| `square.payments.get` | `GET /payments/{payment_id}` | `square.payments.read` | `Safe` | `Low` | `Strict` | Canonical point lookup. |
| `square.payments.create` | `POST /payments` | `square.payments.write` | `Risky` | `High` | `Strict` | Real-money side effects; requires interactive approval. |
| `square.payments.refund` | `POST /refunds` | `square.payments.write` | `Risky` | `High` | `Strict` | Real-money reversal; requires interactive approval. |
| `square.orders.list` | `POST /orders/search` | `square.orders.read` | `Safe` | `Low` | `Strict` | Requires explicit `location_ids`. |
| `square.orders.get` | `GET /orders/{order_id}` | `square.orders.read` | `Safe` | `Low` | `Strict` | Canonical point lookup. |
| `square.orders.create` | `POST /orders` | `square.orders.write` | `Risky` | `Medium` | `BestEffort` | Creates a real order record for one location. |
| `square.catalog.list` | `GET /catalog/list` | `square.catalog.read` | `Safe` | `Low` | `Strict` | Read-only catalog enumeration. |
| `square.customers.list` | `GET /customers` | `square.customers.read` | `Safe` | `Low` | `Strict` | Read-only customer listing inside one seller boundary. |
| `square.customers.get` | `GET /customers/{customer_id}` | `square.customers.read` | `Safe` | `Low` | `Strict` | Point lookup for one customer profile. |

## Explicit Non-Goals

The accepted first slice does not include:

- invoices
- customer creation or update
- order update, fulfillment orchestration, or cancellation
- catalog upsert, image management, or inventory adjustment
- gift cards, terminal flows, disputes, payouts, subscriptions, loyalty, or staff workflows
- webhook ingestion, events, or streaming
- OAuth install, refresh, revocation, or cross-merchant brokering

Invoices are explicitly out of scope for the first slice even though Square supports them. Square's current Invoices docs require additional OAuth permissions such as `INVOICES_READ`, `INVOICES_WRITE`, `ORDERS_WRITE`, and in some flows `CUSTOMERS_READ` plus `PAYMENTS_WRITE`. That is a coupled surface area we are intentionally not collapsing into the first merchant-token contract.

## Verification Bundle

The readiness closeout is anchored on `scripts/e2e/square_connector_verification.sh`.
It writes replayable artifacts under `artifacts/e2e/square_connector/<timestamp>`.

The bundle captures:

- manifest validation for `connectors/square/manifest.toml`
- `cargo fmt --manifest-path connectors/square/Cargo.toml --check` via `rch`
- `cargo check -p fcp-square --all-targets` via `rch`
- targeted readiness evidence for `health`, `doctor`, `self_check`, payments pagination, catalog filters, and high-risk payment creation
- manifest/runtime typed introspection parity evidence
- the Square integration suite and full crate test suite
- `cargo clippy -p fcp-square --all-targets -- -D warnings` via `rch`

## Operator Guidance

Prerequisites:

- Use a dedicated Square Sandbox seller account or a localhost wiremock override before running the verification bundle against payment or order mutations.
- Provision a bearer token that can read locations, payments, orders, catalog objects, and customers for the same seller boundary the connector will operate inside.
- Confirm the configured production or sandbox host matches the token environment before live verification.

Dedicated environment:

- Prefer a Square Sandbox seller with disposable customers, locations, and catalog fixtures. `square.payments.create`, `square.payments.refund`, and `square.orders.create` mutate real merchant state unless the connector is pointed at a localhost mock server.

Redaction rules:

- Redact bearer tokens, Authorization headers, idempotency keys, and copied request or response bodies before sharing artifacts.
- Redact payment IDs, refund IDs, order IDs, location IDs, customer IDs, receipt URLs, and business names.
- If a live sandbox seller is used, sanitize location names, business metadata, and customer-facing notes captured in evidence logs.

Common remediation:

- If `self_check` fails with `square_auth_rejected`, replace the bearer token and verify it matches the configured production or sandbox environment.
- If `self_check` fails with `square_permission_denied`, grant the missing seller permissions for locations, payments, orders, catalog, and customer reads.
- If `self_check` degrades with `square_locations_missing`, verify the seller has at least one visible active location and rerun the bundle.
- If `self_check` degrades with `self_check_retryable`, respect Retry-After or widen the retry and timeout budget before rerunning.
- If doctor flags invalid network constraints, use the canonical Square REST hosts for live runs or a localhost `/v2` override for deterministic verification.

Rerun commands:

- `scripts/e2e/square_connector_verification.sh`
- `fwc manifest fix connectors/square/manifest.toml --check --json`
- `rch exec -- cargo fmt --manifest-path connectors/square/Cargo.toml --check`
- `rch exec -- cargo check -p fcp-square --all-targets`
- `rch exec -- cargo test -p fcp-square --test integration -- --nocapture`
- `rch exec -- cargo test -p fcp-square -- --nocapture`
- `rch exec -- cargo clippy -p fcp-square --all-targets -- -D warnings`

## Source Notes

This contract is grounded in the current connector implementation and current Square docs:

- `connectors/square/src/connector.rs` defines invoke routing, capability verification, deterministic operation ordering, manifest-derived runtime introspection, and readiness behavior.
- `connectors/square/src/client.rs` defines the concrete REST endpoints and confirms the one-bearer-token request model.
- `connectors/square/manifest.toml` defines the operation inventory, metadata contract, network allowlist, and current non-goal boundary.
- Square access tokens and environment mapping: https://developer.squareup.com/docs/build-basics/access-tokens
- Square Sandbox overview: https://developer.squareup.com/docs/devtools/sandbox/overview
- Square OAuth overview: https://developer.squareup.com/docs/oauth-api/overview
- Square Payments overview: https://developer.squareup.com/docs/payments-api/overview
- Square Locations API docs: https://developer.squareup.com/docs/locations-api
- Square Customers API workflows: https://developer.squareup.com/docs/customers-api/how-it-works
- Square Invoices API overview: https://developer.squareup.com/docs/invoices-api/overview
